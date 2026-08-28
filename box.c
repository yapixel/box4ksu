#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <dirent.h>
#include <grp.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>

typedef struct {
    char service_name[64];
    char work_dir[256];
    char bin_path[256];
    char pid_file[256];
    char log_dir[256];
    char log_file[256];
    char error_log[256];
    char singbox_log[256];
    char lock_dir[256];
    char run_user[64];
    char timezone[64];
    long max_log_size;
    int stop_timeout;
    int start_timeout;
    int check_config;
    long nofile_limit;
} Config;

static Config g_cfg;

#define SERVICE_NAME    g_cfg.service_name
#define WORK_DIR        g_cfg.work_dir
#define BIN_PATH        g_cfg.bin_path
#define PID_FILE        g_cfg.pid_file
#define LOG_DIR         g_cfg.log_dir
#define LOG_FILE        g_cfg.log_file
#define ERROR_LOG       g_cfg.error_log
#define SINGBOX_LOG     g_cfg.singbox_log
#define LOCK_DIR        g_cfg.lock_dir
#define RUN_USER        g_cfg.run_user
#define TIMEZONE        g_cfg.timezone
#define MAX_LOG_SIZE    g_cfg.max_log_size
#define STOP_TIMEOUT    g_cfg.stop_timeout
#define START_TIMEOUT   g_cfg.start_timeout
#define CHECK_CONFIG    g_cfg.check_config
#define NOFILE_LIMIT    g_cfg.nofile_limit

static int g_lock_acquired = 0;
static long g_tz_offset_sec = 28800; // Default +8h (CST UTC+8)
static char g_iana_tz[64] = "Asia/Shanghai";

static pid_t get_pid(void);
static void clear_pid(void);
static void release_lock(void);
static int display_status(void);
static int do_check(void);
static int start_service(void);
static int stop_service(void);
static int restart_service(void);
static int reload_service(void);

// ================= String & Path Utilities =================

static char *trim_str(char *str) {
    if (!str) return NULL;
    while (isspace((unsigned char)*str) || *str == '"' || *str == '\'' || *str == '[' || *str == ']') str++;
    if (*str == '\0') return str;
    char *end = str + strlen(str) - 1;
    while (end > str && (isspace((unsigned char)*end) || *end == '"' || *end == '\'' || *end == '[' || *end == ']' || *end == '\r' || *end == '\n')) end--;
    end[1] = '\0';
    return str;
}

static void get_self_dir(char *dir_buf, size_t size) {
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        char *slash = strrchr(exe_path, '/');
        if (slash) {
            *slash = '\0';
            snprintf(dir_buf, size, "%s", exe_path);
            return;
        }
    }
    snprintf(dir_buf, size, ".");
}

static int get_real_path(const char *path, char *resolved, size_t size) {
    if (realpath(path, resolved) != NULL) return 0;
    snprintf(resolved, size, "%s", path);
    return -1;
}

// ================= Permission & User Utilities =================

static uid_t resolve_uid(const char *name) {
    if (!name || name[0] == '\0') return 0;
    if (isdigit((unsigned char)name[0])) return (uid_t)atoi(name);
    if (strcmp(name, "root") == 0) return 0;
    if (strcmp(name, "system") == 0) return 1000;
    if (strcmp(name, "shell") == 0) return 2000;
    if (strcmp(name, "nobody") == 0) return 9999;
    return 0;
}

static gid_t resolve_gid(const char *name) {
    if (!name || name[0] == '\0') return 0;
    if (isdigit((unsigned char)name[0])) return (gid_t)atoi(name);
    if (strcmp(name, "root") == 0) return 0;
    if (strcmp(name, "system") == 0) return 1000;
    if (strcmp(name, "shell") == 0) return 2000;
    if (strcmp(name, "inet") == 0) return 3003;
    if (strcmp(name, "net_raw") == 0) return 3004;
    if (strcmp(name, "net_admin") == 0) return 3005;
    if (strcmp(name, "net_bw_stats") == 0) return 3006;
    if (strcmp(name, "net_bw_acct") == 0) return 3007;
    if (strcmp(name, "everybody") == 0) return 9997;
    if (strcmp(name, "nobody") == 0) return 9999;
    return 0;
}

static int apply_credentials(const char *user_spec) {
    if (!user_spec || user_spec[0] == '\0') return 0;
    if (strcmp(user_spec, "root") == 0 || strcmp(user_spec, "root:root") == 0 || strcmp(user_spec, "0:0") == 0) return 0;

    char spec_copy[64];
    snprintf(spec_copy, sizeof(spec_copy), "%s", user_spec);

    char *colon = strchr(spec_copy, ':');
    char *user_part = spec_copy;
    char *group_part = NULL;

    if (colon) {
        *colon = '\0';
        group_part = colon + 1;
    }

    uid_t target_uid = resolve_uid(user_part);
    gid_t target_gid = (group_part && group_part[0] != '\0') ? resolve_gid(group_part) : (gid_t)target_uid;

    gid_t groups[4];
    int group_count = 0;
    groups[group_count++] = target_gid;

    if (target_gid == 3005) { // AID_NET_ADMIN
        groups[group_count++] = 3003; // AID_INET
        groups[group_count++] = 3004; // AID_NET_RAW
    }

    setgroups(group_count, groups);
    if (setresgid(target_gid, target_gid, target_gid) != 0) setgid(target_gid);
    if (setresuid(target_uid, target_uid, target_uid) != 0) setuid(target_uid);

    return 0;
}

// ================= Configuration & INI Parser =================

static void expand_vars(char *dst, size_t dst_size, const char *src) {
    char temp[256];
    size_t di = 0, si = 0, len = strlen(src);
    while (si < len && di < sizeof(temp) - 1) {
        if (src[si] == '$') {
            if (strncmp(src + si, "${SERVICE_NAME}", 15) == 0) {
                size_t vlen = strlen(g_cfg.service_name);
                if (di + vlen < sizeof(temp) - 1) {
                    memcpy(temp + di, g_cfg.service_name, vlen);
                    di += vlen; si += 15; continue;
                }
            } else if (strncmp(src + si, "$SERVICE_NAME", 13) == 0) {
                size_t vlen = strlen(g_cfg.service_name);
                if (di + vlen < sizeof(temp) - 1) {
                    memcpy(temp + di, g_cfg.service_name, vlen);
                    di += vlen; si += 13; continue;
                }
            } else if (strncmp(src + si, "${WORK_DIR}", 11) == 0) {
                size_t vlen = strlen(g_cfg.work_dir);
                if (di + vlen < sizeof(temp) - 1) {
                    memcpy(temp + di, g_cfg.work_dir, vlen);
                    di += vlen; si += 11; continue;
                }
            } else if (strncmp(src + si, "$WORK_DIR", 9) == 0) {
                size_t vlen = strlen(g_cfg.work_dir);
                if (di + vlen < sizeof(temp) - 1) {
                    memcpy(temp + di, g_cfg.work_dir, vlen);
                    di += vlen; si += 9; continue;
                }
            }
        }
        temp[di++] = src[si++];
    }
    temp[di] = '\0';
    snprintf(dst, dst_size, "%s", temp);
}

static void parse_ini_line(char *line, int *has_bin, int *has_pid, int *has_logdir, int *has_logfile, int *has_errlog, int *has_sblog, int *has_lockdir, int *has_workdir) {
    line = trim_str(line);
    if (!line || line[0] == '\0' || line[0] == '#' || line[0] == ';' || line[0] == '[') return;

    char *eq = strchr(line, '=');
    if (!eq) return;

    *eq = '\0';
    char *key = trim_str(line);
    char *val = trim_str(eq + 1);

    char *comment = strpbrk(val, "#;");
    if (comment) {
        *comment = '\0';
        val = trim_str(val);
    }

    char exp_val[256];
    expand_vars(exp_val, sizeof(exp_val), val);

    if (strcasecmp(key, "service_name") == 0) snprintf(g_cfg.service_name, sizeof(g_cfg.service_name), "%.63s", exp_val);
    else if (strcasecmp(key, "work_dir") == 0) { snprintf(g_cfg.work_dir, sizeof(g_cfg.work_dir), "%.255s", exp_val); *has_workdir = 1; }
    else if (strcasecmp(key, "bin_path") == 0) { snprintf(g_cfg.bin_path, sizeof(g_cfg.bin_path), "%.255s", exp_val); *has_bin = 1; }
    else if (strcasecmp(key, "pid_file") == 0) { snprintf(g_cfg.pid_file, sizeof(g_cfg.pid_file), "%.255s", exp_val); *has_pid = 1; }
    else if (strcasecmp(key, "log_dir") == 0) { snprintf(g_cfg.log_dir, sizeof(g_cfg.log_dir), "%.255s", exp_val); *has_logdir = 1; }
    else if (strcasecmp(key, "log_file") == 0) { snprintf(g_cfg.log_file, sizeof(g_cfg.log_file), "%.255s", exp_val); *has_logfile = 1; }
    else if (strcasecmp(key, "error_log") == 0) { snprintf(g_cfg.error_log, sizeof(g_cfg.error_log), "%.255s", exp_val); *has_errlog = 1; }
    else if (strcasecmp(key, "singbox_log") == 0 || strcasecmp(key, "service_log") == 0) { snprintf(g_cfg.singbox_log, sizeof(g_cfg.singbox_log), "%.255s", exp_val); *has_sblog = 1; }
    else if (strcasecmp(key, "lock_dir") == 0) { snprintf(g_cfg.lock_dir, sizeof(g_cfg.lock_dir), "%.255s", exp_val); *has_lockdir = 1; }
    else if (strcasecmp(key, "run_user") == 0) snprintf(g_cfg.run_user, sizeof(g_cfg.run_user), "%.63s", exp_val);
    else if (strcasecmp(key, "timezone") == 0 || strcasecmp(key, "tz") == 0) snprintf(g_cfg.timezone, sizeof(g_cfg.timezone), "%.63s", exp_val);
    else if (strcasecmp(key, "max_log_size") == 0) g_cfg.max_log_size = atol(exp_val);
    else if (strcasecmp(key, "stop_timeout") == 0) g_cfg.stop_timeout = atoi(exp_val);
    else if (strcasecmp(key, "start_timeout") == 0) g_cfg.start_timeout = atoi(exp_val);
    else if (strcasecmp(key, "check_config") == 0) g_cfg.check_config = atoi(exp_val);
    else if (strcasecmp(key, "nofile_limit") == 0) g_cfg.nofile_limit = atol(exp_val);
}

// ================= Android Property & Timezone =================

static int get_android_prop(const char *prop_name, char *out_val, size_t out_len) {
    if (!prop_name || !out_val || out_len == 0) return -1;
    out_val[0] = '\0';

    int pipe_fd[2];
    if (pipe(pipe_fd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipe_fd[1]);

        char *const argv1[] = {"/system/bin/getprop", (char *)prop_name, NULL};
        char *const argv2[] = {"/vendor/bin/getprop", (char *)prop_name, NULL};
        char *const argv3[] = {"getprop", (char *)prop_name, NULL};

        execv("/system/bin/getprop", argv1);
        execv("/vendor/bin/getprop", argv2);
        execvp("getprop", argv3);
        _exit(127);
    }

    close(pipe_fd[1]);

    ssize_t total = 0;
    char buf[128];
    while (total < (ssize_t)sizeof(buf) - 1) {
        ssize_t n = read(pipe_fd[0], buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    close(pipe_fd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    char *p = trim_str(buf);
    if (p && p[0] != '\0') {
        snprintf(out_val, out_len, "%s", p);
        return 0;
    }
    return -1;
}

static long parse_offset_string(const char *s) {
    if (!s || s[0] == '\0') return 0;
    while (isspace((unsigned char)*s)) s++;
    if (strncasecmp(s, "UTC", 3) == 0 || strncasecmp(s, "GMT", 3) == 0) s += 3;
    while (isspace((unsigned char)*s)) s++;

    int sign = 1;
    if (*s == '+') { sign = 1; s++; }
    else if (*s == '-') { sign = -1; s++; }
    else if (isdigit((unsigned char)*s)) { sign = 1; }
    else return 0;

    int hours = 0, mins = 0;
    if (strchr(s, ':')) {
        if (sscanf(s, "%d:%d", &hours, &mins) < 1) return 0;
    } else {
        int val = atoi(s);
        if (strlen(s) >= 3 || val >= 100 || val <= -100) {
            hours = abs(val) / 100;
            mins = abs(val) % 100;
        } else {
            hours = abs(val);
            mins = 0;
        }
    }
    return sign * ((long)hours * 3600 + (long)mins * 60);
}

static long get_tz_offset_from_name(const char *tz_name) {
    if (!tz_name || tz_name[0] == '\0') return 28800;

    if (strcasecmp(tz_name, "Asia/Shanghai") == 0 || strcasecmp(tz_name, "Asia/Chongqing") == 0 ||
        strcasecmp(tz_name, "Asia/Harbin") == 0 || strcasecmp(tz_name, "Asia/Urumqi") == 0 ||
        strcasecmp(tz_name, "Asia/Kashgar") == 0 || strcasecmp(tz_name, "Asia/Hong_Kong") == 0 ||
        strcasecmp(tz_name, "Asia/Macau") == 0 || strcasecmp(tz_name, "Asia/Taipei") == 0 ||
        strcasecmp(tz_name, "Asia/Singapore") == 0 || strcasecmp(tz_name, "Asia/Kuala_Lumpur") == 0 ||
        strcasecmp(tz_name, "Asia/Manila") == 0 || strcasecmp(tz_name, "Asia/Perth") == 0 ||
        strcasecmp(tz_name, "Asia/Brunei") == 0 || strcasecmp(tz_name, "Asia/Makassar") == 0 ||
        strcasecmp(tz_name, "PRC") == 0 || strcasecmp(tz_name, "China") == 0 ||
        strcasecmp(tz_name, "CST") == 0 || strcasecmp(tz_name, "CST-8") == 0 || strcasecmp(tz_name, "Etc/GMT-8") == 0) {
        return 28800;
    }
    if (strcasecmp(tz_name, "Asia/Tokyo") == 0 || strcasecmp(tz_name, "Asia/Seoul") == 0 ||
        strcasecmp(tz_name, "JST") == 0 || strcasecmp(tz_name, "KST") == 0 || strcasecmp(tz_name, "Etc/GMT-9") == 0) {
        return 32400;
    }
    if (strcasecmp(tz_name, "Asia/Bangkok") == 0 || strcasecmp(tz_name, "Asia/Jakarta") == 0 ||
        strcasecmp(tz_name, "Asia/Ho_Chi_Minh") == 0 || strcasecmp(tz_name, "Etc/GMT-7") == 0) {
        return 25200;
    }
    if (strcasecmp(tz_name, "Asia/Kolkata") == 0 || strcasecmp(tz_name, "Asia/Calcutta") == 0 || strcasecmp(tz_name, "IST") == 0) {
        return 19800;
    }
    if (strcasecmp(tz_name, "Asia/Dubai") == 0 || strcasecmp(tz_name, "GST") == 0) {
        return 14400;
    }
    if (strcasecmp(tz_name, "Europe/London") == 0 || strcasecmp(tz_name, "UTC") == 0 ||
        strcasecmp(tz_name, "GMT") == 0 || strcasecmp(tz_name, "Universal") == 0 ||
        strcasecmp(tz_name, "Zulu") == 0 || strcasecmp(tz_name, "Etc/UTC") == 0 || strcasecmp(tz_name, "Etc/GMT") == 0) {
        return 0;
    }
    if (strcasecmp(tz_name, "Europe/Berlin") == 0 || strcasecmp(tz_name, "Europe/Paris") == 0 ||
        strcasecmp(tz_name, "Europe/Rome") == 0 || strcasecmp(tz_name, "Europe/Madrid") == 0 ||
        strcasecmp(tz_name, "CET") == 0 || strcasecmp(tz_name, "Etc/GMT-1") == 0) {
        return 3600;
    }
    if (strcasecmp(tz_name, "America/New_York") == 0 || strcasecmp(tz_name, "EST") == 0) return -18000;
    if (strcasecmp(tz_name, "America/Chicago") == 0 || strcasecmp(tz_name, "CDT") == 0) return -21600;
    if (strcasecmp(tz_name, "America/Denver") == 0 || strcasecmp(tz_name, "MST") == 0) return -25200;
    if (strcasecmp(tz_name, "America/Los_Angeles") == 0 || strcasecmp(tz_name, "PST") == 0) return -28800;

    if (strchr(tz_name, '+') || strchr(tz_name, '-') || strncasecmp(tz_name, "UTC", 3) == 0 || strncasecmp(tz_name, "GMT", 3) == 0) {
        return parse_offset_string(tz_name);
    }

    return 28800;
}

static void init_timezone(const char *custom_tz) {
    char tz_buf[64] = {0};
    
    if (custom_tz && custom_tz[0] != '\0' && strcasecmp(custom_tz, "auto") != 0) {
        snprintf(g_iana_tz, sizeof(g_iana_tz), "%.63s", custom_tz);
    } else {
        const char *env_tz = getenv("TZ");
        if (env_tz && env_tz[0] != '\0' && strcasecmp(env_tz, "auto") != 0 && strchr(env_tz, '/')) {
            snprintf(g_iana_tz, sizeof(g_iana_tz), "%.63s", env_tz);
        } else {
            char prop_tz[64] = {0};
            if (get_android_prop("persist.sys.timezone", prop_tz, sizeof(prop_tz)) == 0 && prop_tz[0] != '\0') {
                snprintf(g_iana_tz, sizeof(g_iana_tz), "%.63s", prop_tz);
            } else if (get_android_prop("ro.sys.timezone", prop_tz, sizeof(prop_tz)) == 0 && prop_tz[0] != '\0') {
                snprintf(g_iana_tz, sizeof(g_iana_tz), "%.63s", prop_tz);
            } else if (get_android_prop("ro.build.timezone", prop_tz, sizeof(prop_tz)) == 0 && prop_tz[0] != '\0') {
                snprintf(g_iana_tz, sizeof(g_iana_tz), "%.63s", prop_tz);
            } else {
                FILE *tz_file = fopen("/etc/timezone", "r");
                if (tz_file) {
                    if (fgets(tz_buf, sizeof(tz_buf), tz_file)) {
                        char *trimmed = trim_str(tz_buf);
                        if (trimmed && trimmed[0] != '\0') snprintf(g_iana_tz, sizeof(g_iana_tz), "%.63s", trimmed);
                    }
                    fclose(tz_file);
                }
            }
            if (g_iana_tz[0] == '\0') snprintf(g_iana_tz, sizeof(g_iana_tz), "Asia/Shanghai");
        }
    }

    g_tz_offset_sec = get_tz_offset_from_name(g_iana_tz);
    setenv("TZ", g_iana_tz, 1);
    tzset();
}

static void load_config(void) {
    snprintf(g_cfg.service_name, sizeof(g_cfg.service_name), "sing-box");
    g_cfg.work_dir[0] = '\0';
    snprintf(g_cfg.run_user, sizeof(g_cfg.run_user), "root:net_admin");
    g_cfg.timezone[0] = '\0';
    g_cfg.max_log_size = 1048576L;
    g_cfg.stop_timeout = 10;
    g_cfg.start_timeout = 3;
    g_cfg.check_config = 0;
    g_cfg.nofile_limit = 1000000L;

    int has_bin = 0, has_pid = 0, has_logdir = 0, has_logfile = 0, has_errlog = 0, has_sblog = 0, has_lockdir = 0, has_workdir = 0;

    char self_dir[256];
    get_self_dir(self_dir, sizeof(self_dir));

    char self_ini[300];
    snprintf(self_ini, sizeof(self_ini), "%s/box.ini", self_dir);

    const char *candidates[] = {
        "/data/adb/sing-box/box.ini",
        "/data/adb/box.ini",
        self_ini,
        "box.ini",
        NULL
    };

    for (int i = 0; candidates[i] != NULL; i++) {
        FILE *f = fopen(candidates[i], "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                parse_ini_line(line, &has_bin, &has_pid, &has_logdir, &has_logfile, &has_errlog, &has_sblog, &has_lockdir, &has_workdir);
            }
            fclose(f);
            break;
        }
    }

    if (!has_workdir || g_cfg.work_dir[0] == '\0') {
        int is_sys_bin = (strcmp(self_dir, "/system/bin") == 0 ||
                          strcmp(self_dir, "/system/xbin") == 0 ||
                          strcmp(self_dir, "/sbin") == 0 ||
                          strcmp(self_dir, "/bin") == 0 ||
                          strcmp(self_dir, "/usr/bin") == 0 ||
                          strstr(self_dir, "/ksu/bin") != NULL ||
                          strstr(self_dir, "/ap/bin") != NULL ||
                          strstr(self_dir, "/magisk") != NULL);

        if (!is_sys_bin && self_dir[0] != '\0' && strcmp(self_dir, ".") != 0) {
            snprintf(g_cfg.work_dir, sizeof(g_cfg.work_dir), "%.255s", self_dir);
        } else {
            snprintf(g_cfg.work_dir, sizeof(g_cfg.work_dir), "/data/adb/%.63s", g_cfg.service_name);
        }
    }

    if (!has_bin)     snprintf(g_cfg.bin_path, sizeof(g_cfg.bin_path), "%.180s/bin/%.60s", g_cfg.work_dir, g_cfg.service_name);
    if (!has_pid)     snprintf(g_cfg.pid_file, sizeof(g_cfg.pid_file), "%.180s/%.60s.pid", g_cfg.work_dir, g_cfg.service_name);
    if (!has_logdir)  snprintf(g_cfg.log_dir, sizeof(g_cfg.log_dir), "%.240s/logs", g_cfg.work_dir);
    if (!has_logfile) snprintf(g_cfg.log_file, sizeof(g_cfg.log_file), "%.240s/run.log", g_cfg.log_dir);
    if (!has_errlog)  snprintf(g_cfg.error_log, sizeof(g_cfg.error_log), "%.230s/run_error.log", g_cfg.log_dir);
    if (!has_sblog)   snprintf(g_cfg.singbox_log, sizeof(g_cfg.singbox_log), "%.180s/%.60s.log", g_cfg.log_dir, g_cfg.service_name);
    if (!has_lockdir) snprintf(g_cfg.lock_dir, sizeof(g_cfg.lock_dir), "%.240s/.box.lock", g_cfg.work_dir);

    init_timezone(g_cfg.timezone);
}

// ================= Logging System =================

static void ts(char *buffer, size_t size) {
    static int tz_inited = 0;
    if (!tz_inited) {
        init_timezone(g_cfg.timezone[0] != '\0' ? g_cfg.timezone : NULL);
        tz_inited = 1;
    }
    time_t now = time(NULL);
    time_t local_now = now + g_tz_offset_sec;
    struct tm tm_info;
    gmtime_r(&local_now, &tm_info);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tm_info);
}

static void rotate_log(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) != 0) return;
    if (st.st_size > MAX_LOG_SIZE) {
        char backup_path[300];
        snprintf(backup_path, sizeof(backup_path), "%s.1", filepath);
        rename(filepath, backup_path);
    }
}

static void log_msg(int is_err, const char *fmt, ...) {
    const char *target_file = is_err ? ERROR_LOG : LOG_FILE;
    rotate_log(target_file);

    char timestamp[32];
    ts(timestamp, sizeof(timestamp));

    char message[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    FILE *out = is_err ? stderr : stdout;
    const char *tag = is_err ? "[ERROR]" : "[INFO]";
    const char *color_tag = is_err ? "\033[31m[ERROR]\033[0m" : "\033[32m[INFO]\033[0m";

    if (isatty(fileno(out))) {
        fprintf(out, "[%s] %s %s\n", timestamp, color_tag, message);
    } else {
        fprintf(out, "[%s] %s %s\n", timestamp, tag, message);
    }
    fflush(out);

    FILE *f = fopen(target_file, "a");
    if (f) {
        fprintf(f, "[%s] %s %s\n", timestamp, tag, message);
        fclose(f);
    }
}

#define log_info(...)  log_msg(0, __VA_ARGS__)
#define log_error(...) log_msg(1, __VA_ARGS__)

static void show_tail(const char *filepath, int lines) {
    if (lines <= 0) lines = 10;
    FILE *f = fopen(filepath, "r");
    if (!f) {
        printf("(empty)\n");
        return;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return;
    }
    long file_size = ftell(f);
    if (file_size <= 0) {
        printf("(empty)\n");
        fclose(f);
        return;
    }

    long read_size = (file_size > 65536) ? 65536 : file_size;
    fseek(f, file_size - read_size, SEEK_SET);

    char *buf = malloc(read_size + 1);
    if (!buf) {
        fclose(f);
        return;
    }
    size_t bytes = fread(buf, 1, read_size, f);
    buf[bytes] = '\0';
    fclose(f);

    int count = 0;
    char *start = buf + bytes;
    while (start > buf) {
        start--;
        if (*start == '\n' && start != buf + bytes - 1) {
            count++;
            if (count >= lines) {
                start++;
                break;
            }
        }
    }
    printf("%s", start);
    if (bytes > 0 && buf[bytes - 1] != '\n') printf("\n");
    free(buf);
}

// ================= Process & Lock Management =================

static void create_dirs_recursive(const char *path) {
    char temp[300];
    snprintf(temp, sizeof(temp), "%s", path);
    size_t len = strlen(temp);
    if (len == 0) return;
    if (temp[len - 1] == '/') temp[len - 1] = '\0';
    for (char *p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(temp, 0755);
            *p = '/';
        }
    }
    mkdir(temp, 0755);
}

static void prepare_env(void) {
    create_dirs_recursive(WORK_DIR);
    create_dirs_recursive(LOG_DIR);
    char bin_dir[300];
    snprintf(bin_dir, sizeof(bin_dir), "%s/bin", WORK_DIR);
    create_dirs_recursive(bin_dir);

    if (geteuid() != 0 && getuid() != 0) {
        log_error("Root privileges required");
        exit(1);
    }
}

static void remove_lock_dir(void) {
    char pid_path[300];
    snprintf(pid_path, sizeof(pid_path), "%s/pid", LOCK_DIR);
    unlink(pid_path);
    rmdir(LOCK_DIR);
}

static void release_lock(void) {
    if (g_lock_acquired) {
        remove_lock_dir();
        g_lock_acquired = 0;
    }
}

static void write_lock_pid(void) {
    char pid_path[300];
    snprintf(pid_path, sizeof(pid_path), "%s/pid", LOCK_DIR);
    FILE *f = fopen(pid_path, "w");
    if (f) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }
}

static int is_lock_stale(void) {
    char pid_path[300];
    snprintf(pid_path, sizeof(pid_path), "%s/pid", LOCK_DIR);
    FILE *f = fopen(pid_path, "r");
    if (f) {
        char pbuf[32];
        if (fgets(pbuf, sizeof(pbuf), f)) {
            pid_t lock_pid = (pid_t)atoi(pbuf);
            fclose(f);
            if (lock_pid > 0) {
                if (lock_pid == getpid()) return 0;
                if (kill(lock_pid, 0) != 0 && errno == ESRCH) return 1;

                char comm_path[64];
                snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", lock_pid);
                FILE *cf = fopen(comm_path, "r");
                if (cf) {
                    char comm[64] = {0};
                    if (fgets(comm, sizeof(comm), cf)) {
                        comm[strcspn(comm, "\r\n")] = 0;
                        fclose(cf);
                        if (strstr(comm, "box") != NULL) return 0;
                    } else {
                        fclose(cf);
                    }
                }
                return 1;
            }
        } else {
            fclose(f);
        }
    }
    struct stat st;
    if (stat(LOCK_DIR, &st) == 0) {
        time_t now = time(NULL);
        if (st.st_mtime > 0 && now > st.st_mtime && (now - st.st_mtime) > 60) return 1;
    }
    return 1;
}

static void signal_lock_cleanup(int sig) {
    release_lock();
    _exit(128 + sig);
}

static void acquire_lock(void) {
    int attempts = 0;
    while (mkdir(LOCK_DIR, 0755) != 0) {
        if (is_lock_stale()) {
            remove_lock_dir();
            continue;
        }
        attempts++;
        if (attempts >= 10) {
            log_error("Another box operation is in progress, please try again later");
            exit(1);
        }
        sleep(1);
    }
    write_lock_pid();
    g_lock_acquired = 1;
    atexit(release_lock);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_lock_cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

static pid_t check_proc_pid(pid_t p) {
    if (p <= 0 || kill(p, 0) != 0) return -1;

    char expected_bin[256];
    get_real_path(BIN_PATH, expected_bin, sizeof(expected_bin));

    char exe_path[64], link_target[256];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", p);
    ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
    if (len > 0) {
        link_target[len] = '\0';
        if (strcmp(link_target, expected_bin) == 0 || strcmp(link_target, BIN_PATH) == 0) {
            return p;
        }
    }

    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", p);
    FILE *fcmd = fopen(cmdline_path, "r");
    if (fcmd) {
        char cmd_buf[512] = {0};
        size_t n = fread(cmd_buf, 1, sizeof(cmd_buf) - 1, fcmd);
        fclose(fcmd);
        if (n > 0) {
            int match_bin = (strstr(cmd_buf, SERVICE_NAME) != NULL);
            int match_dir = (WORK_DIR[0] != '\0' && memmem(cmd_buf, n, WORK_DIR, strlen(WORK_DIR)) != NULL);
            if (match_bin && match_dir) return p;
        }
    }

    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", p);
    FILE *fcomm = fopen(comm_path, "r");
    if (fcomm) {
        char comm_buf[64] = {0};
        if (fgets(comm_buf, sizeof(comm_buf), fcomm)) {
            comm_buf[strcspn(comm_buf, "\r\n")] = 0;
            if (strcmp(comm_buf, SERVICE_NAME) == 0 && len <= 0) {
                fclose(fcomm);
                return p;
            }
        }
        fclose(fcomm);
    }
    return -1;
}

static pid_t scan_proc_for_service(void) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    struct dirent *entry;
    pid_t found_pid = -1;

    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;
        pid_t p = (pid_t)atoi(entry->d_name);
        if (p <= 0 || p == getpid()) continue;
        if (check_proc_pid(p) > 0) {
            found_pid = p;
            break;
        }
    }
    closedir(dir);
    return found_pid;
}

static pid_t get_pid(void) {
    FILE *f = fopen(PID_FILE, "r");
    if (f) {
        char pbuf[32];
        if (fgets(pbuf, sizeof(pbuf), f)) {
            pid_t p = (pid_t)atoi(pbuf);
            if (p > 0 && check_proc_pid(p) > 0) {
                fclose(f);
                return p;
            }
        }
        fclose(f);
    }

    pid_t discovered_pid = scan_proc_for_service();
    if (discovered_pid > 0) {
        FILE *pf = fopen(PID_FILE, "w");
        if (pf) {
            fprintf(pf, "%d\n", discovered_pid);
            fclose(pf);
        }
        return discovered_pid;
    }

    return -1;
}

static int is_running(void) {
    return get_pid() > 0;
}

static void clear_pid(void) {
    unlink(PID_FILE);
}

// ================= Status Formatting =================

static void fmt_mem(long long kb, char *buf, size_t size) {
    if (kb >= 1048576LL) {
        snprintf(buf, size, "%lld.%02lld GB", kb / 1048576LL, ((kb % 1048576LL) * 100LL) / 1048576LL);
    } else if (kb >= 1024LL) {
        snprintf(buf, size, "%lld.%02lld MB", kb / 1024LL, ((kb % 1024LL) * 100LL) / 1024LL);
    } else {
        snprintf(buf, size, "%lld kB", kb);
    }
}

static void fmt_uptime(long seconds, char *buf, size_t size) {
    long d = seconds / 86400;
    long h = (seconds % 86400) / 3600;
    long m = (seconds % 3600) / 60;
    long s = seconds % 60;

    buf[0] = '\0';
    if (d > 0) snprintf(buf + strlen(buf), size - strlen(buf), "%ldd ", d);
    if (h > 0) snprintf(buf + strlen(buf), size - strlen(buf), "%ldh ", h);
    if (m > 0) snprintf(buf + strlen(buf), size - strlen(buf), "%ldm ", m);
    snprintf(buf + strlen(buf), size - strlen(buf), "%lds", s);
}

static int display_status(void) {
    pid_t pid = get_pid();
    if (pid <= 0) {
        log_info("%s service is stopped.", SERVICE_NAME);
        clear_pid();
        return 1;
    }

    log_info("%s service is running (PID: %d)", SERVICE_NAME, pid);
    if (g_iana_tz[0] != '\0') {
        int off_h = abs((int)(g_tz_offset_sec / 3600));
        int off_m = abs((int)((g_tz_offset_sec % 3600) / 60));
        char sign = (g_tz_offset_sec >= 0) ? '+' : '-';
        log_info("Timezone: %s (UTC%c%02d:%02d)", g_iana_tz, sign, off_h, off_m);
    }

    char status_path[64];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    FILE *f = fopen(status_path, "r");
    if (f) {
        char line[128];
        long long mem_kb = -1;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                char *p = line + 6;
                while (*p == ' ' || *p == '\t') p++;
                mem_kb = strtoll(p, NULL, 10);
                break;
            }
        }
        fclose(f);
        if (mem_kb >= 0) {
            char mem_str[32];
            fmt_mem(mem_kb, mem_str, sizeof(mem_str));
            log_info("Memory usage: %s", mem_str);
        }
    }

    long long sys_uptime_sec = 0;
    struct timespec bts;
    if (clock_gettime(CLOCK_BOOTTIME, &bts) == 0) {
        sys_uptime_sec = (long long)bts.tv_sec;
    } else {
        struct sysinfo si;
        if (sysinfo(&si) == 0) sys_uptime_sec = (long long)si.uptime;
    }

    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    FILE *stat_f = fopen(stat_path, "r");
    if (stat_f) {
        char stat_buf[512];
        if (fgets(stat_buf, sizeof(stat_buf), stat_f)) {
            char *right_paren = strrchr(stat_buf, ')');
            if (right_paren) {
                unsigned long long utime = 0, stime = 0, starttime = 0;
                int field_idx = 3;
                char *token = strtok(right_paren + 2, " ");
                while (token) {
                    if (field_idx == 14) utime = strtoull(token, NULL, 10);
                    else if (field_idx == 15) stime = strtoull(token, NULL, 10);
                    else if (field_idx == 22) { starttime = strtoull(token, NULL, 10); break; }
                    token = strtok(NULL, " ");
                    field_idx++;
                }

                long clk_tck = sysconf(_SC_CLK_TCK);
                if (clk_tck <= 0) clk_tck = 100;

                unsigned long long starttime_sec = starttime / (unsigned long long)clk_tck;
                long long total_sec = (sys_uptime_sec > 0) ? (sys_uptime_sec - (long long)starttime_sec) : 0;
                if (total_sec < 0) total_sec = 0;

                if (total_sec > 0) {
                    unsigned long long cpu_ticks = utime + stime;
                    unsigned long long total_ticks = (unsigned long long)total_sec * (unsigned long long)clk_tck;
                    if (total_ticks > 0) {
                        unsigned long long cpu_tenths = (cpu_ticks * 1000ULL) / total_ticks;
                        log_info("CPU usage: %llu.%llu%% (avg)", cpu_tenths / 10ULL, cpu_tenths % 10ULL);
                    } else {
                        log_info("CPU usage: 0.0%% (avg)");
                    }
                } else {
                    log_info("CPU usage: 0.0%% (avg)");
                }

                char uptime_str[32];
                fmt_uptime((long)total_sec, uptime_str, sizeof(uptime_str));
                log_info("Uptime: %s", uptime_str);
            }
        }
        fclose(stat_f);
    }

    char fd_dir[64];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
    DIR *dir = opendir(fd_dir);
    if (dir) {
        int socket_count = 0;
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            char sym_path[256], target[64];
            snprintf(sym_path, sizeof(sym_path), "%.60s/%.60s", fd_dir, entry->d_name);
            ssize_t len = readlink(sym_path, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                if (strncmp(target, "socket:", 7) == 0) socket_count++;
            }
        }
        closedir(dir);
        log_info("Network sockets: %d", socket_count);
    }

    char io_path[64];
    snprintf(io_path, sizeof(io_path), "/proc/%d/io", pid);
    FILE *io_f = fopen(io_path, "r");
    if (io_f) {
        char line[128];
        long long read_bytes = -1, write_bytes = -1;
        while (fgets(line, sizeof(line), io_f)) {
            if (strncmp(line, "read_bytes:", 11) == 0) {
                char *p = line + 11;
                while (*p == ' ' || *p == '\t') p++;
                read_bytes = strtoll(p, NULL, 10);
            } else if (strncmp(line, "write_bytes:", 12) == 0) {
                char *p = line + 12;
                while (*p == ' ' || *p == '\t') p++;
                write_bytes = strtoll(p, NULL, 10);
            }
        }
        fclose(io_f);
        if (read_bytes >= 0 && write_bytes >= 0) {
            char r_str[32], w_str[32];
            fmt_mem(read_bytes / 1024LL, r_str, sizeof(r_str));
            fmt_mem(write_bytes / 1024LL, w_str, sizeof(w_str));
            log_info("Disk I/O: read %s / write %s", r_str, w_str);
        }
    }

    return 0;
}

// ================= Service Operations =================

static int do_check(void) {
    if (access(BIN_PATH, X_OK) != 0) {
        log_error("Binary not found or not executable: %s", BIN_PATH);
        return 1;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        log_error("Failed to create pipe: %s", strerror(errno));
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        log_error("Failed to fork: %s", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl(BIN_PATH, BIN_PATH, "check", "-D", WORK_DIR, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    char output[1024] = {0};
    size_t total = 0;
    ssize_t n;
    while ((n = read(pipefd[0], output + total, sizeof(output) - 1 - total)) > 0) total += n;
    output[total] = '\0';
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        log_error("Configuration validation failed:");
        if (total > 0) log_error("%s", output);
        return 1;
    }
    return 0;
}

static void check_stale_pid(void) {
    if (access(PID_FILE, F_OK) == 0) {
        FILE *f = fopen(PID_FILE, "r");
        if (f) {
            char pbuf[32];
            if (fgets(pbuf, sizeof(pbuf), f)) {
                pid_t old_pid = (pid_t)atoi(pbuf);
                if (old_pid > 0 && kill(old_pid, 0) != 0) {
                    log_info("Cleaning stale PID file (PID %d not found)", old_pid);
                    clear_pid();
                }
            } else {
                clear_pid();
            }
            fclose(f);
        }
    }
}

static int start_service(void) {
    if (is_running()) {
        log_info("%s is already running.", SERVICE_NAME);
        display_status();
        return 0;
    }

    clear_pid();

    if (access(BIN_PATH, X_OK) != 0) {
        log_error("Binary not found or not executable: %s", BIN_PATH);
        return 1;
    }

    char config_file[300];
    snprintf(config_file, sizeof(config_file), "%s/config.json", WORK_DIR);
    if (access(config_file, F_OK) != 0) {
        log_error("config.json not found in %s", WORK_DIR);
        return 1;
    }

    if (CHECK_CONFIG == 1) {
        log_info("Validating configuration...");
        if (do_check() != 0) {
            log_error("Configuration validation failed, aborting startup");
            return 1;
        }
    }

    log_info("Starting %s...", SERVICE_NAME);
    rotate_log(LOG_FILE);
    rotate_log(ERROR_LOG);
    rotate_log(SINGBOX_LOG);

    pid_t pid = fork();
    if (pid < 0) {
        log_error("Failed to fork process: %s", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        setsid();
        if (chdir(WORK_DIR) != 0) _exit(127);

        struct rlimit rl;
        rl.rlim_cur = NOFILE_LIMIT;
        rl.rlim_max = NOFILE_LIMIT;
        setrlimit(RLIMIT_NOFILE, &rl);

        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            if (null_fd != STDIN_FILENO) close(null_fd);
        }

        int log_fd = open(SINGBOX_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            if (log_fd != STDOUT_FILENO && log_fd != STDERR_FILENO) close(log_fd);
        }

        if (g_iana_tz[0] != '\0') setenv("TZ", g_iana_tz, 1);

        apply_credentials(RUN_USER);
        execl(BIN_PATH, BIN_PATH, "run", "-D", WORK_DIR, (char *)NULL);
        _exit(127);
    }

    FILE *pf = fopen(PID_FILE, "w");
    if (pf) {
        fprintf(pf, "%d\n", pid);
        fclose(pf);
    }

    int max_attempts = START_TIMEOUT > 0 ? START_TIMEOUT : 3;
    int child_alive = 1;

    for (int i = 0; i < max_attempts; i++) {
        sleep(1);
        int status = 0;
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            child_alive = 0;
            if (WIFEXITED(status)) log_error("%s exited immediately with code %d!", SERVICE_NAME, WEXITSTATUS(status));
            else if (WIFSIGNALED(status)) log_error("%s killed by signal %d!", SERVICE_NAME, WTERMSIG(status));
            else log_error("%s exited immediately after startup!", SERVICE_NAME);
            break;
        } else if (w < 0 && errno == ECHILD) {
            if (kill(pid, 0) != 0) { child_alive = 0; break; }
        }
    }

    if (!child_alive || kill(pid, 0) != 0) {
        log_error("%s failed to start! Check %s for details", SERVICE_NAME, SINGBOX_LOG);
        show_tail(SINGBOX_LOG, 10);
        clear_pid();
        return 1;
    }

    log_info("%s started successfully (PID: %d)", SERVICE_NAME, pid);
    display_status();
    return 0;
}

static int stop_service(void) {
    check_stale_pid();

    pid_t pid = get_pid();
    if (pid <= 0) {
        log_info("%s is not running.", SERVICE_NAME);
        clear_pid();
        return 0;
    }

    log_info("Stopping %s (PID: %d)...", SERVICE_NAME, pid);
    kill(pid, SIGTERM);

    for (int i = 0; i < STOP_TIMEOUT; i++) {
        if (kill(pid, 0) != 0) break;
        sleep(1);
    }

    if (kill(pid, 0) == 0) {
        log_info("Process unresponsive (%ds), forcing termination...", STOP_TIMEOUT);
        kill(pid, SIGKILL);
        for (int i = 0; i < 5; i++) {
            if (kill(pid, 0) != 0) break;
            sleep(1);
        }
    }

    if (kill(pid, 0) == 0) {
        log_error("Failed to terminate process %d", pid);
        return 1;
    }

    clear_pid();
    log_info("%s stopped.", SERVICE_NAME);
    return 0;
}

static int restart_service(void) {
    log_info("Restarting %s...", SERVICE_NAME);

    if (CHECK_CONFIG == 1) {
        log_info("Validating configuration before restart...");
        if (do_check() != 0) {
            log_error("Configuration validation failed, aborting restart to preserve running service");
            return 1;
        }
    }

    pid_t pid = get_pid();
    if (pid > 0) {
        if (stop_service() != 0) {
            log_error("Failed to stop existing %s service", SERVICE_NAME);
            return 1;
        }
    } else {
        check_stale_pid();
        clear_pid();
    }

    sync();
    usleep(300000);

    return start_service();
}

static int reload_service(void) {
    pid_t pid = get_pid();
    if (pid <= 0) {
        log_error("%s is not running.", SERVICE_NAME);
        return 1;
    }

    if (CHECK_CONFIG == 1) {
        log_info("Validating configuration before reload...");
        if (do_check() != 0) {
            log_error("Configuration validation failed, aborting reload");
            return 1;
        }
    }

    log_info("Reloading %s configuration (PID: %d)...", SERVICE_NAME, pid);
    if (kill(pid, SIGHUP) == 0) {
        log_info("Reload signal (SIGHUP) sent successfully.");
        return 0;
    } else {
        log_error("Failed to send reload signal: %s", strerror(errno));
        return 1;
    }
}

static void show_log(const char *target, int lines) {
    if (lines <= 0) lines = 50;

    int show_script = 1, show_error = 1, show_service = 0;

    if (target != NULL) {
        if (strcmp(target, "all") == 0) {
            show_script = 1; show_error = 1; show_service = 1;
        } else if (strcmp(target, "sbox") == 0 || strcmp(target, "service") == 0 || strcmp(target, "-s") == 0) {
            show_script = 0; show_error = 0; show_service = 1;
        } else if (strcmp(target, "error") == 0 || strcmp(target, "-e") == 0) {
            show_script = 0; show_error = 1; show_service = 0;
        } else if (strcmp(target, "run") == 0 || strcmp(target, "-r") == 0) {
            show_script = 1; show_error = 0; show_service = 0;
        }
    }

    if (show_script) {
        printf("===== Script Log (%s, last %d lines) =====\n", LOG_FILE, lines);
        show_tail(LOG_FILE, lines);
    }
    if (show_error) {
        if (show_script) printf("\n");
        printf("===== Script Error Log (%s, last %d lines) =====\n", ERROR_LOG, lines);
        show_tail(ERROR_LOG, lines);
    }
    if (show_service) {
        if (show_script || show_error) printf("\n");
        printf("===== %s Service Log (%s, last %d lines) =====\n", SERVICE_NAME, SINGBOX_LOG, lines);
        show_tail(SINGBOX_LOG, lines);
    }
}

static int show_version(void) {
    if (access(BIN_PATH, X_OK) != 0) {
        log_error("Binary not executable: %s", BIN_PATH);
        return 1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        log_error("Failed to fork for version: %s", strerror(errno));
        return 1;
    }
    if (pid == 0) {
        execl(BIN_PATH, BIN_PATH, "version", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

static void usage(const char *prog_name) {
    printf("Usage: %s {start|stop|restart|reload|status|check|log [target] [lines]|version}\n\n", prog_name);
    printf("Commands:\n");
    printf("  start               - Start %s service\n", SERVICE_NAME);
    printf("  stop                - Stop %s service\n", SERVICE_NAME);
    printf("  restart             - Restart %s service\n", SERVICE_NAME);
    printf("  reload              - Hot-reload %s configuration (SIGHUP)\n", SERVICE_NAME);
    printf("  status              - Show service status with detailed info\n");
    printf("  check               - Validate configuration\n");
    printf("  log [target] [n]    - Show last n lines of logs (default: 50)\n");
    printf("                        targets: all, sbox (or service), run, error\n");
    printf("  version             - Show %s version\n", SERVICE_NAME);
}

int main(int argc, char *argv[]) {
    load_config();

    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0)) {
        usage(argv[0]);
        return 0;
    }

    prepare_env();

    if (argc < 2 && !isatty(STDIN_FILENO)) {
        acquire_lock();
        return start_service();
    }

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "start") == 0) {
        acquire_lock();
        return start_service();
    } else if (strcmp(cmd, "stop") == 0) {
        acquire_lock();
        return stop_service();
    } else if (strcmp(cmd, "restart") == 0) {
        acquire_lock();
        return restart_service();
    } else if (strcmp(cmd, "reload") == 0) {
        acquire_lock();
        return reload_service();
    } else if (strcmp(cmd, "status") == 0) {
        return display_status();
    } else if (strcmp(cmd, "check") == 0) {
        int res = do_check();
        if (res == 0) log_info("Configuration validation passed");
        return res;
    } else if (strcmp(cmd, "log") == 0) {
        const char *target = NULL;
        int lines = 50;
        if (argc >= 4) {
            target = argv[2];
            lines = atoi(argv[3]);
        } else if (argc == 3) {
            int is_num = 1;
            for (int i = 0; argv[2][i]; i++) {
                if (!isdigit((unsigned char)argv[2][i])) {
                    is_num = 0;
                    break;
                }
            }
            if (is_num) lines = atoi(argv[2]);
            else target = argv[2];
        }
        show_log(target, lines);
        return 0;
    } else if (strcmp(cmd, "version") == 0) {
        return show_version();
    } else {
        usage(argv[0]);
        return 1;
    }
}
