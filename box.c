#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <grp.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/syscall.h>

struct linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};

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
static void log_msg(int level, const char *fmt, ...);

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
static void reset_lock_cleanup_signals(void);
static int waitpid_retry(pid_t pid, int *status);
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

// ================= Permission & User Utilities =================

static int parse_id(const char *name, unsigned long max, unsigned long *out) {
    char *end;
    unsigned long value;
    if (!name || *name == '\0' || *name == '-') return -1;
    errno = 0;
    value = strtoul(name, &end, 10);
    if (errno || *end != '\0' || value > max) return -1;
    *out = value;
    return 0;
}

static int resolve_uid(const char *name, uid_t *out) {
    unsigned long value;
    if (strcmp(name, "root") == 0) value = 0;
    else if (strcmp(name, "system") == 0) value = 1000;
    else if (strcmp(name, "shell") == 0) value = 2000;
    else if (strcmp(name, "nobody") == 0) value = 9999;
    else if (parse_id(name, (unsigned long)((uid_t)-1), &value) != 0) return -1;
    *out = (uid_t)value;
    return 0;
}

static int resolve_gid(const char *name, gid_t *out) {
    unsigned long value;
    if (strcmp(name, "root") == 0) value = 0;
    else if (strcmp(name, "system") == 0) value = 1000;
    else if (strcmp(name, "shell") == 0) value = 2000;
    else if (strcmp(name, "inet") == 0) value = 3003;
    else if (strcmp(name, "net_raw") == 0) value = 3004;
    else if (strcmp(name, "net_admin") == 0) value = 3005;
    else if (strcmp(name, "net_bw_stats") == 0) value = 3006;
    else if (strcmp(name, "net_bw_acct") == 0) value = 3007;
    else if (strcmp(name, "everybody") == 0) value = 9997;
    else if (strcmp(name, "nobody") == 0) value = 9999;
    else if (parse_id(name, (unsigned long)((gid_t)-1), &value) != 0) return -1;
    *out = (gid_t)value;
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

    uid_t target_uid;
    gid_t target_gid;
    if (resolve_uid(user_part, &target_uid) != 0) {
        log_msg(1, "Invalid UID: %s", user_part);
        return -1;
    }
    if (group_part && group_part[0] != '\0') {
        if (resolve_gid(group_part, &target_gid) != 0) {
            log_msg(1, "Invalid GID: %s", group_part);
            return -1;
        }
    } else target_gid = (gid_t)target_uid;

    gid_t groups[4];
    int group_count = 0;
    groups[group_count++] = target_gid;

    if (target_gid == 3005) { // AID_NET_ADMIN
        groups[group_count++] = 3003; // AID_INET
        groups[group_count++] = 3004; // AID_NET_RAW
    }

    if (setgroups(group_count, groups) != 0) {
        log_msg(1, "setgroups failed: %s", strerror(errno));
        return -1;
    }
    if (setresgid(target_gid, target_gid, target_gid) != 0 && setgid(target_gid) != 0) {
        log_msg(1, "setgid failed: %s", strerror(errno));
        return -1;
    }
    if (setresuid(target_uid, target_uid, target_uid) != 0 && setuid(target_uid) != 0) {
        log_msg(1, "setuid failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

// ================= Configuration & INI Parser =================

static void expand_vars(char *dst, size_t dst_size, const char *src) {
    char temp[256];
    size_t di = 0, si = 0, len = strlen(src);
    while (si < len && di < sizeof(temp) - 1) {
        if (src[si] == '$') {
            const char *val = NULL;
            size_t skip = 0;
            if (strncmp(src + si, "${SERVICE_NAME}", 15) == 0) { val = g_cfg.service_name; skip = 15; }
            else if (strncmp(src + si, "$SERVICE_NAME", 13) == 0) { val = g_cfg.service_name; skip = 13; }
            else if (strncmp(src + si, "${WORK_DIR}", 11) == 0) { val = g_cfg.work_dir; skip = 11; }
            else if (strncmp(src + si, "$WORK_DIR", 9) == 0) { val = g_cfg.work_dir; skip = 9; }

            if (val) {
                size_t vlen = strlen(val);
                if (di + vlen < sizeof(temp) - 1) {
                    memcpy(temp + di, val, vlen);
                    di += vlen;
                    si += skip;
                    continue;
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
        reset_lock_cleanup_signals();
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
    if (waitpid_retry(pid, &status) != 0) return -1;

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
    char *colon = strchr(s, ':');
    if (colon) {
        hours = atoi(s);
        mins = atoi(colon + 1);
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

    static const struct { const char *name; long offset; } tz_tbl[] = {
        {"Asia/Shanghai", 28800}, {"Asia/Chongqing", 28800}, {"Asia/Harbin", 28800},
        {"Asia/Urumqi", 28800}, {"Asia/Kashgar", 28800}, {"Asia/Hong_Kong", 28800},
        {"Asia/Macau", 28800}, {"Asia/Taipei", 28800}, {"Asia/Singapore", 28800},
        {"Asia/Kuala_Lumpur", 28800}, {"Asia/Manila", 28800}, {"Asia/Perth", 28800},
        {"Asia/Brunei", 28800}, {"Asia/Makassar", 28800}, {"PRC", 28800},
        {"China", 28800}, {"CST", 28800}, {"CST-8", 28800}, {"Etc/GMT-8", 28800},
        {"Asia/Tokyo", 32400}, {"Asia/Seoul", 32400}, {"JST", 32400}, {"KST", 32400},
        {"Asia/Bangkok", 25200}, {"Asia/Jakarta", 25200}, {"Asia/Ho_Chi_Minh", 25200},
        {"Asia/Kolkata", 19800}, {"Asia/Calcutta", 19800}, {"IST", 19800},
        {"Asia/Dubai", 14400}, {"GST", 14400},
        {"Europe/London", 0}, {"UTC", 0}, {"GMT", 0}, {"Zulu", 0}, {"Etc/UTC", 0},
        {"Europe/Berlin", 3600}, {"Europe/Paris", 3600}, {"Europe/Rome", 3600},
        {"CET", 3600}, {"America/New_York", -18000}, {"EST", -18000},
        {"America/Chicago", -21600}, {"CDT", -21600},
        {"America/Denver", -25200}, {"MST", -25200},
        {"America/Los_Angeles", -28800}, {"PST", -28800},
        {NULL, 0}
    };

    for (int i = 0; tz_tbl[i].name != NULL; i++) {
        if (strcasecmp(tz_name, tz_tbl[i].name) == 0) return tz_tbl[i].offset;
    }

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
                int tz_fd = open("/etc/timezone", O_RDONLY);
                if (tz_fd >= 0) {
                    ssize_t n = read(tz_fd, tz_buf, sizeof(tz_buf) - 1);
                    close(tz_fd);
                    if (n > 0) {
                        tz_buf[n] = '\0';
                        char *trimmed = trim_str(tz_buf);
                        if (trimmed && trimmed[0] != '\0') snprintf(g_iana_tz, sizeof(g_iana_tz), "%.63s", trimmed);
                    }
                }
            }
            if (g_iana_tz[0] == '\0') snprintf(g_iana_tz, sizeof(g_iana_tz), "Asia/Shanghai");
        }
    }

    g_tz_offset_sec = get_tz_offset_from_name(g_iana_tz);
    setenv("TZ", g_iana_tz, 1);
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
        int fd = open(candidates[i], O_RDONLY);
        if (fd < 0) continue;
        char buf[256];
        char line[256];
        int lpos = 0;
        int line_truncated = 0;
        ssize_t n;
        int found = 1;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            for (ssize_t j = 0; j < n; j++) {
                char c = buf[j];
                if (c == '\n' || c == '\r') {
                    if (line_truncated) {
                        fprintf(stderr, "Configuration line too long in %s\n", candidates[i]);
                        close(fd);
                        return;
                    }
                    if (lpos > 0) {
                        line[lpos] = '\0';
                        parse_ini_line(line, &has_bin, &has_pid, &has_logdir, &has_logfile, &has_errlog, &has_sblog, &has_lockdir, &has_workdir);
                        lpos = 0;
                    }
                } else if (lpos < (int)sizeof(line) - 1) {
                    line[lpos++] = c;
                } else {
                    line_truncated = 1;
                }
            }
        }
        if (line_truncated) {
            fprintf(stderr, "Configuration line too long in %s\n", candidates[i]);
            close(fd);
            return;
        }
        if (lpos > 0) {
            line[lpos] = '\0';
            parse_ini_line(line, &has_bin, &has_pid, &has_logdir, &has_logfile, &has_errlog, &has_sblog, &has_lockdir, &has_workdir);
        }
        close(fd);
        if (found) break;
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
    time_t now = time(NULL);
    time_t local_now = now + g_tz_offset_sec;
    struct tm tm_info;
    gmtime_r(&local_now, &tm_info);
    snprintf(buffer, size, "%04d-%02d-%02d %02d:%02d:%02d",
             (tm_info.tm_year + 1900) % 10000, tm_info.tm_mon + 1, tm_info.tm_mday,
             tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);
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

    int log_fd = open(target_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd >= 0) {
        dprintf(log_fd, "[%s] %s %s\n", timestamp, tag, message);
        close(log_fd);
    }
}

#define log_info(...)  log_msg(0, __VA_ARGS__)
#define log_error(...) log_msg(1, __VA_ARGS__)

static void show_tail(const char *filepath, int lines) {
    if (lines <= 0) lines = 10;
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        printf("(empty)\n");
        return;
    }
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size <= 0) {
        printf("(empty)\n");
        close(fd);
        return;
    }

    char buf[8192];
    off_t read_size = (file_size > (off_t)(sizeof(buf) - 1)) ? (off_t)(sizeof(buf) - 1) : file_size;
    lseek(fd, file_size - read_size, SEEK_SET);

    ssize_t bytes = read(fd, buf, read_size);
    if (bytes <= 0) bytes = 0;
    buf[bytes] = '\0';
    close(fd);

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

    if (geteuid() != 0 && getuid() != 0) {
        log_error("Root privileges required");
        exit(1);
    }
}

static int remove_lock_dir(void) {
    char pid_path[300];
    snprintf(pid_path, sizeof(pid_path), "%s/pid", LOCK_DIR);
    if (unlink(pid_path) != 0 && errno != ENOENT) return -1;
    if (rmdir(LOCK_DIR) != 0) return -1;
    return 0;
}

static void release_lock(void) {
    if (g_lock_acquired) {
        remove_lock_dir();
        g_lock_acquired = 0;
    }
}

static int write_lock_pid(void) {
    char pid_path[300];
    snprintf(pid_path, sizeof(pid_path), "%s/pid", LOCK_DIR);
    int fd = open(pid_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    if (dprintf(fd, "%d\n", getpid()) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (close(fd) != 0) return -1;
    return 0;
}

static int is_lock_stale(void) {
    char pid_path[300];
    snprintf(pid_path, sizeof(pid_path), "%s/pid", LOCK_DIR);
    int fd = open(pid_path, O_RDONLY);
    if (fd >= 0) {
        char pbuf[32];
        ssize_t n = read(fd, pbuf, sizeof(pbuf) - 1);
        close(fd);
        if (n > 0) {
            pbuf[n] = '\0';
            pid_t lock_pid = (pid_t)atoi(pbuf);
            if (lock_pid > 0) {
                if (lock_pid == getpid()) return 0;
                if (kill(lock_pid, 0) != 0 && errno == ESRCH) return 1;

                char comm_path[64];
                snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", lock_pid);
                int cfd = open(comm_path, O_RDONLY);
                if (cfd >= 0) {
                    char comm[64] = {0};
                    ssize_t cn = read(cfd, comm, sizeof(comm) - 1);
                    close(cfd);
                    if (cn > 0) {
                        comm[cn] = '\0';
                        if (strstr(comm, "box") != NULL) return 0;
                    }
                }
                return 1;
            }
        }
    }
    struct stat st;
    if (stat(LOCK_DIR, &st) == 0) {
        time_t now = time(NULL);
        if (st.st_mtime > 0 && now > st.st_mtime && (now - st.st_mtime) > 60) return 1;
        return 0;
    }
    return 0;
}

static int waitpid_retry(pid_t pid, int *status) {
    pid_t result;
    do result = waitpid(pid, status, 0); while (result < 0 && errno == EINTR);
    return result == pid ? 0 : -1;
}

static void signal_lock_cleanup(int sig) {
    release_lock();
    _exit(128 + sig);
}

static void reset_lock_cleanup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

static void acquire_lock(void) {
    int attempts = 0;
    while (mkdir(LOCK_DIR, 0755) != 0) {
        if (errno != EEXIST) {
            log_error("Failed to create lock directory %s: %s", LOCK_DIR, strerror(errno));
            exit(1);
        }
        if (is_lock_stale()) {
            if (remove_lock_dir() != 0) {
                int saved_errno = errno;
                log_error("Failed to remove stale lock directory %s: %s", LOCK_DIR, strerror(saved_errno));
                exit(1);
            }
            continue;
        }
        attempts++;
        if (attempts >= 10) {
            log_error("Another box operation is in progress, please try again later");
            exit(1);
        }
        sleep(1);
    }
    if (write_lock_pid() != 0) {
        log_error("Failed to initialize lock PID file in %s: %s", LOCK_DIR, strerror(errno));
        remove_lock_dir();
        exit(1);
    }
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

    char exe_path[64], link_target[256];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", p);
    ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
    if (len > 0) {
        link_target[len] = '\0';
        if (strcmp(link_target, BIN_PATH) == 0) {
            return p;
        }
    }

    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", p);
    int cfd = open(cmdline_path, O_RDONLY);
    if (cfd >= 0) {
        char cmd_buf[512] = {0};
        ssize_t n = read(cfd, cmd_buf, sizeof(cmd_buf) - 1);
        close(cfd);
        if (n > 0) {
            size_t cmd0_len = strnlen(cmd_buf, (size_t)n);
            int match_bin = (strlen(BIN_PATH) == cmd0_len && memcmp(cmd_buf, BIN_PATH, cmd0_len) == 0);
            int match_dir = (WORK_DIR[0] != '\0' && memmem(cmd_buf, n, WORK_DIR, strlen(WORK_DIR)) != NULL);
            if (match_bin && match_dir) return p;
        }
    }
    return -1;
}

static pid_t scan_proc_for_service(void) {
    int fd = open("/proc", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;
    char buf[1024];
    pid_t found_pid = -1;
    while (1) {
        long nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (nread <= 0) break;
        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + bpos);
            if (isdigit((unsigned char)d->d_name[0])) {
                pid_t p = (pid_t)atoi(d->d_name);
                if (p > 0 && p != getpid() && check_proc_pid(p) > 0) {
                    found_pid = p;
                    break;
                }
            }
            bpos += d->d_reclen;
        }
        if (found_pid > 0) break;
    }
    close(fd);
    return found_pid;
}

static pid_t get_pid(void) {
    int fd = open(PID_FILE, O_RDONLY);
    if (fd >= 0) {
        char pbuf[32];
        ssize_t n = read(fd, pbuf, sizeof(pbuf) - 1);
        close(fd);
        if (n > 0) {
            pbuf[n] = '\0';
            pid_t p = (pid_t)atoi(pbuf);
            if (p > 0 && check_proc_pid(p) > 0) return p;
        }
    }

    pid_t discovered_pid = scan_proc_for_service();
    if (discovered_pid > 0) {
        int pf = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (pf >= 0) {
            dprintf(pf, "%d\n", discovered_pid);
            close(pf);
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

    int pos = 0;
    if (d > 0) pos += snprintf(buf + pos, size - pos, "%ldd ", d);
    if (h > 0) pos += snprintf(buf + pos, size - pos, "%ldh ", h);
    if (m > 0) pos += snprintf(buf + pos, size - pos, "%ldm ", m);
    snprintf(buf + pos, size - pos, "%lds", s);
}

static int count_proc_sockets(pid_t pid) {
    char fd_dir[64];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
    int fd = open(fd_dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return 0;
    char buf[1024];
    int count = 0;
    while (1) {
        long nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (nread <= 0) break;
        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + bpos);
            if (d->d_name[0] != '.') {
                char sym_path[128], target[64];
                snprintf(sym_path, sizeof(sym_path), "%.60s/%.60s", fd_dir, d->d_name);
                ssize_t len = readlink(sym_path, target, sizeof(target) - 1);
                if (len > 0) {
                    target[len] = '\0';
                    if (strncmp(target, "socket:", 7) == 0) count++;
                }
            }
            bpos += d->d_reclen;
        }
    }
    close(fd);
    return count;
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
    int sfd = open(status_path, O_RDONLY);
    if (sfd >= 0) {
        char sbuf[1024];
        ssize_t sn = read(sfd, sbuf, sizeof(sbuf) - 1);
        close(sfd);
        if (sn > 0) {
            sbuf[sn] = '\0';
            char *vm = strstr(sbuf, "VmRSS:");
            if (vm) {
                vm += 6;
                while (*vm == ' ' || *vm == '\t') vm++;
                long long mem_kb = strtoll(vm, NULL, 10);
                if (mem_kb >= 0) {
                    char mem_str[32];
                    fmt_mem(mem_kb, mem_str, sizeof(mem_str));
                    log_info("Memory usage: %s", mem_str);
                }
            }
        }
    }

    long long sys_uptime_sec = 0;
    struct timespec bts;
    if (clock_gettime(CLOCK_BOOTTIME, &bts) == 0) {
        sys_uptime_sec = (long long)bts.tv_sec;
    } else {
        int ufd = open("/proc/uptime", O_RDONLY);
        if (ufd >= 0) {
            char ubuf[64] = {0};
            ssize_t un = read(ufd, ubuf, sizeof(ubuf) - 1);
            close(ufd);
            if (un > 0) sys_uptime_sec = (long long)atoll(ubuf);
        }
    }

    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    int stfd = open(stat_path, O_RDONLY);
    if (stfd >= 0) {
        char stat_buf[512];
        ssize_t stn = read(stfd, stat_buf, sizeof(stat_buf) - 1);
        close(stfd);
        if (stn > 0) {
            stat_buf[stn] = '\0';
            char *right_paren = strrchr(stat_buf, ')');
            if (right_paren) {
                unsigned long long utime = 0, stime = 0, starttime = 0;
                int field_idx = 3;
                char *p = right_paren + 2;
                while (*p && field_idx <= 22) {
                    while (*p == ' ') p++;
                    char *tok_end = p;
                    while (*tok_end && *tok_end != ' ') tok_end++;
                    if (field_idx == 14) utime = strtoull(p, NULL, 10);
                    else if (field_idx == 15) stime = strtoull(p, NULL, 10);
                    else if (field_idx == 22) { starttime = strtoull(p, NULL, 10); break; }
                    p = tok_end;
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
    }

    int socket_count = count_proc_sockets(pid);
    log_info("Network sockets: %d", socket_count);

    char io_path[64];
    snprintf(io_path, sizeof(io_path), "/proc/%d/io", pid);
    int iofd = open(io_path, O_RDONLY);
    if (iofd >= 0) {
        char io_buf[512];
        ssize_t ion = read(iofd, io_buf, sizeof(io_buf) - 1);
        close(iofd);
        if (ion > 0) {
            io_buf[ion] = '\0';
            long long read_bytes = -1, write_bytes = -1;
            char *rpos = strstr(io_buf, "read_bytes:");
            if (rpos) read_bytes = strtoll(rpos + 11, NULL, 10);
            char *wpos = strstr(io_buf, "write_bytes:");
            if (wpos) write_bytes = strtoll(wpos + 12, NULL, 10);

            if (read_bytes >= 0 && write_bytes >= 0) {
                char r_str[32], w_str[32];
                fmt_mem(read_bytes / 1024LL, r_str, sizeof(r_str));
                fmt_mem(write_bytes / 1024LL, w_str, sizeof(w_str));
                log_info("Disk I/O: read %s / write %s", r_str, w_str);
            }
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
        reset_lock_cleanup_signals();
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl(BIN_PATH, BIN_PATH, "check", "-D", WORK_DIR, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    char output[1024] = {0};
    char discard[256];
    size_t total = 0;
    ssize_t n;
    while (1) {
        if (total < sizeof(output) - 1) {
            n = read(pipefd[0], output + total, sizeof(output) - 1 - total);
            if (n > 0) total += n;
        } else {
            n = read(pipefd[0], discard, sizeof(discard));
        }
        if (n <= 0) break;
    }
    output[total] = '\0';
    close(pipefd[0]);

    int status = 0;
    if (waitpid_retry(pid, &status) != 0) {
        log_error("Failed to wait for configuration check: %s", strerror(errno));
        return 1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        log_error("Configuration validation failed:");
        if (total > 0) log_error("%s", output);
        return 1;
    }
    return 0;
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
        reset_lock_cleanup_signals();
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

        if (apply_credentials(RUN_USER) != 0) _exit(126);
        execl(BIN_PATH, BIN_PATH, "run", "-D", WORK_DIR, (char *)NULL);
        _exit(127);
    }

    int pf = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pf >= 0) {
        dprintf(pf, "%d\n", pid);
        close(pf);
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
        } else if (w < 0) {
            if (errno == EINTR) { i--; continue; }
            log_error("Failed to wait for %s startup: %s", SERVICE_NAME, strerror(errno));
            child_alive = 0;
            break;
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
    pid_t pid = get_pid();
    if (pid <= 0) {
        log_info("%s is not running.", SERVICE_NAME);
        clear_pid();
        return 0;
    }

    log_info("Stopping %s (PID: %d)...", SERVICE_NAME, pid);
    kill(pid, SIGTERM);

    for (int i = 0; i < STOP_TIMEOUT; i++) {
        if (check_proc_pid(pid) <= 0) break;
        sleep(1);
    }

    if (check_proc_pid(pid) > 0) {
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
        clear_pid();
    }

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
        reset_lock_cleanup_signals();
        execl(BIN_PATH, BIN_PATH, "version", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    if (waitpid_retry(pid, &status) != 0) return 1;
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
