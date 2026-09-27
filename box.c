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
#include <sys/file.h>
#include <stddef.h>
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
    char work_dir[PATH_MAX];
    char bin_path[PATH_MAX];
    char pid_file[PATH_MAX];
    char log_dir[PATH_MAX];
    char log_file[PATH_MAX];
    char error_log[PATH_MAX];
    char singbox_log[PATH_MAX];
    char lock_dir[PATH_MAX];
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

static int g_lock_fd = -1;
static char g_iana_tz[64] = {0};

static int is_proc_alive(pid_t pid);
static pid_t check_proc_pid(pid_t p, int is_scan);
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
    while (*str && isspace((unsigned char)*str)) str++;
    if (*str == '\0') return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    if (end > str) {
        if ((*str == '"' && *end == '"') || (*str == '\'' && *end == '\'')) {
            str++;
            *end = '\0';
            while (*str && isspace((unsigned char)*str)) str++;
            if (*str != '\0') {
                end = str + strlen(str) - 1;
                while (end > str && isspace((unsigned char)*end)) end--;
                end[1] = '\0';
            }
        }
    }
    return str;
}

static void get_self_dir(char *dir_buf, size_t size) {
    char exe_path[PATH_MAX];
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

static int apply_nofile_limit(void) {
    struct rlimit old_rl;
    if (getrlimit(RLIMIT_NOFILE, &old_rl) != 0) {
        log_msg(1, "getrlimit(RLIMIT_NOFILE) failed: %s", strerror(errno));
        return -1;
    }
    rlim_t target = (rlim_t)NOFILE_LIMIT;
    struct rlimit new_rl;

    if (target <= old_rl.rlim_max) {
        new_rl.rlim_cur = target;
        new_rl.rlim_max = old_rl.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &new_rl) != 0) {
            log_msg(1, "setrlimit(RLIMIT_NOFILE, soft=%ld) failed: %s", (long)target, strerror(errno));
            return -1;
        }
        return 0;
    }

    // target > old_rl.rlim_max: try to raise hard limit first
    new_rl.rlim_cur = target;
    new_rl.rlim_max = target;
    if (setrlimit(RLIMIT_NOFILE, &new_rl) == 0) return 0;

    // Raising hard limit failed, cap soft to current hard limit
    new_rl.rlim_cur = old_rl.rlim_max;
    new_rl.rlim_max = old_rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &new_rl) != 0) {
        log_msg(1, "setrlimit(RLIMIT_NOFILE, capped=%ld) failed: %s", (long)old_rl.rlim_max, strerror(errno));
        return -1;
    }
    log_msg(0, "Warning: requested nofile_limit %ld exceeds hard limit %ld, capped",
            NOFILE_LIMIT, (long)old_rl.rlim_max);
    return 0;
}

static int apply_credentials(const char *user_spec) {
    if (!user_spec || user_spec[0] == '\0') return 0;
    if (strcmp(user_spec, "root") == 0 || strcmp(user_spec, "root:root") == 0 || strcmp(user_spec, "0:0") == 0 || strcmp(user_spec, "0") == 0 || strcmp(user_spec, "root:0") == 0) return 0;

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
    char temp[PATH_MAX];
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

static void strip_inline_comment(char *value) {
    char quote = '\0';
    for (char *p = value; *p; p++) {
        if ((*p == '\'' || *p == '"') && (p == value || p[-1] != '\\')) {
            if (quote == '\0') quote = *p;
            else if (quote == *p) quote = '\0';
        } else if (quote == '\0' && (*p == '#' || *p == ';')) {
            *p = '\0';
            return;
        }
    }
}

static int parse_long_value(const char *key, const char *value, long min, long max, long *out) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < min || parsed > max) {
        fprintf(stderr, "Invalid value for %s: %s (expected %ld..%ld)\n", key, value, min, max);
        return -1;
    }
    *out = parsed;
    return 0;
}

static int parse_ini_raw(char *line,
                         char *raw_work_dir, size_t work_dir_size, int *has_workdir,
                         char *raw_bin, size_t bin_size, int *has_bin,
                         char *raw_pid, size_t pid_size, int *has_pid,
                         char *raw_logdir, size_t logdir_size, int *has_logdir,
                         char *raw_logfile, size_t logfile_size, int *has_logfile,
                         char *raw_errlog, size_t errlog_size, int *has_errlog,
                         char *raw_sblog, size_t sblog_size, int *has_sblog,
                         char *raw_lockdir, size_t lockdir_size, int *has_lockdir) {
    line = trim_str(line);
    if (!line || line[0] == '\0' || line[0] == '#' || line[0] == ';' || line[0] == '[') return 0;

    char *eq = strchr(line, '=');
    if (!eq) return 0;

    *eq = '\0';
    char *key = trim_str(line);
    char *raw_val = eq + 1;
    strip_inline_comment(raw_val);
    char *val = trim_str(raw_val);

    if (strcasecmp(key, "service_name") == 0) snprintf(g_cfg.service_name, sizeof(g_cfg.service_name), "%s", val);
    else if (strcasecmp(key, "work_dir") == 0) { snprintf(raw_work_dir, work_dir_size, "%s", val); *has_workdir = 1; }
    else if (strcasecmp(key, "bin_path") == 0) { snprintf(raw_bin, bin_size, "%s", val); *has_bin = 1; }
    else if (strcasecmp(key, "pid_file") == 0) { snprintf(raw_pid, pid_size, "%s", val); *has_pid = 1; }
    else if (strcasecmp(key, "log_dir") == 0) { snprintf(raw_logdir, logdir_size, "%s", val); *has_logdir = 1; }
    else if (strcasecmp(key, "log_file") == 0) { snprintf(raw_logfile, logfile_size, "%s", val); *has_logfile = 1; }
    else if (strcasecmp(key, "error_log") == 0) { snprintf(raw_errlog, errlog_size, "%s", val); *has_errlog = 1; }
    else if (strcasecmp(key, "singbox_log") == 0 || strcasecmp(key, "service_log") == 0) { snprintf(raw_sblog, sblog_size, "%s", val); *has_sblog = 1; }
    else if (strcasecmp(key, "lock_dir") == 0) { snprintf(raw_lockdir, lockdir_size, "%s", val); *has_lockdir = 1; }
    else if (strcasecmp(key, "run_user") == 0) snprintf(g_cfg.run_user, sizeof(g_cfg.run_user), "%s", val);
    else if (strcasecmp(key, "timezone") == 0 || strcasecmp(key, "tz") == 0) snprintf(g_cfg.timezone, sizeof(g_cfg.timezone), "%s", val);
    else if (strcasecmp(key, "max_log_size") == 0) return parse_long_value(key, val, 1, LONG_MAX, &g_cfg.max_log_size);
    else if (strcasecmp(key, "stop_timeout") == 0) {
        long parsed;
        if (parse_long_value(key, val, 0, 3600, &parsed) != 0) return -1;
        g_cfg.stop_timeout = (int)parsed;
    } else if (strcasecmp(key, "start_timeout") == 0) {
        long parsed;
        if (parse_long_value(key, val, 1, 3600, &parsed) != 0) return -1;
        g_cfg.start_timeout = (int)parsed;
    } else if (strcasecmp(key, "check_config") == 0) {
        long parsed;
        if (parse_long_value(key, val, 0, 1, &parsed) != 0) return -1;
        g_cfg.check_config = (int)parsed;
    } else if (strcasecmp(key, "nofile_limit") == 0) return parse_long_value(key, val, 1, LONG_MAX, &g_cfg.nofile_limit);

    return 0;
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
        if (n < 0 && errno == EINTR) continue;
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

static void init_timezone(const char *custom_tz) {
    char tz_buf[64] = {0};
    g_iana_tz[0] = '\0';

    if (custom_tz && custom_tz[0] != '\0' && strcasecmp(custom_tz, "auto") != 0) {
        snprintf(g_iana_tz, sizeof(g_iana_tz), "%.63s", custom_tz);
        setenv("TZ", g_iana_tz, 1);
        tzset();
        return;
    }

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
        if (g_iana_tz[0] == '\0') {
            char link_buf[PATH_MAX];
            ssize_t llen = readlink("/etc/localtime", link_buf, sizeof(link_buf) - 1);
            if (llen > 0) {
                link_buf[llen] = '\0';
                char *pos = strstr(link_buf, "zoneinfo/");
                if (pos) {
                    pos += 9;
                    if (*pos) snprintf(g_iana_tz, sizeof(g_iana_tz), "%.63s", pos);
                }
            }
        }
    }

    if (g_iana_tz[0] != '\0') {
        setenv("TZ", g_iana_tz, 1);
        tzset();
    }
}

static int load_config(void) {
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
    char raw_work_dir[PATH_MAX] = {0};
    char raw_bin[PATH_MAX] = {0};
    char raw_pid[PATH_MAX] = {0};
    char raw_logdir[PATH_MAX] = {0};
    char raw_logfile[PATH_MAX] = {0};
    char raw_errlog[PATH_MAX] = {0};
    char raw_sblog[PATH_MAX] = {0};
    char raw_lockdir[PATH_MAX] = {0};

    char self_dir[PATH_MAX];
    get_self_dir(self_dir, sizeof(self_dir));

    char self_ini[PATH_MAX + 16];
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
                        return -1;
                    }
                    if (lpos > 0) {
                        line[lpos] = '\0';
                        if (parse_ini_raw(line,
                                          raw_work_dir, sizeof(raw_work_dir), &has_workdir,
                                          raw_bin, sizeof(raw_bin), &has_bin,
                                          raw_pid, sizeof(raw_pid), &has_pid,
                                          raw_logdir, sizeof(raw_logdir), &has_logdir,
                                          raw_logfile, sizeof(raw_logfile), &has_logfile,
                                          raw_errlog, sizeof(raw_errlog), &has_errlog,
                                          raw_sblog, sizeof(raw_sblog), &has_sblog,
                                          raw_lockdir, sizeof(raw_lockdir), &has_lockdir) != 0) {
                            close(fd);
                            return -1;
                        }
                        lpos = 0;
                    }
                } else if (lpos < (int)sizeof(line) - 1) {
                    line[lpos++] = c;
                } else {
                    line_truncated = 1;
                }
            }
        }
        if (n < 0) {
            fprintf(stderr, "Failed to read configuration %s: %s\n", candidates[i], strerror(errno));
            close(fd);
            return -1;
        }
        if (line_truncated) {
            fprintf(stderr, "Configuration line too long in %s\n", candidates[i]);
            close(fd);
            return -1;
        }
        if (lpos > 0) {
            line[lpos] = '\0';
            if (parse_ini_raw(line,
                              raw_work_dir, sizeof(raw_work_dir), &has_workdir,
                              raw_bin, sizeof(raw_bin), &has_bin,
                              raw_pid, sizeof(raw_pid), &has_pid,
                              raw_logdir, sizeof(raw_logdir), &has_logdir,
                              raw_logfile, sizeof(raw_logfile), &has_logfile,
                              raw_errlog, sizeof(raw_errlog), &has_errlog,
                              raw_sblog, sizeof(raw_sblog), &has_sblog,
                              raw_lockdir, sizeof(raw_lockdir), &has_lockdir) != 0) {
                close(fd);
                return -1;
            }
        }
        close(fd);
        if (found) break;
    }

    if (has_workdir && raw_work_dir[0] != '\0') {
        expand_vars(g_cfg.work_dir, sizeof(g_cfg.work_dir), raw_work_dir);
    } else {
        int is_sys_bin = (strcmp(self_dir, "/system/bin") == 0 ||
                          strcmp(self_dir, "/system/xbin") == 0 ||
                          strcmp(self_dir, "/sbin") == 0 ||
                          strcmp(self_dir, "/bin") == 0 ||
                          strcmp(self_dir, "/usr/bin") == 0 ||
                          strstr(self_dir, "/ksu/bin") != NULL ||
                          strstr(self_dir, "/ap/bin") != NULL ||
                          strstr(self_dir, "/magisk") != NULL);

        if (!is_sys_bin && self_dir[0] != '\0' && strcmp(self_dir, ".") != 0) {
            snprintf(g_cfg.work_dir, sizeof(g_cfg.work_dir), "%s", self_dir);
        } else {
            snprintf(g_cfg.work_dir, sizeof(g_cfg.work_dir), "/data/adb/%s", g_cfg.service_name);
        }
    }

    if (has_bin)     expand_vars(g_cfg.bin_path, sizeof(g_cfg.bin_path), raw_bin);
    else             snprintf(g_cfg.bin_path, sizeof(g_cfg.bin_path), "%.1024s/bin/%.60s", g_cfg.work_dir, g_cfg.service_name);

    if (has_pid)     expand_vars(g_cfg.pid_file, sizeof(g_cfg.pid_file), raw_pid);
    else             snprintf(g_cfg.pid_file, sizeof(g_cfg.pid_file), "%.1024s/%.60s.pid", g_cfg.work_dir, g_cfg.service_name);

    if (has_logdir)  expand_vars(g_cfg.log_dir, sizeof(g_cfg.log_dir), raw_logdir);
    else             snprintf(g_cfg.log_dir, sizeof(g_cfg.log_dir), "%.1024s/logs", g_cfg.work_dir);

    if (has_logfile) expand_vars(g_cfg.log_file, sizeof(g_cfg.log_file), raw_logfile);
    else             snprintf(g_cfg.log_file, sizeof(g_cfg.log_file), "%.1024s/run.log", g_cfg.log_dir);

    if (has_errlog)  expand_vars(g_cfg.error_log, sizeof(g_cfg.error_log), raw_errlog);
    else             snprintf(g_cfg.error_log, sizeof(g_cfg.error_log), "%.1024s/run_error.log", g_cfg.log_dir);

    if (has_sblog)   expand_vars(g_cfg.singbox_log, sizeof(g_cfg.singbox_log), raw_sblog);
    else             snprintf(g_cfg.singbox_log, sizeof(g_cfg.singbox_log), "%.1024s/%.60s.log", g_cfg.log_dir, g_cfg.service_name);

    if (has_lockdir) expand_vars(g_cfg.lock_dir, sizeof(g_cfg.lock_dir), raw_lockdir);
    else             snprintf(g_cfg.lock_dir, sizeof(g_cfg.lock_dir), "%.1024s/.box.lock", g_cfg.work_dir);

    init_timezone(g_cfg.timezone);
    return 0;
}

// ================= Logging System =================

static void ts(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
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
        char full_line[1200];
        int n = snprintf(full_line, sizeof(full_line), "[%s] %s %s\n", timestamp, tag, message);
        if (n > 0) {
            size_t to_write = (size_t)n < sizeof(full_line) ? (size_t)n : sizeof(full_line) - 1;
            size_t written = 0;
            while (written < to_write) {
                ssize_t w = write(log_fd, full_line + written, to_write - written);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) break;
                written += (size_t)w;
            }
        }
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
    off_t position = file_size;
    off_t start_offset = 0;
    int count = 0;
    int found = 0;

    while (position > 0 && !found) {
        size_t chunk = position > (off_t)sizeof(buf) ? sizeof(buf) : (size_t)position;
        position -= (off_t)chunk;
        if (lseek(fd, position, SEEK_SET) < 0) break;
        ssize_t bytes = read(fd, buf, chunk);
        if (bytes <= 0) break;

        for (ssize_t i = bytes - 1; i >= 0; i--) {
            off_t absolute = position + i;
            if (buf[i] == '\n' && absolute != file_size - 1) {
                count++;
                if (count >= lines) {
                    start_offset = absolute + 1;
                    found = 1;
                    break;
                }
            }
        }
    }

    if (lseek(fd, start_offset, SEEK_SET) >= 0) {
        ssize_t bytes;
        char last = '\n';
        while ((bytes = read(fd, buf, sizeof(buf))) > 0) {
            last = buf[bytes - 1];
            size_t written = 0;
            while (written < (size_t)bytes) {
                ssize_t n = write(STDOUT_FILENO, buf + written, (size_t)bytes - written);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                written += (size_t)n;
            }
        }
        if (last != '\n') write(STDOUT_FILENO, "\n", 1);
    }
    close(fd);
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

static void release_lock(void) {
    if (g_lock_fd >= 0) {
        close(g_lock_fd);
        g_lock_fd = -1;
    }
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

    sigset_t empty_mask;
    sigemptyset(&empty_mask);
    sigprocmask(SIG_SETMASK, &empty_mask, NULL);
}

static void acquire_lock(void) {
    char lock_path[PATH_MAX];
    struct stat st;
    if (stat(LOCK_DIR, &st) == 0 && S_ISDIR(st.st_mode)) {
        snprintf(lock_path, sizeof(lock_path), "%.1024s/flock", LOCK_DIR);
    } else {
        snprintf(lock_path, sizeof(lock_path), "%s", LOCK_DIR);
    }

    int fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        log_error("Failed to open lock file %s: %s", lock_path, strerror(errno));
        exit(1);
    }

    for (int attempts = 0; attempts < 10; attempts++) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            g_lock_fd = fd;
            atexit(release_lock);
            return;
        }
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) {
            log_error("Failed to lock %s: %s", lock_path, strerror(errno));
            close(fd);
            exit(1);
        }
        sleep(1);
    }

    log_error("Another box operation is in progress, please try again later");
    close(fd);
    exit(1);
}

static int waitpid_retry(pid_t pid, int *status) {
    pid_t result;
    do result = waitpid(pid, status, 0); while (result < 0 && errno == EINTR);
    return result == pid ? 0 : -1;
}

static int is_proc_alive(pid_t pid) {
    if (pid <= 1) return 0;
    if (kill(pid, 0) != 0) {
        if (errno == ESRCH) return 0;
    }
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    int fd = open(stat_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[256];
    ssize_t n = 0;
    while (n < (ssize_t)sizeof(buf) - 1) {
        ssize_t r = read(fd, buf + n, sizeof(buf) - 1 - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += r;
    }
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char *rp = strrchr(buf, ')');
    if (!rp || rp + 2 >= buf + n) return 0;
    char state = *(rp + 2);
    if (state == 'Z' || state == 'X') return 0;
    return 1;
}

static pid_t check_proc_pid(pid_t p, int is_scan) {
    if (!is_proc_alive(p)) return -1;

    char exe_path[64], link_target[PATH_MAX];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", p);
    ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
    int exe_matched = 0;
    if (len > 0) {
        link_target[len] = '\0';
        if (len > 10 && strcmp(link_target + len - 10, " (deleted)") == 0) {
            link_target[len - 10] = '\0';
        }
        if (strcmp(link_target, BIN_PATH) == 0) {
            exe_matched = 1;
        } else {
            char canonical_bin[PATH_MAX];
            if (realpath(BIN_PATH, canonical_bin) != NULL) {
                if (strcmp(link_target, canonical_bin) == 0) exe_matched = 1;
            }
        }
    }

    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", p);
    int cfd = open(cmdline_path, O_RDONLY | O_CLOEXEC);
    if (cfd >= 0) {
        char cmd_buf[1024];
        ssize_t n = 0;
        while (n < (ssize_t)sizeof(cmd_buf)) {
            ssize_t cr = read(cfd, cmd_buf + n, sizeof(cmd_buf) - (size_t)n);
            if (cr < 0 && errno == EINTR) continue;
            if (cr <= 0) break;
            n += cr;
        }
        close(cfd);
        if (n > 0) {
            const char *cursor = cmd_buf;
            size_t remaining = (size_t)n;

            const char *nul0 = memchr(cursor, '\0', remaining);
            if (!nul0) return -1;
            size_t len0 = (size_t)(nul0 - cursor);
            const char *argv0 = cursor;
            cursor = nul0 + 1;
            remaining -= (len0 + 1);

            if (!exe_matched) {
                if (len0 == strlen(BIN_PATH) && memcmp(argv0, BIN_PATH, len0) == 0) {
                    exe_matched = 1;
                } else {
                    char canonical_bin[PATH_MAX];
                    if (realpath(BIN_PATH, canonical_bin) != NULL) {
                        if (len0 == strlen(canonical_bin) && memcmp(argv0, canonical_bin, len0) == 0) {
                            exe_matched = 1;
                        }
                    }
                }
            }
            if (!exe_matched) return -1;

            const char *nul1 = memchr(cursor, '\0', remaining);
            if (!nul1) return -1;
            size_t len1 = (size_t)(nul1 - cursor);
            const char *argv1 = cursor;
            cursor = nul1 + 1;
            remaining -= (len1 + 1);

            if (len1 != 3 || memcmp(argv1, "run", 3) != 0) {
                return -1;
            }

            size_t work_dir_len = strlen(WORK_DIR);
            int matched_work_dir = (work_dir_len == 0) ? 1 : 0;

            while (remaining > 0) {
                const char *nul = memchr(cursor, '\0', remaining);
                if (!nul) return -1;
                size_t tlen = (size_t)(nul - cursor);
                const char *token = cursor;
                cursor = nul + 1;
                remaining -= (tlen + 1);

                if (tlen == 2 && memcmp(token, "-D", 2) == 0) {
                    const char *next_nul = memchr(cursor, '\0', remaining);
                    if (!next_nul) return -1;
                    size_t next_len = (size_t)(next_nul - cursor);
                    const char *next_token = cursor;
                    cursor = next_nul + 1;
                    remaining -= (next_len + 1);

                    if (next_len == work_dir_len && memcmp(next_token, WORK_DIR, work_dir_len) == 0) {
                        matched_work_dir = 1;
                    }
                }
            }

            if (matched_work_dir) return p;
            return -1;
        }
    }

    if (!is_scan && exe_matched) {
        return p;
    }
    return -1;
}

static pid_t scan_proc_for_service(void) {
    int fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[1024];
    pid_t found_pid = -1;
    size_t min_entry = offsetof(struct linux_dirent64, d_name) + 1;
    while (1) {
        long nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (nread < 0 && errno == EINTR) continue;
        if (nread <= 0) break;
        for (long bpos = 0; bpos < nread;) {
            long remaining = nread - bpos;
            if ((size_t)remaining < min_entry) break;
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + bpos);
            if ((size_t)d->d_reclen < min_entry || d->d_reclen > remaining) break;
            size_t name_max = (size_t)d->d_reclen - offsetof(struct linux_dirent64, d_name);
            if (memchr(d->d_name, '\0', name_max) != NULL && isdigit((unsigned char)d->d_name[0])) {
                char *end = NULL;
                long p = strtol(d->d_name, &end, 10);
                if (p > 1 && (pid_t)p != getpid() && check_proc_pid((pid_t)p, 1) > 0) {
                    found_pid = (pid_t)p;
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
    int fd = open(PID_FILE, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char pbuf[32];
        ssize_t n = 0;
        while (n < (ssize_t)sizeof(pbuf) - 1) {
            ssize_t r = read(fd, pbuf + n, sizeof(pbuf) - 1 - n);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            n += r;
        }
        close(fd);
        if (n > 0) {
            pbuf[n] = '\0';
            char *end = NULL;
            long p = strtol(pbuf, &end, 10);
            if (p > 1 && check_proc_pid((pid_t)p, 0) > 0) return (pid_t)p;
        }
    }

    pid_t discovered_pid = scan_proc_for_service();
    if (discovered_pid > 0) {
        int pf = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
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
        time_t now = time(NULL);
        struct tm local_tm;
        localtime_r(&now, &local_tm);
        if (local_tm.tm_gmtoff != 0 || (local_tm.tm_zone && strcmp(local_tm.tm_zone, "UTC") != 0) || strcmp(g_iana_tz, "UTC") == 0) {
            long offset = local_tm.tm_gmtoff;
            int off_h = abs((int)(offset / 3600));
            int off_m = abs((int)((offset % 3600) / 60));
            char sign = offset >= 0 ? '+' : '-';
            log_info("Timezone: %s (UTC%c%02d:%02d)", g_iana_tz, sign, off_h, off_m);
        } else {
            log_info("Timezone: %s (offset unavailable)", g_iana_tz);
        }
    }

    char status_path[64];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    int sfd = open(status_path, O_RDONLY | O_CLOEXEC);
    if (sfd >= 0) {
        char sbuf[512];
        char line_buf[256];
        size_t lpos = 0;
        int found_vm = 0;
        while (!found_vm) {
            ssize_t sn = read(sfd, sbuf, sizeof(sbuf));
            if (sn < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (sn == 0) break;
            for (ssize_t i = 0; i < sn; i++) {
                char c = sbuf[i];
                if (c == '\n') {
                    line_buf[lpos] = '\0';
                    if (strncmp(line_buf, "VmRSS:", 6) == 0) {
                        char *vm = line_buf + 6;
                        while (*vm == ' ' || *vm == '\t') vm++;
                        long long mem_kb = strtoll(vm, NULL, 10);
                        if (mem_kb >= 0) {
                            char mem_str[32];
                            fmt_mem(mem_kb, mem_str, sizeof(mem_str));
                            log_info("Memory usage: %s", mem_str);
                            found_vm = 1;
                            break;
                        }
                    }
                    lpos = 0;
                } else if (lpos < sizeof(line_buf) - 1) {
                    line_buf[lpos++] = c;
                }
            }
        }
        close(sfd);
    }

    long clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0) clk_tck = 100;

    unsigned long long uptime_ticks = 0;
    struct timespec bts;
    if (clock_gettime(CLOCK_BOOTTIME, &bts) == 0) {
        uptime_ticks = (unsigned long long)bts.tv_sec * (unsigned long long)clk_tck +
                       ((unsigned long long)bts.tv_nsec * (unsigned long long)clk_tck) / 1000000000ULL;
    } else {
        int ufd = open("/proc/uptime", O_RDONLY);
        if (ufd >= 0) {
            char ubuf[64] = {0};
            ssize_t un = read(ufd, ubuf, sizeof(ubuf) - 1);
            close(ufd);
            if (un > 0) {
                double up_sec = strtod(ubuf, NULL);
                if (up_sec > 0) uptime_ticks = (unsigned long long)(up_sec * (double)clk_tck);
            }
        }
    }

    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    int stfd = open(stat_path, O_RDONLY);
    if (stfd >= 0) {
        char stat_buf[1024];
        ssize_t stn = read(stfd, stat_buf, sizeof(stat_buf) - 1);
        close(stfd);
        if (stn > 0) {
            stat_buf[stn] = '\0';
            char *right_paren = strrchr(stat_buf, ')');
            if (right_paren && right_paren + 2 < stat_buf + stn) {
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

                unsigned long long elapsed_ticks = 0;
                if (uptime_ticks > starttime) elapsed_ticks = uptime_ticks - starttime;
                long total_sec = (long)(elapsed_ticks / (unsigned long long)clk_tck);

                if (elapsed_ticks > 0) {
                    unsigned long long cpu_ticks = utime + stime;
                    unsigned long long cpu_tenths = (cpu_ticks * 1000ULL) / elapsed_ticks;
                    log_info("CPU usage: %llu.%llu%% (avg)", cpu_tenths / 10ULL, cpu_tenths % 10ULL);
                } else {
                    log_info("CPU usage: 0.0%% (avg)");
                }

                char uptime_str[32];
                fmt_uptime(total_sec, uptime_str, sizeof(uptime_str));
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
        ssize_t total = 0;
        while (total < (ssize_t)sizeof(io_buf) - 1) {
            ssize_t ion = read(iofd, io_buf + total, sizeof(io_buf) - 1 - total);
            if (ion < 0 && errno == EINTR) continue;
            if (ion <= 0) break;
            total += ion;
        }
        close(iofd);
        if (total > 0) {
            io_buf[total] = '\0';
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
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        log_error("Failed to fork: %s", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        reset_lock_cleanup_signals();
        release_lock();
        close(pipefd[0]);

        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }

        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        if (chdir(WORK_DIR) != 0 || apply_nofile_limit() != 0 || apply_credentials(RUN_USER) != 0) _exit(126);
        execl(BIN_PATH, BIN_PATH, "check", "-D", WORK_DIR, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    char output[1024] = {0};
    char discard[256];
    size_t total = 0;
    while (1) {
        ssize_t n;
        if (total < sizeof(output) - 1) {
            n = read(pipefd[0], output + total, sizeof(output) - 1 - total);
            if (n < 0 && errno == EINTR) continue;
            if (n > 0) total += (size_t)n;
        } else {
            n = read(pipefd[0], discard, sizeof(discard));
            if (n < 0 && errno == EINTR) continue;
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

static void child_report_err(int fd, int err, int exit_code) {
    size_t written = 0;
    while (written < sizeof(err)) {
        ssize_t n = write(fd, ((const char *)&err) + written, sizeof(err) - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        written += (size_t)n;
    }
    close(fd);
    _exit(exit_code);
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

    char config_file[PATH_MAX];
    snprintf(config_file, sizeof(config_file), "%.1024s/config.json", WORK_DIR);
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

    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) {
        log_error("Failed to create startup synchronization pipe: %s", strerror(errno));
        return 1;
    }
    fcntl(sync_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(sync_pipe[1], F_SETFD, FD_CLOEXEC);

    pid_t pid = fork();
    if (pid < 0) {
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        log_error("Failed to fork process: %s", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        reset_lock_cleanup_signals();
        release_lock();
        close(sync_pipe[0]);

        if (setsid() < 0) {
            child_report_err(sync_pipe[1], errno, 127);
        }

        if (chdir(WORK_DIR) != 0) {
            child_report_err(sync_pipe[1], errno, 127);
        }

        if (apply_nofile_limit() != 0) {
            child_report_err(sync_pipe[1], errno, 125);
        }

        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            if (null_fd != STDIN_FILENO) close(null_fd);
        }

        int log_fd = open(SINGBOX_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd < 0) {
            child_report_err(sync_pipe[1], errno, 124);
        }
        dup2(log_fd, STDOUT_FILENO);
        dup2(log_fd, STDERR_FILENO);
        if (log_fd != STDOUT_FILENO && log_fd != STDERR_FILENO) close(log_fd);

        if (g_iana_tz[0] != '\0') setenv("TZ", g_iana_tz, 1);

        if (apply_credentials(RUN_USER) != 0) {
            child_report_err(sync_pipe[1], errno, 126);
        }

        execl(BIN_PATH, BIN_PATH, "run", "-D", WORK_DIR, (char *)NULL);
        child_report_err(sync_pipe[1], errno, 127);
    }

    close(sync_pipe[1]);

    int child_err = 0;
    size_t total_read = 0;
    int read_failed = 0;
    int saved_errno = 0;

    while (total_read < sizeof(child_err)) {
        ssize_t sn = read(sync_pipe[0], ((char *)&child_err) + total_read, sizeof(child_err) - total_read);
        if (sn < 0) {
            if (errno == EINTR) continue;
            read_failed = 1;
            saved_errno = errno;
            break;
        }
        if (sn == 0) break;
        total_read += (size_t)sn;
    }
    close(sync_pipe[0]);

    if (read_failed) {
        int status = 0;
        waitpid_retry(pid, &status);
        log_error("Failed to read startup handshake from %s: %s", SERVICE_NAME, strerror(saved_errno));
        clear_pid();
        return 1;
    }

    if (total_read > 0 && total_read < sizeof(child_err)) {
        int status = 0;
        waitpid_retry(pid, &status);
        log_error("%s startup handshake error: incomplete error report from child", SERVICE_NAME);
        show_tail(SINGBOX_LOG, 10);
        clear_pid();
        return 1;
    }

    if (total_read == sizeof(child_err)) {
        int status = 0;
        waitpid_retry(pid, &status);
        log_error("%s failed during startup setup/exec: %s", SERVICE_NAME, strerror(child_err));
        show_tail(SINGBOX_LOG, 10);
        clear_pid();
        return 1;
    }

    int pf = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
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
            if (!is_proc_alive(pid)) { child_alive = 0; break; }
        } else if (w < 0) {
            if (errno == EINTR) { i--; continue; }
            log_error("Failed to wait for %s startup: %s", SERVICE_NAME, strerror(errno));
            child_alive = 0;
            break;
        }

        if (check_proc_pid(pid, 0) <= 0) {
            child_alive = 0;
            break;
        }
    }

    if (!child_alive || check_proc_pid(pid, 0) <= 0) {
        log_error("%s failed to stay alive during startup observation window! Check %s for details", SERVICE_NAME, SINGBOX_LOG);
        show_tail(SINGBOX_LOG, 10);
        clear_pid();
        return 1;
    }

    log_info("%s exec succeeded, process alive (PID: %d)", SERVICE_NAME, pid);
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
        if (!is_proc_alive(pid)) break;
        sleep(1);
    }

    if (is_proc_alive(pid)) {
        log_info("Process unresponsive (%ds), forcing termination...", STOP_TIMEOUT);
        kill(pid, SIGKILL);
        for (int i = 0; i < 5; i++) {
            if (!is_proc_alive(pid)) break;
            sleep(1);
        }
    }

    if (is_proc_alive(pid)) {
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

    if (check_proc_pid(pid, 0) <= 0) {
        log_error("%s process %d is no longer valid.", SERVICE_NAME, pid);
        clear_pid();
        return 1;
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
        release_lock();
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
    if (load_config() != 0) return 1;

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
