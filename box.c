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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <ctype.h>
#include <grp.h>
#include <pwd.h>

typedef struct {
    char service_name[128];
    char work_dir[256];
    char bin_path[256];
    char pid_file[256];
    char log_dir[256];
    char log_file[256];
    char error_log[256];
    char singbox_log[256];
    char lock_dir[256];
    char run_user[128];
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
#define MAX_LOG_SIZE    g_cfg.max_log_size
#define STOP_TIMEOUT    g_cfg.stop_timeout
#define START_TIMEOUT   g_cfg.start_timeout
#define CHECK_CONFIG    g_cfg.check_config
#define NOFILE_LIMIT    g_cfg.nofile_limit

static int g_lock_acquired = 0;

static pid_t get_pid(void);
static void clear_pid(void);
static void release_lock(void);
static int display_status(void);
static int do_check(void);
static int start_service(void);

static char *trim_str(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static void parse_ini_line(char *line, int *has_bin, int *has_pid, int *has_logdir, int *has_logfile, int *has_errlog, int *has_sblog, int *has_lockdir) {
    line = trim_str(line);
    if (line[0] == '\0' || line[0] == '#' || line[0] == ';' || line[0] == '[') return;

    char *eq = strchr(line, '=');
    if (!eq) return;

    *eq = '\0';
    char *key = trim_str(line);
    char *val = eq + 1;

    char *comment = strpbrk(val, "#;");
    if (comment) *comment = '\0';
    val = trim_str(val);

    size_t val_len = strlen(val);
    if (val_len >= 2 && ((val[0] == '"' && val[val_len - 1] == '"') || (val[0] == '\'' && val[val_len - 1] == '\''))) {
        val[val_len - 1] = '\0';
        val++;
        val = trim_str(val);
    }

    if (strcasecmp(key, "service_name") == 0) {
        snprintf(g_cfg.service_name, sizeof(g_cfg.service_name), "%s", val);
    } else if (strcasecmp(key, "work_dir") == 0) {
        snprintf(g_cfg.work_dir, sizeof(g_cfg.work_dir), "%s", val);
    } else if (strcasecmp(key, "bin_path") == 0) {
        snprintf(g_cfg.bin_path, sizeof(g_cfg.bin_path), "%s", val);
        *has_bin = 1;
    } else if (strcasecmp(key, "pid_file") == 0) {
        snprintf(g_cfg.pid_file, sizeof(g_cfg.pid_file), "%s", val);
        *has_pid = 1;
    } else if (strcasecmp(key, "log_dir") == 0) {
        snprintf(g_cfg.log_dir, sizeof(g_cfg.log_dir), "%s", val);
        *has_logdir = 1;
    } else if (strcasecmp(key, "log_file") == 0) {
        snprintf(g_cfg.log_file, sizeof(g_cfg.log_file), "%s", val);
        *has_logfile = 1;
    } else if (strcasecmp(key, "error_log") == 0) {
        snprintf(g_cfg.error_log, sizeof(g_cfg.error_log), "%s", val);
        *has_errlog = 1;
    } else if (strcasecmp(key, "singbox_log") == 0) {
        snprintf(g_cfg.singbox_log, sizeof(g_cfg.singbox_log), "%s", val);
        *has_sblog = 1;
    } else if (strcasecmp(key, "lock_dir") == 0) {
        snprintf(g_cfg.lock_dir, sizeof(g_cfg.lock_dir), "%s", val);
        *has_lockdir = 1;
    } else if (strcasecmp(key, "run_user") == 0) {
        snprintf(g_cfg.run_user, sizeof(g_cfg.run_user), "%s", val);
    } else if (strcasecmp(key, "max_log_size") == 0) {
        g_cfg.max_log_size = atol(val);
    } else if (strcasecmp(key, "stop_timeout") == 0) {
        g_cfg.stop_timeout = atoi(val);
    } else if (strcasecmp(key, "start_timeout") == 0) {
        g_cfg.start_timeout = atoi(val);
    } else if (strcasecmp(key, "check_config") == 0) {
        g_cfg.check_config = atoi(val);
    } else if (strcasecmp(key, "nofile_limit") == 0) {
        g_cfg.nofile_limit = atol(val);
    }
}

static void load_config(void) {
    snprintf(g_cfg.service_name, sizeof(g_cfg.service_name), "sing-box");
    snprintf(g_cfg.work_dir, sizeof(g_cfg.work_dir), "/data/adb/sing-box");
    snprintf(g_cfg.run_user, sizeof(g_cfg.run_user), "root:net_admin");
    g_cfg.max_log_size = 1048576L;
    g_cfg.stop_timeout = 10;
    g_cfg.start_timeout = 3;
    g_cfg.check_config = 0;
    g_cfg.nofile_limit = 1000000L;

    int has_bin = 0, has_pid = 0, has_logdir = 0, has_logfile = 0, has_errlog = 0, has_sblog = 0, has_lockdir = 0;

    const char *candidates[] = {
        "box.ini",
        "bix.ini",
        "/data/adb/sing-box/box.ini",
        "/data/adb/sing-box/bix.ini",
        "/data/adb/box.ini",
        "/data/adb/bix.ini",
        NULL
    };

    for (int i = 0; candidates[i] != NULL; i++) {
        FILE *f = fopen(candidates[i], "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                parse_ini_line(line, &has_bin, &has_pid, &has_logdir, &has_logfile, &has_errlog, &has_sblog, &has_lockdir);
            }
            fclose(f);
            break;
        }
    }

    if (!has_bin)     snprintf(g_cfg.bin_path, sizeof(g_cfg.bin_path), "%s/bin/%s", g_cfg.work_dir, g_cfg.service_name);
    if (!has_pid)     snprintf(g_cfg.pid_file, sizeof(g_cfg.pid_file), "%s/%s.pid", g_cfg.work_dir, g_cfg.service_name);
    if (!has_logdir)  snprintf(g_cfg.log_dir, sizeof(g_cfg.log_dir), "%s/logs", g_cfg.work_dir);
    if (!has_logfile) snprintf(g_cfg.log_file, sizeof(g_cfg.log_file), "%s/run.log", g_cfg.log_dir);
    if (!has_errlog)  snprintf(g_cfg.error_log, sizeof(g_cfg.error_log), "%s/run_error.log", g_cfg.log_dir);
    if (!has_sblog)   snprintf(g_cfg.singbox_log, sizeof(g_cfg.singbox_log), "%s/sing-box.log", g_cfg.log_dir);
    if (!has_lockdir) snprintf(g_cfg.lock_dir, sizeof(g_cfg.lock_dir), "%s/.box.lock", g_cfg.work_dir);
}

static void ts(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

static void rotate_log(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) != 0) return;
    if (st.st_size > MAX_LOG_SIZE) {
        char backup_path[512];
        snprintf(backup_path, sizeof(backup_path), "%s.1", filepath);
        rename(filepath, backup_path);
    }
}

static void log_info(const char *fmt, ...) {
    rotate_log(LOG_FILE);
    char timestamp[64];
    ts(timestamp, sizeof(timestamp));

    char message[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    printf("[%s] [INFO] %s\n", timestamp, message);
    fflush(stdout);

    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        fprintf(f, "[%s] [INFO] %s\n", timestamp, message);
        fclose(f);
    }
}

static void log_error(const char *fmt, ...) {
    rotate_log(ERROR_LOG);
    char timestamp[64];
    ts(timestamp, sizeof(timestamp));

    char message[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    fprintf(stderr, "[%s] [ERROR] %s\n", timestamp, message);
    fflush(stderr);

    FILE *f = fopen(ERROR_LOG, "a");
    if (f) {
        fprintf(f, "[%s] [ERROR] %s\n", timestamp, message);
        fclose(f);
    }
}

static void create_dirs_recursive(const char *path) {
    char temp[512];
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
    char bin_dir[512];
    snprintf(bin_dir, sizeof(bin_dir), "%s/bin", WORK_DIR);
    create_dirs_recursive(bin_dir);

    if (geteuid() != 0 && getuid() != 0) {
        char timestamp[64];
        ts(timestamp, sizeof(timestamp));
        fprintf(stderr, "[%s] [ERROR] Root privileges required\n", timestamp);
        exit(1);
    }

    if (system("command -v busybox >/dev/null 2>&1") != 0) {
        log_error("busybox not found, please ensure KernelSU environment is intact");
        exit(1);
    }
}

static void release_lock(void) {
    if (g_lock_acquired) {
        rmdir(LOCK_DIR);
        g_lock_acquired = 0;
    }
}

static void signal_lock_cleanup(int sig) {
    (void)sig;
    release_lock();
    exit(128 + sig);
}

static void acquire_lock(void) {
    int attempts = 0;
    while (mkdir(LOCK_DIR, 0755) != 0) {
        struct stat st;
        if (stat(LOCK_DIR, &st) == 0) {
            time_t now = time(NULL);
            if (difftime(now, st.st_mtime) > 60.0) {
                rmdir(LOCK_DIR);
                continue;
            }
        }
        attempts++;
        if (attempts >= 10) {
            log_error("Another box operation is in progress, please try again later");
            exit(1);
        }
        sleep(1);
    }
    g_lock_acquired = 1;
    atexit(release_lock);
    signal(SIGINT, signal_lock_cleanup);
    signal(SIGTERM, signal_lock_cleanup);
}

static pid_t get_pid(void) {
    FILE *f = fopen(PID_FILE, "r");
    if (f) {
        pid_t p = -1;
        if (fscanf(f, "%d", &p) == 1 && p > 0) {
            fclose(f);
            if (kill(p, 0) == 0) {
                // 1. Try /proc/<p>/exe readlink
                char exe_path[256];
                char link_target[512];
                snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", p);
                ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
                if (len > 0) {
                    link_target[len] = '\0';
                    if (strstr(link_target, SERVICE_NAME) != NULL) {
                        return p;
                    }
                } else {
                    // 2. Fallback: check /proc/<p>/comm
                    char comm_path[256];
                    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", p);
                    FILE *fcomm = fopen(comm_path, "r");
                    if (fcomm) {
                        char comm_buf[64] = {0};
                        if (fgets(comm_buf, sizeof(comm_buf), fcomm)) {
                            comm_buf[strcspn(comm_buf, "\r\n")] = 0;
                            if (strcmp(comm_buf, SERVICE_NAME) == 0) {
                                fclose(fcomm);
                                return p;
                            }
                        }
                        fclose(fcomm);
                    }
                }
            }
        } else {
            fclose(f);
        }
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "busybox pidof %s 2>/dev/null | awk '{print $1}'", SERVICE_NAME);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        pid_t p = -1;
        if (fscanf(fp, "%d", &p) == 1 && p > 0) {
            pclose(fp);
            if (kill(p, 0) == 0) {
                FILE *pf = fopen(PID_FILE, "w");
                if (pf) {
                    fprintf(pf, "%d\n", p);
                    fclose(pf);
                }
                return p;
            }
        } else {
            pclose(fp);
        }
    }

    return -1;
}

static int is_running(void) {
    return get_pid() > 0;
}

static void clear_pid(void) {
    unlink(PID_FILE);
}

static void fmt_mem(long long kb, char *buf, size_t size) {
    if (kb >= 1048576LL) {
        snprintf(buf, size, "%.2f GB", (double)kb / 1048576.0);
    } else if (kb >= 1024LL) {
        snprintf(buf, size, "%.2f MB", (double)kb / 1024.0);
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

    char status_path[256];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    FILE *f = fopen(status_path, "r");
    if (f) {
        char line[256];
        long long mem_kb = -1;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                sscanf(line + 6, "%lld", &mem_kb);
                break;
            }
        }
        fclose(f);
        if (mem_kb >= 0) {
            char mem_str[64];
            fmt_mem(mem_kb, mem_str, sizeof(mem_str));
            log_info("Memory usage: %s", mem_str);
        }
    }

    char ps_cmd[256];
    snprintf(ps_cmd, sizeof(ps_cmd), "ps -p %d -o %%CPU 2>/dev/null | tail -n 1 | tr -d ' %%'", pid);
    FILE *ps_fp = popen(ps_cmd, "r");
    if (ps_fp) {
        char cpu_buf[64] = {0};
        if (fgets(cpu_buf, sizeof(cpu_buf), ps_fp) && strlen(cpu_buf) > 0) {
            cpu_buf[strcspn(cpu_buf, "\r\n")] = 0;
            if (strlen(cpu_buf) > 0 && strcmp(cpu_buf, "-") != 0) {
                log_info("CPU usage: %s%%", cpu_buf);
            } else {
                log_info("CPU usage: unavailable");
            }
        } else {
            log_info("CPU usage: unavailable");
        }
        pclose(ps_fp);
    } else {
        log_info("CPU usage: unavailable");
    }

    FILE *uptime_f = fopen("/proc/uptime", "r");
    if (uptime_f) {
        double sys_uptime = 0;
        if (fscanf(uptime_f, "%lf", &sys_uptime) == 1) {
            char stat_path[256];
            snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
            FILE *stat_f = fopen(stat_path, "r");
            if (stat_f) {
                char stat_buf[1024];
                if (fgets(stat_buf, sizeof(stat_buf), stat_f)) {
                    char *right_paren = strrchr(stat_buf, ')');
                    if (right_paren) {
                        unsigned long long starttime = 0;
                        int field_idx = 3;
                        char *token = strtok(right_paren + 2, " ");
                        while (token) {
                            if (field_idx == 22) {
                                starttime = strtoull(token, NULL, 10);
                                break;
                            }
                            token = strtok(NULL, " ");
                            field_idx++;
                        }
                        long clk_tck = sysconf(_SC_CLK_TCK);
                        if (clk_tck <= 0) clk_tck = 100;
                        long total_sec = (long)sys_uptime - (long)(starttime / clk_tck);
                        if (total_sec >= 0) {
                            char uptime_str[64];
                            fmt_uptime(total_sec, uptime_str, sizeof(uptime_str));
                            log_info("Uptime: %s", uptime_str);
                        }
                    }
                }
                fclose(stat_f);
            }
        }
        fclose(uptime_f);
    }

    char fd_dir[256];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
    DIR *dir = opendir(fd_dir);
    if (dir) {
        int socket_count = 0;
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            char sym_path[512];
            char target[256];
            snprintf(sym_path, sizeof(sym_path), "%s/%s", fd_dir, entry->d_name);
            ssize_t len = readlink(sym_path, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                if (strncmp(target, "socket:", 7) == 0) {
                    socket_count++;
                }
            }
        }
        closedir(dir);
        if (socket_count > 0) {
            log_info("Network sockets: %d", socket_count);
        }
    }

    char io_path[256];
    snprintf(io_path, sizeof(io_path), "/proc/%d/io", pid);
    FILE *io_f = fopen(io_path, "r");
    if (io_f) {
        char line[256];
        long long read_bytes = -1, write_bytes = -1;
        while (fgets(line, sizeof(line), io_f)) {
            if (strncmp(line, "read_bytes:", 11) == 0) {
                sscanf(line + 11, "%lld", &read_bytes);
            } else if (strncmp(line, "write_bytes:", 12) == 0) {
                sscanf(line + 12, "%lld", &write_bytes);
            }
        }
        fclose(io_f);
        if (read_bytes >= 0 && write_bytes >= 0) {
            double read_mb = (double)read_bytes / 1048576.0;
            double write_mb = (double)write_bytes / 1048576.0;
            log_info("Disk I/O: read %.2f MB / write %.2f MB", read_mb, write_mb);
        }
    }

    FILE *pf = fopen(PID_FILE, "w");
    if (pf) {
        fprintf(pf, "%d\n", pid);
        fclose(pf);
    }

    return 0;
}

static int do_check(void) {
    if (access(BIN_PATH, X_OK) != 0) {
        log_error("Binary not found or not executable: %s", BIN_PATH);
        return 1;
    }
    char check_cmd[512];
    snprintf(check_cmd, sizeof(check_cmd), "%s check -D %s 2>&1", BIN_PATH, WORK_DIR);
    FILE *fp = popen(check_cmd, "r");
    if (!fp) {
        log_error("Failed to execute validation command");
        return 1;
    }
    char output[2048] = {0};
    size_t bytes_read = fread(output, 1, sizeof(output) - 1, fp);
    output[bytes_read] = '\0';
    int status = pclose(fp);

    if (WEXITSTATUS(status) != 0) {
        log_error("Configuration validation failed:");
        if (strlen(output) > 0) {
            log_error("%s", output);
        }
        return 1;
    }
    return 0;
}

static void check_stale_pid(void) {
    if (access(PID_FILE, F_OK) == 0) {
        FILE *f = fopen(PID_FILE, "r");
        if (f) {
            pid_t old_pid = -1;
            if (fscanf(f, "%d", &old_pid) == 1 && old_pid > 0) {
                if (kill(old_pid, 0) != 0) {
                    log_info("Cleaning stale PID file (PID %d not found)", old_pid);
                    clear_pid();
                }
            } else {
                log_info("Invalid PID file content, cleaning up");
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

    char config_file[256];
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

    if (chdir(WORK_DIR) != 0) {
        log_error("Failed to enter working directory: %s", WORK_DIR);
        return 1;
    }

    struct rlimit rl;
    rl.rlim_cur = NOFILE_LIMIT;
    rl.rlim_max = NOFILE_LIMIT;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        log_info("Warn: Failed to set ulimit, using system defaults");
    }

    log_info("Starting %s...", SERVICE_NAME);
    rotate_log(LOG_FILE);
    rotate_log(ERROR_LOG);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), 
        "nohup busybox setuidgid %s %s run -D %s < /dev/null >> %s 2>&1 &",
        RUN_USER, BIN_PATH, WORK_DIR, SINGBOX_LOG);
    
    int ret = system(cmd);
    if (ret == -1) {
        log_error("Failed to execute start command");
        return 1;
    }
    if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0) {
        log_error("Start command failed with exit code %d", WEXITSTATUS(ret));
        return 1;
    }

    int max_attempts = START_TIMEOUT * 2;
    int attempts = 0;
    pid_t running_pid = -1;

    while (attempts < max_attempts) {
        sleep(1);
        attempts++;
        running_pid = get_pid();
        if (running_pid > 0) {
            break;
        }
        if (attempts % 2 == 0) {
            log_info("Waiting for process to start... (%d/%d)", attempts, max_attempts);
        }
    }

    if (running_pid <= 0) {
        log_error("%s failed to start!", SERVICE_NAME);
        log_error("Check %s for details", SINGBOX_LOG);
        char tail_cmd[256];
        snprintf(tail_cmd, sizeof(tail_cmd), "tail -n 10 %s 2>/dev/null", SINGBOX_LOG);
        system(tail_cmd);
        clear_pid();
        return 1;
    }

    FILE *pf = fopen(PID_FILE, "w");
    if (pf) {
        fprintf(pf, "%d\n", running_pid);
        fclose(pf);
    }

    log_info("%s started successfully (PID: %d)", SERVICE_NAME, running_pid);
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

    check_stale_pid();

    pid_t bin_pid = get_pid();
    
    if (bin_pid > 0 && kill(bin_pid, 0) == 0) {
        log_info("Stopping existing process (PID: %d)...", bin_pid);
        kill(bin_pid, SIGTERM);
        
        int waited = 0;
        while (waited < STOP_TIMEOUT) {
            if (kill(bin_pid, 0) != 0) break;
            sleep(1);
            waited++;
        }
        
        if (kill(bin_pid, 0) == 0) {
            log_info("Process unresponsive, force killing...");
            kill(bin_pid, SIGKILL);
            sleep(1);
            
            if (kill(bin_pid, 0) == 0) {
                log_error("Failed to terminate process %d", bin_pid);
                return 1;
            }
        }
        
        clear_pid();
        log_info("Process stopped successfully");
    } else if (bin_pid > 0) {
        log_info("Cleaning stale PID (PID %d not found)", bin_pid);
        clear_pid();
    }

    clear_pid();
    
    sync();
    usleep(500000);
    
    return start_service();
}

static void show_log(int lines) {
    if (lines <= 0) lines = 50;
    printf("===== Script Log (last %d lines) =====\n", lines);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "[ -f \"%s\" ] && tail -n %d \"%s\" || echo \"(empty)\"", LOG_FILE, lines, LOG_FILE);
    system(cmd);
    printf("\n===== Script Error (last %d lines) =====\n", lines);
    snprintf(cmd, sizeof(cmd), "[ -f \"%s\" ] && tail -n %d \"%s\" || echo \"(empty)\"", ERROR_LOG, lines, ERROR_LOG);
    system(cmd);
}

static int show_version(void) {
    if (access(BIN_PATH, X_OK) != 0) {
        log_error("Binary not executable: %s", BIN_PATH);
        return 1;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s version", BIN_PATH);
    return system(cmd);
}

static void usage(const char *prog_name) {
    printf("Usage: %s {start|stop|restart|status|check|log [lines]|version}\n\n", prog_name);
    printf("Commands:\n");
    printf("  start    - Start sing-box service\n");
    printf("  stop     - Stop sing-box service\n");
    printf("  restart  - Restart sing-box service\n");
    printf("  status   - Show service status with detailed info\n");
    printf("  check    - Validate configuration\n");
    printf("  log [n]  - Show last n lines of script logs (default: 50)\n");
    printf("  version  - Show sing-box version\n");
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
    } else if (strcmp(cmd, "status") == 0) {
        return display_status();
    } else if (strcmp(cmd, "check") == 0) {
        int res = do_check();
        if (res == 0) log_info("Configuration validation passed");
        return res;
    } else if (strcmp(cmd, "log") == 0) {
        int lines = (argc >= 3) ? atoi(argv[2]) : 50;
        show_log(lines);
        return 0;
    } else if (strcmp(cmd, "version") == 0) {
        return show_version();
    } else if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "help") == 0) {
        usage(argv[0]);
        return 0;
    } else {
        usage(argv[0]);
        return 1;
    }
}