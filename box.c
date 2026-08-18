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

// ================= Configuration =================
#define SERVICE_NAME    "sing-box"
#define WORK_DIR        "/data/adb/" SERVICE_NAME
#define BIN_PATH        WORK_DIR "/bin/" SERVICE_NAME
#define PID_FILE        WORK_DIR "/" SERVICE_NAME ".pid"
#define LOG_DIR         WORK_DIR "/logs"
#define LOG_FILE        LOG_DIR "/run.log"
#define ERROR_LOG       LOG_DIR "/run_error.log"
#define SINGBOX_LOG     LOG_DIR "/sing-box.log"
#define LOCK_DIR        WORK_DIR "/.box.lock"

#define RUN_USER        "root:net_admin"
#define MAX_LOG_SIZE    1048576L  // 1MB
#define STOP_TIMEOUT    10
#define START_TIMEOUT   3
#define CHECK_CONFIG    0
#define NOFILE_LIMIT    1000000L

static int g_lock_acquired = 0;

// ================= Utility Functions =================
static void ts(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

static void rotate_log(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) != 0) {
        return;
    }
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

// ================= Environment Validation =================
static void prepare_env(void) {
    create_dirs_recursive(WORK_DIR);
    create_dirs_recursive(LOG_DIR);
    create_dirs_recursive(WORK_DIR "/bin");

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
            // If lock dir is older than 60 seconds (1 min), remove it
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

// ================= Process Identification =================
static pid_t find_pid_by_name(const char *name) {
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (!isdigit(entry->d_name[0])) continue;
            pid_t pid = atoi(entry->d_name);

            // 1. Try /proc/<pid>/exe readlink
            char exe_path[256];
            char link_target[512];
            snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
            ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
            if (len > 0) {
                link_target[len] = '\0';
                if (strstr(link_target, name) != NULL) {
                    closedir(dir);
                    return pid;
                }
            }

            // 2. Try /proc/<pid>/comm
            char comm_path[256];
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
            FILE *fcomm = fopen(comm_path, "r");
            if (fcomm) {
                char comm_buf[64] = {0};
                if (fgets(comm_buf, sizeof(comm_buf), fcomm)) {
                    comm_buf[strcspn(comm_buf, "\r\n")] = 0;
                    if (strcmp(comm_buf, name) == 0) {
                        fclose(fcomm);
                        closedir(dir);
                        return pid;
                    }
                }
                fclose(fcomm);
            }
        }
        closedir(dir);
    }

    // 3. Fallback to busybox pidof
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "busybox pidof %s 2>/dev/null | awk '{print $1}'", name);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        pid_t p = -1;
        if (fscanf(fp, "%d", &p) == 1 && p > 0) {
            pclose(fp);
            return p;
        }
        pclose(fp);
    }

    return -1;
}

static pid_t get_pid(void) {
    // 1. Check PID_FILE first
    FILE *f = fopen(PID_FILE, "r");
    if (f) {
        pid_t p = -1;
        if (fscanf(f, "%d", &p) == 1 && p > 0) {
            fclose(f);
            if (kill(p, 0) == 0) {
                char exe_path[256];
                char link_target[512];
                snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", p);
                ssize_t len = readlink(exe_path, link_target, sizeof(link_target) - 1);
                if (len > 0) {
                    link_target[len] = '\0';
                    if (strstr(link_target, SERVICE_NAME) != NULL) {
                        return p;
                    }
                }
            }
        } else {
            fclose(f);
        }
    }

    // 2. Search processes in /proc
    pid_t p = find_pid_by_name(SERVICE_NAME);
    if (p > 0 && kill(p, 0) == 0) {
        FILE *pf = fopen(PID_FILE, "w");
        if (pf) {
            fprintf(pf, "%d\n", p);
            fclose(pf);
        }
        return p;
    }

    return -1;
}

static int is_running(void) {
    return get_pid() > 0;
}

static void clear_pid(void) {
    unlink(PID_FILE);
}

// ================= Status Display =================
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

    // Memory usage
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

    // CPU usage via `ps -p <pid> -o %CPU`
    char ps_cmd[256];
    snprintf(ps_cmd, sizeof(ps_cmd), "ps -p %d -o %%CPU 2>/dev/null | tail -n 1 | tr -d ' %%'", pid);
    FILE *ps_fp = popen(ps_cmd, "r");
    if (ps_fp) {
        char cpu_buf[64] = {0};
        if (fgets(cpu_buf, sizeof(cpu_buf), ps_fp) && strlen(cpu_buf) > 0) {
            // Trim trailing newline
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

    // Process uptime
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

    // Network sockets
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

    // Disk I/O
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

    // Write back PID to PID_FILE
    FILE *pf = fopen(PID_FILE, "w");
    if (pf) {
        fprintf(pf, "%d\n", pid);
        fclose(pf);
    }

    return 0;
}

// ================= Configuration Validation =================
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

// ================= Core Operations =================
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

    pid_t child_pid = fork();
    if (child_pid < 0) {
        log_error("Failed to fork background process: %s", strerror(errno));
        return 1;
    }

    if (child_pid == 0) {
        // Child process
        setsid();

        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }

        int logfd = open(SINGBOX_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (logfd >= 0) {
            dup2(logfd, STDOUT_FILENO);
            dup2(logfd, STDERR_FILENO);
            close(logfd);
        }

        execlp("busybox", "busybox", "setuidgid", RUN_USER, BIN_PATH, "run", "-D", WORK_DIR, (char *)NULL);
        // Fallback if busybox setuidgid fails or busybox not in PATH
        execl(BIN_PATH, BIN_PATH, "run", "-D", WORK_DIR, (char *)NULL);
        exit(1);
    }

    // Parent process
    FILE *pf = fopen(PID_FILE, "w");
    if (pf) {
        fprintf(pf, "%d\n", child_pid);
        fclose(pf);
    }

    for (int i = 0; i < START_TIMEOUT; i++) {
        sleep(1);
        if (!is_running()) {
            log_error("%s exited immediately after startup!", SERVICE_NAME);
            log_error("Check %s for details", SINGBOX_LOG);
            clear_pid();
            return 1;
        }
    }

    log_info("%s started successfully!", SERVICE_NAME);
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

    pid_t pid = get_pid();

    if (access(PID_FILE, F_OK) == 0) {
        FILE *f = fopen(PID_FILE, "r");
        if (f) {
            pid_t old_pid = -1;
            if (fscanf(f, "%d", &old_pid) == 1 && old_pid > 0) {
                if (kill(old_pid, 0) != 0) {
                    log_info("Cleaning stale PID file (PID %d not found)", old_pid);
                    clear_pid();
                }
            }
            fclose(f);
        }
    }

    if (pid > 0 && kill(pid, 0) == 0) {
        log_info("Stopping existing process (PID: %d)...", pid);
        kill(pid, SIGTERM);
        for (int i = 0; i < STOP_TIMEOUT; i++) {
            if (kill(pid, 0) != 0) break;
            sleep(1);
        }
        if (kill(pid, 0) == 0) {
            log_info("Force killing...");
            kill(pid, SIGKILL);
            sleep(1);
        }
        clear_pid();
    }

    rmdir(LOCK_DIR);
    sync();
    sleep(1);
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

// ================= Entry Point =================
int main(int argc, char *argv[]) {
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
