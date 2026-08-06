#!/system/bin/sh
# box - sing-box service management script for KernelSU
# Usage: box {start|stop|restart|status|check|log|version}

# ================= Configuration =================
SERVICE_NAME="sing-box"
WORK_DIR="/data/adb/${SERVICE_NAME}"
BIN_PATH="${WORK_DIR}/bin/${SERVICE_NAME}"
PID_FILE="${WORK_DIR}/${SERVICE_NAME}.pid"
LOG_DIR="${WORK_DIR}/logs"
LOG_FILE="${LOG_DIR}/run.log"
ERROR_LOG="${LOG_DIR}/run_error.log"
LOCK_DIR="${WORK_DIR}/.box.lock"

RUN_USER="root:net_admin"     # user:group for setuidgid
MAX_LOG_SIZE=1048576          # Rotate log when exceeding 1MB
STOP_TIMEOUT=10               # Max wait time (seconds) after SIGTERM
START_TIMEOUT=3               # Seconds to verify process survival after start
CHECK_CONFIG=0                # Enable pre-start configuration validation (0=disabled)
NOFILE_LIMIT=1000000

umask 022

# ================= Core Functions =================
ts() { date '+%Y-%m-%d %H:%M:%S'; }

rotate_log() {
    _f="$1"
    [ -f "${_f}" ] || return 0
    _size=$(stat -c %s "${_f}" 2>/dev/null || busybox stat -c %s "${_f}" 2>/dev/null || echo 0)
    case "${_size}" in
        ''|*[!0-9]*) return 0 ;;
    esac
    [ "${_size}" -gt "${MAX_LOG_SIZE}" ] && mv -f "${_f}" "${_f}.1"
    return 0
}

log() {
    rotate_log "${LOG_FILE}"
    echo "[$(ts)] [INFO] $*" | tee -a "${LOG_FILE}"
}

error_log() {
    rotate_log "${ERROR_LOG}"
    echo "[$(ts)] [ERROR] $*" | tee -a "${ERROR_LOG}" >&2
}

# ================= Environment Validation =================
prepare_env() {
    # Create required directories
    mkdir -p "${WORK_DIR}" 2>/dev/null
    mkdir -p "${LOG_DIR}" 2>/dev/null
    mkdir -p "$(dirname "${BIN_PATH}")" 2>/dev/null

    if [ "$(id -u 2>/dev/null)" != "0" ]; then
        echo "[$(ts)] [ERROR] Root privileges required" >&2
        exit 1
    fi

    if ! command -v busybox >/dev/null 2>&1; then
        error_log "busybox not found, please ensure KernelSU environment is intact"
        exit 1
    fi
}

acquire_lock() {
    _i=0
    while ! mkdir "${LOCK_DIR}" 2>/dev/null; do
        if [ -d "${LOCK_DIR}" ] && [ -z "$(find "${LOCK_DIR}" -maxdepth 0 -mmin -1 2>/dev/null)" ]; then
            rmdir "${LOCK_DIR}" 2>/dev/null && continue
        fi
        _i=$((_i + 1))
        [ "${_i}" -ge 10 ] && { error_log "Another box operation is in progress, please try again later"; exit 1; }
        sleep 1
    done
    trap 'rmdir "${LOCK_DIR}" 2>/dev/null' EXIT INT TERM
}

# ================= Process Identification =================
real_bin() { readlink -f "${BIN_PATH}" 2>/dev/null || echo "${BIN_PATH}"; }

pid_is_ours() {
    _p="$1"
    [ -n "${_p}" ] || return 1
    case "${_p}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ -d "/proc/${_p}" ] || return 1
    _exe=$(readlink -f "/proc/${_p}/exe" 2>/dev/null)
    [ -n "${_exe}" ] && [ "${_exe}" = "$(real_bin)" ]
}

get_pid() {
    if [ -f "${PID_FILE}" ]; then
        _p=$(cat "${PID_FILE}" 2>/dev/null | tr -d ' \r\n')
        if pid_is_ours "${_p}"; then
            echo "${_p}"
            return 0
        fi
    fi
    for _p in $(busybox pidof "${SERVICE_NAME}" 2>/dev/null); do
        if pid_is_ours "${_p}"; then
            echo "${_p}" > "${PID_FILE}"
            echo "${_p}"
            return 0
        fi
    done
    return 1
}

is_running() { get_pid >/dev/null 2>&1; }

clear_pid() { [ -f "${PID_FILE}" ] && rm -f "${PID_FILE}"; return 0; }

# ================= Status Display =================
fmt_mem() {
    _kb="$1"
    if [ "${_kb}" -ge 1048576 ]; then
        echo "$(awk "BEGIN {printf \"%.2f\", ${_kb}/1048576}") GB"
    elif [ "${_kb}" -ge 1024 ]; then
        echo "$(awk "BEGIN {printf \"%.2f\", ${_kb}/1024}") MB"
    else
        echo "${_kb} kB"
    fi
}

fmt_uptime() {
    _t="$1"
    _d=$((_t / 86400)); _h=$(((_t % 86400) / 3600))
    _m=$(((_t % 3600) / 60)); _s=$((_t % 60))
    _o=""
    [ "${_d}" -gt 0 ] && _o="${_o}${_d}d "
    [ "${_h}" -gt 0 ] && _o="${_o}${_h}h "
    [ "${_m}" -gt 0 ] && _o="${_o}${_m}m "
    echo "${_o}${_s}s"
}

display_status() {
    bin_pid=$(get_pid) || {
        log "${SERVICE_NAME} service is stopped."
        clear_pid
        return 1
    }

    log "${SERVICE_NAME} service is running (PID: ${bin_pid})"

    # 1. Memory usage (VmRSS)
    mem_kb=$(awk '/^VmRSS/ {print $2}' "/proc/${bin_pid}/status" 2>/dev/null)
    case "${mem_kb}" in
        ''|*[!0-9]*) ;;
        *) log "Memory usage: $(fmt_mem "${mem_kb}")" ;;
    esac

    # 2. CPU usage
    cpu=$(ps -p "${bin_pid}" -o %CPU 2>/dev/null | tail -n 1 | tr -d ' %')
    case "${cpu}" in
        ''|*[!0-9.]*) log "CPU usage: unavailable" ;;
        *) log "CPU usage: ${cpu}%" ;;
    esac

    # 3. Uptime
    if [ -r "/proc/${bin_pid}/stat" ]; then
        sys_uptime=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
        stat_rest=$(cat "/proc/${bin_pid}/stat" 2>/dev/null)
        stat_rest=${stat_rest#*") "}
        proc_start=$(echo "${stat_rest}" | awk '{print $20}')
        clk_tck=$(getconf CLK_TCK 2>/dev/null || echo 100)
        case "${sys_uptime}${proc_start}" in
            ''|*[!0-9]*) ;;
            *)
                total=$((sys_uptime - proc_start / clk_tck))
                [ "${total}" -ge 0 ] && log "Uptime: $(fmt_uptime "${total}")"
                ;;
        esac
    fi

    # 4. Network sockets
    net_sockets=$(ls -l "/proc/${bin_pid}/fd" 2>/dev/null | grep -c 'socket:' 2>/dev/null)
    [ "${net_sockets}" -gt 0 ] && log "Network sockets: ${net_sockets}"

    # 5. Disk I/O statistics
    if [ -r "/proc/${bin_pid}/io" ]; then
        read_bytes=$(awk '/^read_bytes:/ {print $2}' "/proc/${bin_pid}/io" 2>/dev/null)
        write_bytes=$(awk '/^write_bytes:/ {print $2}' "/proc/${bin_pid}/io" 2>/dev/null)
        if [ -n "${read_bytes}" ] && [ -n "${write_bytes}" ]; then
            read_mb=$(awk "BEGIN {printf \"%.2f\", ${read_bytes}/1048576}")
            write_mb=$(awk "BEGIN {printf \"%.2f\", ${write_bytes}/1048576}")
            log "Disk I/O: read ${read_mb} MB / write ${write_mb} MB"
        fi
    fi

    echo "${bin_pid}" > "${PID_FILE}"
    return 0
}

# ================= Configuration Validation =================
do_check() {
    if [ ! -x "${BIN_PATH}" ]; then
        error_log "Binary not found or not executable: ${BIN_PATH}"
        return 1
    fi
    out=$("${BIN_PATH}" check -D "${WORK_DIR}" 2>&1)
    if [ $? -ne 0 ]; then
        error_log "Configuration validation failed:"
        [ -n "${out}" ] && error_log "${out}"
        return 1
    fi
    return 0
}

# ================= Core Operations =================
start() {
    if is_running; then
        log "${SERVICE_NAME} is already running."
        display_status
        return 0
    fi

    clear_pid

    if [ ! -x "${BIN_PATH}" ]; then
        error_log "Binary not found or not executable: ${BIN_PATH}"
        return 1
    fi

    if [ ! -f "${WORK_DIR}/config.json" ]; then
        error_log "config.json not found in ${WORK_DIR}"
        return 1
    fi

    if [ "${CHECK_CONFIG}" = 1 ]; then
        log "Validating configuration..."
        do_check || { error_log "Configuration validation failed, aborting startup"; return 1; }
    fi

    cd "${WORK_DIR}" || { error_log "Failed to enter working directory: ${WORK_DIR}"; return 1; }

    ulimit -SHn "${NOFILE_LIMIT}" 2>/dev/null || \
        ulimit -n "${NOFILE_LIMIT}" 2>/dev/null || \
        log "Warn: Failed to set ulimit, using system defaults"

    log "Starting ${SERVICE_NAME}..."
    rotate_log "${LOG_FILE}"; rotate_log "${ERROR_LOG}"

    nohup busybox setuidgid "${RUN_USER}" "${BIN_PATH}" run -D "${WORK_DIR}" \
        < /dev/null >> "${LOG_DIR}/sing-box.log" 2>&1 &
    new_pid=$!
    echo "${new_pid}" > "${PID_FILE}"

    i=0
    while [ "${i}" -lt "${START_TIMEOUT}" ]; do
        sleep 1
        if ! is_running; then
            error_log "${SERVICE_NAME} exited immediately after startup!"
            error_log "Check ${LOG_DIR}/sing-box.log for details"
            clear_pid
            return 1
        fi
        i=$((i + 1))
    done

    log "${SERVICE_NAME} started successfully!"
    display_status
    return 0
}

stop() {
    bin_pid=$(get_pid) || {
        log "${SERVICE_NAME} is not running."
        clear_pid
        return 0
    }

    log "Stopping ${SERVICE_NAME} (PID: ${bin_pid})..."

    kill "${bin_pid}" 2>/dev/null
    i=0
    while [ "${i}" -lt "${STOP_TIMEOUT}" ]; do
        kill -0 "${bin_pid}" 2>/dev/null || break
        sleep 1
        i=$((i + 1))
    done

    if kill -0 "${bin_pid}" 2>/dev/null; then
        log "Process unresponsive (${STOP_TIMEOUT}s), forcing termination..."
        kill -9 "${bin_pid}" 2>/dev/null
        i=0
        while [ "${i}" -lt 5 ]; do
            kill -0 "${bin_pid}" 2>/dev/null || break
            sleep 1
            i=$((i + 1))
        done
    fi

    if kill -0 "${bin_pid}" 2>/dev/null; then
        error_log "Failed to terminate process ${bin_pid}"
        return 1
    fi

    clear_pid
    log "${SERVICE_NAME} stopped."
    return 0
}

restart() {
    stop || { error_log "Stop failed, restart cancelled"; return 1; }
    sleep 1
    start
}

status() { display_status; }

show_log() {
    n="${1:-50}"
    echo "===== Script Log (last ${n} lines) ====="
    [ -f "${LOG_FILE}" ] && tail -n "${n}" "${LOG_FILE}" || echo "(empty)"
    echo ""
    echo "===== Script Error (last ${n} lines) ====="
    [ -f "${ERROR_LOG}" ] && tail -n "${n}" "${ERROR_LOG}" || echo "(empty)"
}

version() {
    [ -x "${BIN_PATH}" ] || { error_log "Binary not executable: ${BIN_PATH}"; return 1; }
    "${BIN_PATH}" version
}

usage() {
    echo "Usage: $0 {start|stop|restart|status|check|log [lines]|version}"
    echo ""
    echo "Commands:"
    echo "  start    - Start sing-box service"
    echo "  stop     - Stop sing-box service"
    echo "  restart  - Restart sing-box service"
    echo "  status   - Show service status with detailed info"
    echo "  check    - Validate configuration"
    echo "  log [n]  - Show last n lines of script logs (default: 50)"
    echo "  version  - Show sing-box version"
}

# ================= Entry Point =================
prepare_env

if [ -z "$1" ] && [ ! -t 0 ]; then
    acquire_lock
    start
    exit $?
fi

case "$1" in
    start | stop | restart)
        acquire_lock
        "$1"
        ;;
    status)  status ;;
    check)   do_check && log "Configuration validation passed" ;;
    log)     show_log "$2" ;;
    version) version ;;
    -h | --help | help) usage ;;
    *)       usage; exit 1 ;;
esac