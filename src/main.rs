use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, IsTerminal, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio, exit};
use std::sync::OnceLock;
use std::thread::sleep;
use std::time::Duration;

struct Cfg {
    service_name: String,
    work_dir: String,
    bin_path: String,
    pid_file: String,
    log_dir: String,
    log_file: String,
    error_log: String,
    singbox_log: String,
    lock_dir: String,
    run_user: String,
    timezone: String,
    max_log_size: i64,
    stop_timeout: i64,
    start_timeout: i64,
    check_config: i64,
    nofile_limit: i64,
    iana_tz: String,
}

static CFG: OnceLock<Cfg> = OnceLock::new();
const BOX_VERSION: &str = env!("CARGO_PKG_VERSION");

fn cfg() -> &'static Cfg {
    CFG.get().expect("config not loaded")
}

macro_rules! info { ($($a:tt)*) => { log_msg(false, &format!($($a)*)) } }
macro_rules! error { ($($a:tt)*) => { log_msg(true, &format!($($a)*)) } }

// ================= String & Path Utilities =================

fn is_space(c: char) -> bool {
    c.is_ascii_whitespace() || c == '\x0b'
}

/// Trims whitespace, then one pair of matching surrounding quotes.
fn trim_str(s: &str) -> &str {
    let t = s.trim_matches(is_space);
    let b = t.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        return t[1..t.len() - 1].trim_matches(is_space);
    }
    t
}

/// C-style atoi/strtol: leading whitespace, optional sign, digits; 0 if none.
fn atoi(s: &str) -> i64 {
    let s = s.trim_start_matches(is_space);
    let (neg, s) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let n = s.bytes().take_while(u8::is_ascii_digit).fold(0i64, |n, d| {
        n.saturating_mul(10).saturating_add((d - b'0') as i64)
    });
    if neg { -n } else { n }
}

fn self_dir() -> String {
    match fs::read_link("/proc/self/exe") {
        Ok(p) => {
            let p = p.to_string_lossy().into_owned();
            match p.rfind('/') {
                Some(i) => p[..i].to_string(),
                None => ".".into(),
            }
        }
        Err(_) => ".".into(),
    }
}

fn access(path: &str, mode: libc::c_int) -> bool {
    CString::new(path).is_ok_and(|p| unsafe { libc::access(p.as_ptr(), mode) } == 0)
}

// ================= Permission & User Utilities =================

fn parse_id(name: &str) -> Option<u32> {
    if name.is_empty() || name.starts_with('-') {
        return None;
    }
    name.parse().ok()
}

fn resolve_uid(name: &str) -> Option<u32> {
    match name {
        "root" => Some(0),
        "system" => Some(1000),
        "shell" => Some(2000),
        "nobody" => Some(9999),
        _ => parse_id(name),
    }
}

fn resolve_gid(name: &str) -> Option<u32> {
    match name {
        "root" => Some(0),
        "system" => Some(1000),
        "shell" => Some(2000),
        "inet" => Some(3003),
        "net_raw" => Some(3004),
        "net_admin" => Some(3005),
        "net_bw_stats" => Some(3006),
        "net_bw_acct" => Some(3007),
        "everybody" => Some(9997),
        "nobody" => Some(9999),
        _ => parse_id(name),
    }
}

/// Raises RLIMIT_NOFILE in this process; spawned children inherit it.
fn apply_nofile_limit() -> Result<(), ()> {
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut old) } != 0 {
        error!(
            "getrlimit(RLIMIT_NOFILE) failed: {}",
            io::Error::last_os_error()
        );
        return Err(());
    }
    let target = cfg().nofile_limit as libc::rlim_t;
    let set = |cur, max| {
        let rl = libc::rlimit {
            rlim_cur: cur,
            rlim_max: max,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) == 0 }
    };

    if target <= old.rlim_max {
        if !set(target, old.rlim_max) {
            error!(
                "setrlimit(RLIMIT_NOFILE, soft={target}) failed: {}",
                io::Error::last_os_error()
            );
            return Err(());
        }
        return Ok(());
    }
    // target > hard limit: try to raise hard limit first
    if set(target, target) {
        return Ok(());
    }
    // Raising hard limit failed, cap soft to current hard limit
    if !set(old.rlim_max, old.rlim_max) {
        error!(
            "setrlimit(RLIMIT_NOFILE, capped={}) failed: {}",
            old.rlim_max,
            io::Error::last_os_error()
        );
        return Err(());
    }
    info!(
        "Warning: requested nofile_limit {target} exceeds hard limit {}, capped",
        old.rlim_max
    );
    Ok(())
}

/// Parses RUN_USER into (uid, gid); None means stay root.
fn resolve_creds(spec: &str) -> Result<Option<(u32, u32)>, ()> {
    if spec.is_empty() || matches!(spec, "root" | "root:root" | "0:0" | "0" | "root:0") {
        return Ok(None);
    }
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let Some(uid) = resolve_uid(user) else {
        error!("Invalid UID: {user}");
        return Err(());
    };
    let gid = match group.filter(|g| !g.is_empty()) {
        Some(g) => match resolve_gid(g) {
            Some(v) => v,
            None => {
                error!("Invalid GID: {g}");
                return Err(());
            }
        },
        None => uid,
    };
    Ok(Some((uid, gid)))
}

/// Runs in the forked child before exec: must stay async-signal-safe (no allocation).
fn drop_privs(uid: u32, gid: u32) -> io::Result<()> {
    let groups: [libc::gid_t; 3] = [gid, 3003, 3004]; // AID_NET_ADMIN also gets AID_INET + AID_NET_RAW
    let n = if gid == 3005 { 3 } else { 1 };
    unsafe {
        if libc::setgroups(n, groups.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setresgid(gid, gid, gid) != 0 && libc::setgid(gid) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setresuid(uid, uid, uid) != 0 && libc::setuid(uid) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn service_cmd(args: &[&str], creds: Option<(u32, u32)>, new_session: bool) -> Command {
    let c = cfg();
    let mut cmd = Command::new(&c.bin_path);
    cmd.args(args).current_dir(&c.work_dir);
    // Strip LD_PRELOAD to isolate sing-box from Magisk/Zygisk hooks
    cmd.env_remove("LD_PRELOAD");
    unsafe {
        cmd.pre_exec(move || {
            // Ensure files created by sing-box are not world-writable (umask 027)
            libc::umask(0o027);
            if new_session && libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            match creds {
                Some((uid, gid)) => drop_privs(uid, gid),
                None => Ok(()),
            }
        });
    }
    cmd
}

// ================= Configuration & INI Parser =================

fn expand_vars(src: &str, name: &str, work_dir: &str) -> String {
    let pats = [
        ("${SERVICE_NAME}", name),
        ("$SERVICE_NAME", name),
        ("${WORK_DIR}", work_dir),
        ("$WORK_DIR", work_dir),
    ];
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(ch) = rest.chars().next() {
        if let Some((p, v)) = pats.iter().find(|(p, _)| rest.starts_with(p)) {
            out.push_str(v);
            rest = &rest[p.len()..];
        } else {
            out.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    out
}

fn strip_inline_comment(v: &str) -> &str {
    let b = v.as_bytes();
    let mut quote = 0u8;
    for i in 0..b.len() {
        let c = b[i];
        if (c == b'\'' || c == b'"') && (i == 0 || b[i - 1] != b'\\') {
            if quote == 0 {
                quote = c;
            } else if quote == c {
                quote = 0;
            }
        } else if quote == 0 && (c == b'#' || c == b';') {
            return &v[..i];
        }
    }
    v
}

fn parse_num(key: &str, value: &str, min: i64, max: i64) -> Result<i64, ()> {
    match value.parse::<i64>() {
        Ok(v) if (min..=max).contains(&v) => Ok(v),
        _ => {
            eprintln!("Invalid value for {key}: {value} (expected {min}..{max})");
            Err(())
        }
    }
}

const PATH_KEYS: [&str; 8] = [
    "work_dir",
    "bin_path",
    "pid_file",
    "log_dir",
    "log_file",
    "error_log",
    "singbox_log",
    "lock_dir",
];

fn parse_ini_line(line: &str, c: &mut Cfg, raw: &mut [Option<String>; 8]) -> Result<(), ()> {
    let line = trim_str(line);
    if line.is_empty() || line.starts_with(['#', ';', '[']) {
        return Ok(());
    }
    let Some((k, v)) = line.split_once('=') else {
        return Ok(());
    };
    let key = trim_str(k);
    let val = trim_str(strip_inline_comment(v));
    let lower = key.to_ascii_lowercase();
    let lower = if lower == "service_log" {
        "singbox_log".to_string()
    } else {
        lower
    };

    if let Some(i) = PATH_KEYS.iter().position(|p| *p == lower) {
        raw[i] = Some(val.to_string());
        return Ok(());
    }
    match lower.as_str() {
        "service_name" => c.service_name = val.to_string(),
        "run_user" => c.run_user = val.to_string(),
        "timezone" | "tz" => c.timezone = val.to_string(),
        "max_log_size" => c.max_log_size = parse_num(key, val, 1, i64::MAX)?,
        "stop_timeout" => c.stop_timeout = parse_num(key, val, 0, 3600)?,
        "start_timeout" => c.start_timeout = parse_num(key, val, 1, 3600)?,
        "check_config" => c.check_config = parse_num(key, val, 0, 1)?,
        "nofile_limit" => c.nofile_limit = parse_num(key, val, 1, i64::MAX)?,
        _ => {}
    }
    Ok(())
}

fn is_sys_bin(dir: &str) -> bool {
    matches!(
        dir,
        "/system/bin" | "/system/xbin" | "/sbin" | "/bin" | "/usr/bin"
    ) || dir.contains("/ksu/bin")
        || dir.contains("/ap/bin")
        || dir.contains("/magisk")
}

fn load_config() -> Result<Cfg, ()> {
    let mut c = Cfg {
        service_name: "sing-box".into(),
        work_dir: String::new(),
        bin_path: String::new(),
        pid_file: String::new(),
        log_dir: String::new(),
        log_file: String::new(),
        error_log: String::new(),
        singbox_log: String::new(),
        lock_dir: String::new(),
        run_user: "root:net_admin".into(),
        timezone: String::new(),
        max_log_size: 1048576,
        stop_timeout: 10,
        start_timeout: 3,
        check_config: 0,
        nofile_limit: 1000000,
        iana_tz: String::new(),
    };
    let mut raw: [Option<String>; 8] = Default::default();

    let self_dir = self_dir();
    let self_ini = format!("{self_dir}/box.ini");
    // First candidate that opens wins
    for path in [
        "/data/adb/sing-box/box.ini",
        "/data/adb/box.ini",
        &self_ini,
        "box.ini",
    ] {
        let Ok(mut f) = File::open(path) else {
            continue;
        };
        let mut data = Vec::new();
        if let Err(e) = f.read_to_end(&mut data) {
            eprintln!("Failed to read configuration {path}: {e}");
            return Err(());
        }
        for line in data.split(|&b| b == b'\n' || b == b'\r') {
            if line.len() > 255 {
                eprintln!("Configuration line too long in {path}");
                return Err(());
            }
            parse_ini_line(&String::from_utf8_lossy(line), &mut c, &mut raw)?;
        }
        break;
    }

    let [
        work_dir,
        bin,
        pid,
        log_dir,
        log_file,
        error_log,
        singbox_log,
        lock_dir,
    ] = raw;
    c.work_dir = match work_dir.filter(|s| !s.is_empty()) {
        Some(v) => expand_vars(&v, &c.service_name, ""),
        None if !is_sys_bin(&self_dir) && !self_dir.is_empty() && self_dir != "." => self_dir,
        None => format!("/data/adb/{}", c.service_name),
    };

    let (name, wd) = (c.service_name.clone(), c.work_dir.clone());
    let exp =
        |v: Option<String>, default: String| v.map_or(default, |v| expand_vars(&v, &name, &wd));
    c.bin_path = exp(bin, format!("{wd}/bin/{name}"));
    c.pid_file = exp(pid, format!("{wd}/{name}.pid"));
    c.log_dir = exp(log_dir, format!("{wd}/logs"));
    c.log_file = exp(log_file, format!("{}/run.log", c.log_dir));
    c.error_log = exp(error_log, format!("{}/run_error.log", c.log_dir));
    c.singbox_log = exp(singbox_log, format!("{}/{name}.log", c.log_dir));
    c.lock_dir = exp(lock_dir, format!("{wd}/.box.lock"));

    c.iana_tz = init_timezone(&c.timezone);
    Ok(c)
}

// ================= Android Property & Timezone =================

fn getprop(name: &str) -> Option<String> {
    for bin in ["/system/bin/getprop", "/vendor/bin/getprop", "getprop"] {
        if let Ok(out) = Command::new(bin).arg(name).stderr(Stdio::null()).output() {
            let s = String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(127)]);
            let t = trim_str(&s);
            return (!t.is_empty()).then(|| t.to_string());
        }
    }
    None
}

unsafe extern "C" {
    fn tzset(); // not exported by the libc crate; present in glibc, musl and bionic
}

fn init_timezone(custom: &str) -> String {
    let tz = if !custom.is_empty() && !custom.eq_ignore_ascii_case("auto") {
        custom.to_string()
    } else {
        [
            "persist.sys.timezone",
            "ro.sys.timezone",
            "ro.build.timezone",
        ]
        .iter()
        .find_map(|p| getprop(p))
        .or_else(|| {
            let b = fs::read("/etc/timezone").ok()?;
            let t = trim_str(&String::from_utf8_lossy(&b[..b.len().min(63)])).to_string();
            (!t.is_empty()).then_some(t)
        })
        .or_else(|| {
            let l = fs::read_link("/etc/localtime")
                .ok()?
                .to_string_lossy()
                .into_owned();
            let t = &l[l.find("zoneinfo/")? + 9..];
            (!t.is_empty()).then(|| t.to_string())
        })
        .unwrap_or_default()
    };
    if !tz.is_empty() {
        // Single-threaded at this point; children inherit TZ
        unsafe {
            std::env::set_var("TZ", &tz);
            tzset();
        }
    }
    tz
}

// ================= Logging System =================

fn local_tm() -> libc::tm {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
        tm
    }
}

fn ts() -> String {
    let t = local_tm();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        (t.tm_year + 1900) % 10000,
        t.tm_mon + 1,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec
    )
}

const LOG_BACKUP_KEEP: usize = 3;

fn shift_backups(base: &str, keep: usize) {
    for i in (2..=keep).rev() {
        let _ = fs::rename(format!("{base}.{}", i - 1), format!("{base}.{i}"));
    }
}

fn rotate_file_in_place(path: &str) -> io::Result<()> {
    if !Path::new(path).exists() {
        return Ok(());
    }
    shift_backups(path, LOG_BACKUP_KEEP);
    // Copy and truncate in place (matching atpd) so running sing-box keeps its open O_APPEND fd
    let res = fs::copy(path, format!("{path}.1"))
        .and_then(|_| OpenOptions::new().write(true).open(path))
        .and_then(|f| f.set_len(0));
    if res.is_err() {
        fs::rename(path, format!("{path}.1"))?;
    }
    Ok(())
}

fn rotate_log(path: &str) {
    if fs::metadata(path).is_ok_and(|m| m.len() as i64 > cfg().max_log_size) {
        let _ = rotate_file_in_place(path);
    }
}

fn do_logrotate() -> i32 {
    let c = cfg();
    info!("Rotating log files (retaining up to {LOG_BACKUP_KEEP} copies)...");
    let logs = [&c.log_file, &c.error_log, &c.singbox_log];
    let mut err = false;
    for path in logs {
        if let Err(e) = rotate_file_in_place(path) {
            error!("Failed to rotate {path}: {e}");
            err = true;
        }
    }
    if err {
        1
    } else {
        info!("Log rotation completed successfully.");
        0
    }
}

fn append_file(path: &str, mode: u32) -> io::Result<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(mode)
        .open(path)
}

fn log_msg(is_err: bool, msg: &str) {
    let c = cfg();
    let target = if is_err { &c.error_log } else { &c.log_file };
    rotate_log(target);

    let ts = ts();
    let (tag, color) = if is_err {
        ("[ERROR]", "\x1b[31m[ERROR]\x1b[0m")
    } else {
        ("[INFO]", "\x1b[32m[INFO]\x1b[0m")
    };
    fn emit(mut w: impl Write + IsTerminal, ts: &str, tag: &str, color: &str, msg: &str) {
        let t = if w.is_terminal() { color } else { tag };
        let _ = writeln!(w, "[{ts}] {t} {msg}");
        let _ = w.flush();
    }
    if is_err {
        emit(io::stderr().lock(), &ts, tag, color, msg);
    } else {
        emit(io::stdout().lock(), &ts, tag, color, msg);
    }

    if let Ok(mut f) = append_file(target, 0o644) {
        let _ = f.write_all(format!("[{ts}] {tag} {msg}\n").as_bytes());
    }
}

fn show_tail(path: &str, lines: i64) {
    let lines = if lines <= 0 { 10 } else { lines };
    let mut out = io::stdout().lock();
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            let _ = writeln!(out, "(empty)");
            return;
        }
    };
    let size = f.seek(SeekFrom::End(0)).unwrap_or(0);
    if size == 0 {
        let _ = writeln!(out, "(empty)");
        return;
    }

    let mut buf = [0u8; 8192];
    let (mut pos, mut start, mut count) = (size, 0u64, 0i64);
    'scan: while pos > 0 {
        let chunk = pos.min(buf.len() as u64);
        pos -= chunk;
        let buf = &mut buf[..chunk as usize];
        if f.seek(SeekFrom::Start(pos)).is_err() || f.read_exact(buf).is_err() {
            break;
        }
        for i in (0..buf.len()).rev() {
            let abs = pos + i as u64;
            if buf[i] == b'\n' && abs != size - 1 {
                count += 1;
                if count >= lines {
                    start = abs + 1;
                    break 'scan;
                }
            }
        }
    }

    if f.seek(SeekFrom::Start(start)).is_ok() {
        // shortcut: buffers the whole tail; fine for log-sized files, stream it if tails get huge
        let mut rest = Vec::new();
        let _ = f.read_to_end(&mut rest);
        let _ = out.write_all(&rest);
        if rest.last().is_some_and(|&b| b != b'\n') {
            let _ = out.write_all(b"\n");
        }
    }
    let _ = out.flush();
}

// ================= Process & Lock Management =================

fn prepare_env() {
    let c = cfg();
    let mut b = fs::DirBuilder::new();
    b.recursive(true).mode(0o755);
    let _ = b.create(&c.work_dir);
    let _ = b.create(&c.log_dir);

    if unsafe { libc::geteuid() != 0 && libc::getuid() != 0 } {
        error!("Root privileges required");
        exit(1);
    }
}

/// Holds an exclusive flock for the life of the process (fd is CLOEXEC, so children never inherit it).
fn acquire_lock() -> File {
    let c = cfg();
    let path = if Path::new(&c.lock_dir).is_dir() {
        format!("{}/flock", c.lock_dir)
    } else {
        c.lock_dir.clone()
    };
    let f = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open lock file {path}: {e}");
            exit(1);
        }
    };
    for _ in 0..10 {
        match f.try_lock() {
            Ok(()) => return f,
            Err(TryLockError::WouldBlock) => sleep(Duration::from_secs(1)),
            Err(TryLockError::Error(e)) if e.kind() == io::ErrorKind::Interrupted => {
                sleep(Duration::from_secs(1))
            }
            Err(TryLockError::Error(e)) => {
                error!("Failed to lock {path}: {e}");
                exit(1);
            }
        }
    }
    error!("Another box operation is in progress, please try again later");
    exit(1);
}

fn is_proc_alive(pid: i32) -> bool {
    if pid <= 1 {
        return false;
    }
    if unsafe { libc::kill(pid, 0) } != 0
        && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    {
        return false;
    }
    let Ok(s) = fs::read(format!("/proc/{pid}/stat")) else {
        return false;
    };
    match s.iter().rposition(|&b| b == b')') {
        Some(i) if i + 2 < s.len() => !matches!(s[i + 2], b'Z' | b'X'),
        _ => false,
    }
}

/// Is `p` our sing-box: exe or argv0 matches BIN_PATH, argv1 is "run", and `-D WORK_DIR` is present.
fn check_proc_pid(p: i32, is_scan: bool) -> bool {
    if !is_proc_alive(p) {
        return false;
    }
    let c = cfg();
    let bin = c.bin_path.as_bytes();
    let canon = || {
        fs::canonicalize(&c.bin_path)
            .ok()
            .map(|p| p.into_os_string().into_vec())
    };

    let mut exe_matched = fs::read_link(format!("/proc/{p}/exe")).is_ok_and(|l| {
        let l = l.into_os_string().into_vec();
        let l = l.strip_suffix(b" (deleted)").unwrap_or(&l);
        l == bin || canon().is_some_and(|c| c == l)
    });

    let cmdline = fs::read(format!("/proc/{p}/cmdline")).unwrap_or_default();
    if cmdline.is_empty() {
        return !is_scan && exe_matched;
    }
    let Some(cmdline) = cmdline.strip_suffix(b"\0") else {
        return false;
    };
    let mut args = cmdline.split(|&b| b == 0);
    let argv0 = args.next().unwrap_or_default();
    exe_matched = exe_matched || argv0 == bin || canon().is_some_and(|c| c == argv0);
    if !exe_matched || args.next() != Some(b"run") {
        return false;
    }

    let wd = c.work_dir.as_bytes();
    let mut matched_work_dir = wd.is_empty();
    while let Some(t) = args.next() {
        if t == b"-D" {
            match args.next() {
                Some(next) => matched_work_dir |= next == wd,
                None => return false,
            }
        }
    }
    matched_work_dir
}

fn scan_proc_for_service() -> Option<i32> {
    let me = std::process::id() as i32;
    fs::read_dir("/proc").ok()?.flatten().find_map(|e| {
        let p: i32 = e.file_name().to_str()?.parse().ok()?;
        (p > 1 && p != me && check_proc_pid(p, true)).then_some(p)
    })
}

fn write_pid(pid: i32) {
    if let Ok(mut f) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&cfg().pid_file)
    {
        let _ = writeln!(f, "{pid}");
    }
}

fn get_pid() -> Option<i32> {
    if let Ok(s) = fs::read_to_string(&cfg().pid_file) {
        let p = atoi(&s);
        if p > 1 && p <= i32::MAX as i64 && check_proc_pid(p as i32, false) {
            return Some(p as i32);
        }
    }
    let p = scan_proc_for_service()?;
    write_pid(p);
    Some(p)
}

fn clear_pid() {
    let _ = fs::remove_file(&cfg().pid_file);
}

// ================= Status Formatting =================

fn fmt_mem(kb: i64) -> String {
    if kb >= 1048576 {
        format!("{}.{:02} GB", kb / 1048576, (kb % 1048576) * 100 / 1048576)
    } else if kb >= 1024 {
        format!("{}.{:02} MB", kb / 1024, (kb % 1024) * 100 / 1024)
    } else {
        format!("{kb} kB")
    }
}

fn fmt_uptime(secs: i64) -> String {
    let (d, h, m, s) = (
        secs / 86400,
        secs % 86400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    );
    let mut out = String::new();
    for (v, unit) in [(d, 'd'), (h, 'h'), (m, 'm')] {
        if v > 0 {
            out += &format!("{v}{unit} ");
        }
    }
    out + &format!("{s}s")
}

fn core_version() -> Option<String> {
    let c = cfg();
    if !access(&c.bin_path, libc::X_OK) {
        return None;
    }
    let out = Command::new(&c.bin_path).arg("version").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next()?.trim();
    if !line.is_empty() {
        Some(line.to_string())
    } else {
        None
    }
}

fn parse_io_bytes(s: &str) -> (Option<i64>, Option<i64>) {
    let get = |prefix: &str| {
        s.lines().find_map(|l| l.trim_start().strip_prefix(prefix)).map(atoi)
    };
    (get("read_bytes:"), get("write_bytes:"))
}

fn display_status() -> i32 {
    let c = cfg();
    let Some(pid) = get_pid() else {
        info!("{} service is stopped.", c.service_name);
        if let Some(ver) = core_version() {
            info!("Core version: {ver}");
        }
        clear_pid();
        return 1;
    };

    info!("{} service is running (PID: {pid})", c.service_name);
    if let Some(ver) = core_version() {
        info!("Core version: {ver}");
    }
    if !c.iana_tz.is_empty() {
        let tm = local_tm();
        let zone_not_utc =
            !tm.tm_zone.is_null() && unsafe { CStr::from_ptr(tm.tm_zone) }.to_bytes() != b"UTC";
        if tm.tm_gmtoff != 0 || zone_not_utc || c.iana_tz == "UTC" {
            let off = tm.tm_gmtoff;
            let sign = if off >= 0 { '+' } else { '-' };
            info!(
                "Timezone: {} (UTC{sign}{:02}:{:02})",
                c.iana_tz,
                (off / 3600).abs(),
                (off % 3600 / 60).abs()
            );
        } else {
            info!("Timezone: {} (offset unavailable)", c.iana_tz);
        }
    }

    if let Ok(s) = fs::read_to_string(format!("/proc/{pid}/status"))
        && let Some(kb) = s.lines().find_map(|l| l.strip_prefix("VmRSS:")).map(atoi)
        && kb >= 0
    {
        info!("Memory usage: {}", fmt_mem(kb));
    }

    let clk = match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
        n if n > 0 => n as u64,
        _ => 100,
    };
    let mut bt = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let uptime_ticks = if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut bt) } == 0 {
        bt.tv_sec as u64 * clk + bt.tv_nsec as u64 * clk / 1_000_000_000
    } else {
        fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .filter(|&u| u > 0.0)
            .map_or(0, |u| (u * clk as f64) as u64)
    };

    if let Ok(raw) = fs::read(format!("/proc/{pid}/stat")) {
        let s = String::from_utf8_lossy(&raw);
        if let Some(i) = s.rfind(')').filter(|&i| i + 2 < s.len()) {
            // Fields after "comm)" start at field 3 (state); utime=14, stime=15, starttime=22
            let f: Vec<&str> = s[i + 2..].split_whitespace().collect();
            let field = |n: usize| f.get(n - 3).map_or(0, |t| atoi(t).max(0) as u64);
            let (utime, stime, start) = (field(14), field(15), field(22));
            let elapsed = uptime_ticks.saturating_sub(start);
            let tenths = ((utime + stime) * 1000).checked_div(elapsed).unwrap_or(0);
            info!("CPU usage: {}.{}% (avg)", tenths / 10, tenths % 10);
            info!("Uptime: {}", fmt_uptime((elapsed / clk) as i64));
        }
    }

    let sockets = fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, |d| {
        d.flatten()
            .filter(|e| {
                fs::read_link(e.path())
                    .is_ok_and(|t| t.as_os_str().as_bytes().starts_with(b"socket:"))
            })
            .count()
    });
    info!("Network sockets: {sockets}");

    if let Ok(s) = fs::read_to_string(format!("/proc/{pid}/io")) {
        if let (Some(r), Some(w)) = parse_io_bytes(&s)
            && r >= 0
            && w >= 0
        {
            info!(
                "Disk I/O: read {} / write {}",
                fmt_mem(r / 1024),
                fmt_mem(w / 1024)
            );
        }
    }
    0
}

// ================= Service Operations =================

fn do_check() -> i32 {
    let c = cfg();
    if !access(&c.bin_path, libc::X_OK) {
        error!("Binary not found or not executable: {}", c.bin_path);
        return 1;
    }
    let Ok(creds) = resolve_creds(&c.run_user) else {
        return 1;
    };
    if apply_nofile_limit().is_err() {
        return 1;
    }
    let (mut r, w) = match io::pipe() {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create pipe: {e}");
            return 1;
        }
    };
    // The Command temporary (holding the write ends) drops at the end of this statement, so reads hit EOF.
    let spawned = w.try_clone().and_then(|w2| {
        service_cmd(&["check", "-D", &c.work_dir], creds, false)
            .stdin(Stdio::null())
            .stdout(w2)
            .stderr(w)
            .spawn()
    });
    let mut child = match spawned {
        Ok(ch) => ch,
        Err(e) => {
            error!("Configuration validation failed:");
            error!("{e}");
            return 1;
        }
    };

    let mut output = Vec::new();
    let _ = r.by_ref().take(1023).read_to_end(&mut output);
    let _ = io::copy(&mut r, &mut io::sink());
    drop(r);

    let status = match child.wait() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to wait for configuration check: {e}");
            return 1;
        }
    };
    if !status.success() {
        error!("Configuration validation failed:");
        if !output.is_empty() {
            error!("{}", String::from_utf8_lossy(&output));
        }
        return 1;
    }
    0
}

fn start_service() -> i32 {
    let c = cfg();
    let name = &c.service_name;
    if get_pid().is_some() {
        info!("{name} is already running.");
        display_status();
        return 0;
    }
    clear_pid();

    if !access(&c.bin_path, libc::X_OK) {
        error!("Binary not found or not executable: {}", c.bin_path);
        return 1;
    }
    if !access(&format!("{}/config.json", c.work_dir), libc::F_OK) {
        error!("config.json not found in {}", c.work_dir);
        return 1;
    }
    if c.check_config == 1 {
        info!("Validating configuration...");
        if do_check() != 0 {
            error!("Configuration validation failed, aborting startup");
            return 1;
        }
    }

    info!("Starting {name}...");
    rotate_log(&c.log_file);
    rotate_log(&c.error_log);
    rotate_log(&c.singbox_log);

    let Ok(creds) = resolve_creds(&c.run_user) else {
        return 1;
    };
    if apply_nofile_limit().is_err() {
        return 1;
    }
    // Command::spawn reports setsid/setuid/exec failures from the child via its own CLOEXEC pipe.
    let spawned = append_file(&c.singbox_log, 0o644).and_then(|log| {
        let log2 = log.try_clone()?;
        service_cmd(&["run", "-D", &c.work_dir], creds, true)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log2)
            .spawn()
    });
    let mut child = match spawned {
        Ok(ch) => ch,
        Err(e) => {
            error!("{name} failed during startup setup/exec: {e}");
            show_tail(&c.singbox_log, 10);
            clear_pid();
            return 1;
        }
    };

    let pid = child.id() as i32;
    write_pid(pid);

    let mut alive = true;
    for _ in 0..c.start_timeout {
        sleep(Duration::from_secs(1));
        match child.try_wait() {
            Ok(Some(st)) => {
                alive = false;
                match (st.code(), st.signal()) {
                    (Some(code), _) => error!("{name} exited immediately with code {code}!"),
                    (_, Some(sig)) => error!("{name} killed by signal {sig}!"),
                    _ => error!("{name} exited immediately after startup!"),
                }
                break;
            }
            Ok(None) => {}
            Err(e) => {
                error!("Failed to wait for {name} startup: {e}");
                alive = false;
                break;
            }
        }
        if !check_proc_pid(pid, false) {
            alive = false;
            break;
        }
    }

    if !alive || !check_proc_pid(pid, false) {
        error!(
            "{name} failed to stay alive during startup observation window! Check {} for details",
            c.singbox_log
        );
        show_tail(&c.singbox_log, 10);
        clear_pid();
        return 1;
    }

    info!("{name} exec succeeded, process alive (PID: {pid})");
    display_status();
    0
}

fn stop_service() -> i32 {
    let c = cfg();
    let name = &c.service_name;
    let Some(pid) = get_pid() else {
        info!("{name} is not running.");
        clear_pid();
        return 0;
    };

    info!("Stopping {name} (PID: {pid})...");
    unsafe { libc::kill(pid, libc::SIGTERM) };

    // 100ms micro-polling (matching atpd) for sub-second responsive shutdown
    let attempts = if c.stop_timeout > 0 { c.stop_timeout * 10 } else { 10 };
    for _ in 0..attempts {
        if !is_proc_alive(pid) {
            break;
        }
        sleep(Duration::from_millis(100));
    }

    if is_proc_alive(pid) {
        info!(
            "Process unresponsive ({}s), forcing termination...",
            c.stop_timeout
        );
        unsafe { libc::kill(pid, libc::SIGKILL) };
        for _ in 0..50 {
            if !is_proc_alive(pid) {
                break;
            }
            sleep(Duration::from_millis(100));
        }
    }

    if is_proc_alive(pid) {
        error!("Failed to terminate process {pid}");
        return 1;
    }
    clear_pid();
    info!("{name} stopped.");
    0
}

fn restart_service() -> i32 {
    let c = cfg();
    info!("Restarting {}...", c.service_name);
    if c.check_config == 1 {
        info!("Validating configuration before restart...");
        if do_check() != 0 {
            error!("Configuration validation failed, aborting restart to preserve running service");
            return 1;
        }
    }
    if get_pid().is_some() {
        if stop_service() != 0 {
            error!("Failed to stop existing {} service", c.service_name);
            return 1;
        }
    } else {
        clear_pid();
    }
    start_service()
}

fn reload_service() -> i32 {
    let c = cfg();
    let name = &c.service_name;
    let Some(pid) = get_pid() else {
        info!("{name} is not running, auto-starting...");
        return start_service();
    };
    if c.check_config == 1 {
        info!("Validating configuration before reload...");
        if do_check() != 0 {
            error!("Configuration validation failed, aborting reload");
            return 1;
        }
    }
    if !check_proc_pid(pid, false) {
        info!("{name} process {pid} is no longer valid, auto-starting...");
        clear_pid();
        return start_service();
    }

    info!("Reloading {name} configuration (PID: {pid})...");
    if unsafe { libc::kill(pid, libc::SIGHUP) } != 0 {
        error!(
            "Failed to send reload signal: {}",
            io::Error::last_os_error()
        );
        return 1;
    }

    // Post-reload health observation: ensure sing-box didn't crash on SIGHUP
    sleep(Duration::from_millis(500));
    if !check_proc_pid(pid, false) {
        error!(
            "{name} crashed during configuration reload! Check {} for details",
            c.singbox_log
        );
        show_tail(&c.singbox_log, 15);
        clear_pid();
        return 1;
    }

    info!("Reload signal (SIGHUP) processed successfully.");
    0
}

fn show_log(target: Option<&str>, lines: i64) {
    let c = cfg();
    let lines = if lines <= 0 { 50 } else { lines };
    let (script, err, service) = match target {
        Some("all") => (true, true, true),
        Some("sbox" | "service" | "-s") => (false, false, true),
        Some("error" | "-e") => (false, true, false),
        Some("run" | "-r") => (true, false, false),
        _ => (true, true, false),
    };

    if script {
        println!(
            "===== Script Log ({}, last {lines} lines) =====",
            c.log_file
        );
        show_tail(&c.log_file, lines);
    }
    if err {
        if script {
            println!();
        }
        println!(
            "===== Script Error Log ({}, last {lines} lines) =====",
            c.error_log
        );
        show_tail(&c.error_log, lines);
    }
    if service {
        if script || err {
            println!();
        }
        println!(
            "===== {} Service Log ({}, last {lines} lines) =====",
            c.service_name, c.singbox_log
        );
        show_tail(&c.singbox_log, lines);
    }
}

fn show_version() -> i32 {
    println!("box v{BOX_VERSION}");
    let c = cfg();
    if !access(&c.bin_path, libc::X_OK) {
        info!("{}: not found or not executable ({})", c.service_name, c.bin_path);
        return 0;
    }
    match Command::new(&c.bin_path).arg("version").status() {
        Ok(st) => st.code().unwrap_or(1),
        Err(e) => {
            error!("Failed to execute {}: {e}", c.bin_path);
            1
        }
    }
}

fn usage(prog: &str) {
    let name = &cfg().service_name;
    println!(
        "Usage: {prog} [-v|--version] [-h|--help]\n       {prog} {{start|stop|restart|reload|status|check|log [target] [lines]|logrotate|version}}\n"
    );
    println!("Commands:");
    println!("  start               - Start {name} service");
    println!("  stop                - Stop {name} service");
    println!("  restart             - Restart {name} service");
    println!("  reload              - Hot-reload {name} configuration (auto-starts if stopped)");
    println!("  status              - Show service status with detailed info");
    println!("  check               - Validate configuration");
    println!("  log [target] [n]    - Show last n lines of logs (default: 50)");
    println!("                        targets: all, sbox (or service), run, error");
    println!("  logrotate           - Rotate service and operational log files (retains 3 copies)");
    println!("  version             - Show box and {name} versions\n");
    println!("Options:");
    println!("  -v, --version       - Show box version");
    println!("  -h, --help          - Show this help message");
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let prog = args.first().map_or("box", String::as_str);
    let arg = |i: usize| args.get(i).map(String::as_str);

    if matches!(arg(1), Some("-v" | "--version")) {
        println!("box v{BOX_VERSION}");
        return 0;
    }

    let Ok(c) = load_config() else { return 1 };
    let _ = CFG.set(c);

    if matches!(arg(1), Some("-h" | "--help" | "help")) {
        usage(prog);
        return 0;
    }

    prepare_env();

    // No args and no tty (e.g. boot script): start
    let cmd = match arg(1) {
        Some(cmd) => cmd,
        None if !io::stdin().is_terminal() => "start",
        None => {
            usage(prog);
            return 1;
        }
    };

    let _lock = matches!(cmd, "start" | "stop" | "restart" | "reload" | "logrotate" | "rotate").then(acquire_lock);
    match cmd {
        "start" => start_service(),
        "stop" => stop_service(),
        "restart" => restart_service(),
        "reload" => reload_service(),
        "status" => display_status(),
        "check" => {
            let res = do_check();
            if res == 0 {
                info!("Configuration validation passed");
            }
            res
        }
        "log" => {
            let (target, lines) = match (arg(2), arg(3)) {
                (Some(t), Some(n)) => (Some(t), atoi(n)),
                (Some(a), None) if a.bytes().all(|b| b.is_ascii_digit()) => (None, atoi(a)),
                (Some(t), None) => (Some(t), 50),
                _ => (None, 50),
            };
            show_log(target, lines);
            0
        }
        "logrotate" | "rotate" => do_logrotate(),
        "version" => show_version(),
        _ => {
            usage(prog);
            1
        }
    }
}

fn main() {
    // Match C: die quietly on SIGPIPE (e.g. `box log | head`) instead of erroring
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    exit(run());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_cfg() -> Cfg {
        Cfg {
            service_name: "sing-box".into(),
            work_dir: String::new(),
            bin_path: String::new(),
            pid_file: String::new(),
            log_dir: String::new(),
            log_file: String::new(),
            error_log: String::new(),
            singbox_log: String::new(),
            lock_dir: String::new(),
            run_user: String::new(),
            timezone: String::new(),
            max_log_size: 0,
            stop_timeout: 10,
            start_timeout: 3,
            check_config: 0,
            nofile_limit: 0,
            iana_tz: String::new(),
        }
    }

    #[test]
    fn trims_and_unquotes() {
        assert_eq!(trim_str("  \"  a b \" "), "a b");
        assert_eq!(trim_str("'x\""), "'x\"");
        assert_eq!(trim_str("\""), "\"");
        assert_eq!(atoi("  42 kB"), 42);
        assert_eq!(atoi("-7x"), -7);
        assert_eq!(atoi("abc"), 0);
    }

    #[test]
    fn strips_comments_outside_quotes() {
        assert_eq!(strip_inline_comment("\"a#b\" # c"), "\"a#b\" ");
        assert_eq!(strip_inline_comment("1048576 ; x"), "1048576 ");
        assert_eq!(strip_inline_comment("\\\"#x"), "\\\"");
    }

    #[test]
    fn expands_vars() {
        assert_eq!(
            expand_vars("${WORK_DIR}/bin/$SERVICE_NAME", "sb", "/w"),
            "/w/bin/sb"
        );
        assert_eq!(expand_vars("$HOME/é", "sb", "/w"), "$HOME/é");
    }

    #[test]
    fn parses_ini_lines() {
        let mut c = blank_cfg();
        let mut raw: [Option<String>; 8] = Default::default();
        for l in [
            "[box]",
            "SERVICE_NAME=\"sb\"   # name",
            "WORK_DIR=\"/data/adb/sing-box\"    # dir",
            "SERVICE_LOG = $WORK_DIR/x.log",
            "STOP_TIMEOUT=5",
            "TZ=\"auto\"",
        ] {
            parse_ini_line(l, &mut c, &mut raw).unwrap();
        }
        assert_eq!(c.service_name, "sb");
        assert_eq!(c.stop_timeout, 5);
        assert_eq!(c.timezone, "auto");
        assert_eq!(raw[0].as_deref(), Some("/data/adb/sing-box"));
        assert_eq!(raw[6].as_deref(), Some("$WORK_DIR/x.log"));
        assert!(parse_ini_line("CHECK_CONFIG=2", &mut c, &mut raw).is_err());
        assert!(parse_ini_line("START_TIMEOUT=0", &mut c, &mut raw).is_err());
    }

    #[test]
    fn formats_status_values() {
        assert_eq!(fmt_mem(512), "512 kB");
        assert_eq!(fmt_mem(43520), "42.50 MB");
        assert_eq!(fmt_mem(1572864), "1.50 GB");
        assert_eq!(fmt_uptime(9015), "2h 30m 15s");
        assert_eq!(fmt_uptime(86400), "1d 0s");
        assert_eq!(fmt_uptime(0), "0s");
    }

    #[test]
    fn resolves_ids() {
        assert_eq!(resolve_gid("net_admin"), Some(3005));
        assert_eq!(resolve_uid("-1"), None);
        assert_eq!(resolve_uid("4294967295"), Some(u32::MAX));
        assert_eq!(resolve_uid("4294967296"), None);
    }

    #[test]
    fn validates_box_version() {
        assert!(!BOX_VERSION.is_empty());
        let parts: Vec<&str> = BOX_VERSION.split('.').collect();
        assert!(parts.len() >= 2);
        assert!(parts[0].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn parses_io_bytes_correctly() {
        let sample = "rchar: 100\nwchar: 200\nsyscr: 1\nsyscw: 2\nread_bytes: 1048576\nwrite_bytes: 2097152\ncancelled_write_bytes: 524288\n";
        let (r, w) = parse_io_bytes(sample);
        assert_eq!(r, Some(1048576));
        assert_eq!(w, Some(2097152));
    }

    #[test]
    fn shifts_backups_correctly() {
        let dir = std::env::temp_dir().join(format!("box_rotate_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let base = dir.join("test.log").to_string_lossy().into_owned();
        let _ = fs::write(format!("{base}.1"), "first");
        let _ = fs::write(format!("{base}.2"), "second");
        shift_backups(&base, 3);
        assert_eq!(fs::read_to_string(format!("{base}.3")).unwrap(), "second");
        assert_eq!(fs::read_to_string(format!("{base}.2")).unwrap(), "first");
        assert!(!Path::new(&format!("{base}.1")).exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
