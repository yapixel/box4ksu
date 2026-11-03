# sing-box Service Manager for KernelSU

A native sing-box service manager built for KernelSU / APatch / Magisk, providing full service lifecycle management and status monitoring.

## 📋 Features

- ✅ Full service management (start / stop / restart / hot reload / status)
- ✅ Detailed status monitoring (memory / CPU / uptime / network sockets / disk I/O, read directly from /proc with plain system calls)
- ✅ High-performance design (native Rust, no shell pipeline overhead)
- ✅ Config validation and hot reload (SIGHUP)
- ✅ Log rotation and multi-target log viewing
- ✅ Start on boot (waits for boot completion so the network is ready)
- ✅ Process lock prevents concurrent operations
- ✅ Working directories created automatically
- ✅ Separate logs (manager logs kept apart from sing-box core logs)
- ✅ Automatic timezone (follows the Android system timezone)

## 📂 Directory Layout

```
/data/adb/
├── service.d/
│   └── sing-box.sh              # Boot script
└── sing-box/                    # Working directory
    ├── box                      # Native Rust manager
    ├── box.ini                  # Service configuration
    ├── config.json              # sing-box configuration
    ├── bin/
    │   └── sing-box             # sing-box binary
    ├── logs/
    │   ├── run.log              # Operation log
    │   ├── run_error.log        # Error log
    │   └── sing-box.log         # sing-box runtime log
    ├── .box.lock/               # Process lock (runtime)
    └── sing-box.pid             # PID file (runtime)
```

## 🚀 Quick Start

### 1. Deploy and Set Permissions

```bash
# Create the working directory
mkdir -p /data/adb/sing-box/{bin,logs}

# Copy files
cp sing-box /data/adb/sing-box/bin/
cp configs/config.tun.json /data/adb/sing-box/config.json  # or pick another mode from configs/
cp box /data/adb/sing-box/
cp box.ini /data/adb/sing-box/

# Set permissions
chmod 755 /data/adb/sing-box/bin/sing-box
chmod 755 /data/adb/sing-box/box
chown -R root:root /data/adb/sing-box
```

### 2. Configuration

Create `/data/adb/sing-box/config.json`:

```json
{
  "log": {
    "level": "info",
    "output": "logs/sing-box.log"
  },
  "inbounds": [...],
  "outbounds": [...]
}
```

### 3. Install Start on Boot (Optional)

```bash
mkdir -p /data/adb/service.d
cat > /data/adb/service.d/sing-box.sh << 'EOF'
#!/system/bin/sh
until [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ]; do
    sleep 3
done
sleep 3
rm -rf /data/adb/sing-box/.box.lock
if [ -x /data/adb/sing-box/box ]; then
    /data/adb/sing-box/box start
fi
EOF
chmod 755 /data/adb/service.d/sing-box.sh
```

### 4. Start the Service

```bash
/data/adb/sing-box/box start
```

## 📖 Usage

### Service Management

```bash
# Start the service
/data/adb/sing-box/box start

# Stop the service
/data/adb/sing-box/box stop

# Restart the service
/data/adb/sing-box/box restart

# Hot-reload the configuration (connections stay up)
/data/adb/sing-box/box reload

# Show status
/data/adb/sing-box/box status

# Validate the configuration
/data/adb/sing-box/box check

# View logs
/data/adb/sing-box/box log             # Run and error logs (last 50 lines by default)
/data/adb/sing-box/box log 20          # Last 20 lines of the run and error logs
/data/adb/sing-box/box log sbox 50     # Last 50 lines of the sing-box core log
/data/adb/sing-box/box log all 50      # All logs (run / error / service)

# Show the sing-box version
/data/adb/sing-box/box version

# Show help
/data/adb/sing-box/box help
```

### Viewing Logs

```bash
# Manager operation log
tail -f /data/adb/sing-box/logs/run.log

# Manager error log
tail -f /data/adb/sing-box/logs/run_error.log

# sing-box core runtime log
tail -f /data/adb/sing-box/logs/sing-box.log
```

## 📊 Status Fields

The `status` command shows the following:

| Field | Description | Source |
|------|------|----------|
| PID | Process ID | `/proc/[pid]/` |
| Timezone | Current timezone and offset | Android system property / `box.ini` |
| Memory usage | VmRSS, actual physical memory in use | `/proc/[pid]/status` |
| CPU usage | Average CPU usage of the process | `/proc/[pid]/stat` |
| Uptime | How long the process has run | `/proc/[pid]/stat` |
| Network sockets | Number of open sockets | `/proc/[pid]/fd` |
| Disk I/O | Total bytes read / written | `/proc/[pid]/io` |

### Example Status Output

```text
[2026-08-28 08:30:00] [INFO] sing-box service is running (PID: 12345)
[2026-08-28 08:30:00] [INFO] Timezone: Asia/Shanghai (UTC+08:00)
[2026-08-28 08:30:00] [INFO] Memory usage: 42.50 MB
[2026-08-28 08:30:00] [INFO] CPU usage: 0.5% (avg)
[2026-08-28 08:30:00] [INFO] Uptime: 2h 30m 15s
[2026-08-28 08:30:00] [INFO] Network sockets: 12
[2026-08-28 08:30:00] [INFO] Disk I/O: read 15.20 MB / write 3.80 MB
```

## ⚙️ Configuration

Edit `/data/adb/sing-box/box.ini`:

```ini
SERVICE_NAME="sing-box"          # Service name
WORK_DIR="/data/adb/sing-box"    # Working directory
RUN_USER="root:net_admin"        # Run as user:group
TZ="auto"                        # Timezone (e.g. "Asia/Shanghai", or "auto" to follow the system)
MAX_LOG_SIZE=1048576             # Log rotation threshold (1 MB)
STOP_TIMEOUT=10                  # Stop timeout (seconds)
START_TIMEOUT=3                  # Startup verification time (seconds)
CHECK_CONFIG=0                   # Validate config before start (1 = enabled)
NOFILE_LIMIT=1000000             # Open file descriptor limit
```

### sing-box Configuration

Set the log output path in `config.json`:

```json
{
  "log": {
    "level": "info",
    "output": "logs/sing-box.log"
  }
}
```

## 🛠️ Troubleshooting

### Service Won't Start

1. Check that the binary exists and is executable:
   ```bash
   ls -l /data/adb/sing-box/bin/sing-box
   ```

2. Check that the config file exists:
   ```bash
   ls -l /data/adb/sing-box/config.json
   ```

3. Check the sing-box log:
   ```bash
   tail -50 /data/adb/sing-box/logs/sing-box.log
   ```

4. Check the manager log:
   ```bash
   /data/adb/sing-box/box log
   ```

5. Run it manually to test:
   ```bash
   cd /data/adb/sing-box
   ./bin/sing-box run -D .
   ```

### Not Starting on Boot

1. Check that the service.d script exists:
   ```bash
   ls -l /data/adb/service.d/sing-box.sh
   ```

2. Check that it is executable:
   ```bash
   chmod 755 /data/adb/service.d/sing-box.sh
   ```

### Permission Problems

Make sure every file is owned by root:
```bash
chown -R root:root /data/adb/sing-box
chmod 755 /data/adb/sing-box/box
chmod 755 /data/adb/sing-box/bin/sing-box
```

## 📦 Backup and Restore

### Backup

```bash
# Back up the core files (excluding runtime files)
tar -czf /sdcard/sing-box-backup-$(date +%Y%m%d).tar.gz \
    -C /data/adb \
    --exclude='sing-box/logs/*' \
    --exclude='sing-box/.box.lock' \
    --exclude='sing-box/*.pid' \
    --exclude='sing-box/cache.db' \
    --exclude='sing-box/rule_set' \
    sing-box/
```

### Restore

```bash
# Stop the service
/data/adb/sing-box/box stop

# Restore the backup
tar -xzf /sdcard/sing-box-backup.tar.gz -C /data/adb

# Restore permissions
chown -R root:root /data/adb/sing-box
chmod 755 /data/adb/sing-box/bin/sing-box
chmod 755 /data/adb/sing-box/box

# Start the service
/data/adb/sing-box/box start
```

## 📝 Notes

1. **Root required**: the manager must run as root
2. **Config location**: `config.json` must be in the root of `WORK_DIR`
3. **Separate logs**: manager logs and sing-box logs are separate files
4. **Start on boot**: requires the service.d script to be installed

## 🙏 Acknowledgements

Thanks to these developers for their contributions and reference work:

- [**CHIZI-0618**](https://github.com/CHIZI-0618) 
- [**Yuu518**](https://github.com/Yuu518) 

## 📄 License

MIT License

## 🤝 Contributing

Issues and pull requests are welcome.

## 📚 Links

- [sing-box documentation](https://sing-box.sagernet.org/)
- [KernelSU documentation](https://kernelsu.org/)
