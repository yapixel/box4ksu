# sing-box KernelSU 服务管理脚本

这是一个用于 KernelSU 环境的 sing-box 服务管理脚本，提供完整的服务生命周期管理和状态监控功能。

## 📋 特性

- ✅ 完整的服务管理（启动/停止/重启/热重载/状态）
- ✅ 详细的状态监控（内存/CPU/运行时间/网络连接/磁盘IO，纯C系统调用实现）
- ✅ 高性能架构（原生 C 语言 `fork`/`exec` 实现，零 Shell 管道开销）
- ✅ 配置文件校验与热重载（SIGHUP）
- ✅ 日志轮转管理与多目标日志查看
- ✅ 开机自启支持
- ✅ 进程锁防止重复操作
- ✅ 自动创建工作目录
- ✅ 独立日志系统（脚本日志与 sing-box 日志分离）

## 📂 目录结构

```
/data/adb/
├── service.d/
│   └── sing-box.sh              # 开机自启脚本
└── sing-box/                    # 工作目录
    ├── box                      # 原生 C 管理程序（推荐）
    ├── box.sh                   # Shell 管理脚本
    ├── box.ini                  # 服务配置文件
    ├── config.json              # sing-box 配置文件
    ├── bin/
    │   └── sing-box             # sing-box 二进制文件
    ├── logs/
    │   ├── run.log              # 操作日志
    │   ├── run_error.log        # 错误日志
    │   └── sing-box.log         # sing-box 运行日志
    ├── .box.lock/               # 进程锁（运行时）
    └── sing-box.pid             # PID文件（运行时）
```

## 🚀 快速开始

### 1. 编译与部署

```bash
# 编译原生二进制 (静态链接 aarch64 musl)
make

# 创建工作目录
mkdir -p /data/adb/sing-box/{bin,logs}

# 复制文件
cp sing-box /data/adb/sing-box/bin/
cp config.json /data/adb/sing-box/
cp box /data/adb/sing-box/
cp box.ini /data/adb/sing-box/

# 设置权限
chmod 755 /data/adb/sing-box/bin/sing-box
chmod 755 /data/adb/sing-box/box
chown -R root:root /data/adb/sing-box
```

### 2. 配置文件

创建 `/data/adb/sing-box/config.json`：

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

### 3. 安装开机自启（可选）

```bash
cat > /data/adb/service.d/sing-box.sh << 'EOF'
#!/system/bin/sh
if [ -x /data/adb/sing-box/box ]; then
    /data/adb/sing-box/box start
elif [ -x /data/adb/sing-box/box.sh ]; then
    /data/adb/sing-box/box.sh start &
fi
EOF
chmod 755 /data/adb/service.d/sing-box.sh
```

### 4. 启动服务

```bash
/data/adb/sing-box/box start
```

## 📖 使用方法

### 服务管理

```bash
# 启动服务
/data/adb/sing-box/box start

# 停止服务
/data/adb/sing-box/box stop

# 重启服务
/data/adb/sing-box/box restart

# 热重载配置 (无需断开连接)
/data/adb/sing-box/box reload

# 查看状态
/data/adb/sing-box/box status

# 校验配置
/data/adb/sing-box/box check

# 查看日志
/data/adb/sing-box/box log             # 查看运行和错误日志 (默认50行)
/data/adb/sing-box/box log 20          # 查看运行和错误日志最后20行
/data/adb/sing-box/box log sbox 50     # 查看 sing-box 核心日志最后50行
/data/adb/sing-box/box log all 50      # 查看所有日志 (运行/错误/服务日志)

# 查看 sing-box 版本
/data/adb/sing-box/box version

# 显示帮助
/data/adb/sing-box/box help
```

### 查看日志

```bash
# 查看脚本操作日志
tail -f /data/adb/sing-box/logs/run.log

# 查看脚本错误日志
tail -f /data/adb/sing-box/logs/run_error.log

# 查看 sing-box 运行日志
tail -f /data/adb/sing-box/logs/sing-box.log
```

## 📊 状态信息说明

执行 `status` 命令会显示以下信息：

| 项目 | 说明 | 数据来源 |
|------|------|----------|
| PID | 进程ID | `/proc/[pid]/` |
| 内存占用 | VmRSS 内存使用量 | `/proc/[pid]/status` |
| CPU 占用 | 进程CPU使用率 | `ps -p [pid] -o %CPU` |
| 运行时间 | 进程运行时长 | `/proc/[pid]/stat` |
| 网络套接字 | 打开的socket数量 | `/proc/[pid]/fd` |
| 磁盘IO | 累计读写量 | `/proc/[pid]/io` |

### 状态输出示例

```
[2026-01-01 10:00:00] [INFO] sing-box service is running (PID: 12345)
[2026-01-01 10:00:00] [INFO] Memory usage: 42.50 MB
[2026-01-01 10:00:00] [INFO] CPU usage: 0.5%
[2026-01-01 10:00:00] [INFO] Uptime: 2h 30m 15s
[2026-01-01 10:00:00] [INFO] Network sockets: 12
[2026-01-01 10:00:00] [INFO] Disk I/O: read 15.20 MB / write 3.80 MB
```

## ⚙️ 配置说明

### 脚本配置项

编辑 `box.sh` 开头的配置区：

```bash
SERVICE_NAME="sing-box"          # 服务名称
WORK_DIR="/data/adb/sing-box"    # 工作目录
RUN_USER="root:net_admin"        # 运行用户:组
MAX_LOG_SIZE=1048576             # 日志轮转阈值 (1MB)
STOP_TIMEOUT=10                  # 停止超时时间 (秒)
START_TIMEOUT=3                  # 启动验证时间 (秒)
CHECK_CONFIG=0                   # 启动前校验配置 (1=启用)
NOFILE_LIMIT=1000000             # 文件描述符限制
```

### sing-box 配置

在 `config.json` 中配置日志输出路径：

```json
{
  "log": {
    "level": "info",
    "output": "logs/sing-box.log"
  }
}
```

## 🛠️ 故障排查

### 服务无法启动

1. 检查二进制文件是否存在且可执行：
   ```bash
   ls -l /data/adb/sing-box/bin/sing-box
   ```

2. 检查配置文件是否存在：
   ```bash
   ls -l /data/adb/sing-box/config.json
   ```

3. 查看 sing-box 日志：
   ```bash
   tail -50 /data/adb/sing-box/logs/sing-box.log
   ```

4. 查看脚本错误日志：
   ```bash
   /data/adb/sing-box/box.sh log
   ```

5. 手动运行测试：
   ```bash
   cd /data/adb/sing-box
   ./bin/sing-box run -D .
   ```

### 开机未自动启动

1. 检查 service.d 脚本是否存在：
   ```bash
   ls -l /data/adb/service.d/sing-box.sh
   ```

2. 检查执行权限：
   ```bash
   chmod 755 /data/adb/service.d/sing-box.sh
   ```

3. 检查 KernelSU 版本是否支持 service.d

### 权限问题

确保所有文件属主为 root：
```bash
chown -R root:root /data/adb/sing-box
chmod 755 /data/adb/sing-box/box.sh
chmod 755 /data/adb/sing-box/bin/sing-box
```

## 📦 备份与恢复

### 备份

```bash
# 备份核心文件（排除运行时文件）
tar -czf /sdcard/sing-box-backup-$(date +%Y%m%d).tar.gz \
    -C /data/adb \
    --exclude='sing-box/logs/*' \
    --exclude='sing-box/.box.lock' \
    --exclude='sing-box/*.pid' \
    --exclude='sing-box/cache.db' \
    --exclude='sing-box/rule_set' \
    sing-box/
```

### 恢复

```bash
# 停止服务
/data/adb/sing-box/box.sh stop

# 恢复备份
tar -xzf /sdcard/sing-box-backup.tar.gz -C /data/adb

# 恢复权限
chown -R root:root /data/adb/sing-box
chmod 755 /data/adb/sing-box/bin/sing-box
chmod 755 /data/adb/sing-box/box.sh

# 启动服务
/data/adb/sing-box/box.sh start
```

## 📝 注意事项

1. **需要 root 权限**：脚本需要在 root 环境下运行
2. **依赖 busybox**：KernelSU 环境必须包含 busybox
3. **配置文件位置**：`config.json` 必须放在 `WORK_DIR` 根目录
4. **日志分离**：脚本日志和 sing-box 日志是独立的文件
5. **开机自启**：如需开机自启，必须安装 service.d 脚本

## 🙏 致谢

感谢以下开发者对本项目的贡献和参考：

- [**CHIZI-0618**](https://github.com/CHIZI-0618) 
- [**Yuu518**](https://github.com/Yuu518) 

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request

## 📚 相关链接

- [sing-box 官方文档](https://sing-box.sagernet.org/)
- [KernelSU 官方文档](https://kernelsu.org/)
