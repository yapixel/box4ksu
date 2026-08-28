#!/system/bin/sh
# /data/adb/service.d/sing-box.sh
# sing-box auto-start on boot for KernelSU / APatch / Magisk

# 1. Wait for Android system boot completion
until [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ]; do
    sleep 3
done

# 2. Wait for network stack and storage to settle
sleep 3

# 3. Ensure correct timezone is inherited
if [ -z "${TZ}" ]; then
    _tz=$(getprop persist.sys.timezone 2>/dev/null)
    [ -z "${_tz}" ] && _tz=$(getprop ro.sys.timezone 2>/dev/null)
    [ -z "${_tz}" ] && _tz="Asia/Shanghai"
    export TZ="${_tz}"
fi

# 4. Clean up any leftover lock from prior reboot
rm -rf /data/adb/sing-box/.box.lock

# 5. Start service
if [ -x /data/adb/sing-box/box ]; then
    /data/adb/sing-box/box start
fi