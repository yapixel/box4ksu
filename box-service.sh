#!/system/bin/sh
# /data/adb/service.d/sing-box.sh
# sing-box auto-start on boot

# Ensure correct timezone is inherited
if [ -z "${TZ}" ]; then
    _tz=$(getprop persist.sys.timezone 2>/dev/null)
    [ -z "${_tz}" ] && _tz=$(getprop ro.sys.timezone 2>/dev/null)
    [ -z "${_tz}" ] && _tz="Asia/Shanghai"
    export TZ="${_tz}"
fi

if [ -x /data/adb/sing-box/box ]; then
    /data/adb/sing-box/box start
elif [ -x /data/adb/sing-box/box.sh ]; then
    /data/adb/sing-box/box.sh start &
fi