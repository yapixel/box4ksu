#!/system/bin/sh
# /data/adb/service.d/sing-box.sh
# sing-box auto-start on boot

if [ -x /data/adb/sing-box/box ]; then
    /data/adb/sing-box/box start
elif [ -x /data/adb/sing-box/box.sh ]; then
    /data/adb/sing-box/box.sh start &
fi