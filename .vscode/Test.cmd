adb push build/test /data/local/tmp
adb shell "chmod 777 /data/local/tmp/test"
adb shell "/data/local/tmp/test"