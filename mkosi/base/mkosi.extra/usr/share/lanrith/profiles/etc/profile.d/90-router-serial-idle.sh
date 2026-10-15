# Leave SSH and VGA shells alone. Bash also ends an idle serial login shell
# while the serial watchdog covers foreground programs.
if [ "$(tty 2>/dev/null)" = /dev/ttyS0 ]; then
    TMOUT=300
    readonly TMOUT
    export TMOUT
fi
