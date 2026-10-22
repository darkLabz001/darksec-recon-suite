#!/bin/sh
# Launcher for the ch1m3ra packet sniffer TUI, used by the desktop entry.
#
# The tool needs CAP_NET_RAW/CAP_NET_ADMIN.  We prefer a setcap'd binary
# (no password prompt); otherwise we re-exec through pkexec/sudo so the user
# can authenticate in the terminal that the desktop entry opens.

DIR=$(cd "$(dirname "$0")" && pwd)
BIN="$DIR/ch1m3ra"

# pick a capture interface: honour $SNIFF_IFACE, else the first wireless/up
# non-loopback interface, else wlan0/eth0.
iface=${SNIFF_IFACE:-}
if [ -z "$iface" ]; then
    for i in $(ls /sys/class/net 2>/dev/null); do
        [ "$i" = "lo" ] && continue
        [ -d "/sys/class/net/$i/wireless" ] && { iface=$i; break; }
    done
fi
if [ -z "$iface" ]; then
    for i in $(ls /sys/class/net 2>/dev/null); do
        [ "$i" = "lo" ] && continue
        [ -f "/sys/class/net/$i/operstate" ] &&
            [ "$(cat /sys/class/net/$i/operstate)" = "up" ] && { iface=$i; break; }
    done
fi
[ -z "$iface" ] && iface=wlan0

run() { exec "$BIN" -i "$iface" -U; }

# 1) binary already has the needed capabilities -> run directly
if getcap "$BIN" 2>/dev/null | grep -q cap_net_raw; then
    run
fi

# 2) root already -> run directly
if [ "$(id -u)" = 0 ]; then
    run
fi

# 3) try to elevate.  pkexec gives a graphical prompt; fall back to sudo.
if command -v pkexec >/dev/null 2>&1; then
    exec pkexec "$BIN" -i "$iface" -U
fi
echo "ch1m3ra: need root for raw capture; running 'sudo' ..."
exec sudo "$BIN" -i "$iface" -U
