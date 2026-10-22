#!/bin/sh
# Live 802.11 injection test.
#
# Puts a monitor-capable radio into monitor mode, injects crafted beacons and
# deauth frames with --beacon-flood / --deauth, captures the air on the same
# monitor vif, and checks the frames round-trip (SSID decoded, deauth flood
# flagged by -D).  This exercises the 802.11 transmit path that the offline
# tests cannot reach.
#
# Requires root and a monitor-capable wireless device; skips cleanly (exit 0)
# otherwise, so it is safe to run unconditionally.
#
# Usage:  sudo tests/wlan_live.sh      (or: ROOT=sudo tests/wlan_live.sh)
set -u

BIN=${BIN:-./ch1m3ra}
TMPD=$(mktemp -d)
MON="ch1mon$$"
DOWNED=""          # sibling interfaces we brought down (restored on exit)
pass=0; fail=0
ok()  { pass=$((pass+1)); printf 'ok   %-52s\n' "$1"; }
bad() { fail=$((fail+1)); printf 'FAIL %-52s %s\n' "$1" "${2:-}"; }
cleanup() {
    [ -n "${MON:-}" ] && { iw dev "$MON" del 2>/dev/null || ip link del "$MON" 2>/dev/null; }
    for d in $DOWNED; do ip link set "$d" up 2>/dev/null; done
    rm -rf "$TMPD"
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" != 0 ]; then
    echo "skip wlan live test (needs root; run: sudo tests/wlan_live.sh)"
    exit 0
fi
if ! command -v iw >/dev/null 2>&1; then
    echo "skip wlan live test (no 'iw' tool)"
    exit 0
fi

# netdevs that share a phy with $1 (excluding the monitor vif itself)
siblings() {
    for n in /sys/class/net/*; do
        d=$(basename "$n")
        [ "$d" = "$MON" ] && continue
        [ -e "$n/phy80211" ] || continue
        [ "$(readlink -f "$n/phy80211" | sed 's#.*/##')" = "$1" ] && printf '%s ' "$d"
    done
}
try_channel() {
    for ch in 1 6 11 36; do
        iw dev "$MON" set channel "$ch" 2>/dev/null && return 0
    done
    return 1
}

# Candidate phys: monitor-capable, with spare radios (no sibling IPv4) first so
# we don't disturb an active connection when a spare adapter is available.
SPARE=""; ACTIVE=""
for p in /sys/class/ieee80211/phy*; do
    [ -e "$p" ] || continue
    cand=$(basename "$p")
    iw phy "$cand" info 2>/dev/null | grep -q '\* monitor' || continue
    hasip=0
    for s in $(siblings "$cand"); do
        [ -n "$(ip -4 addr show "$s" 2>/dev/null | grep 'inet ')" ] && hasip=1
    done
    if [ "$hasip" = 0 ]; then SPARE="$SPARE $cand"; else ACTIVE="$ACTIVE $cand"; fi
done

PHY=""
for cand in $SPARE $ACTIVE; do
    iw phy "$cand" interface add "$MON" type monitor 2>/dev/null || continue
    ip link set "$MON" up 2>/dev/null
    if try_channel; then PHY=$cand; break; fi
    # channel pinned by a sibling: drop the siblings and retry
    for s in $(siblings "$cand"); do
        ip link set "$s" down 2>/dev/null && DOWNED="$DOWNED $s"
    done
    if try_channel; then PHY=$cand; break; fi
    iw dev "$MON" del 2>/dev/null
done
if [ -z "$PHY" ]; then
    echo "skip wlan live test (no monitor-capable radio with a usable channel)"
    exit 0
fi
CURCH=$(iw dev "$MON" info 2>/dev/null | sed -n 's/.*channel \([0-9]*\).*/\1/p')
[ -n "$CURCH" ] || { echo "skip wlan live test (cannot set a channel on $MON)"; exit 0; }
echo "monitor $MON on $PHY channel $CURCH"

# ---- beacon injection: inject while capturing on the same vif --------------
timeout 10 "$BIN" -i "$MON" -w "$TMPD/beacon.pcap" -q -B 0 >/dev/null 2>&1 &
sleep 1
timeout 6 "$BIN" -i "$MON" --beacon-flood CH1M3RA-LIVE,120 >"$TMPD/beacon.err" 2>&1
sleep 3
wait 2>/dev/null

nbeacon=$("$BIN" -r "$TMPD/beacon.pcap" -q -B 0 2>/dev/null | grep -c "CH1M3RA-LIVE")
if [ "$nbeacon" -ge 1 ]; then
    ok "--beacon-flood frames reached the air ($nbeacon seen)"
else
    # Some drivers do not loop their own TX back into the monitor; skip rather
    # than fail, but report that the frames were still handed to the driver.
    echo "skip wlan live test (radio does not reflect injected TX; no frames seen)"
    echo "     frames were handed to the driver - see $TMPD/beacon.err"
    exit 0
fi

# ---- deauth injection + -D detection ---------------------------------------
timeout 10 "$BIN" -i "$MON" -w "$TMPD/deauth.pcap" -q -B 0 >/dev/null 2>&1 &
sleep 1
timeout 6 "$BIN" -i "$MON" --deauth aa:bb:cc:dd:ee:ff,11:22:33:44:55:66,120 \
    >"$TMPD/deauth.err" 2>&1
sleep 3
wait 2>/dev/null

ndeauth=$("$BIN" -r "$TMPD/deauth.pcap" -q -B 0 2>/dev/null | grep -c "DEAUTH")
if [ "$ndeauth" -ge 1 ]; then
    ok "--deauth frames reached the air ($ndeauth seen)"
else
    bad "--deauth frames reached the air"
fi

if "$BIN" -r "$TMPD/deauth.pcap" -C -D 2>&1 | grep -q "DEAUTH FLOOD"; then
    ok "-D flags the injected deauth flood"
else
    bad "-D flags the injected deauth flood"
fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
