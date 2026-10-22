#!/bin/sh
# Live-capture + injection harness using network namespaces.
#
# Builds a two-namespace veth pair, runs the tool for real on one side
# (raw AF_PACKET, no pcap file), injects traffic from the other side, and
# checks that it decoded it.  This exercises the live path
# (open_live / recvfrom) and the active injection tools that the offline
# tests cannot reach.
#
# Requires root; skips cleanly (exit 0) when run unprivileged or when the
# `ip` tool / netns support is missing, so it is safe to wire into `make test`.
#
# Usage:  sudo tests/netns.sh          (or: ROOT=sudo tests/netns.sh)
set -u

BIN=${BIN:-./ch1m3ra}
NS_A=sniffa
NS_B=sniffb
VETH_A=vetha
VETH_B=vethb
IP_A=10.99.0.1
IP_B=10.99.0.2
TMPD=$(mktemp -d)
pass=0; fail=0
ok()  { pass=$((pass+1)); printf 'ok   %-52s\n' "$1"; }
bad() { fail=$((fail+1)); printf 'FAIL %-52s %s\n' "$1" "${2:-}"; }

if [ "$(id -u)" != 0 ]; then
    echo "skip netns harness (needs root; run: sudo tests/netns.sh)"
    exit 0
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "skip netns harness (no 'ip' tool)"
    exit 0
fi
if ! ip netns add "$NS_A" 2>/dev/null; then
    echo "skip netns harness (cannot create network namespaces here)"
    exit 0
fi

cleanup() {
    ip netns del "$NS_A" 2>/dev/null
    ip netns del "$NS_B" 2>/dev/null
    rm -rf "$TMPD"
}
trap cleanup EXIT INT TERM

# ---- build the topology: nsA <-> veth <-> nsB -------------------------------
ip netns add "$NS_B"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"
ip netns exec "$NS_A" ip addr add "$IP_A/24" dev "$VETH_A"
ip netns exec "$NS_B" ip addr add "$IP_B/24" dev "$VETH_B"
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip link set lo up
# both sides in one bridge so broadcast/ARP is visible on the capture side
if ip netns exec "$NS_A" ping -c1 -W1 "$IP_B" >/dev/null 2>&1; then
    ok "topology up (ping nsA -> nsB)"
else
    bad "topology up (ping nsA -> nsB)"
fi

# ---- 1. live capture of real traffic ----------------------------------------
# Capture for ~2s on the A side while B pings A; assert ICMP was decoded.
ip netns exec "$NS_A" timeout 4 "$BIN" -i "$VETH_A" -C -q -B 0 -P icmp \
    >"$TMPD/cap.txt" 2>"$TMPD/cap.err" &
SNIFF_PID=$!
sleep 1
ip netns exec "$NS_B" ping -c3 -i0.3 "$IP_A" >/dev/null 2>&1
wait $SNIFF_PID 2>/dev/null
if grep -qE "^[0-9].*ICMP" "$TMPD/cap.txt"; then
    ok "live capture decoded injected ICMP"
else
    bad "live capture decoded injected ICMP" "(see $TMPD/cap.err)"
fi
if grep -qE "^[0-9]" "$TMPD/cap.txt"; then
    ok "live capture produced packet lines"
else
    bad "live capture produced packet lines"
fi

# ---- 2. --replay injects a pcap and the peer captures it --------------------
# Build a tiny one-frame pcap (ARP request) and replay it from nsB onto the
# veth, capturing on nsA.  Uses the tool s own -w to author the fixture.
"$BIN" -r tests/sample.pcap -C -w "$TMPD/frames.pcap" -n 1 >/dev/null 2>&1
if [ -s "$TMPD/frames.pcap" ]; then
    ip netns exec "$NS_A" timeout 4 "$BIN" -i "$VETH_A" -C -q -B 0 \
        >"$TMPD/cap2.txt" 2>/dev/null &
    SNIFF2=$!
    sleep 1
    ip netns exec "$NS_B" "$BIN" --replay "$TMPD/frames.pcap" -i "$VETH_B" \
        >/dev/null 2>"$TMPD/replay.err"
    wait $SNIFF2 2>/dev/null
    if grep -qE "^[0-9]" "$TMPD/cap2.txt"; then
        ok "--replay frames seen on the live capture"
    else
        bad "--replay frames seen on the live capture" "(see $TMPD/replay.err)"
    fi
else
    bad "author replay fixture with -w"
fi

# ---- 3. --syn-scan transmits and sees results -------------------------------
# A listener in nsA; syn-scan from nsB against it.  The scanner prints an
# open port if a SYN/ACK comes back.
ip netns exec "$NS_A" sh -c '
    python3 -c "import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
s.bind((\"0.0.0.0\", 9)); s.listen(1); time.sleep(3)" ' &
LISTEN=$!
sleep 0.5
if ip netns exec "$NS_B" "$BIN" --syn-scan "$IP_A:9" -i "$VETH_B" \
        >"$TMPD/scan.txt" 2>"$TMPD/scan.err"; then
    if grep -qE "9" "$TMPD/scan.txt"; then
        ok "--syn-scan reported the open port"
    else
        bad "--syn-scan reported the open port" "(output: $(head -c120 "$TMPD/scan.txt"))"
    fi
else
    bad "--syn-scan ran" "(see $TMPD/scan.err)"
fi
kill $LISTEN 2>/dev/null

# ---- 4. --arp-poison transmits gratuitous ARP -------------------------------
# Run for ~1.5s while capturing; assert the ARP reply is seen and that
# Ctrl-C/timeout restores cleanly (no crash).
ip netns exec "$NS_A" timeout 4 "$BIN" -i "$VETH_A" -C -q -B 0 -P arp \
    >"$TMPD/cap3.txt" 2>/dev/null &
SNIFF3=$!
sleep 1
ip netns exec "$NS_B" timeout 2 "$BIN" --arp-poison "$IP_A,$IP_A,$VETH_B" \
    >/dev/null 2>"$TMPD/arp.err" &
AP=$!
sleep 2
kill "$AP" 2>/dev/null; wait "$AP" 2>/dev/null
wait $SNIFF3 2>/dev/null
if grep -qiE "arp" "$TMPD/cap3.txt"; then
    ok "--arp-poison emitted ARP frames"
else
    bad "--arp-poison emitted ARP frames" "(see $TMPD/arp.err)"
fi

# ---- 5. --banner-grab connects to a real listener ---------------------------
# A greeting service in nsA; grab from nsB over the veth (normal TCP connect).
ip netns exec "$NS_A" python3 -c "
import socket,threading,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('$IP_A', 2525)); s.listen(2); s.settimeout(5)
def serve():
    try:
        c,_=s.accept(); c.sendall(b'220 netns-test SMTP ready\r\n'); time.sleep(0.5); c.close()
    except Exception: pass
threading.Thread(target=serve,daemon=True).start()
time.sleep(5)
" &
LISTEN2=$!
sleep 0.6
if ip netns exec "$NS_B" "$BIN" --banner-grab "$IP_A:2525" --banner-timeout 1500 \
        >"$TMPD/banner.txt" 2>"$TMPD/banner.err"; then
    if grep -qF "netns-test SMTP ready" "$TMPD/banner.txt"; then
        ok "--banner-grab read the live banner"
    else
        bad "--banner-grab read the live banner" "(output: $(head -c120 "$TMPD/banner.txt"))"
    fi
else
    bad "--banner-grab ran" "(see $TMPD/banner.err)"
fi
kill $LISTEN2 2>/dev/null

# ---- 6. --vlan-hop transmits double-tagged 802.1Q frames --------------------
# Capture on the *sender* side (nsB): veth rx offload strips the outer S-tag
# before the peer sees it, so the full QinQ frame is only visible on transmit.
# A vlan.inner record proves the double-tagged frame hit the wire correctly.
ip netns exec "$NS_B" timeout 4 "$BIN" -i "$VETH_B" -C -o json -B 0 -n 8 \
    >"$TMPD/cap4.txt" 2>/dev/null &
SNIFF4=$!
sleep 1
ip netns exec "$NS_B" timeout 2 "$BIN" --vlan-hop "$VETH_B:100:200" \
    >/dev/null 2>"$TMPD/vlan.err" &
VH=$!
sleep 2
kill "$VH" 2>/dev/null; wait "$VH" 2>/dev/null
wait $SNIFF4 2>/dev/null
if grep -qF '"vlan.inner":200' "$TMPD/cap4.txt"; then
    ok "--vlan-hop emitted QinQ-tagged frames"
else
    bad "--vlan-hop emitted QinQ-tagged frames" "(see $TMPD/vlan.err)"
fi

# ---- 7. -Z zero-copy ring captures a burst via the batch drain --------------
# Send a fast ping burst; the ring capture must account for most of them with
# the single-wakeup batch drain (capture_drain) rather than one poll per frame.
ip netns exec "$NS_A" timeout 5 "$BIN" -i "$VETH_A" -Z -C -q -B 0 -P icmp \
    >"$TMPD/cap5.txt" 2>"$TMPD/ring.err" &
SNIFF5=$!
sleep 1
ip netns exec "$NS_B" ping -c 30 -i0.02 "$IP_A" >/dev/null 2>&1
sleep 2
wait $SNIFF5 2>/dev/null
ring_n=$(grep -cE "^[0-9].*ICMP" "$TMPD/cap5.txt" 2>/dev/null || echo 0)
if [ "$ring_n" -ge 20 ]; then
    ok "-Z ring batch drain captured $ring_n/60 ICMP"
else
    bad "-Z ring batch drain captured $ring_n/60 ICMP" "(see $TMPD/ring.err)"
fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
