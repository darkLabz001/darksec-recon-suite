#!/bin/sh
# Behavior gate: replay the invocation matrix that produced .baseline/ch1m3ra.out
# and diff.  Prints the diff; a clean run means only intended changes.
set -u
BIN=${BIN:-./ch1m3ra}
OUT=/tmp/opencode/gate.out
: > "$OUT"
run() {
    printf '### %s\n' "$*" >> "$OUT"
    "$BIN" "$@" >> "$OUT" 2>&1
    printf '### exit=%d\n' "$?" >> "$OUT"
}
for P in tests/sample.pcap tests/creds.pcap; do
    run -r "$P" -C -B 32
    run -r "$P" -C -q -B 0
    run -r "$P" -C -o json -B 0
    run -r "$P" -C -o csv -B 0
    run -r "$P" -C -e -o json
    run -r "$P" -C -K -O -Y -N -B 64
    run -r "$P" -C -P tcp -B 0
    run -r "$P" -C -P dns -B 0
    run -r "$P" -C -H example.com -B 0
    run -r "$P" -C -p 443 -q -B 0
    run -r "$P" -C -T 0
    run -r "$P" -C -F 'tcp and port 443' -q -B 0
    run -r "$P" -C -E -F 'not arp' -q -B 0
    run -r "$P" -C -n 5 -B 0
    run -r "$P" -C -s 128 -B 0
    run -r "$P" -C -M -B 0
    run -r "$P" -C -o bogus
    run -r /nonexistent.pcap
done
# -l output depends on the host's interfaces; normalise it to the header plus a
# sorted list of interface names so the gate only catches code-driven changes.
{
    printf '### -l (normalised)\n' >> "$OUT"
    "$BIN" -l > /tmp/opencode/.gate_lraw.$$ 2>&1
    rc=$?
    awk 'NR==1{print; next} {print $1}' /tmp/opencode/.gate_lraw.$$ > /tmp/opencode/.gate_l.$$
    head -1 /tmp/opencode/.gate_l.$$ >> "$OUT"
    tail -n +2 /tmp/opencode/.gate_l.$$ | sort >> "$OUT"
    rm -f /tmp/opencode/.gate_lraw.$$ /tmp/opencode/.gate_l.$$
    printf '### exit=%d\n' "$rc" >> "$OUT"
}
run --help
diff -u .baseline/ch1m3ra.out "$OUT"
