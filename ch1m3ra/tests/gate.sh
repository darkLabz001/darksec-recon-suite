#!/bin/sh
# Behavior gate: replay the invocation matrix that produced .baseline/ch1m3ra.out
# and diff.  Prints the diff; a clean run means only intended changes.
set -u
BIN=${BIN:-./ch1m3ra}
OUT=$(mktemp)
RAW=$(mktemp)
trap 'rm -f "$OUT" "$RAW"' EXIT
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
# -l output depends on the host's interfaces: only the header is compared, so
# the gate stays reproducible across machines and still catches code-driven
# changes (a missing header or a non-zero exit).
{
    printf '### -l (normalised)\n' >> "$OUT"
    "$BIN" -l > "$RAW" 2>&1
    rc=$?
    head -1 "$RAW" >> "$OUT"
    printf '### exit=%d\n' "$rc" >> "$OUT"
}
run --help
diff -u .baseline/ch1m3ra.out "$OUT"
