#!/bin/sh
# Assertion tests for ch1m3ra, driven off tests/sample.pcap.
# Run via `make test` (or ./tests/check.sh after a build).
set -u

BIN=${BIN:-./ch1m3ra}
PCAP=${PCAP:-tests/sample.pcap}
pass=0
fail=0

run() { $BIN -r "$PCAP" -C "$@" 2>/dev/null; }
has_from() {
    f=$1; desc=$2; needle=$3; shift 3
    if $BIN -r "$f" -C "$@" 2>/dev/null | grep -qF -- "$needle"; then
        pass=$((pass+1)); printf 'ok   %-52s %s\n' "$desc" "$needle"
    else
        fail=$((fail+1)); printf 'FAIL %-52s missing: %s\n' "$desc" "$needle"
    fi
}

# count_lines <description> <expected> <args...>
count_lines() {
    desc=$1; want=$2; shift 2
    got=$(run "$@" | wc -l | tr -d ' ')
    if [ "$got" = "$want" ]; then
        pass=$((pass+1)); printf 'ok   %-52s %s\n' "$desc" "$got"
    else
        fail=$((fail+1)); printf 'FAIL %-52s want %s got %s\n' "$desc" "$want" "$got"
    fi
}

# has <description> <needle> <args...>
has() {
    desc=$1; needle=$2; shift 2
    if run "$@" | grep -qF -- "$needle"; then
        pass=$((pass+1)); printf 'ok   %-52s %s\n' "$desc" "$needle"
    else
        fail=$((fail+1)); printf 'FAIL %-52s missing: %s\n' "$desc" "$needle"
    fi
}

lacks() {
    desc=$1; needle=$2; shift 2
    if run "$@" | grep -qF -- "$needle"; then
        fail=$((fail+1)); printf 'FAIL %-52s unexpected: %s\n' "$desc" "$needle"
    else
        pass=$((pass+1)); printf 'ok   %-52s no %s\n' "$desc" "$needle"
    fi
}

echo "== decoding =="
has "ARP request decoded"            "who-has 192.168.1.1" -q -B 0
has "IPv4 checksum verified"         "ip-csum=ok"          -B 0 -P ip
has "IPv6 hop-by-hop ext header"     "2001:db8::1"         -q -B 0 -P ipv6
has "TCP options parsed"             "SACK-perm"           -B 0
has "payload dump shown"             "GET / HTTP/1.1"      -B 32

echo "== app-layer decoders =="
has "DNS query decoded"              "query example.com A"  -B 0 -P dns
has "DNS response + answer"          "93.184.216.34"        -B 0 -P dns
has "TLS ClientHello SNI"            "SNI=example.com"      -B 0 -P tls
has "TLS ALPN list"                  "ALPN=h2,http/1.1"     -B 0 -P tls
has "TLS offered versions"           "vers=TLS1.3/TLS1.2"   -B 0 -P tls
has "TLS app-data record"            "app-data"             -B 0 -P tls
has "HTTP request line + Host"       "GET / HTTP/1.1 host=example.com" -B 0 -P http
has "HTTP response + status"         "HTTP/1.1 200 OK"      -B 0 -P http
count_lines "DNS packets (query+response)" 2 -q -B 0 -P dns
count_lines "TLS packets"                  2 -q -B 0 -P tls
count_lines "HTTP packets"                 3 -q -B 0 -P http
count_lines "host filter matches SNI/qname/Host" 4 -q -B 0 -H example.com

echo "== stream reassembly =="
has "follow stream emits seq no"     "GET /reasm HTTP/1.1" -T 0
has "follow reassembled out-of-order" "Host: reasm.test"  -T 0
has "follow reassembled body"        "BODY!!"              -T 0
has "stream ids on packet lines"     "#5"                  -q -B 0
has "stream table in stats"          "#5 "                 -q -B 0

echo "== output formats =="
count_lines "JSON: one object per packet" 23 -o json -B 0
if run -o json -B 16 | python3 -c 'import json,sys
n=0
for line in sys.stdin:
    json.loads(line); n+=1
sys.exit(0 if n else 1)'; then
    pass=$((pass+1)); printf 'ok   %-52s all lines valid\n' "JSON parses"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "JSON parses"
fi
has "JSON app field"                 '"app":"dns"'         -o json -B 0
has "JSON stream field"              '"stream":6'          -o json -B 0
has "JSON tls sni field"             '"tls.sni":"example.com"' -o json -B 0
has "CSV header row"                 "ts,rel,iface,dir"    -o csv -B 0
has "relative timestamps"            "+0.000000"           -e -q -B 0
count_lines "CSV rows + header"      24 -o csv -B 0
has "ndjson schema field"            '"schema":1'          -o ndjson -B 0
has "zeek fields header"             "#fields"             -o zeek -B 0
has "zeek conn row"                  "id.orig_h"           -o zeek -B 0
count_lines "zeek rows + 8 headers"  31 -o zeek -B 0

echo "== BPF filter (-F, offline interpreter) =="
count_lines "bpf: tcp and port 443"  5 -q -B 0 -F 'tcp and port 443'
count_lines "bpf: udp and port 53"   2 -q -B 0 -F 'udp and port 53'
count_lines "bpf: arp"               2 -q -B 0 -F 'arp'
count_lines "bpf: icmp6"             1 -q -B 0 -F 'icmp6'
count_lines "bpf: dns keyword"       2 -q -B 0 -F 'dns'
count_lines "bpf: host 8.8.8.8"      12 -q -B 0 -F 'host 8.8.8.8'
count_lines "bpf: dst host 10.2.2.2" 3 -q -B 0 -F 'dst host 10.2.2.2'
count_lines "bpf: ip6 and tcp port"  1 -q -B 0 -F 'ip6 and tcp port 8443'
count_lines "bpf: not (arp or icmp or icmp6)" 18 -q -B 0 -F '!(arp or icmp or icmp6)'
count_lines "bpf: precedence/or"     6 -q -B 0 -F '(tcp and port 80) or dns'
# cross-check: -F and the userspace -H must agree
a=$(run -q -B 0 -F 'host 10.2.2.2' | wc -l | tr -d ' ')
b=$(run -q -B 0 -H 10.2.2.2       | wc -l | tr -d ' ')
if [ "$a" = "$b" ] && [ "$a" != "0" ]; then
    pass=$((pass+1)); printf 'ok   %-52s %s\n' "-F matches userspace -H" "$a"
else
    fail=$((fail+1)); printf 'FAIL %-52s -F=%s -H=%s\n' "-F matches userspace -H" "$a" "$b"
fi
if run -F 'tcp and' >/dev/null 2>&1; then
    fail=$((fail+1)); printf 'FAIL %-52s\n' "bad -F expression rejected"
else
    pass=$((pass+1)); printf 'ok   %-52s\n' "bad -F expression rejected"
fi
# extended grammar: vlan, ether, greater/less/len, tcp[tcpflags]
count_lines "bpf: vlan"                    1 -q -B 0 -F 'vlan'
count_lines "bpf: ether host (broadcast src)" 22 -q -B 0 -F 'ether host aa:bb:cc:dd:ee:ff'
count_lines "bpf: ether src"              19 -q -B 0 -F 'ether src aa:bb:cc:dd:ee:ff'
count_lines "bpf: ether dst broadcast"    22 -q -B 0 -F 'ether dst ff:ff:ff:ff:ff:ff'
count_lines "bpf: greater 100"             2 -q -B 0 -F 'greater 100'
count_lines "bpf: less 50"                 8 -q -B 0 -F 'less 50'
count_lines "bpf: len > 60"               14 -q -B 0 -F 'len > 60'
count_lines "bpf: tcp[tcpflags] & syn"     3 -q -B 0 -F 'tcp[tcpflags] & syn != 0'
count_lines "bpf: ip and tcp[tcpflags]&syn" 2 -q -B 0 -F 'ip and tcp[tcpflags] & tcp-syn != 0'
count_lines "bpf: tcp[tcpflags] & ack"     7 -q -B 0 -F 'tcp[tcpflags] & tcp-ack != 0'

echo "== credential / token harvesting (-K) =="
CPCAP=${CPCAP:-tests/creds.pcap}
if [ -f "$CPCAP" ]; then
    crun() { $BIN -r "$CPCAP" -C "$@" 2>/dev/null; }
    if crun -K -B 0 | grep -qF "user=admin pass=secret"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-K HTTP Basic"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "-K HTTP Basic"
    fi
    if crun -K -B 0 | grep -qF "user=bob pass=hunter2"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-K HTTP form"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "-K HTTP form"
    fi
    n=$(crun -K -B 0 | grep -c "CRED HTTP form")
    if [ "$n" = "1" ]; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-K form not double-counted"
    else
        fail=$((fail+1)); printf 'FAIL %-52s want 1 got %s\n' "-K form not double-counted" "$n"
    fi
    if crun -K -B 0 | grep -qF "COOK SID=deadbeefcafe"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-K Set-Cookie"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "-K Set-Cookie"
    fi
    if crun -K -B 0 | grep -qF "JWT  sub=42 name=admin"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-K JWT payload summary"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "-K JWT payload summary"
    fi
    if crun -K -B 0 | grep -qF "pass=s3cr3t"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-K FTP PASS"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "-K FTP PASS"
    fi
    if crun -K -B 0 | grep -qF "BANR SSH-2.0-OpenSSH"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-K SSH banner"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "-K SSH banner"
    fi
    if crun -K -o json | grep -qF '"cred":{"kind":"basic"'; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-K JSON cred object"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "-K JSON cred object"
    fi
    if crun -K -o csv | head -1 | grep -qF "user,pass,where,banner,os"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-K CSV new columns"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "-K CSV new columns"
    fi
    credout=$(mktemp)
    crun -k "$credout" -B 0 >/dev/null
    if grep -qF "user=admin pass=secret" "$credout"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "-k writes credential file"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "-k writes credential file"
    fi
    rm -f "$credout"
    # without -K nothing is harvested
    if crun -B 0 | grep -qF "CRED "; then
        fail=$((fail+1)); printf 'FAIL %-52s\n' "no harvest without -K"
    else
        pass=$((pass+1)); printf 'ok   %-52s\n' "no harvest without -K"
    fi
else
    printf 'skip %-52s (no %s)\n' "-K credential tests" "$CPCAP"
fi

echo "== recon: fingerprint / talkers / names =="
has "OS fingerprint from TCP SYN"     "Linux 5.x/6.x"        -O -B 0 -P tcp
# the recon tables are printed in the stats block on stderr
if $BIN -r "$PCAP" -C -O -q -B 0 2>&1 >/dev/null | grep -qF "hosts (passive OS fingerprint)"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "host table in stats"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "host table in stats"
fi
if $BIN -r "$PCAP" -C -Y -q -B 0 2>&1 >/dev/null | grep -qF "top conversations (by bytes)"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "top-talkers table"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "top-talkers table"
fi
if $BIN -r "$PCAP" -C -N -q -B 0 2>&1 >/dev/null | grep -qF "names learned"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "names learned table"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "names learned table"
fi
if run -O -o json -B 0 | grep -qF '"os":"'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "OS field in JSON"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "OS field in JSON"
fi

echo "== evasion-aware filtering (-E) =="
a=$(run -q -B 0 -E -F 'tcp and port 443' | wc -l | tr -d ' ')
if [ "$a" != "0" ]; then
    pass=$((pass+1)); printf 'ok   %-52s %s\n' "-E parsed BPF filter" "$a"
else
    fail=$((fail+1)); printf 'FAIL %-52s got 0\n' "-E parsed BPF filter"
fi

echo "== fragment reassembly (-A) =="
FPCAP=${FPCAP:-tests/frag.pcap}
if [ ! -f "$FPCAP" ]; then

    python3 tests/gen_frag.py "$FPCAP" 2>/dev/null
fi
fr() { $BIN -r "$FPCAP" -C "$@" 2>/dev/null; }
# without -A the fragments stay as IP-FRAG records
n=$(fr -B 0 | grep -c 'IP-FRAG' || true)
if [ "$n" = "3" ]; then
    pass=$((pass+1)); printf 'ok   %-52s %s\n' "fragments shown as IP-FRAG without -A" "$n"
else
    fail=$((fail+1)); printf 'FAIL %-52s want 3 got %s\n' "fragments shown as IP-FRAG without -A" "$n"
fi
# with -A the IPv4 datagram reassembles into a full UDP record
if fr -A -B 0 | grep -qF '40000 -> 192.0.2.2:40001'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "-A reassembles IPv4 UDP fragment"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "-A reassembles IPv4 UDP fragment"
fi
# and the IPv6 datagram too
if fr -A -B 0 | grep -qF '50000 -> [2001:db8::2]:50001'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "-A reassembles IPv6 UDP fragment"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "-A reassembles IPv6 UDP fragment"
fi
# the reassembled payload contains bytes from two different fragments
if fr -A -B 200 | grep -qF '12345678ABCDEFGH'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "-A stitches payload across fragments"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "-A stitches payload across fragments"
fi
# statistics report the reassembly counters
if $BIN -r "$FPCAP" -C -A 2>&1 >/dev/null | grep -qF 'reassembled'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "-A reports reassembly stats"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "-A reports reassembly stats"
fi
# a lone fragment must NOT be reported as a reassembled datagram
# (the "reassembled" marker only appears on completed datagrams)
if fr -A -n 1 -B 0 | grep -qF 'reassembled'; then
    fail=$((fail+1)); printf 'FAIL %-52s\n' "-A leaves incomplete datagram alone"
else
    pass=$((pass+1)); printf 'ok   %-52s\n' "-A leaves incomplete datagram alone"
fi

echo "== QUIC / HTTP3 =="
QPCAP=${QPCAP:-tests/quic.pcap}
if [ ! -f "$QPCAP" ]; then
    python3 tests/gen_quic.py "$QPCAP" 2>/dev/null
fi
qq() { $BIN -r "$QPCAP" -C "$@" 2>/dev/null; }
if qq -B 0 | grep -qF 'QUIC v1 initial'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "QUIC Initial detected"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "QUIC Initial detected"
fi
if qq -B 0 | grep -qF 'SNI=quic.example.test'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "QUIC SNI from ClientHello"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "QUIC SNI from ClientHello"
fi
if qq -B 0 | grep -qF 'version negotiation'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "QUIC version negotiation"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "QUIC version negotiation"
fi
if qq -o json -B 0 | grep -qF '"quic.version":"v1"'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "QUIC fields in JSON"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "QUIC fields in JSON"
fi

echo "== TLS certificate extraction =="
TPCAP=${TPCAP:-tests/tls.pcap}
if [ ! -f "$TPCAP" ]; then
    python3 tests/gen_tls.py "$TPCAP" 2>/dev/null
fi
tt() { $BIN -r "$TPCAP" -C "$@" 2>/dev/null; }
if tt -B 0 | grep -qF 'CN=www.example.test'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TLS cert subject CN"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TLS cert subject CN"
fi
if tt -B 0 | grep -qF 'issuer=Test Issuer CA'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TLS cert issuer CN"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TLS cert issuer CN"
fi
if tt -B 0 | grep -qF 'SAN=www.example.test,api.example.test'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TLS cert subjectAltName"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TLS cert subjectAltName"
fi
if tt -o json -B 0 | grep -qF '"tls.cert.valid":"2024-01-01..2034-01-01"'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TLS cert validity dates in JSON"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TLS cert validity dates in JSON"
fi
if tt -o json -B 0 | grep -qF '"tls.cert.chain":1'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TLS cert chain count in JSON"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TLS cert chain count in JSON"
fi
# JA3 fingerprint must match the value the generator computed independently
want_ja3=$(python3 tests/gen_tls.py "$TPCAP" 2>/dev/null | sed -n 1p)
got_ja3=$(tt -o json -B 0 | grep -o '"tls.ja3":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)
if [ -n "$want_ja3" ] && [ "$got_ja3" = "$want_ja3" ]; then
    pass=$((pass+1)); printf 'ok   %-52s %s\n' "JA3 fingerprint matches" "$got_ja3"
else
    fail=$((fail+1)); printf 'FAIL %-52s want %s got %s\n' "JA3 fingerprint matches" "$want_ja3" "$got_ja3"
fi
# JA4 fingerprint must match the value the generator computed independently
want_ja4=$(python3 tests/gen_tls.py "$TPCAP" 2>/dev/null | sed -n 2p)
got_ja4=$(tt -o json -B 0 | grep -o '"tls.ja4":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -n "$want_ja4" ] && [ "$got_ja4" = "$want_ja4" ]; then
    pass=$((pass+1)); printf 'ok   %-52s %s\n' "JA4 fingerprint matches" "$got_ja4"
else
    fail=$((fail+1)); printf 'FAIL %-52s want %s got %s\n' "JA4 fingerprint matches" "$want_ja4" "$got_ja4"
fi
if tt -B 0 | grep -qF 'SNI=ja3.example.test'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "ClientHello SNI"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "ClientHello SNI"
fi
if tt -o json -B 0 | grep -qF '"tls.ech":true'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "ECH extension flagged"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "ECH extension flagged"
fi
if tt -B 0 | grep -qF 'POST /dns-query' && tt -B 0 | grep -qF 'DoH'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "DNS-over-HTTPS detected"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "DNS-over-HTTPS detected"
fi
if tt -B 0 | grep -qF 'DoT'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "DNS-over-TLS detected"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "DNS-over-TLS detected"
fi

echo "== HTTP/2 frame + HPACK =="
H2PCAP=${H2PCAP:-tests/h2.pcap}
if [ ! -f "$H2PCAP" ]; then
    python3 tests/gen_h2.py "$H2PCAP" 2>/dev/null
fi
h2() { $BIN -r "$H2PCAP" -C "$@" 2>/dev/null; }
if h2 -B 0 | grep -qF 'HTTP/2 preface'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "HTTP/2 connection preface"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "HTTP/2 connection preface"
fi
if h2 -B 0 | grep -qF 'GET h2.example.test/api/v1/items'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "HPACK :method/:authority/:path"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "HPACK :method/:authority/:path"
fi
if h2 -o json -B 0 | grep -qF '"h2.type":"HEADERS"'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "HTTP/2 frame type in JSON"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "HTTP/2 frame type in JSON"
fi
if h2 -o json -B 0 | grep -qF '"h2.ua":"curl/8.0"'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "HPACK literal header no-index"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "HPACK literal header no-index"
fi

echo "== flow metrics: UDP flows + TCP RTT/retrans/ooo/zero-window =="
MPCAP=${MPCAP:-tests/metrics.pcap}
if [ ! -f "$MPCAP" ]; then
    python3 tests/gen_metrics.py "$MPCAP" 2>/dev/null
fi
mm() { $BIN -r "$MPCAP" -C -Y -B 0 2>&1; }
if mm | grep -qE '\[rtt=0\.2ms'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TCP RTT measured from ACK"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TCP RTT measured from ACK"
fi
if mm | grep -qE 'retrans=1([^0-9]|$)'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TCP retransmit counted"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TCP retransmit counted"
fi
if mm | grep -qE 'ooo=2([^0-9]|$)'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TCP out-of-order counted"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TCP out-of-order counted"
fi
if mm | grep -qE 'zerowin'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TCP zero-window flagged"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TCP zero-window flagged"
fi
if mm | grep -qF 'udp flows:'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "UDP flows listed"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "UDP flows listed"
fi
if mm | grep -qE '192\.0\.2\.10:53000.*1/1 dgram'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "UDP flow datagram counts"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "UDP flow datagram counts"
fi

echo "== structured protos: SMB2 / RDP / LDAP / Kerberos =="
PPCAP=${PPCAP:-tests/proto.pcap}
if [ ! -f "$PPCAP" ]; then
    python3 tests/gen_proto.py "$PPCAP" 2>/dev/null
fi
pp() { $BIN -r "$PPCAP" -C -K "$@" 2>/dev/null; }
if pp -B 0 | grep -qF 'user=CORP\alice'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "SMB2 NTLMSSP domain/user"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "SMB2 NTLMSSP domain/user"
fi
if pp -B 0 | grep -qF 'SMB2 SESSION_SETUP'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "SMB2 command named"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "SMB2 command named"
fi
if pp -B 0 | grep -qF 'RDP cookie user=bob'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "RDP mstshash cookie"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "RDP mstshash cookie"
fi
if pp -B 0 | grep -qF 'dn=cn=carol,dc=example,dc=test'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "LDAP bind DN"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "LDAP bind DN"
fi
if pp -B 0 | grep -qF 'Kerberos realm user=EXAMPLE.TEST'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "Kerberos realm"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "Kerberos realm"
fi
if pp -o json -B 0 | grep -qF '"proto":"smb2"' && pp -o json -B 0 | grep -qF '"proto":"kerberos"'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "proto ids in JSON"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "proto ids in JSON"
fi

echo "== defensive anomaly detection (-D) =="
DCAP=${DCAP:-tests/defense.pcap}
if [ ! -f "$DCAP" ]; then
    python3 tests/gen_defense.py "$DCAP" 2>/dev/null
fi
dcout=$($BIN -r "$DCAP" -D -C -q 2>&1)
dcheck() {  # name, needle
    if printf '%s' "$dcout" | grep -qF "$2"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "$1"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "$1"
    fi
}
dcheck "ARP spoof detected"        "ARP SPOOF suspected"
dcheck "ARP over-claim detected"   "ARP over-claim"
dcheck "ICMPv6 NA spoof detected"  "ICMPv6 NA spoof suspected"
dcheck "rogue DHCP detected"       "ROGUE DHCP suspected"
dcheck "name poisoning detected"   "NAME POISONING suspected"
dcheck "WPAD takeover detected"    "WPAD answer"
dcheck "DTP frame detected"        "DTP frame"
dcheck "QinQ double-tag detected"  "double VLAN tag"
dcheck "QinQ reports inner tag"    "inner tag 200"
dcheck "-D stats summary"          "anomalies :"
# -D off must stay silent
if $BIN -r "$DCAP" -C -q 2>&1 | grep -qF "suspected"; then
    fail=$((fail+1)); printf 'FAIL %-52s\n' "-D off is silent"
else
    pass=$((pass+1)); printf 'ok   %-52s\n' "-D off is silent"
fi
if $BIN --help 2>&1 | grep -qF -- "-D"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists -D"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists -D"
fi

echo "== 802.11 / radiotap parsing =="
WCAP=${WCAP:-tests/wlan.pcap}
if [ ! -f "$WCAP" ]; then
    python3 tests/gen_wlan.py "$WCAP" 2>/dev/null
fi
wout=$($BIN -r "$WCAP" -C -D 2>&1)
wcheck() {  # name, needle
    if printf '%s' "$wout" | grep -qF "$2"; then
        pass=$((pass+1)); printf 'ok   %-52s\n' "$1"
    else
        fail=$((fail+1)); printf 'FAIL %-52s\n' "$1"
    fi
}
wcheck "radiotap linktype accepted" "BEACON"
wcheck "beacon SSID decoded"        "ssid=HomeNet"
wcheck "beacon channel decoded"     "ch=1"
wcheck "probe request decoded"      "PROBE-REQ"
wcheck "probe response decoded"     "PROBE-RESP"
wcheck "deauth frame decoded"       "DEAUTH"
wcheck "control CTS frame decoded"  "ctrl"
wcheck "control ACK frame decoded"  "aa:bb:cc:11:22:33"
wcheck "multi-word radiotap chan"   "ch=1"
wcheck "evil-twin rogue AP"         "ROGUE AP suspected"
wcheck "deauth flood detected"      "802.11 DEAUTH FLOOD suspected"
if $BIN -r "$WCAP" -C -o json 2>&1 | grep -qF '"wlan.bssid"'; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "wlan fields in JSON"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "wlan fields in JSON"
fi

echo "== pcapng + -w rotation + --follow-out =="
TMPD=$(mktemp -d)
# pcapng round-trip: write, then read back and compare packet count
$BIN -r "$PCAP" -C -w "$TMPD/out.pcapng" >/dev/null 2>&1
if [ -s "$TMPD/out.pcapng" ]; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "pcapng written"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "pcapng written"
fi
if head -c 4 "$TMPD/out.pcapng" | od -An -tx1 | grep -q "0a 0d 0d 0a"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "pcapng magic correct"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "pcapng magic correct"
fi
n=$($BIN -r "$TMPD/out.pcapng" -C -q -B 0 2>/dev/null | grep -cE "^[0-9]")
if [ "$n" = "23" ]; then
    pass=$((pass+1)); printf 'ok   %-52s %s\n' "pcapng reads back" "$n"
else
    fail=$((fail+1)); printf 'FAIL %-52s want 23 got %s\n' "pcapng reads back" "$n"
fi
# timestamps must round-trip exactly (first packet 17:13:20.000000)
has_from "$TMPD/out.pcapng" "pcapng preserves timestamps" "17:13:20.000000" -q -B 0
# rotation
$BIN -r "$PCAP" -C -w "$TMPD/rot.pcap" --rotate-secs 5 >/dev/null 2>&1
nr=$(ls "$TMPD"/rot*.pcap 2>/dev/null | wc -l | tr -d ' ')
if [ "$nr" -ge 4 ]; then
    pass=$((pass+1)); printf 'ok   %-52s %s files\n' "--rotate-secs splits output" "$nr"
else
    fail=$((fail+1)); printf 'FAIL %-52s want >=4 got %s\n' "--rotate-secs splits output" "$nr"
fi
tot=0
for f in "$TMPD"/rot*.pcap; do
    c=$($BIN -r "$f" -C -q -B 0 2>/dev/null | grep -cE "^[0-9]")
    tot=$((tot+c))
done
if [ "$tot" = "23" ]; then
    pass=$((pass+1)); printf 'ok   %-52s %s\n' "rotation keeps every packet" "$tot"
else
    fail=$((fail+1)); printf 'FAIL %-52s want 23 got %s\n' "rotation keeps every packet" "$tot"
fi
# --follow-out produces a reopenable pcap with the reassembled stream
$BIN -r "$PCAP" -C -T 0 --follow-out "$TMPD/follow.pcap" >/dev/null 2>&1
if [ -s "$TMPD/follow.pcap" ] && $BIN -r "$TMPD/follow.pcap" -C -B 0 -P http 2>/dev/null | grep -qF "GET / HTTP/1.1"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--follow-out exports reassembled stream"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--follow-out exports reassembled stream"
fi
rm -rf "$TMPD"

echo "== active tools (flag plumbing, no transmit without root) =="
if $BIN --help 2>&1 | grep -qF -- "--arp-poison"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists --arp-poison"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists --arp-poison"
fi
if $BIN --help 2>&1 | grep -qF -- "--syn-scan"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists --syn-scan"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists --syn-scan"
fi
if $BIN --help 2>&1 | grep -qF -- "--dhcp-starve"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists --dhcp-starve"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists --dhcp-starve"
fi
if $BIN --help 2>&1 | grep -qF -- "--banner-grab"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists --banner-grab"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists --banner-grab"
fi
if $BIN --help 2>&1 | grep -qF -- "--vlan-hop"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists --vlan-hop"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists --vlan-hop"
fi
if $BIN --help 2>&1 | grep -qF -- "--bench"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists --bench"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists --bench"
fi
# decode benchmark: reports a rate for the sample pcap
if $BIN -r "$PCAP" --bench 200 2>/dev/null | grep -qE "packets/sec"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--bench reports decode throughput"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--bench reports decode throughput"
fi
# --bench with no -r must fail cleanly
if $BIN --bench 100 2>&1 | grep -qF "needs an input pcap"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--bench without -r errors cleanly"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--bench without -r errors cleanly"
fi
# banner grab against a local listener that greets first (no root needed)
BG_PORT=25711
python3 -c "
import socket,threading,time
def serve(p,g):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('127.0.0.1',p)); s.listen(1); s.settimeout(6)
    try:
        c,_=s.accept(); c.sendall(g); time.sleep(0.4); c.close()
    except Exception: pass
    s.close()
threading.Thread(target=serve,args=($BG_PORT,b'SSH-2.0-OpenSSH_test\r\n'),daemon=True).start()
time.sleep(6)
" &
sleep 0.4
if $BIN --banner-grab 127.0.0.1:$BG_PORT --banner-timeout 1000 2>/dev/null | grep -qF "SSH-2.0-OpenSSH_test"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--banner-grab reads a service banner"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--banner-grab reads a service banner"
fi
wait 2>/dev/null
# vlan-hop without root must fail cleanly (socket EPERM), not crash
if $BIN --vlan-hop lo:1:1 2>&1 | grep -qF "root"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--vlan-hop needs root (clean error)"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--vlan-hop needs root (clean error)"
fi
# 802.11 injection flags: help + clean argument errors (no radio needed)
if $BIN --help 2>&1 | grep -qF -- "--deauth"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists --deauth"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists --deauth"
fi
if $BIN --help 2>&1 | grep -qF -- "--beacon-flood"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists --beacon-flood"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists --beacon-flood"
fi
if $BIN --deauth badmac 2>&1 | grep -qF "needs <bssid>"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--deauth rejects a bad BSSID"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--deauth rejects a bad BSSID"
fi
if $BIN --deauth aa:bb:cc:dd:ee:ff 2>&1 | grep -qF "needs -i"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--deauth needs -i (clean error)"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--deauth needs -i (clean error)"
fi
if $BIN --beacon-flood SSID 2>&1 | grep -qF "needs -i"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--beacon-flood needs -i (clean error)"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--beacon-flood needs -i (clean error)"
fi
# without root the socket must fail cleanly, not crash
if $BIN --deauth aa:bb:cc:dd:ee:ff -i lo 2>&1 | grep -qF "root"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--deauth needs root (clean error)"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--deauth needs root (clean error)"
fi

echo "== config file --save-config / --load-config =="
RCDIR=$(mktemp -d)
rc="$RCDIR/rc"
if HOME="$RCDIR" $BIN --save-config -K -A -p 443 >/dev/null 2>&1 && \
   [ -f "$RCDIR/.ch1m3rarc" ]; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--save-config writes ~/.ch1m3rarc"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--save-config writes ~/.ch1m3rarc"
fi
if HOME="$RCDIR" $BIN -r "$PCAP" --load-config - -C -q 2>&1 | grep -qF "port=443"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--load-config applies saved filter"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--load-config applies saved filter"
fi
printf 'port = 443\n' > "$rc"
if $BIN -r "$PCAP" --load-config "$rc" -p 22 -C 2>&1 | grep -qF "port=22"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "CLI flag overrides --load-config"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "CLI flag overrides --load-config"
fi
if $BIN --load-config /no/such/rcfile 2>&1 | grep -qF "cannot read"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--load-config missing file errors"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--load-config missing file errors"
fi
if $BIN --help 2>&1 | grep -qF -- "--save-config"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "--help lists config flags"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--help lists config flags"
fi
rm -rf "$RCDIR"
# a bad --syn-scan target gives a clear error and a non-zero exit
if $BIN -i lo --syn-scan not.an.ip >/dev/null 2>&1; then
    fail=$((fail+1)); printf 'FAIL %-52s\n' "--syn-scan rejects bad host"
else
    pass=$((pass+1)); printf 'ok   %-52s\n' "--syn-scan rejects bad host"
fi

echo "== interactive TUI (-U) =="
# The TUI needs a tty, so drive it through a pty and check it starts, toggles
# stop/start/render, and exits cleanly with status 0.
if command -v python3 >/dev/null 2>&1; then
tui_out=$(python3 - "$BIN" "$PCAP" <<'PY' 2>&1
import os, pty, time, select, sys, fcntl, termios, struct
binp, pcap = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.execvp(binp, [binp, "-r", pcap, "-U", "-O", "-Y", "-N", "-K"])
    os._exit(1)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))
def drain(t=0.3):
    o = b""; end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try: x = os.read(fd, 65536)
            except OSError: break
            if not x: break
            o += x
    return o
buf = drain(1.5)
# detail view (Enter), then navigate + panes
os.write(fd, b"j"); buf += drain(0.3)
os.write(fd, b"\r"); buf += drain(0.4)     # detail on
os.write(fd, b"\r"); buf += drain(0.3)     # detail off
for k in (b"k", b"g", b"G", b"x", b"c", b"s", b"f", b"p", b"p", b"p", b"p"):
    os.write(fd, k); buf += drain(0.2)
# exercise the ':' live command prompt
for k in (b":", b"proto icmp", b"\r", b":", b"filter", b"\r"):
    os.write(fd, k); buf += drain(0.25)
# exercise search ('/')
for k in (b"/", b"443", b"\r"):
    os.write(fd, k); buf += drain(0.3)
os.write(fd, b"q")
buf += drain(0.4)
try: os.close(fd)
except OSError: pass
_, status = os.waitpid(pid, 0)
sys.stdout.write(buf.decode("utf-8", "replace"))
sys.exit(0 if (status >> 8) == 0 else (status >> 8 or 1))
PY
)
if printf '%s' "$tui_out" | grep -qF "ch1m3ra 2.0" && \
   printf '%s' "$tui_out" | grep -qE "RUNNING|STOPPED"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI renders header + state"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI renders header + state"
fi
if printf '%s' "$tui_out" | grep -qF "quit"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI key hints footer"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI key hints footer"
fi
if printf '%s' "$tui_out" | grep -qF "8.8.8.8:443"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI logs decoded packets"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI logs decoded packets"
fi
if printf '%s' "$tui_out" | grep -qF "hosts (passive OS fingerprint)"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI hosts pane renders"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI hosts pane renders"
fi
if printf '%s' "$tui_out" | grep -qF "top conversations (by bytes)"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI talkers pane renders"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI talkers pane renders"
fi
if printf '%s' "$tui_out" | grep -qF "hits: creds/tokens/banners/os"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI hits pane renders"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI hits pane renders"
fi
if printf '%s' "$tui_out" | grep -qF "proto=icmp" && \
   printf '%s' "$tui_out" | grep -qF "filters cleared"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI ':' prompt sets/clears filters"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI ':' prompt sets/clears filters"
fi
if printf '%s' "$tui_out" | grep -qF "pps "; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI per-second sparkline renders"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI per-second sparkline renders"
fi
if printf '%s' "$tui_out" | grep -qF "SUMMARY"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI packet column header"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI packet column header"
fi
if printf '%s' "$tui_out" | grep -qF "match(es)"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI / search reports matches"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI / search reports matches"
fi
if printf '%s' "$tui_out" | grep -qF "L4"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI Enter opens the detail pane"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI Enter opens the detail pane"
fi
if printf '%s' "$tui_out" | grep -qF "malformed" && \
   printf '%s' "$tui_out" | grep -qF "captured"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI dashboard metric row"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI dashboard metric row"
fi
if printf '%s' "$tui_out" | grep -qF "PROTOCOL MIX" && \
   printf '%s' "$tui_out" | grep -qF "TOP TALKERS"; then
    pass=$((pass+1)); printf 'ok   %-52s\n' "TUI dashboard side panel"
else
    fail=$((fail+1)); printf 'FAIL %-52s\n' "TUI dashboard side panel"
fi
else
    printf 'skip %-52s (no python3)\n' "TUI interactive tests"
fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
