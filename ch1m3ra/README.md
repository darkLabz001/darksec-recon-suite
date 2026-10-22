# ch1m3ra

> **ch1m3ra** — a cyberpunk-flavoured packet sniffer.

A packet sniffer written from scratch in C — **no libpcap, no scapy, no Wireshark**.
Raw `AF_PACKET` socket, every byte parsed by hand. Live capture, kernel BPF
filtering, zero-copy ring capture, IPv4/IPv6 fragment reassembly, TCP/UDP flow
tracking with metrics, TLS/QUIC/HTTP2 decode + JA3/JA4 fingerprinting, JSON/CSV/
ndjson/Zeek output, pcap **and pcapng** read/write with rotation, an interactive
terminal TUI (`-U`), passive credential/OS/name harvesting, and a set of **active
offensive tools** (ARP poisoning, SYN scanning, banner grabbing, VLAN-hopping
injection, DHCP starvation, raw replay).

## What it decodes

| Layer | Details |
|---|---|
| Ethernet | src/dst MAC, ethertype, 802.3 length frames, 802.1Q/802.1ad VLAN tags (QinQ flagged) |
| **802.11 (`-D`)** | radiotap (multi-word bitmap channel) + mgmt frames: beacon/probe req-resp (SSID, BSSID, channel, privacy), deauth/disassoc, and control (RTS/CTS/ACK); live monitor-vif auto-detect |
| ARP | request/reply, sender/target MAC+IP, non-standard variants flagged |
| IPv4 | version/IHL, TOS, total length, ID, DF/MF, fragment offset, TTL, protocol, **header checksum verification** |
| IPv6 | traffic class/flow, hop limit, **extension-header chain** (hop-by-hop, routing, fragment, AH, dst-opts) |
| **IP reassembly (`-A`)** | IPv4/IPv6 **fragment reassembly**; once a datagram is complete it is decoded as a whole (TCP/UDP/app layer), incomplete fragments stay shown as `IP-FRAG` |
| TCP | ports, seq/ack, data offset, **all 9 flags**, window, urgent pointer, **option parsing** (MSS, WS, SACK, Timestamp, TO, MPTCP, Fast Open), **pseudo-header checksum verification** |
| UDP | ports, length, **pseudo-header checksum verification** (incl. detection of illegal zero checksums) |
| ICMP / ICMPv6 | type/code names, echo id/seq, checksum verification |
| DNS | query/response, opcode, rcode, question name + type, first answer (A/AAAA/CNAME/MX/NS/PTR/SRV/TXT), name-compression pointers; also mDNS (5353) and LLMNR (5355) |
| TLS | record type/version; **ClientHello SNI, ALPN, supported versions**; ServerHello cipher; alert level+description; app-data sizes; **X.509 certificate extraction** (subject/issuer/validity/SAN, DER walker); **JA3** and **JA4** client fingerprints (own MD5/SHA256) |
| QUIC / HTTP3 | long/short header, version, packet type, DCID/SCID, **Initial decryption + SNI** (own AES-128-GCM/HKDF) |
| HTTP/1.x | request method/URI/version, status line + code, Host header, Content-Length, Server |
| HTTP/2 | connection preface, **frame types** (SETTINGS/HEADERS/DATA/WINDOW_UPDATE/RST/GOAWAY…), **HPACK static-table header decode** (`:method`, `:path`, `:authority`, `user-agent`, …) |
| DoH / DoT | detects DNS-over-HTTPS (port 443 + `application/dns-message`) and DNS-over-TLS (port 853) |
| SMB2 / RDP / LDAP / Kerberos | structured decoders feeding `-K`/`-N` (SMB2 commands, RDP `mstshash` cookie, LDAP bind DN, Kerberos realm) |
| Payload | hex + ASCII dump of everything above L4 (and raw payloads of unknown protocols) |

Bad checksums are flagged `BAD`, truncated/corrupt frames are flagged with `!` and a reason.

## Build

```sh
make            # multi-module build, cc -std=gnu11 -O2 -Wall -Wextra
make test       # generate the test pcaps, decode one, run 174 assertions
make asan       # ASan + UBSan build for the suite
make gate       # replay the frozen behavior baseline and show the diff
make netns      # live-capture + injection harness (needs root; skips otherwise)
make wlan       # live 802.11 injection test (needs root + monitor-capable radio)
```

Zero warnings with `-Wall -Wextra`; also verified clean under
`-fsanitize=address,undefined`.

## Run

Live capture needs root (or `cap_net_raw`):

```sh
sudo ./ch1m3ra -i wlan0                 # capture on one interface
sudo ./ch1m3ra                          # all interfaces
sudo ./ch1m3ra -i eth0 -Z               # zero-copy ring capture (mmap, no recvfrom)
sudo ./ch1m3ra -i wlan0 -U              # interactive TUI (start/stop dashboard)
sudo ./ch1m3ra -i wlan0 -K -O -U        # creds + OS fingerprint, in the TUI
sudo setcap cap_net_raw,cap_net_admin+ep ./ch1m3ra   # ...then no sudo needed
./ch1m3ra -l                            # list interfaces (no root needed)
```

Offline (no root needed):

```sh
./ch1m3ra -r capture.pcap               # read a pcap file
./ch1m3ra -r in.pcap -P tcp -w out.pcap # filter a pcap into a new one
./ch1m3ra -r in.pcap -w out.pcapng      # write pcapng (by extension)
```

## Filters

```sh
-P tcp              # protocol: tcp udp icmp icmpv6 arp ip ipv6 dns tls http frag ...
-H example.com      # src/dst address substring, ARP sender/target, or a decoded
                    # DNS question name / TLS SNI / HTTP Host
-p 443              # src or dst port
-F 'tcp and port 443'   # kernel BPF filter (see below)
-n 100              # stop after 100 packets
-B 512              # dump up to 512 payload bytes (0 = none)
-q                  # one line per packet, no details/payload
-T 3                # follow TCP stream 3 as reassembled text (0 = every stream)
-o json             # output format: text, json, ndjson, csv, zeek
-e                  # timestamps relative to the first packet
-M                  # no promiscuous mode
-C                  # no colors
-s 256              # snapshot length
-A                  # reassemble IPv4/IPv6 fragments, decode the whole datagram
-D                  # defensive anomaly detection (ARP/ND spoof, rogue DHCP/AP,
                    # mDNS/LLMNR/WPAD poisoning, VLAN double-tag/DTP, deauth flood)
-Z                  # zero-copy capture via PACKET_RX_RING (live only)
-U                  # interactive TUI: live dashboard with start/stop
-K                  # harvest cleartext credentials/tokens/banners
-k <file>           # like -K, and append each hit to <file>
-O                  # passive OS fingerprinting (TTL + TCP options, p0f-style)
-Y                  # top-talkers: rank hosts/conversations by bytes
-N                  # learn hostnames from mDNS/LLMNR/NBNS/DNS
-E                  # thorough parsing for -F (VLAN/ext-header aware, userspace)
-w <file>           # write packets to a pcap/pcapng (.pcapng => pcapng)
-W <MB>             # with -w: rotate to file-NNNNN after <MB> megabytes
--rotate-secs <n>   # with -w: rotate every <n> seconds
--follow-out <file> # with -T: export the followed stream's reassembled
                    # payloads as a pcap you can reopen in Wireshark
```

Filters combine (AND). Ctrl-C prints a stats summary
(total / shown / filtered / malformed + per-protocol, app, and per-stream counts).

### Kernel BPF filter (`-F`)

`-F` compiles a tcpdump-like expression to classic BPF and attaches it with
`SO_ATTACH_FILTER`, so **the kernel drops non-matching packets before they reach
userspace** — cheaper than filtering after the copy. The same program runs
through a small built-in interpreter in `-r` mode, so `-F` works offline too.

Supported grammar: `tcp udp icmp icmp6 icmpv6 arp ip ip4 ipv4 ip6 ipv6 dns`,
`port N`, `src|dst port N`, `host A.B.C.D`, `host 2001:db8::1`, `src|dst host …`,
`and`/`&&`, `or`/`||`, `not`/`!`, parentheses, implicit `and` between terms.

Extended grammar: `vlan`, `ether [src|dst] host <mac>`, `greater N` / `less N`
(packet length), `len > N` / `len < N`, and `tcp[tcpflags]` with an optional
`& FLAGS` mask (`fin syn rst psh ack urg ece cwr`, `tcp-syn`/`tcp-ack`/… aliases,
or a number) plus an optional `= N` / `!= 0` comparison.

```sh
sudo ./ch1m3ra -i eth0 -F 'tcp and port 443'
sudo ./ch1m3ra -i eth0 -F 'not (arp or icmp or icmp6) and not port 22'
sudo ./ch1m3ra -i eth0 -F 'vlan and greater 100'
sudo ./ch1m3ra -i eth0 -F 'tcp[tcpflags] & tcp-syn != 0'
./ch1m3ra -r capture.pcap -F 'udp and port 53'
./ch1m3ra -r capture.pcap -F 'ether host aa:bb:cc:dd:ee:ff'
```

Results are cross-checked against `tcpdump` in the test suite. Unlike tcpdump's
fixed-offset `tcp[...]` primitive, the `tcp[tcpflags]` test here is evaluated for
**both IPv4 and IPv6** (IPv6 without extension headers), so it also catches SYNs
on IPv6 flows.

Limitations (fast-path trade-off, both live and offline): offsets assume plain
Ethernet frames **without VLAN tags**, and TCP/UDP ports are read at the fixed
IPv4/IPv6 header offsets — i.e. **IPv6 extension headers shift them out of view**
(`host` tests still work, since addresses sit at fixed offsets). Use `-P`/`-p`
(userspace, fully parsed) when you need VLAN/ext-header awareness, or add `-E` —
that runs the same expression through the **userspace interpreter** even live, so
the filter sees fully parsed frames (VLAN tags and IPv6 extension headers
included) at the cost of copying every frame up first.

### Zero-copy ring (`-Z`)

`-Z` switches live capture from `recvfrom` copies to a `TPACKET_V2`
`PACKET_RX_RING` mapped with `mmap`; the decoder parses frames in place and each
frame is returned to the kernel only after it has been consumed. Frame/block
sizes are chosen so they tile the ring exactly. The final stats report
`PACKET_STATISTICS` drops when the ring overflowed. Falls back to `recvfrom`
with a warning if the ring cannot be set up.

## Interactive TUI (`-U`)

`-U` turns ch1m3ra into a full-screen dashboard. It is built from scratch
too — raw termios + ANSI escapes, no ncurses — and runs in the same process as
the capture, so stopping and starting is instant.

```sh
sudo ./ch1m3ra -i wlan0 -U          # live, starts stopped - press s
./ch1m3ra -r capture.pcap -U        # offline: autostarts and replays the file
```

Keys:

| key | action |
|-----|--------|
| `s` | start capture |
| `x` / space | stop capture |
| `j` / `k` | scroll the log down / up |
| `Ctrl-U` / `Ctrl-D`, `PgUp` / `PgDn` | scroll by half / full page |
| `g` / `G`, `Home` / `End` | jump to oldest / follow the tail |
| mouse wheel / ↑ ↓ | scroll the pane (SGR mouse + arrow keys) |
| `Enter` | toggle the **detail pane** for the selected row |
| `[` / `]` | scroll within the detail pane |
| `/` then text | **search** the log; `n` / `N` jump to the next / previous match |
| `p` | cycle pane: packets → hits → hosts → talkers |
| `r` | refresh the host/talker panes |
| `c` | clear the log |
| `f` | toggle follow-all-streams (reassembled payload) |
| `:` | open the live command prompt (see below) |
| `q` (or Ctrl-C) | quit |

The dashboard is a six-part grid. The **title row** carries the name and a
running/stopped light; the **metric row** shows captured / shown / filtered /
malformed packet counts (and the byte total on wide terminals); the **elite
row** shows elapsed time, average and current packet rate, a `⚑ hits` badge
plus cred/host counters for anything harvested, and a 48-second per-second
packet-rate **sparkline** (`pps N [bars]`); an active `-P`/`-H`/`-p` filter adds
a **filter line**; the last two rows are the **key hints** and a **status bar**
(interface, state, colour mode, follow mode). The body is a scrolling
one-line-per-packet log with a **column header**, a **colour per protocol**
(TCP green, UDP cyan, ICMP yellow, ARP blue, DNS/TLS/HTTP/QUIC and 802.11 their
own hues, malformed frames bold red, harvested secrets bold yellow) and a
**scrollbar** in the right-hand column showing the current position (`N/M`, plus
`SCROLLED`) in the header line.

On terminals at least 100 columns wide the packets view splits into two columns:
the log on the left and a **side panel** on the right with a protocol-mix
histogram, the top talkers, and a harvest summary. Narrower terminals (and the
detail pane) use the full width for the log.

Press `Enter` to open a **detail pane** below the log with a sectioned decode of
the selected packet — frame/L2/L3/L4, application layer (DNS/TLS/HTTP/QUIC/H2,
certs, JA3/JA4), any harvested credentials, and a payload hexdump. Press `/` to
**search** the log; matches are underlined and `n`/`N` step between them.

Press `p` to cycle four views: **packets**, **hits** (every credential, token,
cookie, banner and OS guess), **hosts** (passive OS fingerprint table) and
**talkers** (top conversations by bytes); the hint row lists the keys (and
compacts itself on narrow terminals). While stopped the dashboard keeps
refreshing, and the terminal is restored on exit or on a signal. `-U` needs a
tty on stdout; every other flag (`-P`, `-H`, `-p`, `-F`, `-T`, `-o`, `-K`,
`-O`, …) still applies inside the TUI. Colours follow `-C` / `NO_COLOR`
(reverse-video selection and underlined search matches are kept either way).

### Live command prompt (`:`)

Press `:` to retarget filtering and analysis without restarting:

```
p icmp            # set the -P protocol filter (p all to clear)
h 10.0.0.           # set the -H host filter
port 443          # set the -p port filter
n 100             # stop after 100 packets
harvest on|off    # toggle -K credential harvesting
finger on|off     # toggle -O OS fingerprinting
names on|off      # toggle -N name learning
reasm on|off      # toggle -A fragment reassembly
save              # write the current settings to ~/.ch1m3rarc
load [file]       # apply settings (default ~/.ch1m3rarc)
filter            # clear proto/host/port filters
help              # list the commands
```

### Config file (`--save-config` / `--load-config`)

Settings can be persisted to `~/.ch1m3rarc` (simple `key = value`, hand-editable)
and reapplied on the next run. `--load-config <file>` applies a file **before**
the other flags, so any explicit command-line flag wins; `-` or `auto` means
`~/.ch1m3rarc`. `--save-config` writes the current settings and exits.

```sh
./ch1m3ra -K -O -A -p 443 --save-config    # remember this setup
./ch1m3ra -i wlan0 --load-config -          # ...apply it here
```


## TCP / UDP flows (`-T`)

TCP flows are tracked in a 4096-slot open-addressed hash table keyed by the
canonicalised endpoint pair (both directions share one entry). Per direction the
ch1m3ra keeps the next expected sequence number and up to 8 out-of-order
segments; in-order data is emitted and forgotten, so memory stays bounded on
long captures. Sequence arithmetic uses signed 32-bit differences, so it
survives wraparound. `seq`/`ack`/flags are tracked and reassembly resets on SYN.

TCP health metrics are derived per stream and shown in the stats table:
**RTT** (SYN → SYN/ACK), **retransmissions**, **out-of-order** segments and
**zero-window** events. UDP "flows" are tracked alongside in a separate id space
(`u1`, `u2`, …) with per-direction datagram and byte counts; when any UDP flows
exist the summary reads `streams N (x tcp, y udp)`.

Packet lines show `#N` (or `uN` for UDP); the stats summary lists every flow
(`#N a <-> b`, per-direction bytes, packets, duration, state). To read a
conversation as text:

```sh
./ch1m3ra -r capture.pcap -q      # see which stream you want
./ch1m3ra -r capture.pcap -T 3    # follow stream 3
./ch1m3ra -r capture.pcap -T 0    # follow all streams
./ch1m3ra -r capture.pcap -T 0 --follow-out stream.pcap   # export it as a pcap
```

`--follow-out` writes each reassembled chunk as a synthetic Ethernet/IP/TCP
frame, so the followed conversation can be reopened in Wireshark (checksums are
left zero — the frames are payload carriers, not wire-accurate).

## Credential & token harvesting (`-K`, `-k`)

`-K` runs passive parsers over every cleartext payload and pulls out anything
sensitive that is sent in the clear. It never decrypts TLS; it only reads bytes
that were already plaintext (or, for TLS, the unencrypted metadata).

| Source | What is extracted |
|---|---|
| HTTP `Authorization: Basic` | username + password (base64-decoded) |
| HTTP `Authorization: Bearer` | the bearer token, and a decoded **JWT payload summary** |
| HTTP form / query bodies | `username=`/`user=`/`login=`/`email=` paired with `password=`/`pass=`/`pwd=` |
| HTTP `Set-Cookie` / `Cookie` | the session id (`name=value`) |
| FTP | `USER` / `PASS` |
| POP3 | `USER` / `PASS` |
| IMAP | `LOGIN` |
| SMTP | `AUTH` |
| Telnet | `login:` / `Password:` |
| SNMP v1/v2c | community string |
| SSH/SMTP/FTP/POP3/IMAP/MySQL/Telnet | server **banner** (service + version) |
| SMB2 | command/operation names, file share paths |
| RDP | `Cookie: mstshash=<user>` from the connection request |
| LDAP | bind DN (distinguished name) |
| Kerberos | realm / principal |

TLS captures are augmented with **certificate metadata** (subject, issuer,
validity, subjectAltName) parsed by a small DER walker, and every ClientHello
gets **JA3** and **JA4** fingerprints.

Hits are shown inline in text mode (`CRED`, `TOKN`, `JWT`, `COOK`, `BANR`), added
as JSON fields (`"cred":{…}`, `"token"`, `"jwt"`, `"cookie"`, `"banner"`,
`"service"`) and CSV columns (`user,pass,where,banner,os`), and collected in the
TUI hits pane. `-k <file>` also appends every hit to a timestamped log line.

```sh
sudo ./ch1m3ra -i wlan0 -K
sudo ./ch1m3ra -i wlan0 -K -O -U         # harvest + fingerprint in the TUI
sudo ./ch1m3ra -i wlan0 -k creds.log -q  # one line per packet + creds file
./ch1m3ra -r capture.pcap -K -o json | jq 'select(.cred)'
```

## Reconnaissance (`-O`, `-Y`, `-N`)

All three are passive — they only look at traffic you already see.

- **`-O` passive OS fingerprinting** — p0f-style guesses from each host's initial
  TTL plus its SYN's MSS and window scale, e.g. `Linux 5.x/6.x`, `Windows 10/11`,
  `macOS/iOS`, `network device (Cisco/embedded)`. The guess is attached to each
  packet (`OS` line / `"os"` field) and the stats print a per-host table with
  bytes, packets and activity duration.
- **`-Y` top-talkers** — ranks host conversations by bytes and prints the top 16
  as a `<a> <-> <b>  bytes  packets` table in the stats summary.
- **`-N` name harvest** — learns hostnames from mDNS (5353), LLMNR (5355) and DNS
  responses (A/AAAA) and prints a `name -> address` table.

```sh
sudo ./ch1m3ra -i eth0 -O -Y -N
./ch1m3ra -r capture.pcap -O -Y -N -q     # tables go to stderr
```

## Defensive anomaly detection (`-D`)

`-D` turns on a set of passive detectors for the classic layer-2/3 attacks a
sniffer is uniquely placed to notice. Nothing is transmitted; each *distinct*
anomaly is printed once to stderr (so a long capture doesn't repeat itself) and
counted in the stats summary.

| detector | what it flags |
|---|---|
| ARP spoof | an IPv4 address whose MAC binding changes, or one MAC claiming an implausible number of addresses (an ARP-sweep / MITM tell) |
| ICMPv6 NA spoof | a Neighbor Advertisement that changes the MAC bound to an address |
| rogue DHCP | more than one DHCP server answering on the segment |
| name poisoning | a name (mDNS/LLMNR/NBNS) answered by two different hosts — the Responder.py signature — and WPAD takeover |
| VLAN / DTP | 802.1Q **double tagging** (QinQ) and Cisco **DTP** frames (VLAN-hop risk) |
| 802.11 rogue AP | the same SSID advertised by two different BSSIDs (evil twin) |
| 802.11 deauth flood | a burst of deauthentication/disassociation frames |

```sh
sudo ./ch1m3ra -i wlan0 -D              # watch the segment (and Wi-Fi, if seen)
./ch1m3ra -r capture.pcap -D -q         # offline: replay a capture through it
```

## 802.11 (Wi-Fi) decoding

Radiotap and raw-802.11 frames (pcap linktypes 127 / 105) are decoded: channel
from radiotap (handles multi-word present bitmaps), plus management frames —
beacon and probe response (SSID, BSSID, channel, privacy bit), probe request and
deauth/disassoc (with reason code) — and control frames (RTS/CTS/ACK, which have
short 10-byte headers). This works on offline captures without any monitor-mode
hardware, and on **live** monitor interfaces too: `-i <mon>` auto-detects the
link-layer type (ARPHRD 803/801), so a monitor vif is decoded as radiotap with no
extra flags.

To capture live Wi-Fi, put a supported adapter into monitor mode first:

```sh
sudo ip link set wlx00c0cab67b50 down
sudo iw dev wlx00c0cab67b50 interface add mon0 type monitor
sudo ip link set mon0 up
sudo iw dev mon0 set channel 6
sudo ./ch1m3ra -i mon0 -D               # live beacons / data / ctrl / deauth
```

```sh
./ch1m3ra -r wifi.pcap -D              # decode + rogue-AP / deauth-flood warnings
./ch1m3ra -r wifi.pcap -o json | jq 'select(.wlan.ssid) | {bssid:.wlan.bssid, ssid:.wlan.ssid}'
```

### 802.11 injection (`--deauth`, `--beacon-flood`)

Two active tools craft raw 802.11 frames (with a minimal radiotap header) and
inject them over a monitor vif — authorised testing only:

```sh
sudo ./ch1m3ra -i mon0 --deauth aa:bb:cc:dd:ee:ff              # deauth to broadcast
sudo ./ch1m3ra -i mon0 --deauth aa:bb:cc:dd:ee:ff,11:22:33:44:55:66,500
sudo ./ch1m3ra -i mon0 --beacon-flood "Free WiFi",1000         # fake-AP flood
```

`--deauth` takes `<bssid>[,<client>][,<count>]` (client defaults to broadcast,
count defaults to forever until Ctrl-C); `--beacon-flood` takes
`<ssid>[,<count>]` and emits beacons with a fresh random BSSID each time. Both
print a send-failure hint if the vif is not in monitor mode. A deauth burst is
detected by `-D` on the receiving side (see above).

## Active / offensive tools

These build Ethernet frames by hand and send them on an `AF_PACKET` socket. They
**transmit real packets**, so they require root (or `cap_net_raw`) *and* an
explicit flag, and you must only use them on networks you own or are authorised
to test. Long-running ones install a SIGINT handler that stops cleanly (ARP
poisoning also restores the caches it poisoned).

| flag | what it does |
|---|---|
| `--arp-poison <victim>,<gateway>[,<iface>]` | ARP-spoofs the pair to MITM their traffic; on Ctrl-C re-asserts the true MAC↔IP bindings |
| `--syn-scan <host>[:<ports>]` | half-open TCP port scan (`:22,80,443` or `:1-1024`); reports open/closed/filtered and RSTs half-open sockets |
| `--banner-grab <host>[:<ports>]` | full-connect probe: reads the first bytes each service sends (SSH/SMTP/FTP/IMAP…) or nudges HTTP with a `HEAD`; `--banner-timeout <ms>` sets the read timeout |
| `--vlan-hop <iface>:<outer>:<inner>` | sends 802.1ad QinQ double-tagged frames (S-tag `outer`, C-tag `inner`) to hop into another VLAN |
| `--dhcp-starve <iface>[:<count>]` | floods a DHCP server with DISCOVERs using random client MACs to exhaust the pool |
| `--deauth <bssid>[,<client>][,<count>]` | injects 802.11 deauthentication frames over a monitor vif (authorised testing only) |
| `--beacon-flood <ssid>[,<count>]` | floods the air with fake-AP beacons (random BSSIDs) over a monitor vif |
| `--replay <pcap>` | re-sends captured frames (optionally editing them first) |
| `--rewrite-src <ip>` | with `--replay`, replaces the source IPv4 address (and fixes the IP checksum) |
| `--bench <n>` | decodes the `-r` pcap `n` times through the full pipeline and reports packets/sec + ns/packet |

```sh
sudo ./ch1m3ra -i eth0 --arp-poison 192.168.1.5,192.168.1.1
sudo ./ch1m3ra -i eth0 --syn-scan 10.0.0.1:22,80,443
./ch1m3ra --banner-grab 10.0.0.1:22,80,8080
sudo ./ch1m3ra -i eth0 --vlan-hop eth0:1:100
sudo ./ch1m3ra -i eth0 --dhcp-starve eth0:256
sudo ./ch1m3ra -i mon0 --deauth aa:bb:cc:dd:ee:ff,11:22:33:44:55:66   # 802.11
sudo ./ch1m3ra -i mon0 --beacon-flood FreeWiFi,500                    # 802.11
sudo ./ch1m3ra -i eth0 --replay capture.pcap --rewrite-src 10.0.0.9
./ch1m3ra -r capture.pcap --bench 20000     # decode throughput benchmark
```

Run as a non-root user these fail fast with `socket(AF_PACKET): Operation not
permitted` and a hint to use root/`cap_net_raw`.

## Output formats (`-o`, `-e`)

| format | shape |
|---|---|
| `text` (default) | human-readable, multi-line per packet |
| `json` | one flat JSON object per packet (jq-friendly) |
| `ndjson` | JSON with a `"schema":1` field up front, one object per line |
| `csv` | header row plus one row per packet |
| `zeek` | TSV log with a Zeek-style `#fields`/`#types` header (`ch1m3ra` path) |

All keep stdout pure data (banner and stats go to stderr). `-e` adds a
`+seconds` column relative to the first printed packet.

```sh
./ch1m3ra -r capture.pcap -o json | jq -r 'select(.app=="dns") | .dns.qname'
./ch1m3ra -r capture.pcap -o json | jq 'select(.tls.sni) | {src, tls, ja3, ja4}'
./ch1m3ra -r capture.pcap -o ndjson | jq 'select(.schema==1)'
./ch1m3ra -r capture.pcap -o csv -e > packets.csv
./ch1m3ra -r capture.pcap -o zeek > ch1m3ra.log
```

## pcap / pcapng I/O

The reader auto-detects classic **pcap** (µs or ns magic, either byte order) and
**pcapng** (multiple sections, `if_tsresol`, `if_name`, little/big endian). The
writer picks the container from the `-w` extension (`.pcapng` ⇒ pcapng,
otherwise pcap) and emits a valid Section Header Block + Interface Description
Block + Enhanced Packet Blocks; output is verified against `tshark`/`capinfos`.

```sh
./ch1m3ra -r in.pcap  -w out.pcapng      # convert to pcapng
./ch1m3ra -r in.pcapng -P tcp -w out.pcap
./ch1m3ra -i eth0 -w cap.pcapng -W 100 --rotate-secs 3600   # size + time rotation
```

`-W <MB>` rotates to `cap-NNNNN.pcap(ng)` once the current file passes `<MB>`;
`--rotate-secs <n>` rotates on the packet timestamp advance (works offline too).
Every rotated file is a standalone, valid capture and no packet is lost across
the switch.

## Examples

```text
$ sudo ./ch1m3ra -i wlp4s0 -P tcp -p 443
17:13:22.000274 wlp4s0  #1 TCP  192.168.1.50:51344 -> 8.8.8.8:443(https)  len=74 ttl=64
        IPv4 ttl=64 id=0x1234 ip-csum=ok
        seq=1000 ack=0 win=64240 [SYN] csum=ok
        opts: MSS=1460, SACK-perm, TS=111111/0, NOP, WS=7
```

```text
$ ./ch1m3ra -r tests/sample.pcap -P tls
17:13:36.002192 file  #3 TCP  192.168.1.50:51346 -> 8.8.8.8:443(https)  len=155 ttl=64
        IPv4 ttl=64 id=0x1241 ip-csum=ok
        seq=7000 ack=8000 win=64240 [PSH, ACK] csum=ok
        TLS  ClientHello SNI=example.com ALPN=h2,http/1.1 vers=TLS1.3/TLS1.2
```

```text
$ ./ch1m3ra -r tests/sample.pcap -T 6
=== stream 6: 10.2.2.2:80 <-> 192.168.1.50:52000 ===
>>> 192.168.1.50:52000 -> 10.2.2.2:80
GET /reasm HTTP/1.1
Host: reasm.test

BODY!!
```

## Tests

`tests/gen_pcap.py` hand-builds 23 frames with correct checksums: ARP
request/reply, TCP SYN-with-options, TCP PSH/ACK with an HTTP request, TCP with
a *deliberately corrupted* checksum, DNS query **and response** (with a
compression pointer), ICMP echo pair, IPv6 TCP with a hop-by-hop header plus a
plain IPv6 TCP SYN, ICMPv6 echo, VLAN-tagged UDP, truncated IPv4, EAPOL, an IPv4
fragment, a bad IP checksum, **TLS ClientHello (SNI/ALPN/versions)**, **TLS
app-data**, an **HTTP response**, and a **3-segment TCP stream whose middle
segment arrives out of order**.

`tests/gen_creds.py` builds a second 7-frame capture that exercises every
credential harvester: HTTP Basic, an HTTP form POST, a `Set-Cookie`, a bearer
JWT, FTP `USER`/`PASS`, and an SSH banner.

`tests/check.sh` runs **174 assertions** across the captures (decoding, each app
decoder, stream reassembly, JSON/CSV/ndjson/Zeek validity via python, the `-F`
interpreter cross-checked against the userspace `-H` filter and against
`tcpdump`, `-K` credential extraction and its JSON/CSV/file outputs, the
`-O`/`-Y`/`-N` recon tables, `-E` parsed filtering, QUIC/HTTP2/TLS-cert/proto
decoders, `-D` defensive detections, 802.11/radiotap parsing, pcapng round-trip,
`-w` rotation and `--follow-out`, `--save-config`/`--load-config`, active-tool
flag plumbing (including a live `--banner-grab` against a local listener), and a
pty-driven smoke test of the `-U` TUI). `make test` runs the
decode dump plus the assertions.

`tests/gate.sh` (`make gate`) replays the exact invocation matrix that produced
the frozen `.baseline/ch1m3ra.out` and diffs it, so any unintended change to
pre-existing output is caught.

`tests/netns.sh` (`make netns`) builds a two-namespace veth pair and exercises
the **live** path for real: raw `AF_PACKET` capture of injected ICMP, `--replay`,
`--syn-scan`, `--arp-poison`, `--banner-grab`, `--vlan-hop` and the `-Z` ring
batch drain (9 checks). It
needs root and **skips cleanly** (exit 0) when run unprivileged or when netns is
unavailable.

`tests/wlan_live.sh` (`make wlan`) puts a monitor-capable radio into monitor mode
and exercises the **802.11 injection** path: it injects beacons and deauth frames
with `--beacon-flood`/`--deauth`, captures the air on the same vif, and checks the
frames round-trip and that `-D` flags the deauth flood. It needs root plus a
wireless device, and **skips cleanly** otherwise (it also skips if the driver does
not reflect injected TX back into the monitor).

`make fuzz` builds a structure-aware fuzz target (`fuzz.c`) that feeds mutated
frames straight into the decode pipeline under ASan+UBSan; it also builds under
libFuzzer (`-DFUZZ_LIBFUZZER`).

## Layout

ch1m3ra is split into one shared header plus focused modules:

- `ch1m3ra.h` — shared types (`cfg_t`, `packet_t`, `stats_t`), prototypes.
- `globals.c` — shared state (config, stats, stop flag, buckets).
- `util.c` — small helpers, name tables, MD5/SHA256, JA3/JA4 hashing.
- `decode.c` — L2/L3/L4 decoding (Ethernet/VLAN/ARP/IP/TCP/UDP/ICMP) + 802.11/radiotap.
- `app.c` — DNS/TLS(+certs, JA3/JA4)/QUIC/HTTP1/HTTP2/DoH/DoT/SMB2/RDP/LDAP/Kerberos.
- `harvest.c` — `-K` credentials/tokens/banners and the structured protos.
- `recon.c` — `-O`/`-Y`/`-N` fingerprinting, talkers, name harvest.
- `flows.c` — TCP reassembly + UDP flows + TCP metrics.
- `frag.c` — `-A` IPv4/IPv6 fragment reassembly.
- `defense.c` — `-D` defensive anomaly detection (ARP/ND/DHCP/name/VLAN/802.11).
- `filter.c` — `-P`/`-H`/`-p` userspace filtering.
- `print.c` — text / json / ndjson / csv / zeek printers.
- `pcap.c` — pcap **and pcapng** reader/writer, rotation, `--follow-out`.
- `bpf.c` — BPF compiler + interpreter (kernel attach and offline).
- `capture.c` — live, zero-copy ring, and pcap capture sources.
- `tui.c` — the from-scratch terminal TUI (panes + `:` command prompt).
- `config.c` — `~/.ch1m3rarc` save/load (`--save-config`/`--load-config`).
- `craft.c` — active frame crafter (ARP poison / SYN scan / DHCP starve / replay).
- `fuzz.c` — structure-aware fuzz harness (separate binary).
- `main.c` — option parsing and orchestration.
- `Makefile` — `all`, `test`, `asan`, `gate`, `netns`, `fuzz`, `modules`, `install`, `clean`.
- `ch1m3ra.c` — frozen original single-file source (regeneration input for
  `tools/split.py`); not built by `make`.
- `tests/gen_*.py` — test-frame generators (python3, for `make test`).
- `tests/check.sh` — assertion suite; `tests/gate.sh` — behavior gate;
  `tests/netns.sh` — live netns harness; `tests/tui_pty.py` — TUI pty driver.

Only capture or inject traffic on networks you own or are authorized to test.
The active tools put real frames on the wire.
