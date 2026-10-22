# ch1m3ra upgrade plan

Working agreement: modules + build via Makefile, zero warnings (-Wall -Wextra),
clean under ASan/UBSan, tests + README updated per feature.
sudo password is available for runtime testing (live capture, injection, netns).

Done so far: 174-assertion suite (0 failing), behavior gate shows only intended
diffs, dock/panel launcher fixed and verified under a pty.

Naming: the tool was renamed from `sniffer` to **ch1m3ra** (binary, banner, help,
man page, README, desktop entries, config path `~/.ch1m3rarc`). The frozen
single-file original is now `ch1m3ra.c` (regeneration input, not built); the
behavior gate baseline is `.baseline/ch1m3ra.out`.

## Phase 0 — refactor into modules (DONE — behavior-diff gate passed)
- [x] ch1m3ra.h        shared types (cfg_t, packet_t, stats_t), protos, config
- [x] globals.c        cfg/st/g_stop/bucket + cap
- [x] util.c           tiny helpers, name tables
- [x] decode.c         L2/L3/L4 decoding
- [x] app.c            DNS/TLS/HTTP
- [x] harvest.c        -K creds/tokens/banners
- [x] recon.c          -O/-Y/-N
- [x] flows.c          TCP streams
- [x] filter.c         filtering
- [x] print.c          text/json/csv
- [x] pcap.c           pcap read/write
- [x] bpf.c            BPF compiler + interpreter
- [x] capture.c        live/ring/capture source
- [x] tui.c            TUI
- [x] craft.c          active tools
- [x] main.c           option parsing + orchestration
- [x] behavior diff vs frozen .baseline/ch1m3ra.out: IDENTICAL (modulo argv[0])
- [x] 66/66 tests pass, ASan/UBSan clean, zero warnings

## Phase 1 — protocol coverage
- [x] IPv4/IPv6 fragment reassembly (-A) — frag.c, tests/frag.pcap, 6 assertions
- [x] TLS certificate extraction (subject/issuer/SAN/validity) — app.c DER walker, tests/tls.pcap, 5 assertions
- [x] QUIC / HTTP3 Initial detection + SNI — app.c, tests/quic.pcap, 4 assertions
- [x] JA3 TLS client fingerprint (from-scratch MD5) + ECH flag — util.c/app.c, 3 assertions
- [x] JA4 fingerprint (sorted ciphers/exts + sigalgs, ALPN-aware) — app.c, verified vs independent Python ref
- [x] DoH / DoT detection — app.c (HTTP /dns-query + TLS port 853), 2 assertions
- [x] HTTP/2 frame + HPACK header decode — app.c (static table, 4 assertions)

## Phase 2 — analysis depth
- [x] UDP flow tracking — flows.c (separate `u` id space, per-dir dgram/byte counts), 2 assertions
- [x] TCP metrics: retransmit/RTT/out-of-order/zero-window — flows.c, tests/metrics.pcap, 4 assertions
- [x] SMB2, RDP, LDAP, Kerberos decoders (feed -K/-N) — harvest.c, tests/proto.pcap

## Phase 3 — output & tooling
- [x] pcapng read + write (own reader/writer: SHB/IDB/EPB/SPB, tsresol, verified vs tshark)
- [x] -o zeek / ndjson (schema version)
- [x] --follow-out <pcap> subset export (reassembled stream payloads)
- [x] -W <MB> / --rotate-secs <n> output rotation
- [x] BPF grammar: vlan, ether [src|dst] host, greater/less, len, tcp[tcpflags]

## Phase 4 — TUI & UX
- [x] multi-pane view: packets / hits / hosts / talkers (p cycles)
- [x] live filter + config: `:` command prompt (p/h/port/n/harvest/finger/names/reasm/save/load/filter)
- [x] host & talker panes fed from the recon tables, rebuilt live
- [x] active-filter indicator in the header
- [x] per-second sparklines (48-s packet-rate history on the histogram line; `pps N [bars]`)
- [x] mouse support (SGR 1006 wheel + arrow keys scroll the packet pane)
- [x] colour-coded packet rows (per protocol/severity), column header, scrollbar
- [x] packet detail pane (Enter) — sectioned L2/L3/L4/app/creds/hexdump decode
- [x] in-log search (/ then n/N, matches underlined) + page/half-page nav
- [x] richer header (elapsed time, average pps) + ANSI-aware width truncation
- [x] adaptive footer that keeps `quit` visible on narrow terminals

## Phase 5 — active/offensive depth
- [x] passive ARP spoof detection (MAC/IP binding change, over-claim sweep) — defense.c
- [x] ICMPv6 Neighbor Advertisement spoof detection
- [x] rogue DHCP detection (multiple servers on the segment)
- [x] mDNS/LLMNR/NBNS name poisoning + WPAD takeover detection
- [x] VLAN double-tag (QinQ) + Cisco DTP frame detection
- [x] 802.11 radiotap + management-frame parse (beacon/probe/deauth), linktypes 127/105 — decode.c
- [x] 802.11 rogue-AP (evil twin) + deauth-flood detection — defense.c
- [x] tests/wlan.pcap generator + radiotap linktype plumbing + JSON wlan fields
- [x] live monitor-mode capture (linklayer-type auto-detect: ARPHRD 803/801 → radiotap,
      multi-word present-bitmap walker, control-frame 10-byte headers) — verified live
      against a MediaTek MT7612U `mon0`: beacons/probe-resp/data/ctrl/deauth decoded
- [x] 802.11 injection: --deauth + --beacon-flood (radiotap-prefixed crafted frames)
      — verified live (tests/wlan_live.sh: 120 beacons + 120 deauths captured on the
      air and the injected deauth flood flagged by -D)
- [x] SYN scan service/version probing: --banner-grab connect + read banners (tests/check.sh local listener + netns live)
- [x] VLAN hopping injection (double-tagging attack) --vlan-hop (netns-verified; QinQ decoded w/ inner tag)

## Phase 6 — engineering
- [x] fuzz decoders — fuzz.c, libFuzzer + self-loop mutator, 1M+ frames ASan/UBSan clean
- [x] ch1m3ra.1 man page (all options, installed by `make install`)
- [x] config file + profiles (--load-config/--save-config, ~/.ch1m3rarc, TUI :save/:load)
- [x] netns live-capture + injection test harness (tests/netns.sh; 9 live tests incl. banner-grab, vlan-hop, -Z ring drain; needs root, skips otherwise)
- [x] 802.11 live injection test harness (tests/wlan_live.sh; beacons+deauth on the air; needs root + monitor radio, skips otherwise)
- [x] decode benchmark (--bench <n>, packets/sec + ns/packet) + ring batch reads (capture_drain consumes a whole burst per poll)
- [x] ring robustness: shared scan state across blocking/non-blocking readers + POLLERR/HUP handling (fixed a 100% CPU spin + ignored SIGTERM when the interface vanished)

