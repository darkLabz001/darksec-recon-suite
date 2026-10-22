#!/usr/bin/env python3
"""Split ch1m3ra.c into modules mechanically (phase 0 refactor).

Partitions the original file by section banners, emits each module verbatim,
and strips top-level `static` so the shared prototypes in ch1m3ra.h match.
Blocks that now live in ch1m3ra.h (config, helpers' macros, packet_t, stats)
are omitted from the modules; util.c keeps the helper/name *bodies*.

Run from the repo root: python3 tools/split.py
"""
import os, re

SRC = "ch1m3ra.c"

# name -> line range(s) (1-based inclusive start, exclusive end)
RANGES = {
    "globals.c": [(46, 90), (91, 93), (283, 307), (308, 312), (3116, 3117)],
    "util.c":    (94, 190),
    "decode.c":  [(312, 490), (1545, 1727)],
    "app.c":     (490, 980),
    "harvest.c": (980, 1334),
    "recon.c":   (1334, 1545),
    "flows.c":   (1727, 1992),
    "filter.c":  (1992, 2031),
    "print.c":   (2031, 2440),
    "pcap.c":    (2440, 2519),
    "bpf.c":     (2519, 2914),
    "capture.c": [(2914, 2989), (2989, 3100), (3469, 3543)],
    "tui.c":     (3100, 3469),
    "craft.c":   (3543, 3991),
    "main.c":    (3991, 4230),
}

BANNER = {
    "globals.c": "shared globals (config, stats, signal, buckets, TUI hooks)",
    "util.c":    "tiny helpers + name tables",
    "decode.c":  "link/network/transport decoding",
    "app.c":     "application layer (DNS / TLS / HTTP)",
    "harvest.c": "credential / token / banner harvesting (-K)",
    "recon.c":   "reconnaissance: OS fingerprint / talkers / names",
    "flows.c":   "TCP stream + UDP flow tracking",
    "filter.c":  "filtering",
    "print.c":   "printing (text / json / csv)",
    "pcap.c":    "pcap file I/O (own minimal reader/writer)",
    "bpf.c":     "kernel BPF filter (-F) + offline interpreter",
    "capture.c": "capture sources (live, zero-copy ring, pcap)",
    "tui.c":     "interactive TUI (-U)",
    "craft.c":   "raw frame crafting + transmit (active tools)",
    "main.c":    "option parsing + main",
}

HEAD = "/* {name} - {banner} */\n\n#include \"ch1m3ra.h\"\n\n"

# blocks now provided by ch1m3ra.h: drop these exact source ranges from modules
# (only util.c would otherwise carry helpers/names; the macros/tables stay in
# the header, so we drop the macro/enum/struct definition lines below).
DROP_PREFIXES = (
    "static struct {",          # cfg / st / cap definitions
    "static volatile sig_atomic_t g_stop",
    "static void on_sigint",
    "static int bucket(",
    "static const char *bucket_name(",
    "static int  tui_active;",
    "static void tui_packet_line(",
    "static int  tui_run(void);",
)

# names that ch1m3ra.h declares non-static: strip `static` from their defs
SHARED = set("""
rd16 rd32 ck_add ck_fold lstv lst lsts mac_str
ipproto_name icmp4_name icmp6_name ethertype_name port_service
bucket bucket_name
tcp_flags_str tcp_opts_str fmt_ep decode decode_app decode_banner decode_arp
decode_l4 decode_ipv4 decode_ipv6 l4_cksum ck_ok_incl
dns_type_name dns_rcode_name dns_opcode_name
tls_ver_str tls_cipher_name http_hdr looks_http
harvest cred_kind_name credfile_close
finger_observe name_learn hn cn talkers_observe finger_stats talkers_stats names_stats
recon_cleanup recon_nhosts recon_cleanup_tables
stream_track stream_follow_emit streams_stats streams_cleanup
proto_match pass_filter
print_record rel_secs csum_val csum_str pcol
get32 put32 pcapin_open pcapin_next open_pcap_write
bpf_compile bpf_run bpf_attach
open_live list_ifaces ring_setup ring_stats
ring_map ring_len ring_req
capture_init capture_next process_frame print_stats
tui_packet_line tui_run
arp_poison_run syn_scan_run dhcp_starve_run replay_run
usage on_sigint
cfg st g_stop cap tui_active
""".split())

def strip_static(lines):
    """Drop `static ` from top-level definitions whose name is shared."""
    out = []
    skip_until = None
    for idx, l in enumerate(lines):
        # drop blocks that ch1m3ra.h already provides
        if l.startswith("typedef struct {") or l.startswith("} cap_t;"):
            pass
        m = re.match(r'^static\s+(.+)$', l)
        if m and l.startswith("static "):
            rest = l[len("static "):]
            names = re.findall(r'([A-Za-z_]\w*)\s*[\(\[]?', rest)
            if any(n in SHARED for n in names):
                out.append(rest)
                continue
        out.append(l)
    return out

def drop_header_dupes(name, lines):
    """Remove definitions that ch1m3ra.h supplies."""
    if name == "globals.c":
        out, i = [], 0
        while i < len(lines):
            l = lines[i]
            if "tui_packet_line(const packet_t *p);" in l or \
               "tui_run(void);" in l:
                i += 1
                continue
            if l.startswith("static struct {"):
                # peek the closing line to know which global this is
                j = i + 1
                while j < len(lines) and not lines[j].startswith("}"):
                    j += 1
                close = lines[j]
                if "} cfg" in close:
                    out.append("cfg_t cfg" + close.split("cfg", 1)[1])
                elif "} st;" in close:
                    out.append("stats_t st;")
                else:
                    out.append(close)
                i = j + 1
                continue
            out.append(l); i += 1
        return out
    if name == "pcap.c":
        out, i = [], 0
        while i < len(lines):
            if lines[i].startswith("typedef struct { FILE *f;"):
                i += 1
                continue
            out.append(lines[i]); i += 1
        return out
    if name == "tui.c":
        out, i = [], 0
        while i < len(lines):
            if lines[i].startswith("typedef struct {") and i + 1 < len(lines) \
               and "pcapin_t  pr;" in lines[i + 1]:
                i += 1
                while i < len(lines) and not lines[i].startswith("} cap_t;"):
                    i += 1
                i += 1                       # skip the closing brace line
                while i < len(lines) and lines[i].strip() in ("", "static cap_t cap;"):
                    if lines[i].strip() == "static cap_t cap;":
                        i += 1
                        break
                    i += 1
                continue
            out.append(lines[i]); i += 1
        return out
    return lines

def main():
    lines = open(SRC, encoding="utf-8").read().splitlines(keepends=True)
    for name, rng in RANGES.items():
        parts = rng if isinstance(rng, list) else [rng]
        body = []
        for (a, b) in parts:
            body.extend(lines[a - 1:b - 1])
        # util.c keeps rd16/ck_add/... bodies but not the macros (header has them)
        if name == "util.c":
            body = [l for l in body
                    if not re.match(r'^#define C(DIM|RED|GRN|YEL|BLU|MAG|CYN|0|WHT)\b', l)]
        body = drop_header_dupes(name, body)
        text = HEAD.format(name=name, banner=BANNER[name]) + "".join(strip_static(body))
        with open(name, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {name}: {len(body)} lines")

if __name__ == "__main__":
    main()
