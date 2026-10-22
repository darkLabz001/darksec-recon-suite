/* main.c - option parsing + main */

#include "ch1m3ra.h"

/* ---------- main ---------- */
void usage(FILE *o, const char *argv0) {
    fprintf(o,
"ch1m3ra " VERSION " - packet sniffer built from scratch (no libpcap)\n"
"\n"
"usage: %s [options]\n"
"  -i <iface>   capture on <iface> (default: all interfaces)\n"
"  -l           list interfaces and exit\n"
"  -r <file>    read packets from a pcap file (no root needed)\n"
"  -w <file>    write captured packets to a pcap file (with -r: filter a pcap offline)\n"
"               .pcapng extension selects the pcapng container\n"
"  -W <MB>      with -w: rotate to file-NNNNN after <MB> megabytes\n"
"  --rotate-secs <n>  with -w: rotate every <n> seconds\n"
"  -H <host>    only packets matching this: IP substring, or a decoded\n"
"               DNS question name / TLS SNI / HTTP Host header\n"
"  -p <port>    only packets with this source or destination port\n"
"  -P <proto>   only this protocol: tcp udp icmp icmpv6 arp ip ipv6 dns tls http frag ...\n"
"  -n <count>   stop after <count> packets\n"
"  -s <len>     snapshot length, bytes captured per packet (default 65535)\n"
"  -B <len>     payload bytes to dump (default 96, 0 = none)\n"
"  -q           quiet: one line per packet, no details or payload\n"
"  -o <fmt>     output format: text (default), json (one object per line,\n"
"               jq-friendly), csv (header row + rows)\n"
"               extras: ndjson (json + \"schema\":1), zeek (TSV conn-style log)\n"
"  -e           timestamps relative to the first displayed packet\n"
"  -T <id>      follow a TCP stream: print reassembled payload as text and\n"
"               suppress packet lines (0 = follow every stream; ids shown\n"
"               as #N on packet lines and in the final stats)\n"
"  -F <expr>    kernel BPF filter (tcpdump-like subset): tcp udp icmp icmp6\n"
"               arp ip ip6, port N [src|dst] host ADDR, and/or/not/() with\n"
"               implicit and - e.g. -F 'tcp and port 443'.  Matching runs\n"
"               in the kernel (and in our own interpreter for -r); assumes\n"
"               untagged frames and no IPv6 extension headers\n"
"  -Z           zero-copy capture: kernel writes into an mmap PACKET_RX_RING\n"
"               instead of recvfrom copies (live capture only)\n"
"  -U           interactive TUI: colour-coded log, start/stop (s/x), scroll\n"
"               (j/k, PgUp/PgDn), search (/ then n/N), detail pane (Enter),\n"
"               pane switch (p), clear (c), follow (f), quit (q)\n"
"  -K           harvest cleartext credentials/tokens (HTTP basic/bearer/form,\n"
"               FTP, POP3, IMAP, SMTP, Telnet, SNMP, cookies, JWTs)\n"
"  -k <file>    like -K but also append each hit to <file>\n"
"  -O           passive OS fingerprint hosts (TTL + TCP options, p0f-style)\n"
"  -Y           top-talkers: rank hosts/conversations by bytes\n"
"  -N           learn hostnames from mDNS/LLMNR/NBNS/DNS responses\n"
"  -E           thorough filtering: parse frames instead of fixed BPF offsets\n"
"               (VLAN- and IPv6-extension-header aware)\n"
"  -A           reassemble IPv4/IPv6 fragments and decode the whole datagram\n"
"  -D           defensive anomaly detection: ARP/ND spoof, rogue DHCP, mDNS/\n"
"               LLMNR/WPAD poisoning, VLAN double-tag/DTP (passive, warns to stderr)\n"
"  --follow-out <file>  with -T: write the followed stream's reassembled\n"
"               payloads to a pcap you can reopen in Wireshark\n"
"  -M           do not enter promiscuous mode\n"
"  -C           disable colors\n"
"  --load-config <file>  apply saved settings first (\"-\" = ~/.ch1m3rarc)\n"
"  --save-config         write the current settings to ~/.ch1m3rarc and exit\n"
"  -h, --help   this help page\n"
"\n"
"offensive / active tools (root + explicit flag; they transmit real packets):\n"
"  --arp-poison <victim>,<gateway>[,<iface>]\n"
"               ARP-spoof the pair to MITM their traffic (Ctrl-C to restore)\n"
"  --syn-scan <host>[:<ports>]\n"
"               half-open port scan; <ports> like 22,80,443 or 1-1024\n"
"  --dhcp-starve <iface>[:<count>]\n"
"               exhaust a DHCP server's pool with random-client DISCOVERs\n"
"  --replay <pcap>          re-send frames from a pcap (edit with --rewrite-src)\n"
 "  --banner-grab <host>[:<ports>]  connect + read service banners\n"
 "               (--banner-timeout <ms> read timeout, default 1500)\n"
 "  --vlan-hop <iface>:<outer>:<inner>\n"
 "               double-tagged 802.1Q frames to hop into another VLAN\n"
 "  --bench <n>             decode the -r pcap n times and report packets/sec\n"
 "  --deauth <bssid>[,<client>][,<count>]\n"
 "               802.11 deauth frames over a monitor vif (authorised testing)\n"
 "  --beacon-flood <ssid>[,<count>]  fake-AP beacon flood over a monitor vif\n"
"  --rewrite-src <ip>       replace source IP in replayed frames\n"
"\n"
"examples:\n"
"  sudo %s -i wlan0 -P tcp -p 443\n"
"  sudo %s -i eth0 -w capture.pcap\n"
"  sudo %s -i eth0 -Z -F 'tcp and port 443'\n"
"  sudo %s -i wlan0 -U            (interactive TUI, start with s)\n"
"  sudo %s -i wlan0 -K -O -U      (harvest creds + fingerprint, in the TUI)\n"
"  sudo %s -i eth0 --arp-poison 192.168.1.5,192.168.1.1\n"
"  sudo %s -i eth0 --syn-scan 10.0.0.1:22,80,443\n"
"  %s -r capture.pcap -H 8.8.8.8 -B 256\n"
"  %s -r capture.pcap -o json | jq -r 'select(.app==\"dns\") | .dns.qname'\n"
"  %s -r capture.pcap -q        (note stream ids #N, then)\n"
"  %s -r capture.pcap -T 3      ...follow stream 3 as text\n",
    argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    cfg.port = -1;

    /* Load saved settings first so explicit command-line flags, parsed below,
     * always override them.  --load-config <file>; "-" or "auto" = ~/.ch1m3rarc. */
    for (int i = 1; i < argc; i++) {
        const char *path = NULL;
        if (!strcmp(argv[i], "--load-config") && i + 1 < argc)
            path = argv[i + 1];
        else if (!strncmp(argv[i], "--load-config=", 14))
            path = argv[i] + 14;
        else
            continue;
        if (!strcmp(path, "-") || !strcmp(path, "auto")) path = NULL;
        char err[300];
        if (config_load(path, err, sizeof err) != 0) {
            fprintf(stderr, "ch1m3ra: %s\n", err);
            return 1;
        }
        break;
    }

    int opt;
    static const struct option longopts[] = {
        { "arp-poison",  required_argument, NULL, 1000 },
        { "syn-scan",    required_argument, NULL, 1001 },
        { "dhcp-starve", required_argument, NULL, 1002 },
        { "replay",      required_argument, NULL, 1003 },
        { "rewrite-src", required_argument, NULL, 1004 },
        { "follow-out",  required_argument, NULL, 1005 },
        { "rotate-secs", required_argument, NULL, 1006 },
        { "load-config", required_argument, NULL, 1007 },
        { "save-config", no_argument,       NULL, 1008 },
        { "banner-grab", required_argument, NULL, 1009 },
        { "vlan-hop",    required_argument, NULL, 1010 },
        { "banner-timeout", required_argument, NULL, 1011 },
        { "bench",       required_argument, NULL, 1012 },
        { "deauth",      required_argument, NULL, 1013 },
        { "beacon-flood", required_argument, NULL, 1014 },
        { "help",        no_argument,       NULL, 'h'  },
        { 0, 0, 0, 0 }
    };
    while ((opt = getopt_long(argc, argv,
                              "i:r:w:H:p:P:n:s:B:T:o:eF:ZUqMChlKk:OYNECAW:D",
                              longopts, NULL)) != -1) {
        switch (opt) {
            case 'i': cfg.iface = optarg; break;
            case 'r': cfg.rfile = optarg; break;
            case 'w': cfg.wfile = optarg; break;
            case 'H': cfg.host = optarg; break;
            case 'K': cfg.harvest = 1; break;
            case 'k': cfg.harvest = 1; cfg.credfile = optarg; break;
            case 'O': cfg.finger = 1; break;
            case 'Y': cfg.talkers = 1; break;
            case 'N': cfg.names = 1; break;
            case 'E': cfg.evasion = 1; break;
            case 'A': cfg.reasm = 1; break;
            case 'D': cfg.defense = 1; break;
            case 1000: cfg.arp_poison = optarg; cfg.active = 1; break;
            case 1001: cfg.syn_scan = optarg; cfg.active = 1; break;
            case 1002: cfg.dhcp_starve = optarg; cfg.active = 1; break;
            case 1003: cfg.replay = optarg; break;
            case 1004: cfg.rewrite_src = optarg; break;
            case 1005: cfg.follow_out = optarg; break;
            case 1006:
                cfg.rot_secs = atol(optarg);
                if (cfg.rot_secs < 0) cfg.rot_secs = 0;
                break;
            case 1007: break;   /* handled in the pre-scan before getopt */
            case 1008: cfg.save_config = 1; break;
            case 1009: cfg.banner_grab = optarg; cfg.active = 1; break;
            case 1010: cfg.vlan_hop = optarg; cfg.active = 1; break;
            case 1011:
                cfg.banner_timeout_ms = atoi(optarg);
                if (cfg.banner_timeout_ms <= 0) cfg.banner_timeout_ms = 1500;
                break;
            case 1012:
                cfg.bench_iters = atol(optarg);
                if (cfg.bench_iters <= 0) cfg.bench_iters = 1;
                break;
            case 1013: cfg.deauth = optarg; cfg.active = 1; break;
            case 1014: cfg.beacon_flood = optarg; cfg.active = 1; break;
            case 'W':
                cfg.rot_size = atol(optarg);
                if (cfg.rot_size < 0) cfg.rot_size = 0;
                break;
            case 'T':
                cfg.follow = strtol(optarg, NULL, 10);
                if (cfg.follow < 0) {
                    fprintf(stderr, "ch1m3ra: -T needs a stream id >= 0\n"); return 2;
                }
                break;
            case 'p':
                cfg.port = strtol(optarg, NULL, 10);
                if (cfg.port < 0 || cfg.port > 65535) {
                    fprintf(stderr, "ch1m3ra: bad port: %s\n", optarg); return 2;
                }
                break;            case 'P': cfg.proto = optarg; break;
            case 'n': cfg.count = atol(optarg); break;
            case 's':
                cfg.snaplen = atol(optarg);
                if (cfg.snaplen < 64 || cfg.snaplen > 65535) {
                    fprintf(stderr, "ch1m3ra: -s must be 64..65535\n"); return 2;
                }
                break;
            case 'B':
                cfg.dumpbytes = atol(optarg);
                if (cfg.dumpbytes < 0) cfg.dumpbytes = 0;
                if (cfg.dumpbytes > 65535) cfg.dumpbytes = 65535;
                break;
            case 'q': cfg.quiet = 1; break;
            case 'o':
                if (strcmp(optarg, "text") && strcmp(optarg, "json") && strcmp(optarg, "csv") &&
                    strcmp(optarg, "ndjson") && strcmp(optarg, "zeek")) {
                    fprintf(stderr, "ch1m3ra: -o must be text, json, ndjson, csv, or zeek\n");
                    return 2;
                }
                cfg.outfmt = optarg;
                break;
            case 'e': cfg.reltime = 1; break;
            case 'F': cfg.bfilter = optarg; break;
            case 'Z': cfg.ring = 1; break;
            case 'U': cfg.tui = 1; break;
            case 'M': cfg.nopromisc = 1; break;
            case 'C': cfg.color = 0; break;
            case 'l': list_ifaces(); return 0;
            case 'h': usage(stdout, argv[0]); return 0;
            default:  usage(stderr, argv[0]); return 2;
        }
    }

    if (cfg.save_config) {
        char err[300];
        int rc = config_save(err, sizeof err);
        fprintf(stderr, "ch1m3ra: %s\n", err);
        return rc == 0 ? 0 : 1;
    }
    if (cfg.color < 0) cfg.color = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* active tools run instead of a normal capture (they transmit) */
    if (cfg.replay) {
        replay_run(cfg.replay, cfg.rewrite_src, cfg.iface);
        return 0;
    }
    if (cfg.arp_poison)  { arp_poison_run(cfg.arp_poison, cfg.iface); return 0; }
    if (cfg.syn_scan)    { syn_scan_run(cfg.syn_scan, cfg.iface); return 0; }
    if (cfg.banner_grab) { banner_grab_run(cfg.banner_grab, cfg.iface, cfg.banner_timeout_ms); return 0; }
    if (cfg.vlan_hop)    { vlan_hop_run(cfg.vlan_hop, cfg.iface); return 0; }
    if (cfg.dhcp_starve) { dhcp_starve_run(cfg.dhcp_starve, cfg.iface); return 0; }
    if (cfg.deauth)      { deauth_run(cfg.deauth, cfg.iface); return 0; }
    if (cfg.beacon_flood){ beacon_flood_run(cfg.beacon_flood, cfg.iface); return 0; }

    /* decode benchmark: replay the pcap through the pipeline, report the rate */
    if (cfg.bench_iters > 0) {
        if (!cfg.rfile) {
            fprintf(stderr, "ch1m3ra: --bench needs an input pcap (-r <file>)\n");
            return 2;
        }
        bench_run(cfg.rfile, cfg.bench_iters);
        return 0;
    }

    if (cfg.bfilter) bpf_compile(cfg.bfilter);   /* fails fast on bad syntax */

    if (cfg.rfile) {
        if (pcapin_open(&cap.pr, cfg.rfile) != 0) return 1;
        cap.pcap_mode = 1;
        if (cfg.ring)
            fprintf(stderr, "ch1m3ra: warning: -Z applies to live capture, ignored with -r\n");
    } else {
        cap.fd = open_live(cfg.iface, &cap.ifindex);
        if (cfg.bfilter && !cfg.evasion) bpf_attach(cap.fd);
        if (cfg.ring && ring_setup(cap.fd) != 0) cfg.ring = 0;
    }
    /* -w works live and in -r mode (offline: filters a pcap into a new one) */
    if (cfg.wfile) {
        if (cfg.rot_size > 0 || cfg.rot_secs > 0) pcapw_rotate_init(cfg.wfile);
        else cap.wf = open_pcap_write(cfg.wfile);
    }
    if (cfg.follow_out) follow_out_open(cfg.follow_out);
    print_zeek_headers();

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (cfg.tui) return tui_run();

    /* banner on stderr so stdout stays pure packet data */
    fprintf(stderr, "%sch1m3ra " VERSION "%s - raw AF_PACKET, all decoding done here\n",
            CWHT, C0);
    if (cap.pcap_mode) fprintf(stderr, "  source  : %s (pcap file)\n", cfg.rfile);
    else if (cfg.iface)
        fprintf(stderr, "  device  : %s (ifindex %d%s)\n", cfg.iface, cap.ifindex,
                cfg.nopromisc ? "" : ", promisc");
    else fprintf(stderr, "  device  : all interfaces\n");
    {
        char fbuf[256];
        fbuf[0] = 0;
        if (cfg.proto) lst(fbuf, sizeof fbuf, "proto=%s", cfg.proto);
        if (cfg.host)  lst(fbuf, sizeof fbuf, "host=%s", cfg.host);
        if (cfg.port >= 0) lst(fbuf, sizeof fbuf, "port=%ld", cfg.port);
        if (cfg.bfilter) lst(fbuf, sizeof fbuf, "bpf=%s", cfg.bfilter);
        if (!fbuf[0]) snprintf(fbuf, sizeof fbuf, "none");
        fprintf(stderr, "  filter  : %s\n", fbuf);
    }
    if (cfg.ring) fprintf(stderr, "  capture : PACKET_RX_RING zero-copy (tp_frame=%u x%u)\n",
                          ring_req.tp_frame_size, ring_req.tp_frame_nr);
    if (cfg.evasion) fprintf(stderr, "  evasion : -E thorough filtering (parsed, VLAN/ext-aware)\n");
    if (cfg.reasm)   fprintf(stderr, "  reassem : -A IPv4/IPv6 fragment reassembly on\n");
    if (cfg.harvest) fprintf(stderr, "  harvest : credentials/tokens/banners%s%s\n",
                             cfg.credfile ? " -> " : "", cfg.credfile ? cfg.credfile : "");
    if (cfg.finger)  fprintf(stderr, "  finger  : passive OS fingerprinting on\n");
    if (cfg.talkers) fprintf(stderr, "  talkers : top-talker ranking on\n");
    if (cfg.names)   fprintf(stderr, "  names   : mDNS/LLMNR/NBNS/DNS harvesting on\n");
    fprintf(stderr, "  payload : %s\n\n",
            cfg.quiet ? "quiet" : (cfg.dumpbytes ? "dump up to requested bytes" : "off"));

    static uint8_t buf[65536];
    long capbuf = cfg.snaplen < 65536 ? cfg.snaplen : 65536;

    while (!g_stop) {
        const uint8_t *frame = buf;
        size_t capn = 0, wire = 0;
        struct timespec ts = {0, 0};
        int have_dir = 0, out = 0;
        char ifn[IF_NAMESIZE] = "";

        /* zero-copy ring: pull every frame already queued in one batch */
        long drained = 0;
        int drc = capture_drain(64, &drained);
        if (drc == 1) {
            if (cfg.count > 0 && (long long)st.shown >= cfg.count) break;
            continue;
        }

        int rc = capture_next(buf, (size_t)capbuf, &frame, &capn, &wire, &ts,
                              &have_dir, &out, ifn);
        if (rc == 0) break;
        if (rc == -1) return 1;
        if (rc == 2) continue;                 /* EINTR */

        process_frame(frame, capn, wire, &ts, ifn, have_dir, out);
        if (cfg.count > 0 && (long long)st.shown >= cfg.count) break;
    }

    if (cap.wf) { fflush(cap.wf->f); fclose(cap.wf->f); free(cap.wf); cap.wf = NULL; }
    if (cfg.follow_out) follow_out_close();
    if (cap.pcap_mode) fclose(cap.pr.f);
    print_stats();
    if (cap.fd >= 0) { ring_stats(cap.fd); close(cap.fd); }
    if (ring_map) munmap(ring_map, ring_len);
    streams_cleanup();
    recon_cleanup();
    if (cfg.credfile) credfile_close();
    return 0;
}
