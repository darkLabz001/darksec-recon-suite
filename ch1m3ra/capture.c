/* capture.c - capture sources (live, zero-copy ring, pcap) */

#include "ch1m3ra.h"

/* ---------- live capture ---------- */
void list_ifaces(void) {
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) != 0) { perror("getifaddrs"); exit(1); }
    printf("%-16s %-22s %-18s %s\n", "IFACE", "STATE", "MAC", "ADDR");
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_name || !p->ifa_addr || p->ifa_addr->sa_family != AF_PACKET) continue;
        const struct sockaddr_ll *s = (const struct sockaddr_ll *)p->ifa_addr;
        char mac[24] = "-";
        if (s->sll_halen == 6)
            snprintf(mac, sizeof mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                     s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                     s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
        char state[40] = "";
        snprintf(state, sizeof state, "%s", (p->ifa_flags & IFF_UP) ? "up" : "down");
        if (p->ifa_flags & IFF_RUNNING) strncat(state, ",running", sizeof state - strlen(state) - 1);
        if (p->ifa_flags & IFF_LOOPBACK) strncat(state, ",loopback", sizeof state - strlen(state) - 1);
        if (p->ifa_flags & IFF_PROMISC) strncat(state, ",promisc", sizeof state - strlen(state) - 1);
        char addr[INET6_ADDRSTRLEN] = "";
        for (struct ifaddrs *q = ifa; q; q = q->ifa_next) {
            if (q->ifa_name && !strcmp(q->ifa_name, p->ifa_name) &&
                q->ifa_addr && q->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *in = (struct sockaddr_in *)q->ifa_addr;
                inet_ntop(AF_INET, &in->sin_addr, addr, sizeof addr);
                break;
            }
        }
        printf("%-16s %-22s %-18s %s\n", p->ifa_name, state, mac, addr);
    }
    freeifaddrs(ifa);
}

int open_live(const char *iface, int *ifindex_out) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr, "ch1m3ra: socket(AF_PACKET): %s\n", strerror(errno));
        if (errno == EPERM)
            fprintf(stderr, "ch1m3ra: needs root - run from your Kali Root Terminal, or:\n"
                            "         sudo setcap cap_net_raw,cap_net_admin+ep ./ch1m3ra\n");
        exit(1);
    }
    int ifindex = 0;
    if (iface) {
        ifindex = (int)if_nametoindex(iface);
        if (!ifindex) {
            fprintf(stderr, "ch1m3ra: no such interface: %s (use -l to list)\n", iface);
            exit(1);
        }
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof sll);
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = ifindex;
        if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
            fprintf(stderr, "ch1m3ra: bind %s: %s\n", iface, strerror(errno));
            exit(1);
        }
        if (!cfg.nopromisc) {
            struct packet_mreq mr;
            memset(&mr, 0, sizeof mr);
            mr.mr_ifindex = ifindex;
            mr.mr_type = PACKET_MR_PROMISC;
            if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) < 0)
                fprintf(stderr, "ch1m3ra: warning: no promiscuous mode: %s\n", strerror(errno));
        }
        /* Detect the link-layer type so 802.11 monitor interfaces are decoded
         * as radiotap frames instead of being mis-parsed as Ethernet.  A
         * monitor vif reports ARPHRD_IEEE80211_RADIOTAP (803). */
        {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof ifr);
            snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", iface);
            if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                unsigned short ht = (unsigned short)ifr.ifr_hwaddr.sa_family;
                if (ht == ARPHRD_IEEE80211_RADIOTAP)      g_linktype = 127;
                else if (ht == ARPHRD_IEEE80211)          g_linktype = 105;
                else                                      g_linktype = 1;
            }
        }
    }
    *ifindex_out = ifindex;
    if (cfg.tui) {
        /* non-blocking so the TUI can poll keys between packets */
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
    return fd;
}

/* ---------- zero-copy ring capture (-Z, TPACKET_V2) ----------
 * Instead of recvfrom() copying every packet into a userspace buffer, the
 * kernel writes frames straight into a shared mmap ring; we parse in place
 * and hand the frame pointers to the decoder - no copy per packet.        */
uint8_t *ring_map;
size_t ring_len;
struct tpacket_req ring_req;
static int ring_on;

/* Shared ring scan state.  Both the blocking reader (ring_next) and the
 * non-blocking one (ring_next_nowait) walk the same ring, so they must share
 * the "frame handed out last" pointer and scan position; otherwise a frame
 * released by one is never released by the other and the ring fills up. */
static struct tpacket2_hdr *ring_last_h;
static size_t ring_scan_off;

/* Release the frame handed out on the previous read back to the kernel. */
static void ring_release_last(void) {
    if (ring_last_h) {
        __atomic_store_n(&ring_last_h->tp_status, (uint32_t)TP_STATUS_KERNEL,
                         __ATOMIC_RELEASE);
        ring_last_h = NULL;
    }
}

int ring_setup(int fd) {
    int ver = TPACKET_V2;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof ver) < 0) {
        fprintf(stderr, "ch1m3ra: warning: PACKET_VERSION: %s (falling back to recvfrom)\n",
                strerror(errno));
        return -1;
    }
    /* frames must be a power of two >= snaplen + headers so they tile the
     * 2 MiB block exactly (kernel requires block_nr * block/frame == frame_nr) */
    size_t need = (size_t)cfg.snaplen + 512;
    size_t fsz = 2048;
    while (fsz < need) fsz <<= 1;
    size_t blk = 1u << 21;                       /* 2 MiB blocks */
    if (fsz > blk) { fprintf(stderr, "ch1m3ra: snaplen too large for ring\n"); return -1; }
    ring_req.tp_block_size = (unsigned)blk;
    ring_req.tp_block_nr = 48;                   /* 96 MiB mapped */
    ring_req.tp_frame_size = (unsigned)fsz;
    ring_req.tp_frame_nr = (unsigned)(ring_req.tp_block_nr * (blk / fsz));
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring_req, sizeof ring_req) < 0) {
        fprintf(stderr, "ch1m3ra: warning: PACKET_RX_RING: %s (falling back to recvfrom)\n",
                strerror(errno));
        return -1;
    }
    ring_len = (size_t)ring_req.tp_block_nr * blk;
    ring_map = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring_map == MAP_FAILED) {
        fprintf(stderr, "ch1m3ra: warning: mmap ring: %s (falling back to recvfrom)\n",
                strerror(errno));
        ring_map = NULL;
        /* undo the ring so recvfrom still works */
        struct tpacket_req off = {0};
        setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &off, sizeof off);
        return -1;
    }
    ring_on = 1;
    return 0;
}

/* fetch the next frame; blocks via poll.  returns 1 = packet, 0 = stop.
 * The previous frame is released only when the next one is requested, so
 * the caller can decode in place without racing the kernel's writer.      */
int ring_next(int fd, uint8_t **pkt, size_t *cap, size_t *wire,
                     struct timespec *ts, int *have_dir, int *out, char *ifn) {
    const size_t fsz = ring_req.tp_frame_size;

    for (;;) {
        if (g_stop) { ring_release_last(); return 0; }
        ring_release_last();                     /* done decoding the old one */
        for (size_t off = 0; off < ring_len; off += fsz) {
            size_t o = (ring_scan_off + off) < ring_len ? ring_scan_off + off
                                                        : (ring_scan_off + off) - ring_len;
            struct tpacket2_hdr *h = (struct tpacket2_hdr *)(ring_map + o);
            if (!(h->tp_status & TP_STATUS_USER)) continue;

            *pkt = ring_map + o + h->tp_mac;
            *cap = h->tp_snaplen;
            *wire = h->tp_len;
            ts->tv_sec = (time_t)h->tp_sec;
            ts->tv_nsec = (long)h->tp_nsec;
            struct sockaddr_ll *sll = (struct sockaddr_ll *)
                ((uint8_t *)h + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll));
            *have_dir = 1;
            *out = (sll->sll_pkttype == PACKET_OUTGOING);
            if (!if_indextoname(sll->sll_ifindex, ifn))
                snprintf(ifn, IF_NAMESIZE, "if%d", sll->sll_ifindex);

            ring_last_h = h;                     /* release on the next call */
            ring_scan_off = o + fsz;
            if (ring_scan_off >= ring_len) ring_scan_off = 0;
            return 1;
        }
        /* ring empty: sleep until the kernel says there is data (briefly, so
         * the TUI can service keys; a full wait in plain capture mode) */
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int rc = poll(&p, 1, cfg.tui ? 100 : 1000);
        if (rc == 0) {                           /* timeout: re-check g_stop */
            if (cfg.tui) return 2;               /* let the TUI service keys */
            continue;
        }
        if (rc < 0) {
            if (errno == EINTR) { if (g_stop) { ring_release_last(); return 0; } continue; }
            fprintf(stderr, "ch1m3ra: poll: %s\n", strerror(errno));
            ring_release_last();
            return 0;
        }
        /* The interface vanished (netns removed, vif deleted): poll reports
         * POLLERR/POLLHUP immediately and forever.  Without this check we would
         * spin at 100% CPU and never honour SIGTERM. */
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "ch1m3ra: capture interface closed (poll: %s)\n",
                    (p.revents & POLLNVAL) ? "invalid fd" :
                    (p.revents & POLLHUP) ? "hangup" : "error");
            ring_release_last();
            return 0;
        }
    }
}

void ring_stats(int fd) {
    if (!ring_on) return;
    struct tpacket_stats s;
    socklen_t sl = sizeof s;
    memset(&s, 0, sizeof s);
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &s, &sl) == 0 && s.tp_drops)
        fprintf(stderr, "  kernel : %u packet(s) dropped by the ring buffer\n", s.tp_drops);
}

/* Non-blocking ring read: return the next frame that is already in the ring
 * (TP_STATUS_USER) without ever polling.  Returns 1 = frame, 0 = none ready.
 * Used by the batch drain so a single poll wakeup can consume every frame the
 * kernel queued, instead of one frame per syscall round-trip. */
static int ring_next_nowait(int fd, uint8_t **pkt, size_t *cap, size_t *wire,
                            struct timespec *ts, int *have_dir, int *out, char *ifn) {
    const size_t fsz = ring_req.tp_frame_size;
    (void)fd;

    /* release the frame we handed out on the previous call (shared state with
     * ring_next so the two readers don't leak each other's frames) */
    ring_release_last();
    for (size_t off = 0; off < ring_len; off += fsz) {
        size_t o = (ring_scan_off + off) < ring_len ? ring_scan_off + off
                                                    : (ring_scan_off + off) - ring_len;
        struct tpacket2_hdr *h = (struct tpacket2_hdr *)(ring_map + o);
        if (!(h->tp_status & TP_STATUS_USER)) continue;

        *pkt = ring_map + o + h->tp_mac;
        *cap = h->tp_snaplen;
        *wire = h->tp_len;
        ts->tv_sec = (time_t)h->tp_sec;
        ts->tv_nsec = (long)h->tp_nsec;
        struct sockaddr_ll *sll = (struct sockaddr_ll *)
            ((uint8_t *)h + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll));
        *have_dir = 1;
        *out = (sll->sll_pkttype == PACKET_OUTGOING);
        if (!if_indextoname(sll->sll_ifindex, ifn))
            snprintf(ifn, IF_NAMESIZE, "if%d", sll->sll_ifindex);

        ring_last_h = h;
        ring_scan_off = o + fsz;
        if (ring_scan_off >= ring_len) ring_scan_off = 0;
        return 1;
    }
    return 0;
}

/* Batch drain: process every ring frame that is ready right now, up to maxn,
 * then return.  In a burst the kernel may queue dozens of frames per poll, so
 * decoding them all in one pass avoids a poll() per packet.  For non-ring
 * sources (pcap file / plain recvfrom) this behaves exactly like a single
 * capture_next() so callers can use it unconditionally.
 *
 * returns 1 if at least one frame was processed, 0 = none (ring empty, or
 * EOF/stop), -1 on error.  *n_out receives the number processed. */
int capture_drain(int maxn, long *n_out) {
    if (!ring_on || cap.pcap_mode) {
        /* single-shot fall back: the caller's normal path */
        *n_out = 0;
        return -2;                              /* -2 = not a ring source */
    }
    if (maxn <= 0) maxn = 64;
    long done = 0;
    static uint8_t buf[65536];                  /* unused for ring, kept for API */
    (void)buf;
    while (done < maxn && !g_stop) {
        uint8_t *rp = NULL;
        size_t capn = 0, wiren = 0;
        struct timespec ts = {0, 0};
        int hd = 0, o = 0;
        char ifn[IF_NAMESIZE] = "";
        int rc = ring_next_nowait(cap.fd, &rp, &capn, &wiren, &ts, &hd, &o, ifn);
        if (rc != 1) break;
        process_frame(rp, capn, wiren, &ts, ifn, hd, o);
        done++;
        if (cfg.count > 0 && (long long)st.shown >= cfg.count) break;
    }
    *n_out = done;
    return done > 0 ? 1 : 0;
}

/* ---------- capture source (shared by plain loop and TUI) ---------- */

/* read the next frame into buf; returns 1 = frame, 0 = EOF/stop, -1 = error */
int capture_next(uint8_t *buf, size_t bufsz, const uint8_t **frame_out,
                        size_t *cap_out, size_t *wire, struct timespec *ts,
                        int *have_dir, int *out, char *ifn) {
    size_t capn = 0, wiren = 0;
    int hd = 0, o = 0, rc;
    const uint8_t *frame = buf;

    ifn[0] = 0;
    if (cap.pcap_mode) {
        rc = pcapin_next(&cap.pr, buf, bufsz, &capn, &wiren, ts);
        if (rc <= 0) return rc;
        g_linktype = cap.pr.linktype;
        snprintf(ifn, IF_NAMESIZE, "file");
    } else if (ring_on) {
        uint8_t *rp = NULL;
        int rrc = ring_next(cap.fd, &rp, &capn, &wiren, ts, &hd, &o, ifn);
        if (rrc != 1) return rrc;               /* 0 = stop, 2 = no frame yet */
        frame = rp;
    } else {
        struct sockaddr_ll sl;
        socklen_t slen = sizeof sl;
        ssize_t n = recvfrom(cap.fd, buf, bufsz, 0, (struct sockaddr *)&sl, &slen);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return 2;                          /* caller decides (tui polls) */
            fprintf(stderr, "ch1m3ra: recvfrom: %s\n", strerror(errno));
            return -1;
        }
        capn = (size_t)n;
        wiren = capn;
        clock_gettime(CLOCK_REALTIME, ts);
        if (sl.sll_ifindex && if_indextoname(sl.sll_ifindex, ifn) == NULL)
            snprintf(ifn, IF_NAMESIZE, "if%d", sl.sll_ifindex);
        hd = 1;
        o = (sl.sll_pkttype == PACKET_OUTGOING);
    }
    *frame_out = frame;
    *cap_out = capn;
    *wire = wiren;
    *have_dir = hd;
    *out = o;
    return 1;
}

/* decode + filter + record one frame; returns 1 if it was displayed */
int process_frame(const uint8_t *frame, size_t capn, size_t wire,
                         const struct timespec *ts, const char *ifn,
                         int have_dir, int out) {
    st.cap++;
    st.bytes += capn;
    if ((cap.pcap_mode || cfg.evasion) && cfg.bfilter && !bpf_run(frame, (uint32_t)capn)) {
        st.filtered++;
        return 0;
    }
    packet_t pkt;
    decode(&pkt, frame, capn, wire, ts, ifn, have_dir, out);

    /* IPv4/IPv6 fragment reassembly (-A): if this fragment completes a
     * datagram, decode and report the assembled packet instead of the
     * raw fragment.  Incomplete fragments are still shown as IP-FRAG. */
    if (cfg.reasm && pkt.l3) {
        packet_t asm_pkt;
        if (frag_feed(&pkt, pkt.l3, pkt.l3len, &asm_pkt)) {
            pkt = asm_pkt;
        }
    }

    stream_track(&pkt);
    if (!pass_filter(&pkt)) { st.filtered++; return 0; }
    if (cap.wf) {
        if (cfg.rot_size > 0 || cfg.rot_secs > 0) {
            if (pcapw_rotate_need(ts)) pcapw_rotate_do(ts);
        }
        pcap_write(cap.wf, frame, capn, wire, ts);
    }
    if (cfg.follow < 0) {
        if (tui_active) tui_packet_line(&pkt);
        else print_record(&pkt);
    }
    st.shown++;
    if (pkt.malformed) st.bad++;
    st.b[bucket(&pkt)]++;
    if (pkt.app == APP_DNS) st.a[0]++;
    else if (pkt.app == APP_TLS) st.a[1]++;
    else if (pkt.app == APP_HTTP) st.a[2]++;
    else if (pkt.app == APP_QUIC) st.a[3]++;
    return 1;
}

/* Decode benchmark: replay the pcap through the full decode pipeline <iters>
 * times (no output, no writes) and report packets/second + ns/packet.  Uses
 * CLOCK_MONOTONIC so it measures only the decode cost, not file I/O after the
 * first pass (the file is re-opened each pass for a fair read cost too). */
void bench_run(const char *pcap, long iters) {
    if (iters <= 0) iters = 1;
    static uint8_t buf[65536];
    long total = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (long it = 0; it < iters; it++) {
        pcapin_t pr;
        if (pcapin_open(&pr, pcap) != 0) {
            fprintf(stderr, "ch1m3ra: --bench cannot read %s\n", pcap);
            return;
        }
        g_linktype = pr.linktype;
        size_t capn, wire;
        struct timespec ts;
        while (pcapin_next(&pr, buf, sizeof buf, &capn, &wire, &ts) == 1) {
            /* decode-only: parse but suppress all output */
            packet_t pkt;
            decode(&pkt, buf, capn, wire, &ts, "bench", 0, 0);
            total++;
        }
        fclose(pr.f);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (double)(t1.tv_sec - t0.tv_sec)
                + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    double pps = secs > 0 ? (double)total / secs : 0.0;
    double nspp = total > 0 ? (secs * 1e9) / (double)total : 0.0;
    printf("bench: %ld packets x %ld pass(es) = %ld decoded in %.4fs\n",
           total / iters, iters, total, secs);
    printf("bench: %.0f packets/sec, %.1f ns/packet\n", pps, nspp);
}

