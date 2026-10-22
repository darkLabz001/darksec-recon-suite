/* ch1m3ra.h - shared declarations for the ch1m3ra modules.
 *
 * The structs and the config/stats globals live here; every module includes
 * this header.  Cross-module functions are declared at the bottom.        */
#ifndef CH1M3RA_H
#define CH1M3RA_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <strings.h>
#include <time.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
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
typedef struct {
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
    const char *outfmt;   /* -o text|json|csv|zeek|ndjson */
    int    reltime;       /* -e relative timestamps */
    const char *bfilter;  /* -F kernel BPF filter expression */
    int    ring;          /* -Z zero-copy PACKET_RX_RING capture */
    int    tui;           /* -U interactive TUI */
    const char *follow_out; /* --follow-out <file> export followed stream bytes */
    long   rot_size;      /* -W <MB> rotate -w file after N MB (0 = off) */
    long   rot_secs;      /* --rotate-secs N rotate -w file after N seconds */
    int    save_config;   /* --save-config: write settings out and exit */

    /* --- offensive / analysis features --- */
    int    harvest;       /* -K harvest credentials/tokens/banners */
    int    finger;        /* -O passive OS fingerprinting */
    int    talkers;       /* -Y top-talkers / connection matrix */
    int    names;         /* -N mDNS/LLMNR/NBNS name harvest */
    const char *credfile; /* -k <file> append harvested creds to a file */
    int    evasion;       /* -E thorough filtering: parse instead of fixed offsets */
    int    reasm;         /* -A reassemble IPv4/IPv6 fragments */
    int    defense;       /* -D defensive anomaly detection (ARP/ND/DHCP/name/VLAN) */

    /* active tools (all require root + explicit flag) */
    const char *arp_poison;  /* --arp-poison A,B[,iface] */
    const char *syn_scan;    /* --syn-scan host[:ports] */
    const char *dhcp_starve; /* --dhcp-starve iface[:count] */
    const char *replay;      /* --replay <pcap> re-send captured frames */
    const char *rewrite_src; /* --rewrite-src A.B.C.D for replay */
    const char *banner_grab; /* --banner-grab host[:ports] connect + read banner */
    const char *vlan_hop;    /* --vlan-hop iface[:native_vlan]:<tag> double-tag */
    const char *deauth;      /* --deauth <bssid>[,<client>][,<count>] 802.11 deauth */
    const char *beacon_flood;/* --beacon-flood <ssid>[,<count>] fake-AP flood */
    int    banner_timeout_ms;/* --banner-grab read timeout (default 1500) */
    long   bench_iters;      /* --bench <n>: decode the -r pcap n times, report rate */
    long   syn_ports_a, syn_ports_b; /* parsed port range holder */
    int    active;           /* set once any active tool is requested */
} cfg_t;
extern cfg_t cfg;

extern volatile sig_atomic_t g_stop;
void on_sigint(int s);

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

uint16_t rd16(const uint8_t *p);
uint32_t rd32(const uint8_t *p);
uint32_t ck_add(uint32_t sum, const uint8_t *d, size_t n);
uint16_t ck_fold(uint32_t s);
void lstv(char *dst, size_t sz, const char *sep, const char *fmt, va_list ap);
void lst(char *dst, size_t sz, const char *fmt, ...);
void lsts(char *dst, size_t sz, const char *fmt, ...);
void mac_str(const uint8_t *m, char *out, size_t sz);
void md5_hex(const char *s, char *out, size_t sz);

/* ---------- name tables ---------- */
const char *ipproto_name(uint8_t p);
const char *icmp4_name(uint8_t t);
const char *icmp6_name(uint8_t t);
const char *ethertype_name(uint16_t e);
const char *port_service(uint16_t port, int istcp);

/* ---------- decoded packet ---------- */
enum { APP_NONE = 0, APP_DNS, APP_TLS, APP_HTTP, APP_QUIC };

typedef struct {
    struct timespec ts;
    char   ifname[IF_NAMESIZE];
    int    have_dir, outgoing;
    size_t caplen, wirelen;

    int    has_l2;
    uint8_t eth_src[6], eth_dst[6];
    uint16_t etype;
    int    vlan;
    int    qinq;                /* outer 0x88a8 tag seen (double tagging) */
    int    inner_vlan;          /* inner 802.1Q C-tag when qinq (else -1) */

    /* --- 802.11 (radiotap or raw) --- */
    int    wlan;                /* frame is 802.11 */
    int    wlan_type;           /* 0 mgmt, 1 ctrl, 2 data */
    int    wlan_subtype;        /* e.g. 8 beacon, 12 deauth, 4 probe-req */
    char   wlan_ssid[64];       /* SSID from beacon/probe-resp */
    char   wlan_bssid[18];      /* BSSID (addr3) */
    int    wlan_channel;        /* from radiotap if present, else 0 */
    int    wlan_protected;      /* privacy bit set in a beacon */
    int    wlan_deauth;         /* deauthentication/disassoc frame */

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

    /* L3 view for fragment reassembly: points at the IPv4/IPv6 header */
    const uint8_t *l3;
    size_t l3len;

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
    /* TLS certificate (from a Certificate handshake message) */
    char   cert_subject[192];   /* CN of the leaf subject */
    char   cert_issuer[192];    /* CN of the leaf issuer */
    char   cert_san[256];       /* comma-joined subjectAltName DNS entries */
    char   cert_valid[48];      /* "notBefore..notAfter" (YYYY-MM-DD) */
    int    cert_n;              /* number of certificates in the chain */
    /* JA3 TLS client fingerprint */
    char   ja3[33];             /* MD5 hex of the ClientHello fields */
    char   ja3_str[256];        /* the raw "ver,ciphers,ext,curves,fmt" string */
    int    ech;                 /* ECH (encrypted client hello) extension seen */
    /* JA4 fingerprint (FoxIO spec): deterministic string, not a hash */
    char   ja4[64];
    /* HTTP */
    char   http_line[256];     /* request line or status line */
    char   http_host[192];
    int    http_code;
    int    doh;                 /* DNS-over-HTTPS request seen */
    int    dot;                 /* DNS-over-TLS (port 853) */
    /* HTTP/2 */
    char   h2_type[24];         /* frame type name */
    uint32_t h2_stream;         /* stream id */
    char   h2_method[12];       /* :method from HPACK */
    char   h2_path[256];        /* :path from HPACK */
    char   h2_authority[192];   /* :authority (Host) from HPACK */
    char   h2_useragent[160];   /* user-agent from HPACK */
    int    h2_headers;          /* number of decoded header fields */

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

    /* --- structured protocol decoders (SMB2 / RDP / LDAP / Kerberos) --- */
    char   proto[16];          /* "smb2", "rdp", "ldap", "kerberos" */
    char   proto_s[160];       /* short human summary of the message */
    int    ldap_msg;           /* LDAP messageID (0 if not LDAP) */

    /* --- QUIC / HTTP3 (UDP 443) --- */
    char   quic_ver[32];       /* version string, e.g. "v1", "draft-29", "negotiation" */
    char   quic_type[24];      /* initial, 0-rtt, handshake, 1-rtt, retry, version-neg */
    char   quic_sni[192];      /* SNI from the ClientHello inside a QUIC Initial */
    int    quic_dcid_len;      /* destination connection id length */
    char   quic_dcid[48];      /* hex destination connection id */

    /* --- passive OS fingerprint (-O): filled by finger_observe --- */
    char   os_guess[64];       /* e.g. "Linux 5.x", "Windows 10/11" */

    const char *err;
    int malformed;
} packet_t;

/* credential kinds for harvest */
enum { CRED_NONE = 0, CRED_BASIC, CRED_BEARER, CRED_FTP, CRED_POP3, CRED_IMAP,
       CRED_SMTP, CRED_TELNET, CRED_FORM, CRED_SNMP, CRED_COOKIE,
       CRED_NTLM, CRED_LDAP, CRED_KERB };

/* ---------- stats ---------- */
typedef struct {
    unsigned long long cap, shown, filtered, bad, bytes;
    unsigned long long b[8];    /* tcp udp icmp icmpv6 arp ip ipv6 other */
    unsigned long long a[4];    /* dns tls http quic */
    unsigned long long creds;   /* credentials/tokens harvested */
    unsigned long long banners; /* service banners seen */
    unsigned long long names;   /* names learned via mDNS/LLMNR/NBNS */
    unsigned long long anoms;   /* defensive anomalies flagged (-D) */
} stats_t;
extern stats_t st;

int bucket(const packet_t *p);
const char *bucket_name(int i);

/* ---------- decoding ---------- */
void tcp_flags_str(uint16_t f, char *out, size_t sz);
void tcp_opts_str(const uint8_t *o, size_t n, char *out, size_t sz);
void decode_l4(packet_t *p, const uint8_t *seg, size_t avail, size_t total,
               uint8_t nh, int is_v6);
void decode_ipv4(packet_t *p, const uint8_t *b, size_t len);
void decode_ipv6(packet_t *p, const uint8_t *b, size_t len);
void decode(packet_t *p, const uint8_t *f, size_t cap, size_t wire,
            const struct timespec *ts, const char *ifname, int have_dir, int out);
void decode_app(packet_t *p);
void decode_banner(packet_t *p, const uint8_t *b, size_t n);
void decode_proto(packet_t *p, const uint8_t *b, size_t n);
void decode_arp(packet_t *p, const uint8_t *b, size_t len);
void decode_wlan(packet_t *p, const uint8_t *f, size_t cap, int radiotap);
int  ck_ok_incl(const uint8_t *d, size_t n);
uint16_t l4_cksum(const packet_t *p, const uint8_t *seg, size_t n, int is_v6, uint8_t proto);

/* ---------- application layer ---------- */
const char *tls_ver_str(uint16_t v, char *buf, size_t sz);
const char *tls_cipher_name(uint16_t c);
const char *dns_type_name(uint16_t t);
const char *dns_rcode_name(int r);
const char *dns_opcode_name(int o);
int http_hdr(const uint8_t *b, size_t n, const char *key, char *out, size_t sz);
int looks_http(const uint8_t *b, size_t n);

/* ---------- harvest ---------- */
void harvest(packet_t *p);
const char *cred_kind_name(int k);
void credfile_close(void);

/* ---------- recon ---------- */
#define NHOST 512
#define NCONV 1024
extern unsigned hn;
extern unsigned cn;
void finger_observe(packet_t *p);
void name_learn(packet_t *p);
void talkers_observe(const packet_t *p);
void finger_stats(FILE *o);
void talkers_stats(FILE *o);
void names_stats(FILE *o);
void recon_cleanup(void);
unsigned recon_nhosts(void);
void recon_cleanup_tables(void);

/* TUI accessors: emit ranked host / conversation lines through a callback */
void finger_hosts_each(void (*cb)(const char *line, void *ctx), void *ctx, int max);
void talkers_each(void (*cb)(const char *line, void *ctx), void *ctx, int max);

/* ---------- config file (--load-config / TUI :save / :load) ---------- */
const char *config_path(void);
int  config_save(char *err, size_t errsz);
int  config_load(const char *path, char *err, size_t errsz);

/* ---------- defensive anomaly detection (-D) ---------- */
void defense_observe(const packet_t *p);
void defense_report(const packet_t *p, const char *kind, const char *detail);
void defense_stats(FILE *o);

/* ---------- fragment reassembly (-A) ---------- */
int  frag_feed(const packet_t *p, const uint8_t *l3, size_t l3len, packet_t *out);
void frag_stats(FILE *o);
void frag_cleanup(void);

/* ---------- flows (TCP streams + UDP) ---------- */
void stream_track(packet_t *p);
void stream_follow_emit(const packet_t *p, const uint8_t *data, size_t n);
void streams_stats(FILE *o);
void streams_cleanup(void);

/* ---------- filtering ---------- */
int proto_match(const packet_t *p, const char *req);
int pass_filter(const packet_t *p);

/* ---------- printing ---------- */
void print_record(const packet_t *p);
void print_zeek_headers(void);
void print_zeek(const packet_t *p);
void print_ndjson(const packet_t *p);
double rel_secs(const struct timespec *ts);
const char *csum_val(int v);
const char *csum_str(int v);
const char *pcol(const packet_t *p);
void fmt_ep(const packet_t *p, int is_src, char *out, size_t sz);

/* ---------- pcap file I/O (pcap + pcapng) ---------- */
typedef struct {
    FILE *f;
    int   swap, ns;      /* pcap: byte order / nanosecond timestamps */
    int   ng;            /* 1 = pcapng input */
    int   ng_swap;       /* pcapng: byte order of the section */
    int   ng_endian;     /* pcapng interface tsresol handled */
    int   if_tsresol;    /* 10^-n seconds per tick (default 6 = micro) */
    int   if_tsresol_bin;/* tsresol was a power-of-2 divisor */
    char  ifname[16];
    uint32_t linktype;   /* DLT: 1=EN10MB, 113=SLL, 127=radiotap, 105=802.11 */
} pcapin_t;
uint32_t get32(const uint8_t *d, int swap);
void put32(uint8_t *d, uint32_t v);
int pcapin_open(pcapin_t *p, const char *path);
int pcapin_next(pcapin_t *p, uint8_t *buf, size_t bufsz, size_t *caplen,
                size_t *wirelen, struct timespec *ts);

/* writer: pick pcap or pcapng from the path / explicit fmt */
#define PCAPW_PCAP  0
#define PCAPW_PCAPNG 1
typedef struct { FILE *f; int fmt; uint16_t if_id; } pcapw_t;
pcapw_t *open_pcap_write(const char *path);          /* fmt by extension */
pcapw_t *open_pcap_write_fmt(const char *path, int fmt);
void pcap_write(pcapw_t *w, const uint8_t *b, size_t cap, size_t wire,
                const struct timespec *ts);
void pcap_write_close(pcapw_t *w);

/* ---------- pcap writer rotation (-w with -W / --rotate-secs) ---------- */
void pcapw_rotate_init(const char *path);
int  pcapw_rotate_need(const struct timespec *ts);
void pcapw_rotate_do(const struct timespec *ts);

/* ---------- --follow-out: export followed stream payload as a pcap ---------- */
void follow_out_open(const char *path);
void follow_out_write(const uint8_t *b, size_t cap, size_t wire,
                      const struct timespec *ts);
void follow_out_close(void);

/* ---------- BPF ---------- */
void bpf_compile(const char *expr);
int bpf_run(const uint8_t *frame, uint32_t caplen);
void bpf_attach(int fd);

/* ---------- capture sources ---------- */
typedef struct {
    pcapin_t pr;
    pcapw_t *wf;
    int      fd;
    int      ifindex;
    int      pcap_mode;
    int      started;
} cap_t;
extern cap_t cap;
/* DLT of the frame currently being decoded (set by the capture sources before
 * decode(); 0 = plain Ethernet, so live capture keeps its default). */
extern uint32_t g_linktype;

int open_live(const char *iface, int *ifindex_out);
void list_ifaces(void);
extern uint8_t *ring_map;
extern size_t   ring_len;
extern struct tpacket_req ring_req;
int ring_setup(int fd);
void ring_stats(int fd);
void bench_run(const char *pcap, long iters);
void capture_init(void);
int capture_next(uint8_t *buf, size_t bufsz, const uint8_t **frame_out,
                 size_t *cap_out, size_t *wire, struct timespec *ts,
                 int *have_dir, int *out, char *ifn);
int capture_drain(int maxn, long *n_out);
int process_frame(const uint8_t *f, size_t capn, size_t wire,
                  const struct timespec *ts, const char *ifname,
                  int have_dir, int out);
void print_stats(void);

/* ---------- TUI ---------- */
extern int tui_active;
void tui_packet_line(const packet_t *p);
int  tui_run(void);

/* ---------- craft / active tools ---------- */
void arp_poison_run(const char *spec, const char *iface);
void syn_scan_run(const char *spec, const char *iface);
void banner_grab_run(const char *spec, const char *iface, int timeout_ms);
void vlan_hop_run(const char *spec, const char *iface);
void deauth_run(const char *spec, const char *iface);
void beacon_flood_run(const char *spec, const char *iface);
void dhcp_starve_run(const char *spec, const char *iface);
void replay_run(const char *pcap, const char *rewrite, const char *iface);

/* ---------- misc ---------- */
void usage(FILE *o, const char *argv0);

#endif /* CH1M3RA_H */
