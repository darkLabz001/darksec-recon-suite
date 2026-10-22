/* tui.c - interactive TUI (-U) */

#include "ch1m3ra.h"

/* ---------- interactive TUI (-U) ----------
 * Full-screen dashboard driven in the same process as the capture: keys are
 * polled between packets, and the capture source is only read while running
 * so "stop" is instant.  Raw termios + ANSI escapes, no ncurses.           */
#define TUI_LOGMAX 4096
#define NSPARK 48            /* seconds of packet-rate history for the sparkline */
#define TUI_ACC(_sum, _n) (((_n) > 0) ? ((_sum) / (unsigned long long)(_n)) : 0)

/* capture source context; defined in full in the capture-source section */

int  capture_next(uint8_t *buf, size_t bufsz, const uint8_t **frame_out,
                         size_t *cap_out, size_t *wire, struct timespec *ts,
                         int *have_dir, int *out, char *ifn);
int  process_frame(const uint8_t *frame, size_t capn, size_t wire,
                          const struct timespec *ts, const char *ifn,
                          int have_dir, int out);
static int tui_body_top(void);

/* row colours for the packet log (index into tui_color()) */
enum {
    TC_DEF = 0, TC_TCP, TC_UDP, TC_ICMP, TC_ICMP6, TC_ARP, TC_IP, TC_IP6,
    TC_OTHER, TC_BAD, TC_HIT, TC_WLAN, TC_MGMT, TC_DNS, TC_TLS, TC_HTTP,
    TC_QUIC, TC_N
};

static struct {
    int      running;        /* capture active (start/stop via s / x) */
    int      logn;           /* entries used */
    int      loghead;        /* next overwrite slot */
    int      scroll;         /* 0 = follow tail, >0 = lines back from tail */
    int      follow_on;      /* -T all-streams toggle from the TUI */
    int      panel;          /* 0 packets, 1 hits, 2 hosts, 3 talkers */
    int      hitn, hithead;  /* credential/banner "hits" ring */
    char    *line[TUI_LOGMAX];
    uint8_t  lcolor[TUI_LOGMAX];   /* row colour, parallel to line[] */
    char    *detail[TUI_LOGMAX];   /* full decode of the row (lazy-built, may be NULL) */
    char    *hit[TUI_LOGMAX];
    char    *dyn[512];       /* rendered host/talker pane lines (rebuilt) */
    int      dynn;
    char    *side[TUI_LOGMAX]; /* right-hand dashboard panel lines (packets view) */
    int      siden;          /* number of side[] lines */
    int      sideshown;      /* lines painted in the last frame (ascii fallback) */
    /* command prompt (: opens it) */
    int      prompt_on;
    char     prompt[256];
    int      prompt_len;
    /* search (/ opens it): matches highlighted, n/N jump between them */
    int      search_on;
    char     search[128];
    int      search_len;
    int      search_n;       /* number of matches for the current query */
    /* detail pane (Enter toggles): full decode of the selected row */
    int      detail_on;
    int      detail_scroll;
    int      last_sel;       /* selection at the previous render (reset detail scroll) */
    /* help overlay (? toggles): key reference drawn over the body */
    int      help_on;
    char     status[320];    /* last command result, shown in the footer */
    struct timespec last_render;  /* throttles redraws; zero forces one */
    struct timespec started;      /* capture start (elapsed + average rate) */
    int      cols, rows;          /* last known terminal size */
    /* rate history over the last second, for the header rate readout */
    unsigned long long show_prev;
    struct timespec    show_t;
    unsigned           rate;      /* packets/second shown right now (EMA-free) */
    char    *own_proto;      /* TUI-owned copies of the live :proto/:host filters */
    char    *own_host;
    /* per-second packet-rate sparkline (last NSPARK seconds) */
    unsigned long long spark_seen;      /* st.shown at the last tick */
    unsigned           spark[NSPARK];   /* packets in each of the last N seconds */
    int                spark_i;         /* current slot */
    struct timespec    spark_t;         /* last tick time */
    /* escape-sequence assembler (mouse / cursor keys may split across reads) */
    char               esc[32];
    int                esc_len;
    int      width;          /* terminal width of the last painted frame */
    int      height;         /* terminal height of the last painted frame */
} tui;

/* set by the SIGWINCH handler; the main loop repaints and clears it */
static volatile sig_atomic_t tui_resized;

/* chrome colours (stripped at flush time when -C / NO_COLOR disables colour) */
#define T_RST "\x1b[0m"
#define T_BLD "\x1b[1;37m"
#define T_DIM "\x1b[90m"
#define T_GRN "\x1b[92m"
#define T_YEL "\x1b[93m"
#define T_RED "\x1b[91m"
#define T_REV "\x1b[7m"      /* reverse video: selection (an attribute, kept under NO_COLOR) */
#define T_UND "\x1b[4m"      /* underline: search match */

/* Remove colour SGR sequences from a rendered buffer, keeping attributes
 * (reverse/underline) so the selection + search markers survive NO_COLOR. */
static void tui_strip_color(char *s) {
    char *d = s;
    while (*s) {
        if (s[0] == '\x1b' && s[1] == '[') {
            char *e = s + 2;
            while (*e && !(*e >= '@' && *e <= '~')) e++;
            if (*e == 'm') {
                int keep = 0, reset = 0;
                char *p = s + 2;
                while (p < e) {
                    int v = 0;
                    while (p < e && *p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
                    if (v == 7 || v == 4) keep = 1;
                    if (v == 0) reset = 1;
                    if (p < e) p++;             /* skip ';' */
                }
                if (keep && !reset) { while (s <= e) *d++ = *s++; continue; }
                s = e + 1; continue;            /* drop the colour/reset sequence */
            }
        }
        *d++ = *s++;
    }
    *d = 0;
}

/* map a row colour index to an ANSI escape (empty when -C disabled colours) */static const char *tui_color(int c) {
    if (!cfg.color) return "";
    switch (c) {
        case TC_TCP:   return "\x1b[92m";   /* bright green */
        case TC_UDP:   return "\x1b[96m";   /* bright cyan */
        case TC_ICMP:  return "\x1b[93m";   /* bright yellow */
        case TC_ICMP6: return "\x1b[95m";   /* bright magenta */
        case TC_ARP:   return "\x1b[94m";   /* bright blue */
        case TC_IP:    return "\x1b[32m";   /* green */
        case TC_IP6:   return "\x1b[36m";   /* cyan */
        case TC_OTHER: return "\x1b[90m";   /* dim */
        case TC_BAD:   return "\x1b[1;91m"; /* bold red */
        case TC_HIT:   return "\x1b[1;93m"; /* bold yellow */
        case TC_WLAN:  return "\x1b[95m";
        case TC_MGMT:  return "\x1b[95m";
        case TC_DNS:   return "\x1b[96m";
        case TC_TLS:   return "\x1b[92m";
        case TC_HTTP:  return "\x1b[93m";
        case TC_QUIC:  return "\x1b[96m";
        default:       return "\x1b[0m";
    }
}

/* pick a row colour from a decoded packet */
static int tui_color_of(const packet_t *p) {
    if (p->malformed || p->err) return TC_BAD;
    if (p->cred_kind || p->token[0]) return TC_HIT;
    if (p->wlan) return p->wlan_deauth ? TC_BAD : TC_WLAN;
    if (p->app == APP_DNS)  return TC_DNS;
    if (p->app == APP_TLS)  return TC_TLS;
    if (p->app == APP_HTTP) return TC_HTTP;
    if (p->app == APP_QUIC) return TC_QUIC;
    if (p->has_arp) return TC_ARP;
    if (p->has_icmp) return p->icmp_ver == 6 ? TC_ICMP6 : TC_ICMP;
    if (p->has_tcp) return TC_TCP;
    if (p->has_udp) return TC_UDP;
    if (p->ip_ver == 4) return TC_IP;
    if (p->ip_ver == 6) return TC_IP6;
    return TC_OTHER;
}

/* pane names for the header / footer */
static const char *tui_pane_name(int p) {
    switch (p) {
        case 1: return "hits";
        case 2: return "hosts";
        case 3: return "talkers";
        default: return "packets";
    }
}

static struct termios tui_saved;      /* stdin (input) settings */
static struct termios tui_saved_out;  /* stdout settings */
static int tui_raw;
static int tui_raw_out;

static void tui_enter_raw(void) {
    if (!isatty(STDIN_FILENO)) return;
    if (tcgetattr(STDIN_FILENO, &tui_saved) != 0) return;
    struct termios t = tui_saved;
    t.c_lflag &= ~(ICANON | ECHO);
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
    tui_raw = 1;

    /* stdout: turn OFF output post-processing (OPOST|ONLCR).  Otherwise the
     * terminal rewrites each '\n' we write into "\r\n", so our "\r\n" lands as
     * "\r\r\n" - which nudges the cursor and produced the shimmering/jitter.
     * Doing this on stdout (a different fd to stdin, even on the same tty)
     * makes the frame bytes we emit exactly the bytes the terminal sees. */
    if (isatty(STDOUT_FILENO) && tcgetattr(STDOUT_FILENO, &tui_saved_out) == 0) {
        struct termios o = tui_saved_out;
        o.c_oflag &= ~(OPOST);
        tcsetattr(STDOUT_FILENO, TCSANOW, &o);
        tui_raw_out = 1;
    }
}
static void tui_leave_raw(void) {
    if (tui_raw) { tcsetattr(STDIN_FILENO, TCSANOW, &tui_saved); tui_raw = 0; }
    if (tui_raw_out) { tcsetattr(STDOUT_FILENO, TCSANOW, &tui_saved_out); tui_raw_out = 0; }
}
static void tui_term_restore(void) {
    tui_leave_raw();
    /* cursor on, mouse tracking off, leave alt screen */
    fputs("\x1b[?1006l\x1b[?1000l\x1b[?25h\x1b[?1049l", stdout);
    fflush(stdout);
}
static void tui_panic(int sig) { (void)sig; tui_term_restore(); _exit(128); }
static void tui_on_winch(int sig) { (void)sig; tui_resized = 1; }

/* push one formatted log line (oldest overwritten once the ring is full) */
static void tui_logc(int color, const char *detail, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    int slot = tui.loghead;
    free(tui.line[slot]);
    tui.line[slot] = strdup(buf);
    tui.lcolor[slot] = (uint8_t)color;
    free(tui.detail[slot]);
    tui.detail[slot] = detail ? strdup(detail) : NULL;
    tui.loghead = (tui.loghead + 1) % TUI_LOGMAX;
    if (tui.logn < TUI_LOGMAX) tui.logn++;
    if (tui.scroll) tui.scroll++;   /* hold position while scrolled back */
}

/* convenience: default-coloured, no detail */
static void tui_logf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    tui_logc(TC_DEF, NULL, "%s", buf);
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

/* Build a multi-line, sectioned decode of a packet for the detail pane.
 * Returns the number of characters written (buffer is always NUL-terminated). */
static size_t tui_detail(const packet_t *p, char *buf, size_t sz) {
    size_t o = 0;
#define DADD(...) do {                                                    \
        if (o < sz) {                                                     \
            int _w = snprintf(buf + o, sz - o, __VA_ARGS__);              \
            if (_w > 0) o += (size_t)_w;                                  \
            if (o >= sz) o = sz - 1;                                      \
        }                                                                 \
    } while (0)

    char tbuf[32];
    struct tm tm;
    localtime_r(&p->ts.tv_sec, &tm);
    strftime(tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", &tm);

    DADD("frame    %s.%09ld  iface %s  dir %s  len %zu",
         tbuf, (long)p->ts.tv_nsec, p->ifname[0] ? p->ifname : "-",
         p->have_dir ? (p->outgoing ? "out" : "in") : "?", p->caplen);
    if (p->wirelen != p->caplen) DADD(" (wire %zu)", p->wirelen);
    DADD("\n");

    /* L2 */
    if (p->wlan) {
        DADD("802.11   type %s  subtype %d",
             p->wlan_type == 0 ? "mgmt" : p->wlan_type == 1 ? "ctrl" : "data",
             p->wlan_subtype);
        if (p->wlan_bssid[0]) DADD("  bssid %s", p->wlan_bssid);
        if (p->wlan_channel) DADD("  ch %d", p->wlan_channel);
        if (p->wlan_ssid[0]) DADD("  ssid \"%s\"", p->wlan_ssid);
        if (p->wlan_protected) DADD("  protected");
        if (p->wlan_deauth) DADD("  DEAUTH");
        DADD("\n");
    }
    if (p->has_l2 && !p->wlan) {
        char a[24], b[24];
        mac_str(p->eth_src, a, sizeof a);
        mac_str(p->eth_dst, b, sizeof b);
        DADD("L2       %s -> %s  ethertype 0x%04x %s", a, b, p->etype,
             ethertype_name(p->etype) ? ethertype_name(p->etype) : "");
        if (p->vlan >= 0) {
            if (p->inner_vlan >= 0) DADD("  QinQ %d.%d", p->vlan, p->inner_vlan);
            else DADD("  vlan %d", p->vlan);
        }
        DADD("\n");
    }

    /* ARP */
    if (p->has_arp && p->arp_ok) {
        char m[24];
        if (p->arp_op == 1) DADD("ARP      request  who-has %s tell %s\n", p->arp_tpa, p->arp_spa);
        else if (p->arp_op == 2) {
            mac_str(p->arp_sha, m, sizeof m);
            DADD("ARP      reply    %s is-at %s\n", p->arp_spa, m);
        } else DADD("ARP      op %u  %s -> %s\n", p->arp_op, p->arp_spa, p->arp_tpa);
    }

    /* L3 */
    if (p->ip_ver) {
        DADD("L3       IPv%d  %s -> %s  ttl %u  id %u",
             p->ip_ver, p->src_s, p->dst_s, p->ttl, p->ip_id);
        if (p->df || p->mf || p->frag_off)
            DADD("  frag df=%d mf=%d off=%d", p->df, p->mf, p->frag_off);
        DADD("  csum %s", p->ip_csum == 1 ? "ok" : p->ip_csum == 0 ? "BAD" : "n/a");
        if (p->ext_s[0]) DADD("  ext[%s]", p->ext_s);
        DADD("\n");
    }

    /* L4 */
    if (p->has_tcp) {
        DADD("L4       TCP  %s:%u -> %s:%u  [%s]  seq %u  ack %u  win %u",
             p->src_s, p->sport, p->dst_s, p->dport, p->flags_s,
             p->seq, p->ack, p->win);
        if (p->opts_s[0]) DADD("  opts[%s]", p->opts_s);
        if (p->stream_id > 0) DADD("  stream #%d", p->stream_id);
        DADD("\n");
    } else if (p->has_udp) {
        DADD("L4       UDP  %s:%u -> %s:%u  len %u", p->src_s, p->sport,
             p->dst_s, p->dport, p->udp_len);
        if (p->stream_id > 0) DADD("  stream #%d", p->stream_id);
        DADD("\n");
    } else if (p->has_icmp) {
        DADD("L4       ICMPv%d  %s  type %u code %u  id %u seq %u\n",
             p->icmp_ver, p->icmp_ver == 6 ? icmp6_name(p->icmp_type)
                                           : icmp4_name(p->icmp_type),
             p->icmp_type, p->icmp_code, p->icmp_id, p->icmp_seq);
    }
    if (p->l4_csum == 0) DADD("         ! L4 checksum BAD\n");

    /* application */
    if (p->app_s[0]) DADD("app      %s\n", p->app_s);
    if (p->app == APP_DNS) {
        DADD("dns      qr=%d rcode=%d qd=%d an=%d  qtype=%u  name %s\n",
             p->dns_qr, p->dns_rcode, p->dns_qd, p->dns_an, p->dns_qtype, p->dns_name);
        if (p->dns_first[0]) DADD("         answer %s\n", p->dns_first);
    }
    if (p->app == APP_TLS) {
        DADD("tls      %s  ver %s", p->tls_type, p->tls_ver);
        if (p->tls_sni[0]) DADD("  sni %s", p->tls_sni);
        if (p->tls_alpn[0]) DADD("  alpn %s", p->tls_alpn);
        DADD("\n");
        if (p->cert_subject[0]) DADD("         cert subj %s  issuer %s\n",
                                     p->cert_subject, p->cert_issuer);
        if (p->cert_san[0]) DADD("         san %s\n", p->cert_san);
        if (p->ja3[0]) DADD("         ja3 %s\n", p->ja3);
        if (p->ja4[0]) DADD("         ja4 %s\n", p->ja4);
        if (p->ech) DADD("         ECH present\n");
    }
    if (p->app == APP_HTTP) {
        if (p->http_line[0]) DADD("http     %s\n", p->http_line);
        if (p->http_host[0]) DADD("         host %s\n", p->http_host);
        if (p->doh) DADD("         DNS-over-HTTPS\n");
    }
    if (p->app == APP_QUIC)
        DADD("quic     %s %s  sni %s  dcid %s\n", p->quic_ver, p->quic_type,
             p->quic_sni, p->quic_dcid);
    if (p->proto[0]) DADD("proto    %s  %s\n", p->proto, p->proto_s);
    if (p->h2_type[0]) DADD("h2       %s  stream %u  %s %s\n", p->h2_type,
                            p->h2_stream, p->h2_method, p->h2_path);

    /* harvested secrets */
    if (p->cred_kind)
        DADD("CRED     [%s] %s:%u -> %s:%u  user=%s pass=%s\n", p->cred_where,
             p->src_s, p->sport, p->dst_s, p->dport, p->cred_user, p->cred_pass);
    if (p->token[0]) DADD("TOKEN    %s  %s\n", p->token, p->jwt_sub);
    if (p->cookie[0]) DADD("COOKIE   %s\n", p->cookie);
    if (p->banner[0]) DADD("BANNER   %s %s\n", p->svc, p->banner);
    if (p->os_guess[0]) DADD("OS       %s => %s\n", p->src_s, p->os_guess);

    if (p->err) DADD("error    %s\n", p->err);

    /* payload hexdump (first 64 bytes) */
    if (p->payload && p->plen) {
        size_t n = p->plen < 64 ? p->plen : 64;
        DADD("payload  %zu byte%s%s\n", p->plen, p->plen == 1 ? "" : "s",
             p->plen > n ? " (first 64 shown)" : "");
        for (size_t i = 0; i < n; i += 16) {
            DADD("         %04zx  ", i);
            for (size_t j = 0; j < 16; j++) {
                if (i + j < n) DADD("%02x ", p->payload[i + j]);
                else DADD("   ");
                if (j == 7) DADD(" ");
            }
            DADD(" ");
            for (size_t j = 0; j < 16 && i + j < n; j++) {
                unsigned char c = p->payload[i + j];
                DADD("%c", (c >= 32 && c < 127) ? c : '.');
            }
            DADD("\n");
        }
    }
#undef DADD
    return o;
}

/* compact one-line summary of a packet for the log pane */
void tui_packet_line(const packet_t *p) {
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

    char det[4096];
    tui_detail(p, det, sizeof det);
    tui_logc(tui_color_of(p), det,
             "%s.%03ld %-7s%s%4zu  %s%s",
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

static void tui_clear_dyn(void) {
    for (int i = 0; i < tui.dynn; i++) { free(tui.dyn[i]); tui.dyn[i] = NULL; }
    tui.dynn = 0;
    for (int i = 0; i < tui.siden; i++) { free(tui.side[i]); tui.side[i] = NULL; }
    tui.siden = 0;
    tui.sideshown = 0;
}

static void tui_dyn_add(const char *line, void *ctx) {
    (void)ctx;
    if (tui.dynn >= (int)(sizeof tui.dyn / sizeof tui.dyn[0])) return;
    tui.dyn[tui.dynn++] = strdup(line);
}

/* rebuild the host / talker pane content from the recon tables */
static void tui_build_dyn(void) {
    tui_clear_dyn();
    if (tui.panel == 2) finger_hosts_each(tui_dyn_add, NULL, 500);
    else if (tui.panel == 3) talkers_each(tui_dyn_add, NULL, 500);
}

/* ---------- dashboard side panel (packets view, wide terminals) ----------
 * Three stacked mini-cards: protocol mix, top talkers, and whatever was
 * harvested.  Text only; the renderer pads each line to the panel width. */
static void tui_side_add(const char *fmt, ...) {
    if (tui.siden >= (int)(sizeof tui.side / sizeof tui.side[0])) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    tui.side[tui.siden++] = strdup(buf);
}

static void tui_side_talk(const char *line, void *ctx) {
    (void)ctx;
    tui_side_add("%s", line);
}

static void tui_build_side(void) {
    for (int i = 0; i < tui.siden; i++) { free(tui.side[i]); tui.side[i] = NULL; }
    tui.siden = 0;

    /* protocol mix: share of shown packets, largest first (local working copy) */
    unsigned long long v[8];
    unsigned long long tot = 0;
    for (int i = 0; i < 8; i++) { v[i] = st.b[i]; tot += v[i]; }
    tui_side_add("PROTOCOL MIX");
    if (tot == 0) tui_side_add("  (no packets yet)");
    for (int n = 0; n < 8 && tot; n++) {
        int best = -1;
        for (int i = 0; i < 8; i++) {
            if (!v[i]) continue;
            if (best < 0 || v[i] > v[best]) best = i;
        }
        if (best < 0) break;
        int pct = (int)(v[best] * 100 / tot);
        int bars = pct * 12 / 100;
        if (bars < 0) bars = 0;
        if (bars > 12) bars = 12;
        char bar[16];
        for (int k = 0; k < bars; k++) bar[k] = '#';
        bar[bars] = 0;
        tui_side_add("  %-7s %3d%% %s", bucket_name(best), pct, bar);
        v[best] = 0;                                 /* consume for the next pick */
    }

    tui_side_add("");
    tui_side_add("TOP TALKERS");
    int before = tui.siden;
    talkers_each(tui_side_talk, NULL, 6);
    if (tui.siden == before) tui_side_add("  (none)");

    tui_side_add("");
    tui_side_add("HARVEST");
    if (st.creds)                    tui_side_add("  creds  %llu", st.creds);
    if (cfg.finger || cfg.names)     tui_side_add("  hosts  %u", hn);
    if (!st.creds && !cfg.finger && !cfg.names) tui_side_add("  (off)");
}

/* ---------- live command prompt (: in the TUI) ----------
 * Lets the analyst retarget filters and analysis without restarting.  The
 * filters are the same cfg fields the userspace -P/-H/-p filters use, so a
 * change takes effect on the next packet. */
static void tui_cmd(const char *cmd) {
    while (*cmd == ' ') cmd++;
    tui.status[0] = 0;
    if (!strcmp(cmd, "help")) {
        snprintf(tui.status, sizeof tui.status,
                 "p <proto> | h <host> | port <n> | n <count> | "
                 "harvest on|off | finger on|off | names on|off | reasm on|off | "
                 "save | load [file] | filter");
        return;
    }
    char word[64];
    const char *rest = cmd;
    int n = 0;
    while (*rest && *rest != ' ' && n < (int)sizeof word - 1) word[n++] = *rest++;
    word[n] = 0;
    while (*rest == ' ') rest++;

    if (!strcmp(word, "p") || !strcmp(word, "proto")) {
        free(tui.own_proto);                    /* release the previous TUI copy */
        if (*rest && strcmp(rest, "all")) {
            tui.own_proto = strdup(rest);
            cfg.proto = tui.own_proto;
        } else {
            tui.own_proto = NULL;
            cfg.proto = NULL;
        }
        snprintf(tui.status, sizeof tui.status, "proto=%s", cfg.proto ? cfg.proto : "all");
    } else if (!strcmp(word, "h") || !strcmp(word, "host")) {
        free(tui.own_host);
        if (*rest) {
            tui.own_host = strdup(rest);
            cfg.host = tui.own_host;
        } else {
            tui.own_host = NULL;
            cfg.host = NULL;
        }
        snprintf(tui.status, sizeof tui.status, "host=%s", cfg.host ? cfg.host : "off");
    } else if (!strcmp(word, "port")) {
        cfg.port = *rest ? strtol(rest, NULL, 10) : -1;
        snprintf(tui.status, sizeof tui.status, "port=%ld", cfg.port);
    } else if (!strcmp(word, "n")) {
        cfg.count = *rest ? strtol(rest, NULL, 10) : 0;
        snprintf(tui.status, sizeof tui.status, "count=%ld", cfg.count);
    } else if (!strcmp(word, "harvest")) {
        cfg.harvest = !strcmp(rest, "on");
        snprintf(tui.status, sizeof tui.status, "harvest %s", cfg.harvest ? "on" : "off");
    } else if (!strcmp(word, "finger")) {
        cfg.finger = !strcmp(rest, "on");
        snprintf(tui.status, sizeof tui.status, "finger %s", cfg.finger ? "on" : "off");
    } else if (!strcmp(word, "names")) {
        cfg.names = !strcmp(rest, "on");
        snprintf(tui.status, sizeof tui.status, "names %s", cfg.names ? "on" : "off");
    } else if (!strcmp(word, "reasm") || !strcmp(word, "reassemble")) {
        cfg.reasm = !strcmp(rest, "on");
        snprintf(tui.status, sizeof tui.status, "reasm %s", cfg.reasm ? "on" : "off");
    } else if (!strcmp(word, "filter")) {
        /* clear everything */
        free(tui.own_proto); tui.own_proto = NULL;
        free(tui.own_host);  tui.own_host = NULL;
        cfg.proto = cfg.host = NULL; cfg.port = -1;
        snprintf(tui.status, sizeof tui.status, "filters cleared");
    } else if (!strcmp(word, "save")) {
        char err[300];
        if (config_save(err, sizeof err) == 0) snprintf(tui.status, sizeof tui.status, "%s", err);
        else snprintf(tui.status, sizeof tui.status, "\x1b[91m%s", err);
    } else if (!strcmp(word, "load")) {
        char err[300];
        const char *path = *rest ? rest : NULL;
        if (config_load(path, err, sizeof err) == 0) {
            snprintf(tui.status, sizeof tui.status, "%s", err);
            tui_build_dyn();
        } else {
            snprintf(tui.status, sizeof tui.status, "\x1b[91m%s", err);
        }
    } else {
        snprintf(tui.status, sizeof tui.status, "unknown command: %s (try :help)", word);
    }
    tui_build_dyn();
}

static void tui_clear_log(void) {
    for (int i = 0; i < TUI_LOGMAX; i++) {
        free(tui.line[i]); tui.line[i] = NULL;
        free(tui.detail[i]); tui.detail[i] = NULL;
        free(tui.hit[i]);  tui.hit[i] = NULL;
        tui.lcolor[i] = TC_DEF;
    }
    tui.logn = tui.loghead = tui.scroll = 0;
    tui.hitn = tui.hithead = 0;
    tui.search_n = 0;
    tui.detail_on = 1;               /* Wireshark-style: detail pane always on */
    tui.detail_scroll = 0;
    tui_clear_dyn();
}

/* physical slot for visible index i (0 = oldest kept) */
static int tui_slot(int i) {
    int start = (tui.logn == TUI_LOGMAX) ? tui.loghead : 0;
    return (start + i) % TUI_LOGMAX;
}

/* return the i-th visible log line (0 = oldest kept) */
static const char *tui_line_at(int i) {
    if (i < 0 || i >= tui.logn) return "";
    const char *s = tui.line[tui_slot(i)];
    return s ? s : "";
}

/* colour of the i-th visible log line */
static int tui_line_color(int i) {
    if (i < 0 || i >= tui.logn) return TC_DEF;
    return tui.lcolor[tui_slot(i)];
}

/* detail text of the i-th visible log line (NULL if none) */
static const char *tui_line_detail(int i) {
    if (i < 0 || i >= tui.logn) return NULL;
    return tui.detail[tui_slot(i)];
}

/* return the i-th visible hit line (0 = oldest kept) */
static const char *tui_hit_at(int i) {
    if (i < 0 || i >= tui.hitn) return "";
    int start = (tui.hitn == TUI_LOGMAX) ? tui.hithead : 0;
    return tui.hit[(start + i) % TUI_LOGMAX] ? tui.hit[(start + i) % TUI_LOGMAX] : "";
}

/* Roll the per-second packet-rate history forward to 'now'.  Called from the
 * render path; fills any whole seconds that have elapsed since the last tick
 * (so a stall shows as zero-rate slots rather than being skipped). */
static void tui_spark_tick(struct timespec now) {
    if (tui.spark_t.tv_sec == 0) { tui.spark_t = now; tui.spark_seen = st.shown; return; }
    long dsec = now.tv_sec - tui.spark_t.tv_sec;
    if (dsec <= 0) return;
    if (dsec > NSPARK) dsec = NSPARK;           /* cap catch-up */
    unsigned long long delta = st.shown - tui.spark_seen;
    for (long k = 0; k < dsec; k++) {
        tui.spark_i = (tui.spark_i + 1) % NSPARK;
        tui.spark[tui.spark_i] = (k == dsec - 1) ? (unsigned)delta : 0;
    }
    tui.spark_seen = st.shown;
    tui.spark_t = now;
}

/* Build the sparkline string (oldest -> newest) using ASCII bars, showing the
 * last `nbars` seconds (clamped to NSPARK) so it can be sized to fit. */
static void tui_spark_str(char *out, size_t sz, int nbars) {
    if (nbars > NSPARK) nbars = NSPARK;
    if (nbars < 1) nbars = 1;
    unsigned mx = 1;
    for (int i = 0; i < NSPARK; i++) if (tui.spark[i] > mx) mx = tui.spark[i];
    static const char *bars = " .:-=+*#%@";
    size_t o = 0;
    for (int i = 0; i < nbars; i++) {
        /* newest is spark_i; show the last nbars slots, oldest first */
        int idx = (tui.spark_i - (nbars - 1) + i + NSPARK * 2) % NSPARK;
        unsigned v = tui.spark[idx];
        int lvl = (int)((unsigned long long)v * 9 / mx);
        if (lvl < 0) lvl = 0;
        if (lvl > 9) lvl = 9;
        if (o + 2 < sz) out[o++] = bars[lvl];
    }
    out[o] = 0;
}

/* ANSI-aware truncation: copy `s` into out[*n..], stopping after maxcols visible
 * columns (escape sequences are copied but not counted).  A reset is appended. */
static int tui_chw(const char *s);
static void tui_put_trunc(char *out, size_t cap, size_t *n, const char *s, int maxcols) {
    int vis = 0;
    while (*s && vis < maxcols) {
        if (*s == '\x1b') {                       /* copy an escape sequence */
            if (*n + 1 < cap) out[(*n)++] = *s++;
            while (*s && *s != 'm') { if (*n + 1 < cap) out[(*n)++] = *s; s++; }
            if (*s && *n + 1 < cap) out[(*n)++] = *s++;
            continue;
        }
        unsigned char c = (unsigned char)*s;
        int len = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 1;
        int cw = tui_chw(s);                 /* 1 or 2 terminal cells */
        /* never let a wide glyph straddle the right edge: a 2-cell glyph in a
         * 1-cell gap would push the row past `maxcols` and trigger a wrap */
        if (vis + cw > maxcols) { s += len; break; }
        for (int k = 0; k < len && s[k]; k++)
            if (*n + 1 < cap) out[(*n)++] = s[k];
        s += len; vis += cw;
    }
    if (*n + 5 < cap) { out[(*n)++] = '\x1b'; out[(*n)++] = '['; out[(*n)++] = '0'; out[(*n)++] = 'm'; }
    out[*n] = 0;
}

/* visible width of a string with ANSI escapes (escapes and UTF-8 handled,
 * double-width glyphs count as two cells) */
static size_t tui_vislen(const char *s) {
    size_t v = 0;
    while (*s) {
        if (*s == '\x1b') { while (*s && *s != 'm') s++; if (*s) s++; continue; }
        unsigned char c = (unsigned char)*s;
        int len = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 1;
        v += (size_t)tui_chw(s);
        s += len;
    }
    return v;
}

/* case-insensitive substring test (avoids relying on strcasestr) */
static int tui_has_match(const char *hay, const char *needle) {
    if (!needle || !needle[0]) return 0;
    size_t nl = strlen(needle);
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < nl && hay[i] &&
               tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nl) return 1;
    }
    return 0;
}

/* absolute visible index of the row under the cursor (bottom of the viewport) */
static int tui_sel(int total) {
    if (total <= 0) return -1;
    int sel = total - 1 - tui.scroll;
    if (sel < 0) sel = 0;
    if (sel > total - 1) sel = total - 1;
    /* Wireshark-style: never auto-select the synthetic EOF marker */
    if (sel < total) {
        const char *ls = tui_line_at(sel);
        if (ls[0] == '-' && ls[1] == '-' && ls[2] == '-') {
            if (sel > 0) sel--;
        }
    }
    return sel;
}

/* compact byte count: "512", "1.5K", "2.3M" */
static void tui_human(unsigned long long v, char *out, size_t sz) {
    if (v < 1000ULL)             snprintf(out, sz, "%llu", v);
    else if (v < 1000ULL * 1000) snprintf(out, sz, "%.1fK", (double)v / 1000.0);
    else if (v < 1000ULL * 1000 * 1000)
                                 snprintf(out, sz, "%.1fM", (double)v / 1e6);
    else                         snprintf(out, sz, "%.1fG", (double)v / 1e9);
}

/* display width of the UTF-8 character at s (2 for pictograms / CJK), so the
 * fixed packet columns line up even though some glyphs are double-width */
static int tui_chw(const char *s) {
    unsigned char c = (unsigned char)s[0];
    if (c < 0x80) return 1;
    unsigned cp = 0;
    if (c >= 0xF0)      cp = (unsigned)(c & 0x07);
    else if (c >= 0xE0) cp = (unsigned)(c & 0x0F);
    else if (c >= 0xC0) cp = (unsigned)(c & 0x1F);
    else                return 1;
    int len = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : 2;
    for (int k = 1; k < len; k++) {
        if (!s[k]) return 1;
        cp = (cp << 6) | (unsigned)((unsigned char)s[k] & 0x3F);
    }
    if ((cp >= 0x1100 && cp <= 0x115F) ||                  /* Hangul Jamo */
        (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) ||  /* CJK ... Yi */
        (cp >= 0xAC00 && cp <= 0xD7A3) ||                  /* Hangul syllables */
        (cp >= 0xF900 && cp <= 0xFAFF) ||                  /* CJK compat */
        (cp >= 0xFE30 && cp <= 0xFE6F) ||                  /* CJK compat forms */
        (cp >= 0xFF00 && cp <= 0xFF60) ||                  /* fullwidth forms */
        (cp >= 0xFFE0 && cp <= 0xFFE6) ||
        (cp >= 0x1F300 && cp <= 0x1FAFF) ||                /* emoji / pictographs */
        (cp >= 0x20000 && cp <= 0x3FFFD))
        return 2;
    return 1;
}

/* copy UTF-8 `msg` into out, padded to `width` display cells ("~" if clipped) */
static void tui_col_str(const char *msg, int width, char *out, size_t sz) {
    int used = 0;
    size_t o = 0;
    const char *s = msg;
    int clipped = 0;
    while (*s && used < width) {
        int cw = tui_chw(s);
        int len = ((unsigned char)*s) >= 0xF0 ? 4 :
                  ((unsigned char)*s) >= 0xE0 ? 3 :
                  ((unsigned char)*s) >= 0xC0 ? 2 : 1;
        if (used + cw > width) { clipped = 1; break; }
        for (int k = 0; k < len && s[k]; k++)
            if (o + 1 < sz) out[o++] = s[k];
        s += len; used += cw;
    }
    if (*s) clipped = 1;
    if (clipped && width >= 1) {
        /* mark the cut: drop one cell and put '~' at the end */
        if (used == width && o > 0) {
            /* remove a trailing byte of the last glyph to make room */
            while (o > 0 && ((unsigned char)out[o - 1] & 0xC0) == 0x80) o--;
            if (o > 0) o--;
            used--;
        }
        while (used < width - 1 && o + 1 < sz) { out[o++] = ' '; used++; }
        if (o + 1 < sz) out[o++] = '~';
        used++;
    }
    while (used < width && o + 1 < sz) { out[o++] = ' '; used++; }
    out[o] = 0;
}

/* split a stored packet row "HH:MM:SS.mmm PROTO iFACE LEN  summary" into its
 * fixed columns (all NUL-terminated, clipped).  Missing fields are blank. */
static void tui_split_row(const char *ln,
                          char *t, char *pr, char *ifc, char *le, char *sum,
                          size_t sz) {
    const char *p = ln;
    #define TAKE(dst) do {                                              \
        const char *s = p;                                             \
        while (*p && *p != ' ') p++;                                    \
        size_t l = (size_t)(p - s);                                    \
        if (l >= sz) l = sz - 1;                                       \
        memcpy(dst, s, l); dst[l] = 0;                                 \
        while (*p == ' ') p++;                                          \
    } while (0)
    TAKE(t);                  /* timestamp */
    TAKE(pr);                 /* proto     */
    TAKE(ifc);                /* iface     */
    TAKE(le);                 /* length    */
    snprintf(sum, sz, "%s", p);
    #undef TAKE
}

/* append a dim horizontal rule exactly `cols` cells wide to the frame buffer */
static void tui_rule(char *out, size_t cap, size_t *n, int cols, const char *color) {
    size_t o = *n;
    if (color) { while (*color && o + 1 < cap) out[o++] = *color++; }
    for (int i = 0; i < cols && o + 4 < cap; i++) {
        out[o++] = '\xe2'; out[o++] = '\x94'; out[o++] = '\x80';
    }
    if (o + 4 < cap) { out[o++] = '\x1b'; out[o++] = '['; out[o++] = '0'; out[o++] = 'm'; }
    out[o] = 0;
    *n = o;
}

static void tui_render(int rows, int cols) {
    char out[32768];
    size_t n = 0;
    if (cols < 40) cols = 40;
    if (cols > 1000) cols = 1000;
    /* Write at most cols-1 display cells per row.  Filling the final column
     * leaves the real terminal (and xterm) in "pending wrap" state; the next
     * glyph then wraps early and the whole frame drifts one row down per line,
     * which is what pushed the footer off the bottom of the screen. */
    int fw = cols - 1;
    tui.cols = cols; tui.rows = rows;
#define TUI_ADD(...) do {                                            \
        if (n + 4 < sizeof out) {                                    \
            int _w = snprintf(out + n, sizeof out - n, __VA_ARGS__); \
            if (_w > 0) n += (size_t)_w;                             \
            if (n >= sizeof out) n = sizeof out - 1;                 \
        }                                                            \
    } while (0)
#define TUI_LINE(buf, c) do {                                        \
        tui_put_trunc(out, sizeof out, &n, (buf), (c));              \
        TUI_ADD("\x1b[K\r\n");                                       \
    } while (0)
    if (tui.width == 0 || tui.width != cols || tui.height != rows) {
        /* first paint or resized: blank once so stale glyphs can't survive */
        TUI_ADD("\x1b[2J");
        tui.width = cols; tui.height = rows;
    }
    /* home + erase-to-end-of-display: repaint in place with no full-screen
     * blank, which is what caused the flicker on every 50 ms tick */
    TUI_ADD("\x1b[H\x1b[J");

    int filtline = (cfg.proto || cfg.host || cfg.port >= 0) ? 1 : 0;
    int is_hits = (tui.panel == 1);
    int is_dyn  = (tui.panel == 2 || tui.panel == 3);
    int total = is_hits ? tui.hitn : (is_dyn ? tui.dynn : tui.logn);

    /* ---- layout: dashboard grid ----
     *  row 1        title bar (name plaque + iface/colour context)
     *  row 2        metric cards (captured / shown / filtered / malformed / bytes)
     *  row 3        elite band (elapsed, rate, badges, pps sparkline)
     *  row 4        dim rule framing the header block
     *  [filter]     active -P/-H/-p filter line
     *  [1 line]     column header
     *  [body_rows]  rows (with a scrollbar column)
     *  [detail]     rule + detail lines
     *  rows-1       key hints
     *  rows         status / prompt (footer, never scrolled off) */
    int detail_rows = 0, detail_extra = 0;   /* detail extra rows = detail_rows+1 */
    int hex_rows = 0;
    if (tui.detail_on && !is_hits && !is_dyn) {
        /* Wireshark-style: the lower half is split into a details sub-pane and
         * a bytes (hex) sub-pane, each with a title bar, always visible. */
        int lower = rows / 2;
        if (lower < 6) lower = 6;
        detail_rows = lower * 3 / 5;
        if (detail_rows < 3) detail_rows = 3;
        hex_rows = lower - detail_rows;
        if (hex_rows < 3) { hex_rows = 3; detail_rows = lower > 4 ? lower - 3 : 2; }
        detail_extra = detail_rows + hex_rows + 2;   /* +2 title bars */
    }
    /* reserve: 4 header rows + filter + column header + hints + footer = 7 */
    int body_rows = rows - 7 - filtline - detail_extra;
    if (body_rows < 1) body_rows = 1;

    int sidew = 0, side_full = 0;
    if (tui.panel == 0 && fw >= 100 && detail_rows == 0) {
        sidew = fw * 26 / 100;
        if (sidew < 24) sidew = 24;
        if (sidew > 44) sidew = 44;
        if (fw - sidew < 48) sidew = 0;       /* keep the log readable */
    } else if (is_dyn || is_hits) {
        side_full = 1;
    }
    int mainw = sidew ? fw - sidew : fw;

    /* ---- rate: packets shown since the last sample, ~1 Hz ---- */
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (tui.show_t.tv_sec == 0) { tui.show_t = now; tui.show_prev = st.shown; }
        long ds = now.tv_sec - tui.show_t.tv_sec;
        if (ds >= 1) {
            unsigned long long delta = st.shown - tui.show_prev;
            tui.rate = (unsigned)(delta / (unsigned long long)ds);
            tui.show_prev = st.shown;
            tui.show_t = now;
        }
    }

    double el = 0;
    if (tui.started.tv_sec) {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        el = (now.tv_sec - tui.started.tv_sec)
           + (now.tv_nsec - tui.started.tv_nsec) / 1e9;
        if (el < 0) el = 0;
    }
    unsigned long long avg = (el > 0.5) ? (unsigned long long)(st.shown / el) : 0;
    long eh = (long)(el / 3600), emm = (long)((long)el % 3600) / 60, ess = (long)el % 60;

    /* ---- title bar: reverse-video name plaque on the left, context right ---- */
    {
        char hdr[512];
        char left[128], right[128];
        snprintf(left, sizeof left, T_REV T_BLD " ch1m3ra " VERSION " " T_RST
                 " %s" T_RST,
                 tui.running ? T_GRN "● RUNNING" : T_YEL "■ STOPPED");
        snprintf(right, sizeof right,
                 T_DIM "IFACE" T_RST " %s   " T_DIM "COLORS" T_RST " %s",
                 cfg.iface ? cfg.iface : (cap.pcap_mode ? "pcap" : "-"),
                 cfg.color ? "on" : "off");
        int lw = (int)tui_vislen(left), rw = (int)tui_vislen(right);
        int gap = fw - lw - rw;
        if (gap < 1) {
            snprintf(hdr, sizeof hdr, "%s" T_RST, left);
        } else {
            /* pad with spaces to place `right` flush against the right margin */
            snprintf(hdr, sizeof hdr, "%s", left);
            size_t hl = strlen(hdr);
            for (int i = 0; i < gap && hl + 1 < sizeof hdr; i++) hdr[hl++] = ' ';
            hdr[hl] = 0;
            snprintf(hdr + hl, sizeof hdr - hl, "%s" T_RST, right);
        }
        TUI_LINE(hdr, fw);
    }

    /* ---- metric cards, separated by dim vertical rules ---- */
    {
        char card[1024];
        size_t c = 0;
        char hb[32];
        tui_human(st.bytes, hb, sizeof hb);
        /* each fragment goes into its own temp so the compiler never worries
         * about the remaining space in `card` (avoids -Wformat-truncation) */
#define CARD(_label, _col, _val) do {                                   \
        char _frag[128];                                                \
        snprintf(_frag, sizeof _frag,                                   \
                 "  " T_DIM _label T_RST " " _col "%s" T_RST, (_val));  \
        size_t _fl = strlen(_frag);                                     \
        if (c + _fl < sizeof card) { memcpy(card + c, _frag, _fl); c += _fl; } \
    } while (0)
#define VRULE() do {                                                    \
        char _frag[64];                                                 \
        snprintf(_frag, sizeof _frag, T_DIM "  │" T_RST);               \
        size_t _fl = strlen(_frag);                                     \
        if (c + _fl < sizeof card) { memcpy(card + c, _frag, _fl); c += _fl; } \
    } while (0)
        char v_cap[32], v_sho[32], v_fil[32], v_bad[32];
        snprintf(v_cap, sizeof v_cap, "%llu", st.cap);
        snprintf(v_sho, sizeof v_sho, "%llu", st.shown);
        snprintf(v_fil, sizeof v_fil, "%llu", st.filtered);
        snprintf(v_bad, sizeof v_bad, "%llu", st.bad);
        CARD("captured",  T_GRN, v_cap);
        VRULE();
        CARD("shown",     T_GRN, v_sho);
        VRULE();
        CARD("filtered",  T_YEL, v_fil);
        VRULE();
        CARD("malformed", T_RED, v_bad);
        if (fw >= 96) {
            VRULE();
            CARD("bytes", T_GRN, hb);
        }
        card[c] = 0;
        TUI_LINE(card, fw);
#undef CARD
#undef VRULE
    }

    /* ---- elite row: state metrics on the left, sparkline pushed right ---- */
    {
        char band[512];
        size_t b = 0;
#define BAND_ADD(...) do {                                              \
        if (b < sizeof band) {                                          \
            int _w = snprintf(band + b, sizeof band - b, __VA_ARGS__);  \
            if (_w > 0) b += (size_t)_w;                                \
            if (b >= sizeof band) b = sizeof band - 1;                  \
        }                                                               \
    } while (0)
        BAND_ADD("  " T_DIM "elapsed " T_RST "%02ld:%02ld:%02ld",
                 eh, emm, ess);
        BAND_ADD("   " T_DIM "avg " T_RST T_GRN "%llu/s" T_RST, avg);
        if (tui.hitn)           BAND_ADD("   " T_RED "⚑ %d hits" T_RST, tui.hitn);
        if (cfg.harvest)        BAND_ADD("   " T_YEL "creds %llu" T_RST, st.creds);
        if (cfg.finger || cfg.names) BAND_ADD("   " T_YEL "hosts %u" T_RST, hn);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        tui_spark_tick(now);
        unsigned cur = tui.spark[tui.spark_i];
        /* right-align the sparkline block when it fits, else tack it on */
        char spb[128];
        int avail = fw - (int)tui_vislen(band) - 18;
        if (avail > NSPARK) avail = NSPARK;
        if (avail >= 6) {
            char sp[NSPARK + 1];
            tui_spark_str(sp, sizeof sp, avail);
            snprintf(spb, sizeof spb,
                     "  " T_DIM "pps " T_GRN "%u " T_DIM "[" T_GRN "%.*s" T_DIM "]" T_RST,
                     cur, NSPARK, sp);
            int gap = fw - (int)tui_vislen(band) - (int)tui_vislen(spb);
            if (gap >= 1) BAND_ADD("%*s", gap, "");
            BAND_ADD("%s", spb);
        }
        BAND_ADD(T_RST);
        TUI_LINE(band, fw);
#undef BAND_ADD
    }

    /* ---- dim rule framing the header block ---- */
    {
        tui_rule(out, sizeof out, &n, fw, T_DIM);
        TUI_ADD("\x1b[K\r\n");
    }

    /* ---- active filter line ---- */
    if (filtline) {
        char fl[300];
        int fo = 0;
        fo += snprintf(fl + fo, sizeof fl - fo, T_DIM "filter: ");
        if (cfg.proto) fo += snprintf(fl + fo, sizeof fl - fo, "proto=%s ", cfg.proto);
        if (cfg.host)  fo += snprintf(fl + fo, sizeof fl - fo, "host=%s ", cfg.host);
        if (cfg.port >= 0) fo += snprintf(fl + fo, sizeof fl - fo, "port=%ld ", cfg.port);
        snprintf(fl + fo, sizeof fl - fo, "(:filter to clear)" T_RST);
        TUI_LINE(fl, fw);
    }

    /* ---- scrolling window ---- */
    int top = total - body_rows - tui.scroll;
    if (top > total - body_rows) top = total - body_rows;
    if (top < 0) top = 0;
    int sel = tui_sel(total);
    if (sel != tui.last_sel) { tui.detail_scroll = 0; tui.last_sel = sel; }

    /* ---- column header ---- */
    char meta[300];
    int mo = 0;
    if (tui.panel == 0) {
        int tw = 12, pw = 7, iw = 8, lw = 6;    /* time proto iface len */
        int sw = mainw - 1 - tw - pw - iw - lw;
        if (sw < 12) sw = 12;
        mo = snprintf(meta, sizeof meta,
                      T_DIM "%-*s %-*s %-*s %*s  %s" T_RST,
                      tw, "TIME", pw, "PROTO", iw, "IFACE", lw, "LEN", "SUMMARY");
        (void)sw;
        if (total > 0)
            snprintf(meta + mo, sizeof meta - mo, "  " T_DIM "%d/%d%s" T_RST,
                     sel + 1, total, tui.scroll ? " (scrolled)" : "");
    } else {
        const char *pdesc = tui.panel == 1 ? "hits: creds/tokens/banners/os" :
                            tui.panel == 2 ? "hosts (passive OS fingerprint)" :
                                             "top conversations (by bytes)";
        mo = snprintf(meta, sizeof meta, T_DIM "[%s]" T_RST, pdesc);
        if (total > 0)
            snprintf(meta + mo, sizeof meta - mo, "  " T_DIM "%d%s" T_RST,
                     total, tui.scroll ? " (scrolled)" : "");
    }
    TUI_LINE(meta, fw);

    /* ---- body: main pane rows (packets/hits/hosts/talkers) ---- */
    int maxw = mainw - 1;                 /* leave the last column for the bar */
    if (maxw < 8) maxw = 8;
    if (maxw > 1000) maxw = 1000;
    char tmp[1200];
    for (int r = 0; r < body_rows; r++) {
        int idx = top + r;
        if (!sidew) {
            /* full-width (or full-pane) row: one colour, plain padding */
            const char *ln;
            int col = TC_DEF;
            if (is_hits)      ln = tui_hit_at(idx), col = TC_HIT;
            else if (is_dyn)  ln = (idx < tui.dynn) ? tui.dyn[idx] : "";
            else              ln = tui_line_at(idx), col = tui_line_color(idx);
            snprintf(tmp, sizeof tmp, "%-*.*s", maxw, maxw, ln);
            int is_sel = (idx == sel) && total > 0 && !side_full;
            int match  = (!is_hits && !is_dyn) && tui.search[0] && tui_has_match(ln, tui.search);
            int zebra  = (r % 2 == 1);
            if (is_sel) {
                if (cfg.color) {
                    TUI_ADD("\x1b[44m\x1b[97m");
                    TUI_ADD("%s", tui_color(col));
                } else {
                    TUI_ADD(T_REV T_BLD);
                }
            } else if (match) {
                TUI_ADD(T_UND);
                TUI_ADD("%s", tui_color(col));
            } else if (zebra && cfg.color) {
                TUI_ADD("\x1b[48;5;234m%s", tui_color(col));
            } else {
                TUI_ADD("%s", tui_color(col));
            }
            TUI_ADD("%s", tmp);
            if (is_sel || (zebra && cfg.color && !match)) TUI_ADD(T_RST);
        } else {
            /* packets pane with a side panel: fixed, aligned columns so the
             * rows line up (the glyph-only width tricks are not needed here) */
            const char *ln = tui_line_at(idx);
            int col = tui_line_color(idx);
            int is_sel = (idx == sel) && total > 0;
            int match  = tui.search[0] && tui_has_match(ln, tui.search);
            if (ln[0] < '0' || ln[0] > '9') {
                /* non-packet row (e.g. the "--- end of file ---" note): plain */
                snprintf(tmp, sizeof tmp, "%-*.*s", maxw, maxw, ln);
                if (is_sel)     TUI_ADD(T_REV "%s", "");
                else if (match) TUI_ADD(T_UND "%s", "");
                TUI_ADD("%s%s", tui_color(col), tmp);
            } else {
                char tcol[16], pcol[16], icol[16], lcol[16], sum[1200];
                tui_split_row(ln, tcol, pcol, icol, lcol, sum, sizeof sum);
                char row[1200];
                int rw = snprintf(row, sizeof row, "%-12s %-7.7s %-8.8s %4.4s  ",
                                  tcol, pcol, icol, lcol);
                if (rw < 0) rw = 0;
                if (rw > maxw) rw = maxw;
                if (is_sel)     TUI_ADD(T_REV "%s", "");
                else if (match) TUI_ADD(T_UND "%s", "");
                TUI_ADD("%s%.*s", tui_color(col), rw, row);
                int rem = maxw - rw;
                if (rem > 0) {
                    char scol[1200];
                    tui_col_str(sum, rem, scol, sizeof scol);
                    TUI_ADD("%s", scol);
                }
            }
        }
        /* scrollbar / separator in the last column */
        if (total > body_rows) {
            int track = body_rows - 1;
            int pos = track > 0 ? (int)((long)top * track / (total - body_rows)) : 0;
            if (pos < 0) pos = 0;
            if (pos > track) pos = track;
            TUI_ADD(T_RST T_DIM "%s" T_RST, (r == pos) ? "█" : "│");
        } else {
            TUI_ADD(T_RST T_DIM "│" T_RST);
        }
        /* side panel (right-hand column); the scrollbar column above already
         * provides the divider, so only a gap is needed here */
        if (sidew) {
            const char *sl = tui.side[r] ? tui.side[r] : "";
            char srow[300];
            snprintf(srow, sizeof srow, " %-*.*s", sidew - 1, sidew - 1, sl);
            TUI_ADD(T_RST T_DIM "%s" T_RST, srow);
        }
        TUI_ADD(T_RST "\x1b[K");          /* erase any stale tail on this row */
        if (r < body_rows - 1) TUI_ADD("\r\n");   /* no newline on the last row */
        if (n > sizeof out - 1400) {
            if (!cfg.color) { out[n] = 0; tui_strip_color(out); n = strlen(out); }
            fwrite(out, 1, n, stdout); n = 0;
        }
    }

    /* ---- lower panes (Wireshark-style): details + bytes ----
     * The decode text is split at the "payload" line: everything before it is
     * the protocol-field tree (details pane), the payload hexdump becomes the
     * bytes pane.  Each sub-pane gets a reverse-video title bar like Wireshark. */
    if (detail_rows || hex_rows) {
        TUI_ADD("\r\n");                  /* body left the cursor at EOL */
        const char *det = (sel >= 0) ? tui_line_detail(sel) : NULL;
        char dbuf[8192];
        snprintf(dbuf, sizeof dbuf, "%s", det ? det : "(no packet selected)");
        /* split into field lines and hex lines at the first "payload" line */
        char *lines[256];
        int nlines = 0, split = -1;
        char *save = NULL;
        for (char *t = strtok_r(dbuf, "\n", &save); t && nlines < 256;
             t = strtok_r(NULL, "\n", &save)) {
            if (split < 0 && strncmp(t, "payload", 7) == 0) split = nlines;
            lines[nlines++] = t;
        }
        if (split < 0) split = nlines;    /* no hex section */

        /* details sub-pane title bar */
        {
            const char *cl = (sel >= 0) ? tui_line_at(sel) : "";
            char tb[360];
            /* show the selected packet's own line (proto/summary), like the
             * Wireshark "Frame N" header */
            snprintf(tb, sizeof tb, T_BLD "  Details" T_RST T_DIM "  %.*s" T_RST,
                     fw > 80 ? fw - 18 : 40, cl);
            tui_put_trunc(out, sizeof out, &n, tb, fw);
            TUI_ADD("\x1b[K\r\n");
        }
        int dfirst = split;               /* field lines are lines[0..split) */
        int dtop = dfirst - detail_rows - tui.detail_scroll;
        if (dtop > dfirst - detail_rows) dtop = dfirst - detail_rows;
        if (dtop < 0) dtop = 0;
        for (int r = 0; r < detail_rows; r++) {
            const char *ln = (dtop + r) < dfirst ? lines[dtop + r] : "";
            snprintf(tmp, sizeof tmp, " %.*s", fw - 1, ln);
            TUI_ADD("%s\x1b[K", tmp);
            TUI_ADD("\r\n");
        }
        /* bytes sub-pane title bar */
        {
            int nhex = nlines - split;
            char tb[128];
            snprintf(tb, sizeof tb, T_BLD "  Bytes" T_RST T_DIM
                     "  (%d)" T_RST, nhex > 0 ? nhex : 0);
            TUI_ADD("%s\x1b[K\r\n", tb);
        }
        for (int r = 0; r < hex_rows; r++) {
            int idx = split + r;
            const char *ln = (idx < nlines) ? lines[idx] : "";
            snprintf(tmp, sizeof tmp, " %.*s", fw - 1, ln);
            TUI_ADD("%s\x1b[K", tmp);
            if (r < hex_rows - 1) TUI_ADD("\r\n");
        }
    }

    /* ---- help overlay (?): a framed key reference drawn over the body ---- */
    if (tui.help_on) {
        static const char *kh[][2] = {
            { "s / x / space", "start / stop / pause capture" },
            { "j k  ↑ ↓  wheel","scroll the log" },
            { "g / G  PgUp/Dn", "jump to oldest / newest" },
            { "Enter",          "toggle the detail decode pane" },
            { "[ / ]",          "scroll the detail pane" },
            { "p",              "cycle pane: packets / hits / hosts / talkers" },
            { "r",              "refresh the hosts & talkers panes" },
            { "f",              "toggle follow (pin the tail)" },
            { "/ …  n / N",     "search; jump to next / previous match" },
            { ":cmd",           "command (see :help in the status bar)" },
            { "c",              "clear the log" },
            { "? ",             "toggle this help" },
            { "q / Ctrl-C",     "quit" },
        };
        int nh = (int)(sizeof kh / sizeof kh[0]);
        int bw = 46;
        if (bw > fw - 4) bw = fw - 4;
        int bh = nh + 4;                       /* border + title + rows + hint */
        if (bh > body_rows) bh = body_rows;
        int top_row = tui_body_top() + 1;      /* 1-based row of first border */
        /* border top */
        TUI_ADD("\x1b[%d;3H", top_row);
        TUI_ADD(T_DIM "┌");
        for (int i = 0; i < bw - 2; i++) TUI_ADD("─");
        TUI_ADD("┐" T_RST "\x1b[K");
        /* title line */
        TUI_ADD("\x1b[%d;3H" T_DIM "│" T_RST T_BLD " keys%*s" T_RST T_DIM "│" T_RST "\x1b[K",
                top_row + 1, bw - 7, "");
        /* one row per key entry */
        for (int i = 0; i < nh && i < bh - 3; i++) {
            char body[120];
            snprintf(body, sizeof body, " %-18.18s %.24s", kh[i][0], kh[i][1]);
            TUI_ADD("\x1b[%d;3H" T_DIM "│" T_RST "%-*.*s" T_DIM "│" T_RST "\x1b[K",
                    top_row + 2 + i, bw - 2, bw - 2, body);
        }
        /* border bottom */
        TUI_ADD("\x1b[%d;3H" T_DIM "└", top_row + bh - 1);
        for (int i = 0; i < bw - 2; i++) TUI_ADD("─");
        TUI_ADD("┘" T_RST "\x1b[K");
        /* put the cursor back where the footer expects it (bottom-left) */
        TUI_ADD("\x1b[%d;1H", rows);
    }

    /* ---- key hints (rows-1) ---- */
    TUI_ADD("\r\n");
    {
        char ft[520];
        if (fw >= 110) {
            snprintf(ft, sizeof ft,
                T_BLD " s" T_RST " %s  " T_BLD "x" T_RST " stop  "
                T_BLD "Enter" T_RST " details %s%s  " T_BLD "/" T_RST " search%s  "
                T_BLD "p" T_RST " pane:%s  " T_BLD "c" T_RST " clear  "
                T_BLD ":" T_RST " cmd  " T_BLD "?" T_RST " help  " T_BLD "q" T_RST " quit",
                tui.running ? "stop" : "start",
                tui.detail_on ? T_GRN "on" T_RST : "off",
                tui.detail_on ? " " T_BLD "[/]" T_RST : "",
                tui.search[0] ? tui.search : "",
                tui_pane_name(tui.panel));
        } else {
            snprintf(ft, sizeof ft,
                T_BLD " s" T_RST " %s  " T_BLD "Enter" T_RST " details%s  "
                T_BLD "/" T_RST " search  " T_BLD "p" T_RST " pane  "
                T_BLD "?" T_RST " help  " T_BLD "q" T_RST " quit",
                tui.running ? "stop" : "start",
                tui.detail_on ? T_GRN "on" T_RST : "off");
        }
        tui_put_trunc(out, sizeof out, &n, ft, fw);
        TUI_ADD(T_RST "\x1b[K");
    }

    /* ---- footer (row `rows`; never write past it so the screen can't
     *      scroll, which is what jumped the whole UI every frame) ---- */
    TUI_ADD("\r\n");
    if (tui.search_on) {
        TUI_ADD(T_BLD "/" T_RST "%s\x1b[K\x1b[?25h", tui.search);
    } else if (tui.prompt_on) {
        TUI_ADD(T_BLD ":" T_RST "%s\x1b[K\x1b[?25h", tui.prompt);
    } else if (tui.status[0]) {
        tui_put_trunc(out, sizeof out, &n, tui.status, fw);
        TUI_ADD(T_RST "\x1b[K");
    } else {
        char ft[260];
    snprintf(ft, sizeof ft,
             T_DIM "IFACE" T_RST " %s   " T_DIM "STATUS" T_RST " %s   " T_DIM "COLORS" T_RST " %s   " T_DIM "FOLLOW" T_RST " %s" T_RST,
             cfg.iface ? cfg.iface : (cap.pcap_mode ? "pcap" : "-"),
             tui.running ? "capturing" : "stopped",
             cfg.color ? "on" : "off",
             tui.follow_on ? "on" : "off");
        tui_put_trunc(out, sizeof out, &n, ft, fw);
        TUI_ADD(T_RST "\x1b[K");
    }
    if (!cfg.color) { out[n] = 0; tui_strip_color(out); n = strlen(out); }
    fwrite(out, 1, n, stdout);
    fflush(stdout);
#undef TUI_ADD
#undef TUI_LINE
}

/* rows available to the body, for page-sized scrolling */
static int tui_page(void) {
    int r = tui.rows > 0 ? tui.rows : 24;
    int p = r - 7;                 /* 4 header rows + colhdr + hints + footer */
    return p > 1 ? p : 1;
}

/* 0-based screen row where the packet body starts, matching tui_render()'s
 * layout (title, cards, band, rule, [filter], column header). */
static int tui_body_top(void) {
    int filtline = (cfg.proto || cfg.host || cfg.port >= 0) ? 1 : 0;
    return 4 + filtline + 1;       /* header rows + optional filter + col header */
}

/* Feed one byte to the escape-sequence assembler.  Returns 1 if the byte
 * completed a sequence this function consumed (so the caller skips normal
 * handling), 0 if the byte is an ordinary key.  Recognises SGR mouse reports
 * (\x1b[<b;x;yM/m): button 64/65 = wheel up/down, which scroll the pane. */
static int tui_feed_esc(unsigned char c) {
    if (tui.esc_len == 0) {
        if (c != 27) return 0;                    /* not the start of a seq */
        tui.esc[tui.esc_len++] = (char)c;
        return 1;                                 /* swallow the ESC for now */
    }
    if (tui.esc_len < (int)sizeof tui.esc - 1)
        tui.esc[tui.esc_len++] = (char)c;
    tui.esc[tui.esc_len] = 0;

    /* SGR mouse: ESC [ < b ; x ; y M|m  */
    if (tui.esc_len >= 3 && tui.esc[1] == '[' && tui.esc[2] == '<') {
        char last = tui.esc[tui.esc_len - 1];
        if (last == 'M' || last == 'm') {
            int b = 0, x = 0, y = 0;
            if (sscanf(tui.esc + 3, "%d;%d;%d", &b, &x, &y) >= 1) {
                int btn = b & 0x3;      /* low bits: button; bit6/7: wheel */
                if (b == 64) { if (tui.scroll < (1 << 30)) tui.scroll += 3; }
                else if (b == 65) { tui.scroll -= 3; if (tui.scroll < 0) tui.scroll = 0; }
                else if (last == 'M' && btn == 0) {
                    /* left click: select the log row under the cursor.  The
                     * dashboard body starts at row `body_top` (0-based); the
                     * bottom visible body line is `total-1-scroll`. */
                    if (tui.panel == 0 && tui.help_on) {
                        tui.help_on = 0;
                    } else if (tui.panel == 0) {
                        int brow = tui_body_top();
                        int total = tui.logn;
                        int sel = total - 1 - tui.scroll;   /* bottom visible row */
                        int clicked = sel - (y - 1 - brow);
                        if (clicked >= 0 && clicked < total) {
                            tui.scroll = total - 1 - clicked;
                            if (tui.scroll < 0) tui.scroll = 0;
                            tui.detail_scroll = 0;
                        }
                    }
                }
                tui.last_render = (struct timespec){0, 0};
            }
            tui.esc_len = 0;
            return 1;
        }
        return 1;                                 /* still assembling */
    }
    /* generic CSI (e.g. arrow keys ESC [ A): consume up to the final byte.
     * The final byte is the one AFTER the '[' introducer (esc_len >= 3). */
    if (tui.esc_len >= 2 && tui.esc[1] == '[') {
        if (tui.esc_len >= 3 && c >= 0x40 && c <= 0x7e) {
            int page = tui_page();
            if (c == '~') {                       /* ESC [ n ~ */
                switch (atoi(tui.esc + 2)) {
                    case 5: tui.scroll += page; break;                 /* PgUp */
                    case 6: tui.scroll -= page;                        /* PgDn */
                            if (tui.scroll < 0) tui.scroll = 0;
                            break;
                    case 1: tui.scroll = 1 << 30; break;               /* Home */
                    case 4: tui.scroll = 0; break;                     /* End */
                    default: break;
                }
            } else {
                switch (c) {                      /* plain arrows scroll too */
                    case 'A': if (tui.scroll > 0) tui.scroll--; break;  /* up */
                    case 'B': tui.scroll++; break;                      /* down */
                    case 'H': tui.scroll = 1 << 30; break;              /* home = oldest */
                    case 'F': tui.scroll = 0; break;                    /* end = tail */
                    default: break;
                }
            }
            tui.esc_len = 0;
        }
        return 1;
    }
    /* ESC + single char (Alt-…): consume both */
    tui.esc_len = 0;
    return 1;
}

/* count log rows matching the current search query */
static int tui_search_count(void) {
    if (!tui.search[0] || tui.panel != 0) return 0;
    int c = 0;
    for (int i = 0; i < tui.logn; i++)
        if (tui_has_match(tui_line_at(i), tui.search)) c++;
    return c;
}

/* jump to the next (+1) or previous (-1) matching row, wrapping around */
static void tui_search_jump(int dir) {
    if (tui.panel != 0 || !tui.search[0] || tui.logn == 0) return;
    int total = tui.logn;
    int cur = tui_sel(total);
    if (cur < 0) cur = total - 1;
    for (int step = 1; step <= total; step++) {
        int idx = cur + dir * step;
        if (idx < 0) idx += total;
        if (idx >= total) idx -= total;
        if (tui_has_match(tui_line_at(idx), tui.search)) {
            tui.scroll = total - 1 - idx;
            if (tui.scroll < 0) tui.scroll = 0;
            tui.detail_scroll = 0;
            return;
        }
    }
}

/* drain pending keys; returns 0 to keep running, 1 to quit */
static int tui_keys(void) {
    char buf[64];
    ssize_t n;
    int quit = 0;
    while ((n = read(STDIN_FILENO, buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)buf[i];

            /* search prompt ('/'): every key edits the query */
            if (tui.search_on) {
                if (c == '\r' || c == '\n') {
                    tui.search_on = 0;
                    tui.search_n = tui_search_count();
                    tui_search_jump(-1);          /* start at the newest match */
                    if (tui.search[0])
                        snprintf(tui.status, sizeof tui.status,
                                 "%d match(es) for \"%s\"", tui.search_n, tui.search);
                    tui.last_render = (struct timespec){0, 0};
                } else if (c == 27) {             /* Esc cancels */
                    tui.search_on = 0;
                    tui.search[0] = 0;
                    tui.search_len = 0;
                    tui.search_n = 0;
                    tui.last_render = (struct timespec){0, 0};
                } else if (c == 127 || c == 8) {
                    if (tui.search_len > 0) {
                        tui.search[--tui.search_len] = 0;
                        tui.last_render = (struct timespec){0, 0};
                    }
                } else if (c >= 32 && c < 127 &&
                           tui.search_len < (int)sizeof tui.search - 1) {
                    tui.search[tui.search_len++] = (char)c;
                    tui.search[tui.search_len] = 0;
                    tui.last_render = (struct timespec){0, 0};
                }
                continue;
            }

            /* ':' command prompt: every key edits the command line */
            if (tui.prompt_on) {
                if (c == '\r' || c == '\n') {
                    tui.prompt_on = 0;
                    tui.last_render = (struct timespec){0, 0};
                    tui_cmd(tui.prompt);
                    tui.prompt[0] = 0;
                    tui.prompt_len = 0;
                } else if (c == 27) {                            /* Esc cancels */
                    tui.prompt_on = 0;
                    tui.last_render = (struct timespec){0, 0};
                    tui.prompt[0] = 0;
                    tui.prompt_len = 0;
                    tui.status[0] = 0;
                } else if (c == 127 || c == 8) {                 /* backspace */
                    if (tui.prompt_len > 0) {
                        tui.prompt[--tui.prompt_len] = 0;
                        tui.last_render = (struct timespec){0, 0};
                    }
                } else if (c >= 32 && c < 127 &&
                           tui.prompt_len < (int)sizeof tui.prompt - 1) {
                    tui.prompt[tui.prompt_len++] = (char)c;
                    tui.prompt[tui.prompt_len] = 0;
                    tui.last_render = (struct timespec){0, 0};
                }
                continue;
            }
            /* assemble escape sequences (mouse wheel / arrow keys / PgUp/PgDn) */
            if (tui.esc_len > 0 || c == 27) {
                if (tui_feed_esc(c)) continue;
            }
            int page = tui_page();
            switch (c) {
                case ':':
                    tui.prompt_on = 1;
                    tui.prompt[0] = 0;
                    tui.prompt_len = 0;
                    tui.status[0] = 0;
                    tui.last_render = (struct timespec){0, 0};
                    break;
                case '/':                              /* search */
                    tui.search_on = 1;
                    tui.search[0] = 0;
                    tui.search_len = 0;
                    tui.status[0] = 0;
                    tui.last_render = (struct timespec){0, 0};
                    break;
                case '\r': case '\n':                  /* Enter: toggle detail */
                    if (tui.panel == 0) {
                        tui.detail_on = !tui.detail_on;
                        tui.detail_scroll = 0;
                        tui.last_render = (struct timespec){0, 0};
                    }
                    break;
                case 'n': if (tui.search[0]) tui_search_jump(+1); break;
                case 'N': if (tui.search[0]) tui_search_jump(-1); break;
                case '?':                                       /* help overlay */
                    tui.help_on = !tui.help_on;
                    tui.last_render = (struct timespec){0, 0};
                    break;
                case '[': if (tui.detail_on) tui.detail_scroll++; break;      /* detail up */
                case ']':                                                     /* detail down */
                    if (tui.detail_on && tui.detail_scroll > 0) tui.detail_scroll--;
                    break;
                case 'q': case 3: quit = 1; break;               /* q / Ctrl-C */
                case 's': if (!tui.running) { tui.running = 1;
                              clock_gettime(CLOCK_MONOTONIC, &tui.started); } break;
                case 'x': tui.running = 0; break;
                case ' ': tui.running = !tui.running;
                          if (tui.running && !tui.started.tv_sec)
                              clock_gettime(CLOCK_MONOTONIC, &tui.started);
                          break;                           /* pause/resume */
                case 'c': tui_clear_log(); break;
                case 'p':
                    tui.panel = (tui.panel + 1) % 4;
                    tui.scroll = 0;
                    tui_build_dyn();
                    break;
                case 'r':                       /* refresh host/talker panes */
                    tui_build_dyn();
                    break;
                case 'f':
                    tui.follow_on = !tui.follow_on;
                    cfg.follow = tui.follow_on ? 0 : -1;
                    break;
                case 21: tui.scroll += page / 2; break;          /* Ctrl-U half up */
                case 4:  tui.scroll -= page / 2;                 /* Ctrl-D half down */
                         if (tui.scroll < 0) tui.scroll = 0;
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

int tui_run(void) {
    if (!isatty(STDOUT_FILENO)) {
        fprintf(stderr, "ch1m3ra: -U needs a terminal (stdout is not a tty)\n");
        return 2;
    }
    cfg.dumpbytes = 0;
    tui.follow_on = (cfg.follow >= 0);
    tui_active = 1;
    /* Wireshark-style: the details + bytes panes are on from the start */
    tui.detail_on = 1;

    /* capture starts only when the user presses 's' (unless it's a pcap file,
     * where there is nothing to wait for - autostart so -r -U shows data) */
    tui.running = cap.pcap_mode ? 1 : 0;
    if (tui.running) clock_gettime(CLOCK_MONOTONIC, &tui.started);

    tui_enter_raw();
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = tui_panic;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    /* repaint immediately on resize so the layout never shows through garbled */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = tui_on_winch;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa, NULL);
    tui_resized = 0;
    tui.width = 0; tui.height = 0;      /* force a full blank on the first paint */
    /* alt screen, cursor off, SGR mouse reporting on (scroll wheel) */
    fputs("\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1006h", stdout);
    fflush(stdout);

    static uint8_t buf[65536];
    size_t capbuf = (size_t)(cfg.snaplen < 65536 ? cfg.snaplen : 65536);
    int needs_render = 1;
    tui.last_render = (struct timespec){0, 0};

    for (;;) {
        if (tui_keys()) break;

        if (tui.running) {
            const uint8_t *frame = buf;
            size_t capn = 0, wire = 0;
            struct timespec ts = {0, 0};
            int have_dir = 0, out = 0;
            char ifn[IF_NAMESIZE] = "";

            /* zero-copy ring: consume every queued frame in one batch so a
             * burst doesn't stall the UI on a poll() per packet */
            long drained = 0;
            if (capture_drain(128, &drained) == 1) {
                needs_render = 1;
                if (cfg.count > 0 && (long long)st.shown >= cfg.count) tui.running = 0;
                continue;
            }

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
        int resized = 0;
        if (tui_resized) { tui_resized = 0; resized = 1; needs_render = 1; }
        if (needs_render) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long dms = (now.tv_sec - tui.last_render.tv_sec) * 1000
                     + (now.tv_nsec - tui.last_render.tv_nsec) / 1000000;
            if (resized || dms >= 50 || tui.last_render.tv_sec == 0) {
                if (tui.panel == 2 || tui.panel == 3) tui_build_dyn();
                if (tui.panel == 0 && ws.ws_col >= 100 && !tui.detail_on)
                    tui_build_side();
                tui_render(ws.ws_row, ws.ws_col);
                needs_render = 0;
                tui.last_render = now;
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
    free(tui.own_proto); tui.own_proto = NULL;
    free(tui.own_host);  tui.own_host = NULL;

    if (cap.wf) { fflush(cap.wf->f); fclose(cap.wf->f); free(cap.wf); cap.wf = NULL; }
    if (cap.pcap_mode && cap.pr.f) { fclose(cap.pr.f); cap.pr.f = NULL; }
    if (cap.fd >= 0) { ring_stats(cap.fd); close(cap.fd); cap.fd = -1; }
    if (ring_map) munmap(ring_map, ring_len);
    streams_cleanup();
    if (g_stop) return 0;
    return 0;
}

