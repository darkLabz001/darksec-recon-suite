/* recon.c - reconnaissance: OS fingerprint / talkers / names */

#include "ch1m3ra.h"

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
unsigned hn = 0;

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
void finger_observe(packet_t *p) {
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
void name_learn(packet_t *p) {
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
unsigned cn = 0;

void talkers_observe(const packet_t *p) {
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

void talkers_stats(FILE *o) {
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

void finger_stats(FILE *o) {
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

void names_stats(FILE *o) {
    if (!cfg.names || !hn) return;
    int any = 0;
    for (unsigned i = 0; i < hn && !any; i++) if (htab[i].used && htab[i].name[0]) any = 1;
    if (!any) return;
    fprintf(o, "  names learned\n");
    for (unsigned i = 0; i < hn; i++)
        if (htab[i].used && htab[i].name[0])
            fprintf(o, "    %-40s %s\n", htab[i].name, htab[i].ip_s);
}

/* ---------- TUI accessors ---------- */

void finger_hosts_each(void (*cb)(const char *line, void *ctx), void *ctx, int max) {
    if (!hn) return;
    hostent_t *v = malloc(hn * sizeof *v);
    if (!v) return;
    unsigned m = 0;
    for (unsigned i = 0; i < hn; i++) if (htab[i].used) v[m++] = htab[i];
    qsort(v, m, sizeof *v, host_cmp);
    char line[400];
    for (unsigned i = 0; i < m && (int)i < max; i++) {
        hostent_t *h = &v[i];
        double dur = (h->t1_ms > h->t0_ms) ? (double)(h->t1_ms - h->t0_ms) / 1000.0 : 0;
        snprintf(line, sizeof line, "%-30s ttl=%-3u %-28s %llu B  %llup  %.2fs%s%s",
                 h->ip_s, h->ttl, h->os[0] ? h->os : "-",
                 h->bytes, h->pkts, dur,
                 h->name[0] ? "  name=" : "", h->name);
        cb(line, ctx);
    }
    free(v);
}

void talkers_each(void (*cb)(const char *line, void *ctx), void *ctx, int max) {
    if (!cn) return;
    conv_t *v = malloc(cn * sizeof *v);
    if (!v) return;
    unsigned m = 0;
    for (unsigned i = 0; i < cn; i++) if (ctab[i].used) v[m++] = ctab[i];
    qsort(v, m, sizeof *v, conv_cmp);
    char line[400];
    for (unsigned i = 0; i < m && (int)i < max; i++) {
        snprintf(line, sizeof line, "%-34s <-> %-34s %llu B  %llup",
                 v[i].a, v[i].b, v[i].bytes, v[i].pkts);
        cb(line, ctx);
    }
    free(v);
}

void recon_cleanup(void) { }   /* tables are static, nothing to free */

