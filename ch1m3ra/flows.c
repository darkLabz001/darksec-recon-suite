/* flows.c - TCP stream + UDP flow tracking */

#include "ch1m3ra.h"

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
    /* TCP health metrics */
    unsigned long long retrans;   /* duplicate data seen */
    unsigned long long ooo;       /* out-of-order segments */
    uint32_t          maxseq;     /* highest seq+len seen (for retransmit detect) */
    int               maxhave;
} fdir_t;

typedef struct {
    int      used;
    fkey_t   key;
    unsigned id;
    fdir_t   d[2];            /* d[0] = a->b, d[1] = b->a */
    struct timespec t0, t1;
    unsigned long long pkts, bytes;
    int      syn, fin, rst;
    int      lastdir;              /* follow mode: direction of last printed chunk */
    int      closed_seen;
    unsigned long long last;  /* recency stamp for full-table eviction */
    /* --- UDP flow tracking --- */
    int      udp;                 /* 1 if this is a UDP flow */
    unsigned long long upkts[2];  /* datagrams per direction */
    unsigned long long ubytes[2]; /* payload bytes per direction */
    /* --- TCP metrics --- */
    unsigned long long retrans, ooo;   /* totals across both directions */
    double   rtt_ms;              /* last ACK-based RTT estimate, <0 = unknown */
    int      rtt_valid;
    uint32_t rtt_seq;             /* seq of the segment awaiting the ACK */
    struct timespec rtt_ts;       /* send time of that segment */
    int      zw;                  /* zero-window advertised seen */
} fent_t;

static fent_t ftab[NSTREAM];
static unsigned fnxt = 1;      /* TCP stream id counter */
static unsigned unxt = 1;      /* UDP flow id counter (separate id space) */
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

static fent_t *f_lookup(const fkey_t *k, int create, const packet_t *p, int udp) {
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
    e->udp = udp;
    e->key = *k;
    e->id = udp ? unxt++ : fnxt++;      /* TCP ids stay stable regardless of UDP */
    e->rtt_ms = -1;
    e->lastdir = -1;
    e->t0 = e->t1 = p->ts;
    return e;
}

/* Build a synthetic Ethernet/IP/TCP frame carrying a reassembled chunk and
 * write it to the --follow-out pcap, so the followed stream can be reopened
 * in Wireshark.  We only need IP addresses/ports, not a valid checksum. */
static void f_emit_pcap(fent_t *e, int dir, const uint8_t *d, size_t n) {
    /* src/dst from this direction's perspective */
    const uint8_t *src = dir ? e->key.b : e->key.a;
    const uint8_t *dst = dir ? e->key.a : e->key.b;
    uint16_t sp = dir ? e->key.bp : e->key.ap;
    uint16_t dp = dir ? e->key.ap : e->key.bp;
    static uint8_t frame[14 + 40 + 20 + 65535];
    uint8_t *q = frame;
    if (n > 65535) n = 65535;
    int ihl = 20, l4 = 20;
    int v6 = (e->key.fam == 6);
    size_t l3len = (size_t)ihl + l4 + n;
    if (v6) l3len = 40 + l4 + n;

    /* Ethernet header with an arbitrary but distinct MAC pair */
    memcpy(q, "\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02", 12);
    q[12] = v6 ? 0x86 : 0x08; q[13] = v6 ? 0xdd : 0x00;
    q += 14;

    size_t seglen = 0;
    if (v6) {
        q[0] = 0x60; q[1] = q[2] = q[3] = 0;
        q[4] = (uint8_t)((l4 + n) >> 8); q[5] = (uint8_t)(l4 + n);
        q[6] = 6; q[7] = 0;                    /* next header = TCP */
        q[8] = 64;                             /* hop limit */
        memcpy(q + 8, src, 16); memcpy(q + 24, dst, 16);
        seglen = 40 + l4 + n;
        q += 40;
    } else {
        q[0] = 0x45; q[1] = 0; q[2] = (uint8_t)(l3len >> 8); q[3] = (uint8_t)l3len;
        q[4] = q[5] = 0; q[6] = 0x40; q[7] = 0; q[8] = 64; q[9] = 6;
        q[10] = q[11] = 0;                     /* checksum left zero */
        memcpy(q + 12, src, 4); memcpy(q + 16, dst, 4);
        seglen = 20 + l4 + n;
        q += 20;
    }
    q[0] = (uint8_t)(sp >> 8); q[1] = (uint8_t)sp;
    q[2] = (uint8_t)(dp >> 8); q[3] = (uint8_t)dp;
    q[4] = q[5] = q[6] = q[7] = 0;             /* seq */
    q[8] = q[9] = q[10] = q[11] = 0;           /* ack */
    q[12] = 0x50; q[13] = 0x18;                /* data offset, PSH|ACK */
    q[14] = q[15] = 0;                         /* window */
    q[16] = q[17] = 0;                         /* checksum */
    q[18] = q[19] = 0;                         /* urgent */
    memcpy(q + 20, d, n);
    (void)seglen;

    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    follow_out_write(frame, 14 + l3len, 14 + l3len, &ts);
}

/* emit a reassembled chunk (follow mode prints it as text) */
static void f_emit(fent_t *e, int dir, const uint8_t *d, size_t n) {
    if (!n || !is_follow(e)) return;
    if (cfg.follow_out) f_emit_pcap(e, dir, d, n);
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

/* track a UDP datagram in the same flow table (lightweight: just counters) */
static void udp_track(packet_t *p) {
    fkey_t k;
    int dir = key_build(&k, p);
    fent_t *e = f_lookup(&k, 1, p, 1);
    if (!e) { p->stream_id = -1; return; }

    p->stream_id = -1;              /* UDP has no stream id: don't shadow TCP ids */
    e->udp = 1;
    e->pkts++;
    e->bytes += p->plen;
    e->upkts[dir]++;
    e->ubytes[dir] += p->plen;
    if (e->t1.tv_sec == e->t0.tv_sec && e->t1.tv_nsec == e->t0.tv_nsec) e->t0 = p->ts;
    e->t1 = p->ts;
    e->last = fnow++;
}

/* record a TCP data segment; detect retransmits / out-of-order / RTT */
static void tcp_metrics(fent_t *e, int dir, const packet_t *p, uint32_t seq) {
    fdir_t *d = &e->d[dir];
    uint32_t end = seq + (uint32_t)p->avail;

    if (d->maxhave) {
        if ((int32_t)(end - d->maxseq) <= 0) {
            /* ends within what we've seen; retransmit only if it starts below
             * the highest contiguous position (otherwise it fills a hole) */
            if (d->have && (int32_t)(seq - d->nxt) < 0) {
                e->retrans++;
                d->retrans++;
            } else {
                e->ooo++;
                d->ooo++;
            }
        } else if ((int32_t)(seq - d->maxseq) > 0) {
            /* starts beyond the highest byte seen -> a gap: out of order */
            e->ooo++;
            d->ooo++;
        }
        /* else: partially new, arriving after a gap -> fills the hole, not counted */
    }
    if (!d->maxhave || (int32_t)(end - d->maxseq) > 0) {
        d->maxseq = end;
        d->maxhave = 1;
    }

    /* RTT: remember the seq we last sent so a later ACK can be timed */
    e->rtt_seq = end;
    e->rtt_ts = p->ts;
}

void stream_track(packet_t *p) {
    if (!p->ip_ver) return;

    if (p->has_udp && !p->has_tcp) {
        if (cfg.talkers) udp_track(p);          /* UDP flows only when tracking */
        return;
    }
    if (!p->has_tcp) return;

    fkey_t k;
    int dir = key_build(&k, p);
    fent_t *e = f_lookup(&k, 1, p, 0);
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
        e->d[0].maxhave = e->d[1].maxhave = 0;
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
    if (p->win == 0) e->zw = 1;                   /* zero-window advertisement */

    if (p->payload && p->avail) {
        uint32_t seq = p->seq + ((p->flags & 0x0002) ? 1u : 0u);  /* SYN eats 1 */
        tcp_metrics(e, dir, p, seq);
        f_data(e, dir, p, seq);
    } else if ((p->flags & 0x0010) && e->rtt_valid == 0 && e->rtt_seq) {
        /* a bare ACK that acknowledges data we timed: compute the RTT once */
        if ((int32_t)(p->ack - e->rtt_seq) >= 0) {
            double dt = (double)(p->ts.tv_sec - e->rtt_ts.tv_sec) +
                        (double)(p->ts.tv_nsec - e->rtt_ts.tv_nsec) / 1e9;
            if (dt >= 0 && dt < 60) {
                e->rtt_ms = dt * 1000.0;
                e->rtt_valid = 1;
            }
        }
    }
}

void streams_cleanup(void) {
    for (unsigned i = 0; i < NSTREAM; i++) {
        f_free_pend(&ftab[i].d[0]);
        f_free_pend(&ftab[i].d[1]);
    }
}

static int fcmp_idp(const void *a, const void *b) {
    const fent_t *const *x = a, *const *y = b;
    return (int)((*x)->id - (*y)->id);
}

void streams_stats(FILE *o) {
    static fent_t *view[NSTREAM];
    int n = 0;
    for (unsigned i = 0; i < NSTREAM; i++)
        if (ftab[i].used) view[n++] = &ftab[i];
    if (!n) return;
    qsort(view, (size_t)n, sizeof *view, fcmp_idp);

    int ntcp = 0, nudp = 0;
    for (int i = 0; i < n; i++) { if (view[i]->udp) nudp++; else ntcp++; }
    /* keep the original line exactly when there are no UDP flows */
    if (nudp) fprintf(o, "  streams %d (%d tcp, %d udp)\n", n, ntcp, nudp);
    else      fprintf(o, "  streams %d\n", ntcp);

    /* TCP flows */
    for (int i = 0; i < n; i++) {
        fent_t *e = view[i];
        if (e->udp) continue;
        if (i >= 32) { fprintf(o, "    ... and %d more\n", n - 32); break; }
        char A[80], B[80];
        key_ep(&e->key, 0, A, sizeof A);
        key_ep(&e->key, 1, B, sizeof B);
        double dur = (double)(e->t1.tv_sec - e->t0.tv_sec) +
                     (double)(e->t1.tv_nsec - e->t0.tv_nsec) / 1e9;
        const char *stt = e->rst ? "rst" : e->fin ? "fin" : e->syn ? "open" : "mid";
        fprintf(o, "    #%-3u %-24s <-> %-24s %llu/%llu B  %llup  %.3fs  %s",
                e->id, A, B, e->d[0].bytes, e->d[1].bytes,
                e->pkts, dur < 0 ? 0.0 : dur, stt);
        if (e->retrans || e->ooo || e->rtt_valid || e->zw) {
            fprintf(o, "  [");
            const char *sep = "";
            if (e->rtt_valid) { fprintf(o, "%srtt=%.1fms", sep, e->rtt_ms); sep = " "; }
            if (e->retrans)   { fprintf(o, "%sretrans=%llu", sep, e->retrans); sep = " "; }
            if (e->ooo)       { fprintf(o, "%sooo=%llu", sep, e->ooo); sep = " "; }
            if (e->zw)        { fprintf(o, "%szerowin", sep); }
            fprintf(o, "]");
        }
        fprintf(o, "\n");
    }

    /* UDP flows */
    if (nudp) {
        fprintf(o, "  udp flows:\n");
        int shown = 0;
        for (int i = 0, j = 0; i < n; i++) {
            fent_t *e = view[i];
            if (!e->udp) continue;
            if (++j > 32) { fprintf(o, "    ... and %d more\n", nudp - 32); break; }
            char A[80], B[80];
            key_ep(&e->key, 0, A, sizeof A);
            key_ep(&e->key, 1, B, sizeof B);
            double dur = (double)(e->t1.tv_sec - e->t0.tv_sec) +
                         (double)(e->t1.tv_nsec - e->t0.tv_nsec) / 1e9;
            fprintf(o, "    u%-3u %-24s <-> %-24s %llu/%llu dgram  %llup  %.3fs\n",
                    e->id, A, B, e->upkts[0], e->upkts[1],
                    e->pkts, dur < 0 ? 0.0 : dur);
            shown++;
        }
        (void)shown;
    }
}

