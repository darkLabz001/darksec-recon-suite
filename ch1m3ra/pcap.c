/* pcap.c - pcap + pcapng file I/O (own minimal reader/writer) */

#include "ch1m3ra.h"

/* ---------- little helpers ---------- */

uint32_t get32(const uint8_t *d, int swap) {
    uint32_t v = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
    if (swap) v = __builtin_bswap32(v);
    return v;
}
void put32(uint8_t *d, uint32_t v) { d[0] = v; d[1] = v >> 8; d[2] = v >> 16; d[3] = v >> 24; }
static uint16_t get16(const uint8_t *d, int swap) {
    uint16_t v = (uint16_t)(d[0] | (d[1] << 8));
    if (swap) v = (uint16_t)__builtin_bswap16(v);
    return v;
}
static void put16(uint8_t *d, uint16_t v) { d[0] = (uint8_t)v; d[1] = (uint8_t)(v >> 8); }
static void put64(uint8_t *d, uint64_t v) { int i; for (i = 0; i < 8; i++) d[i] = (uint8_t)(v >> (8 * i)); }

/* ---------- pcap (classic) reader ---------- */

static int pcap_open_classic(pcapin_t *p, const uint8_t *gh, int magic) {
    switch (magic) {
        case 0xa1b2c3d4: p->swap = 0; p->ns = 0; break;
        case 0xd4c3b2a1: p->swap = 1; p->ns = 0; break;
        case 0xa1b23c4d: p->swap = 0; p->ns = 1; break;
        case 0x4d3cb2a1: p->swap = 1; p->ns = 1; break;
        default: return -1;
    }
    uint32_t link = get32(gh + 20, p->swap);
    /* 1=EN10MB, 113=LINUX_SLL, 127=radiotap+802.11, 105=raw 802.11 */
    if (link != 1 && link != 113 && link != 127 && link != 105) {
        fprintf(stderr, "ch1m3ra: unsupported linktype %u\n", link);
        fclose(p->f); return -1;
    }
    p->linktype = link;
    p->ng = 0;
    return 0;
}

/* ---------- pcapng reader ---------- */

/* Read one block; returns block type or -1 on EOF/error. Body (without the
 * leading type / trailing length) is returned in *body, padded length in *blen. */
static int ng_read_block(pcapin_t *p, uint32_t *type, const uint8_t **body,
                         size_t *blen, uint8_t *scratch, size_t scratchsz) {
    uint8_t hdr[8];
    if (fread(hdr, 1, 8, p->f) != 8) return -1;
    *type = get32(hdr, p->ng_swap);
    uint32_t total = get32(hdr + 4, p->ng_swap);
    if (total < 12 || total > 0x1000000) return -1;
    uint32_t bodylen = total - 12;
    if (bodylen > scratchsz) {   /* skip oversized block */
        if (fseek(p->f, (long)bodylen + 4, SEEK_CUR) != 0) return -1;
        *blen = 0; *body = scratch; return (int)*type;
    }
    if (fread(scratch, 1, bodylen, p->f) != bodylen) return -1;
    uint8_t tail[4];
    if (fread(tail, 1, 4, p->f) != 4) return -1;
    if (get32(tail, p->ng_swap) != total) return -1;   /* length check */
    *body = scratch; *blen = bodylen;
    return (int)*type;
}

static int ng_open(pcapin_t *p, const char *path) {
    /* we already consumed the first 4 magic bytes; next 4 are the block total
     * length, then 4 bytes of byte-order magic. */
    uint8_t skip_len[4], bom[4];
    if (fread(skip_len, 1, 4, p->f) != 4) { fclose(p->f); return -1; }
    if (fread(bom, 1, 4, p->f) != 4) { fclose(p->f); return -1; }
    if (bom[0] == 0x1a && bom[1] == 0x2b && bom[2] == 0x3a && bom[3] == 0x1b)
        p->ng_swap = 1;
    else if (bom[0] == 0x4d && bom[1] == 0x3c && bom[2] == 0x2b && bom[3] == 0x1a)
        p->ng_swap = 0;
    else { fprintf(stderr, "ch1m3ra: %s: bad pcapng byte-order magic\n", path); fclose(p->f); return -1; }

    uint8_t scratch[65536];
    p->ng = 1;
    p->if_tsresol = 6;          /* default microseconds */
    p->if_tsresol_bin = 0;
    p->ifname[0] = 0;

    /* Rewind and parse the mandatory Section Header Block in full. */
    if (fseek(p->f, 0, SEEK_SET) != 0) { fclose(p->f); return -1; }
    uint32_t type; const uint8_t *body; size_t blen;
    int t = ng_read_block(p, &type, &body, &blen, scratch, sizeof scratch);
    if (t < 0 || type != 0x0a0d0d0a) {
        fprintf(stderr, "ch1m3ra: %s: not a valid pcapng file\n", path);
        fclose(p->f); return -1;
    }
    return 0;
}

/* Parse an Interface Description Block body: linktype, snaplen, options. */
static int ng_parse_idb(pcapin_t *p, const uint8_t *body, size_t blen) {
    if (blen < 8) return -1;
    uint16_t link = get16(body, p->ng_swap);
    if (link != 1 && link != 113 && link != 127 && link != 105) {
        fprintf(stderr, "ch1m3ra: unsupported pcapng linktype %u\n", link);
        return -1;
    }
    p->linktype = link;
    /* walk options looking for if_name (2) and if_tsresol (9) */
    uint16_t otype;
    size_t off = 8;
    while (off + 4 <= blen) {
        otype = get16(body + off, p->ng_swap);
        uint16_t olen = get16(body + off + 2, p->ng_swap);
        off += 4;
        if (otype == 0) break;                     /* opt_endofopt */
        if (off + olen > blen) break;
        if (otype == 9 && olen >= 1) {              /* if_tsresol */
            uint8_t r = body[off];
            if (r & 0x80) { p->if_tsresol_bin = 1; p->if_tsresol = r & 0x7f; }
            else          { p->if_tsresol_bin = 0; p->if_tsresol = r; }
        } else if (otype == 2 && olen) {            /* if_name */
            size_t n = olen < sizeof(p->ifname) - 1 ? olen : sizeof(p->ifname) - 1;
            memcpy(p->ifname, body + off, n); p->ifname[n] = 0;
        }
        off += (olen + 3) & ~3u;                    /* pad to 32-bit */
    }
    return 0;
}

/* next packet from a pcapng stream; 1=ok 0=eof -1=error */
static int ng_next(pcapin_t *p, uint8_t *b, size_t bufsz, size_t *caplen,
                   size_t *wirelen, struct timespec *ts) {
    uint8_t scratch[131072];
    uint32_t type; const uint8_t *body; size_t blen;
    for (;;) {
        int t = ng_read_block(p, &type, &body, &blen, scratch, sizeof scratch);
        if (t < 0) return 0;
        if (type == 0x00000001) {                    /* Interface Description Block */
            if (ng_parse_idb(p, body, blen) != 0) return -1;
            continue;
        }
        if (type == 0x00000006) {                    /* Enhanced Packet Block */
            if (blen < 20) return -1;
            uint32_t capl = get32(body + 12, p->ng_swap);
            uint32_t orig = get32(body + 16, p->ng_swap);
            if (capl > bufsz) { fprintf(stderr, "ch1m3ra: record larger than buffer\n"); return -1; }
            if (20 + capl > blen) return -1;
            memcpy(b, body + 20, capl);
            uint64_t ticks = ((uint64_t)get32(body + 4, p->ng_swap) << 32) |
                              get32(body + 8, p->ng_swap);
            /* convert ticks to nanoseconds using if_tsresol:
             * value_seconds = ticks / 10^resol  =>  ns = ticks * 10^(9-resol) */
            uint64_t ns;
            if (p->if_tsresol_bin) {
                unsigned sh = p->if_tsresol > 63 ? 63 : p->if_tsresol;
                /* 2^-sh seconds per tick => ns = ticks * 1e9 / 2^sh */
                ns = (ticks * 1000000000ull) >> sh;
            } else if (p->if_tsresol <= 9) {
                static const uint32_t p10[10] = {1u,10u,100u,1000u,10000u,100000u,
                                                 1000000u,10000000u,100000000u,1000000000u};
                unsigned scale = 9 - p->if_tsresol;
                ns = ticks * p10[scale];
            } else {
                /* coarser than seconds: each tick is multiple seconds */
                static const uint32_t p10[10] = {1u,10u,100u,1000u,10000u,100000u,
                                                 1000000u,10000000u,100000000u,1000000000u};
                unsigned over = p->if_tsresol - 9;
                uint64_t mult = over <= 9 ? p10[over] : 1000000000ull;
                ns = ticks * mult * 1000000000ull;
            }
            ts->tv_sec  = (time_t)(ns / 1000000000ull);
            ts->tv_nsec = (long)(ns % 1000000000ull);
            *caplen = capl; *wirelen = orig;
            return 1;
        }
        /* Simple Packet Block (3): no timestamp */
        if (type == 0x00000003) {
            if (blen < 4) return -1;
            uint32_t orig = get32(body, p->ng_swap);
            uint32_t capl = blen - 4;
            if (capl > bufsz) capl = (uint32_t)bufsz;
            memcpy(b, body + 4, capl);
            ts->tv_sec = 0; ts->tv_nsec = 0;
            *caplen = capl; *wirelen = orig;
            return 1;
        }
        /* everything else (NRB, ISB, custom) is skipped */
    }
}

/* ---------- public reader ---------- */

int pcapin_open(pcapin_t *p, const char *path) {
    memset(p, 0, sizeof *p);
    p->f = fopen(path, "rb");
    if (!p->f) { fprintf(stderr, "ch1m3ra: %s: %s\n", path, strerror(errno)); return -1; }
    uint8_t gh[24];
    if (fread(gh, 1, 4, p->f) != 4) {
        fprintf(stderr, "ch1m3ra: %s: short file\n", path); fclose(p->f); return -1;
    }
    uint32_t m = get32(gh, 0);
    if (m == 0x0a0d0d0a) return ng_open(p, path);

    if (fread(gh + 4, 1, 20, p->f) != 20) {
        fprintf(stderr, "ch1m3ra: %s: short pcap header\n", path); fclose(p->f); return -1;
    }
    if (pcap_open_classic(p, gh, m) != 0) {
        fprintf(stderr, "ch1m3ra: %s: not a pcap/pcapng file\n", path);
        fclose(p->f); return -1;
    }
    return 0;
}

/* 1 = ok, 0 = EOF, -1 = error */
int pcapin_next(pcapin_t *p, uint8_t *b, size_t bufsz, size_t *cap, size_t *wire,
                struct timespec *ts) {
    if (p->ng) return ng_next(p, b, bufsz, cap, wire, ts);
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

/* ---------- writers ---------- */

static int fmt_from_path(const char *path) {
    size_t n = strlen(path);
    if (n >= 7 && !strcasecmp(path + n - 7, ".pcapng")) return PCAPW_PCAPNG;
    return PCAPW_PCAP;
}

static pcapw_t *w_alloc(const char *path, int fmt) {
    pcapw_t *w = calloc(1, sizeof *w);
    if (!w) { fprintf(stderr, "ch1m3ra: out of memory\n"); exit(1); }
    w->f = fopen(path, "wb");
    if (!w->f) { fprintf(stderr, "ch1m3ra: %s: %s\n", path, strerror(errno)); exit(1); }
    w->fmt = fmt;
    uint32_t lt = g_linktype ? g_linktype : 1;   /* Ethernet unless radiotap/802.11 */
    if (fmt == PCAPW_PCAP) {
        uint8_t gh[24] = { 0xd4,0xc3,0xb2,0xa1, 2,0, 4,0, 0,0,0,0, 0,0,0,0,
                           0xff,0xff,0,0, 1,0,0,0 };
        put32(gh + 20, lt);                     /* network / linktype */
        if (fwrite(gh, 1, 24, w->f) != 24) { fprintf(stderr, "ch1m3ra: write failed\n"); exit(1); }
    } else {
        /* Section Header Block */
        uint8_t shb[28];
        put32(shb, 0x0a0d0d0a);
        put32(shb + 4, 28);
        put32(shb + 8, 0x1a2b3c4d);        /* byte-order magic (little endian) */
        put16(shb + 12, 1); put16(shb + 14, 0);   /* version 1.0 */
        put64(shb + 16, 0xffffffffffffffffull);   /* section length: unknown */
        put32(shb + 24, 28);
        if (fwrite(shb, 1, 28, w->f) != 28) { fprintf(stderr, "ch1m3ra: write failed\n"); exit(1); }
        /* Interface Description Block: linktype from the capture, tsresol ns */
        uint8_t idb[32];
        put32(idb, 0x00000001);
        put32(idb + 4, 32);
        put16(idb + 8, (uint16_t)lt);      /* LINKTYPE_* */
        put16(idb + 10, 0);
        put32(idb + 12, 262144);           /* snaplen */
        /* options: if_tsresol = 9 (nanoseconds) => 1 option, 4 bytes + code/len */
        put16(idb + 16, 9); put16(idb + 18, 1); idb[20] = 9; idb[21] = idb[22] = idb[23] = 0;
        put16(idb + 24, 0); put16(idb + 26, 0);    /* opt_endofopt */
        put32(idb + 28, 32);
        if (fwrite(idb, 1, 32, w->f) != 32) { fprintf(stderr, "ch1m3ra: write failed\n"); exit(1); }
    }
    w->if_id = 0;
    return w;
}

pcapw_t *open_pcap_write(const char *path) { return w_alloc(path, fmt_from_path(path)); }
pcapw_t *open_pcap_write_fmt(const char *path, int fmt) { return w_alloc(path, fmt); }

void pcap_write(pcapw_t *w, const uint8_t *b, size_t cap, size_t wire,
                const struct timespec *ts) {
    if (w->fmt == PCAPW_PCAP) {
        uint8_t rh[16];
        put32(rh, (uint32_t)ts->tv_sec);
        put32(rh + 4, (uint32_t)(ts->tv_nsec / 1000));
        put32(rh + 8, (uint32_t)cap);
        put32(rh + 12, (uint32_t)wire);
        if (fwrite(rh, 1, 16, w->f) != 16 || fwrite(b, 1, cap, w->f) != cap) {
            fprintf(stderr, "ch1m3ra: write failed\n"); exit(1);
        }
    } else {
        /* Enhanced Packet Block */
        uint32_t pad = (uint32_t)((4 - (cap & 3)) & 3);
        uint32_t total = 32 + (uint32_t)cap + pad;
        uint8_t eh[28];
        put32(eh, 0x00000006);
        put32(eh + 4, total);
        put32(eh + 8, w->if_id);
        uint64_t ns = (uint64_t)ts->tv_sec * 1000000000ull + (uint64_t)ts->tv_nsec;
        put32(eh + 12, (uint32_t)(ns >> 32));
        put32(eh + 16, (uint32_t)ns);
        put32(eh + 20, (uint32_t)cap);
        put32(eh + 24, (uint32_t)wire);
        if (fwrite(eh, 1, 28, w->f) != 28) { fprintf(stderr, "ch1m3ra: write failed\n"); exit(1); }
        if (fwrite(b, 1, cap, w->f) != cap) { fprintf(stderr, "ch1m3ra: write failed\n"); exit(1); }
        if (pad) { uint8_t z[3] = {0,0,0}; if (fwrite(z, 1, pad, w->f) != pad) { fprintf(stderr, "ch1m3ra: write failed\n"); exit(1);} }
        put32(eh, total);                  /* trailing block total length */
        if (fwrite(eh, 1, 4, w->f) != 4) { fprintf(stderr, "ch1m3ra: write failed\n"); exit(1); }
    }
}

void pcap_write_close(pcapw_t *w) {
    if (!w) return;
    if (w->f) fflush(w->f);
    /* note: caller owns the FILE via cap.wf in some paths; keep FILE open only
     * if the caller still needs it.  Here we just flush; the FILE is closed at
     * process exit or by the caller for rotation. */
    if (w->f) fclose(w->f);
    free(w);
}

/* ---------- -w rotation ---------- */

static char  rot_base[4096];
static long  rot_size_bytes;     /* rotate when file exceeds this (0 = off) */
static long  rot_secs;           /* rotate when time advances this much */
static long  rot_index;
static long  rot_written;        /* bytes written to current file */
static struct timespec rot_start;

/* Build "base-NNNN.ext" keeping the original extension. */
static void rot_name(const char *base, long idx, char *out, size_t sz) {
    const char *dot = strrchr(base, '.');
    const char *slash = strrchr(base, '/');
    if (dot && (!slash || dot > slash)) {
        size_t stem = (size_t)(dot - base);
        snprintf(out, sz, "%.*s-%05ld%s", (int)stem, base, idx, dot);
    } else {
        snprintf(out, sz, "%s-%05ld", base, idx);
    }
}

void pcapw_rotate_init(const char *path) {
    snprintf(rot_base, sizeof rot_base, "%s", path);
    rot_size_bytes = cfg.rot_size > 0 ? cfg.rot_size * 1024L * 1024L : 0;
    rot_secs = cfg.rot_secs;
    rot_index = 0;
    rot_written = 0;
    rot_start.tv_sec = 0; rot_start.tv_nsec = 0;   /* set on first packet */
    /* first file is the plain name; subsequent ones get -NNNNN */
    cap.wf = open_pcap_write(path);
}

int pcapw_rotate_need(const struct timespec *ts) {
    if (!cap.wf) return 0;
    if (rot_secs > 0 && ts) {
        if (rot_start.tv_sec == 0) { rot_start = *ts; return 0; }  /* seed from data */
        long elapsed = (long)(ts->tv_sec - rot_start.tv_sec);
        if (elapsed >= rot_secs) return 1;
    }
    if (rot_size_bytes > 0) {
        fflush(cap.wf->f);
        long pos = ftell(cap.wf->f);
        if (pos >= 0 && pos >= rot_size_bytes) return 1;
    }
    return 0;
}

void pcapw_rotate_do(const struct timespec *ts) {
    if (cap.wf) { fflush(cap.wf->f); fclose(cap.wf->f); free(cap.wf); cap.wf = NULL; }
    rot_index++;
    char name[4096 + 32];
    rot_name(rot_base, rot_index, name, sizeof name);
    cap.wf = open_pcap_write(name);
    rot_written = 0;
    if (ts) rot_start = *ts;
}

/* ---------- --follow-out: write followed-stream payloads as a pcap ---------- */

static pcapw_t *fo_w;

void follow_out_open(const char *path) {
    if (fo_w) return;
    fo_w = open_pcap_write(path);
}

void follow_out_write(const uint8_t *b, size_t cap, size_t wire,
                      const struct timespec *ts) {
    if (!fo_w) return;
    pcap_write(fo_w, b, cap, wire, ts);
}

void follow_out_close(void) {
    if (fo_w) { pcap_write_close(fo_w); fo_w = NULL; }
}
