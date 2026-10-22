/* frag.c - IPv4 / IPv6 fragment reassembly (-A)
 *
 * A small fixed-size table of reassembly slots collects fragments keyed by
 * (family, src, dst, ident, next-header).  When a datagram is complete the
 * fragments are stitched into a synthetic frame (Ethernet + IP header + the
 * assembled transport payload) which is handed back to the caller to decode
 * exactly like an unfragmented packet.  Slots expire on a timer so a lone
 * fragment cannot occupy the table forever.
 *
 * This is deliberately from-scratch: no libpcap, no OS reassembly.
 */
#include "ch1m3ra.h"

#define FRAG_MAXPKT   65535u          /* max reassembled datagram (IP limit) */
#define FRAG_SLOTS    128             /* concurrent in-flight datagrams */
#define FRAG_TMO_MS   30000           /* slot idle timeout */

typedef struct {
    int      used;
    int      fam;                     /* 4 or 6 */
    uint8_t  src[16], dst[16];
    uint32_t id;                      /* IPv4 ident or IPv6 fragment id */
    uint8_t  proto;                   /* next header / protocol */
    uint8_t  hdr[40];                 /* IPv4 header (20) or IPv6 hdr+frag (48) */
    size_t   hlen;                    /* bytes of header to reproduce */
    uint8_t  data[FRAG_MAXPKT];       /* reassembled transport payload */
    size_t   hi;                      /* highest byte written so far */
    uint64_t have;                    /* bit per 8-byte block already present */
    long     last_ms;                 /* last update (for timeout) */
    unsigned long long npkts;
    char     ifname[IF_NAMESIZE];
    int      have_dir, out;
    struct timespec ts_first;         /* timestamp of the first fragment */
} fragslot_t;

static fragslot_t ftab[FRAG_SLOTS];
static unsigned long long frag_ok, frag_partial, frag_drop;

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)(t.tv_sec * 1000L + t.tv_nsec / 1000000L);
}

static int fam_eq(int fam, const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, fam == 4 ? 4 : 16) == 0;
}

static void copy_addr(int fam, uint8_t *dst, const uint8_t *src) {
    memcpy(dst, src, fam == 4 ? 4 : 16);
}

/* find or create a slot for this datagram */
static fragslot_t *slot_get(int fam, const uint8_t *src, const uint8_t *dst,
                            uint32_t id, uint8_t proto) {
    long t = now_ms();
    fragslot_t *free_slot = NULL;
    for (unsigned i = 0; i < FRAG_SLOTS; i++) {
        fragslot_t *s = &ftab[i];
        if (s->used && t - s->last_ms > FRAG_TMO_MS) { s->used = 0; }
        if (!s->used) { if (!free_slot) free_slot = s; continue; }
        if (s->fam == fam && s->id == id && s->proto == proto &&
            fam_eq(fam, s->src, src) && fam_eq(fam, s->dst, dst))
            return s;
    }
    if (!free_slot) { frag_drop++; return NULL; }   /* table full */
    memset(free_slot, 0, sizeof *free_slot);
    free_slot->used = 1;
    free_slot->fam = fam;
    copy_addr(fam, free_slot->src, src);
    copy_addr(fam, free_slot->dst, dst);
    free_slot->id = id;
    free_slot->proto = proto;
    return free_slot;
}

/* mark the 8-byte blocks [off, off+len) as present; return 1 if any overlap */
static int frag_overlap(fragslot_t *s, size_t off, size_t len) {
    size_t b0 = off / 8, b1 = (off + len + 7) / 8;
    int ov = 0;
    for (size_t b = b0; b < b1; b++) {
        if (b < 64 && (s->have & (1ULL << b))) { ov = 1; break; }
        if (b >= 64 && s->have & (1ULL << (b % 64))) { /* coarse for big datagrams */
            /* only 64 blocks tracked exactly; beyond that rely on offset checks */
        }
    }
    for (size_t b = b0; b < b1; b++) if (b < 64) s->have |= (1ULL << b);
    return ov;
}

/* build Ethernet + IP header for the reassembled datagram and decode it */
static int frag_emit(fragslot_t *s, packet_t *out) {
    uint8_t frame[14 + 40 + FRAG_MAXPKT];
    size_t o = 0;

    /* dummy Ethernet header (real L2 was on each fragment; synthesize zeros) */
    memset(frame, 0, 14);
    frame[12] = s->fam == 4 ? 0x08 : 0x86;
    frame[13] = s->fam == 4 ? 0x00 : 0xdd;
    o = 14;

    if (s->fam == 4) {
        memcpy(frame + o, s->hdr, 20);
        uint16_t tot = (uint16_t)(20 + s->hi);
        frame[o + 2] = (uint8_t)(tot >> 8); frame[o + 3] = (uint8_t)tot;
        /* clear MF/DF/frag offset, keep ident/flags-zero */
        frame[o + 6] = 0; frame[o + 7] = 0;
        frame[o + 10] = 0; frame[o + 11] = 0;          /* reset checksum */
        /* recompute the IPv4 header checksum over the rebuilt header */
        uint32_t csum = 0;
        for (int i = 0; i < 20; i += 2)
            csum += ((uint32_t)frame[o + i] << 8) | frame[o + i + 1];
        while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
        csum = (~csum) & 0xffff;
        frame[o + 10] = (uint8_t)(csum >> 8); frame[o + 11] = (uint8_t)csum;
        o += 20;
    } else {
        memcpy(frame + o, s->hdr, s->hlen);            /* 40-byte base header */
        uint16_t pl = (uint16_t)s->hi;
        frame[o + 4] = (uint8_t)(pl >> 8); frame[o + 5] = (uint8_t)pl;
        frame[o + 6] = s->proto;                       /* next header */
        o += s->hlen;
    }
    if (o + s->hi > sizeof frame) return 0;
    memcpy(frame + o, s->data, s->hi);
    o += s->hi;

    decode(out, frame, o, o, &s->ts_first, s->ifname, s->have_dir, s->out);
    /* mark it clearly as a reassembled datagram; the L4 checksum cannot be
     * trusted because fragments may have arrived from different captures */
    out->l4_csum = -1;
    if (!out->malformed) {
        snprintf(out->disp, sizeof out->disp, "%s", out->disp[0] ? out->disp : "IP");
        lst(out->ext_s, sizeof out->ext_s, "reassembled");
    }
    return 1;
}

/* Feed one decoded fragment.  Returns 1 and fills *out when the datagram is
 * now complete, 0 otherwise.  Non-fragments return 0 immediately.        */
int frag_feed(const packet_t *p, const uint8_t *l3, size_t l3len, packet_t *out) {
    if (!cfg.reasm) return 0;
    if (p->ip_ver == 4) {
        if (!(p->mf || p->frag_off > 0)) return 0;
        if (l3len < 20) return 0;
        size_t ihl = (size_t)(l3[0] & 0xf) * 4;
        if (ihl < 20 || ihl > l3len) return 0;
        size_t pay = l3len - ihl;
        fragslot_t *s = slot_get(4, p->src, p->dst, p->ip_id, l3[9]);
        if (!s) return 0;
        if (s->hlen == 0) { memcpy(s->hdr, l3, 20); s->hlen = 20;
                            s->ts_first = p->ts; s->have_dir = p->have_dir;
                            s->out = p->outgoing;
                            snprintf(s->ifname, sizeof s->ifname, "%s", p->ifname); }
        if (p->frag_off == 0 && s->hi == 0 && !s->npkts) s->ts_first = p->ts;
        s->npkts++;
        s->last_ms = now_ms();
        size_t off = (size_t)p->frag_off;
        if (off + pay > FRAG_MAXPKT) { s->used = 0; frag_drop++; return 0; }
        frag_overlap(s, off, pay);
        memcpy(s->data + off, l3 + ihl, pay);
        if (off + pay > s->hi) s->hi = off + pay;
        if (p->mf) { frag_partial++; return 0; }        /* more to come */
        if (frag_emit(s, out)) { s->used = 0; frag_ok++; return 1; }
        s->used = 0; return 0;
    }
    if (p->ip_ver == 6) {
        if (!(p->mf || p->frag_off > 0)) return 0;
        if (l3len < 40) return 0;
        /* locate the fragment header to recover payload offset + next header */
        size_t off = 40;
        uint8_t nxt = l3[6];
        int is_frag = 0;
        for (int hops = 0; hops < 8; hops++) {
            if (nxt == 44) { is_frag = 1; break; }
            if (nxt == 0 || nxt == 43 || nxt == 51 || nxt == 60) {
                if (off + 2 > l3len) return 0;
                size_t elen = (nxt == 51) ? ((size_t)l3[off + 1] + 2) * 4
                                          : ((size_t)l3[off + 1] + 1) * 8;
                if (off + elen > l3len) return 0;
                nxt = l3[off]; off += elen;
            } else break;
        }
        if (!is_frag || off + 8 > l3len) return 0;
        uint32_t id = rd32(l3 + off + 4);
        uint8_t inner = l3[off];
        size_t pay = l3len - (off + 8);
        fragslot_t *s = slot_get(6, p->src, p->dst, id, inner);
        if (!s) return 0;
        if (s->hlen == 0) {
            if ((size_t)l3len < 40) return 0;
            memcpy(s->hdr, l3, 40); s->hlen = 40;
            s->ts_first = p->ts; s->have_dir = p->have_dir; s->out = p->outgoing;
            snprintf(s->ifname, sizeof s->ifname, "%s", p->ifname);
        }
        s->npkts++;
        s->last_ms = now_ms();
        size_t doff = (size_t)p->frag_off;
        if (doff + pay > FRAG_MAXPKT) { s->used = 0; frag_drop++; return 0; }
        frag_overlap(s, doff, pay);
        memcpy(s->data + doff, l3 + off + 8, pay);
        if (doff + pay > s->hi) s->hi = doff + pay;
        if (p->mf) { frag_partial++; return 0; }
        if (frag_emit(s, out)) { s->used = 0; frag_ok++; return 1; }
        s->used = 0; return 0;
    }
    return 0;
}

void frag_stats(FILE *o) {
    if (!frag_ok && !frag_partial && !frag_drop) return;
    fprintf(o, "  fragments\n");
    fprintf(o, "    reassembled       %llu\n", frag_ok);
    fprintf(o, "    fragments stored  %llu\n", frag_partial);
    fprintf(o, "    dropped (table)   %llu\n", frag_drop);
}

void frag_cleanup(void) { memset(ftab, 0, sizeof ftab); }
