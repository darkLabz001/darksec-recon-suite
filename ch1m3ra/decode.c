/* decode.c - link/network/transport decoding */

#include "ch1m3ra.h"

/* ---------- decoding ---------- */
void tcp_flags_str(uint16_t f, char *out, size_t sz) {
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

void tcp_opts_str(const uint8_t *o, size_t n, char *out, size_t sz) {
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
uint16_t l4_cksum(const packet_t *p, const uint8_t *seg, size_t n, int is_v6, uint8_t proto) {
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
void decode_app(packet_t *p);
void decode_banner(packet_t *p, const uint8_t *b, size_t n);

void decode_l4(packet_t *p, const uint8_t *seg, size_t avail, size_t total, uint8_t nh, int is_v6) {
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

void decode_arp(packet_t *p, const uint8_t *b, size_t len) {
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

void decode_ipv4(packet_t *p, const uint8_t *b, size_t len) {
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

void decode_ipv6(packet_t *p, const uint8_t *b, size_t len) {
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

void decode_wlan(packet_t *p, const uint8_t *f, size_t cap, int radiotap) {
    size_t off = 0;
    /* radiotap and 802.11 are little-endian, unlike the Ethernet/IPv4 headers
     * rd16/rd32 assume, so read the fields explicitly here. */
#define RD16LE(b) ((uint16_t)((b)[0] | ((b)[1] << 8)))
    if (radiotap) {
        if (cap < 8) { p->err = "runt radiotap"; p->malformed = 1;
            snprintf(p->disp, sizeof p->disp, "BAD");
            snprintf(p->primary, sizeof p->primary, "other"); return; }
        uint16_t rlen = RD16LE(f + 2);
        if (rlen < 8 || rlen > cap) { p->err = "bad radiotap length"; p->malformed = 1;
            snprintf(p->disp, sizeof p->disp, "BAD");
            snprintf(p->primary, sizeof p->primary, "other"); return; }
        /* Properly walk the present-bitmap words accumulating each present
         * field's offset with its natural alignment, so we locate the channel
         * (bit 3) and rate (bit 2) wherever they really sit.  The bitmap is a
         * continuous bit namespace: word N carries bits 32N..32N+31, and bit 31
         * of each word signals another extension word follows. */
        static const struct { uint8_t align, size; } rtf[] = {
            /* 0 TSFT       */ {8,8}, /* 1 FLAGS   */ {1,1}, /* 2 RATE   */ {1,1},
            /* 3 CHANNEL    */ {2,4}, /* 4 FHSS    */ {2,2}, /* 5 DBM_ANTSIG */ {1,1},
            /* 6 DBM_ANTNOISE */ {1,1}, /* 7 LOCKQ */ {2,2}, /* 8 TXATTEN */ {2,2},
            /* 9 DB_TXATTEN */ {2,2}, /* 10 DBM_TXPOW */ {1,1}, /* 11 ANTENNA */ {1,1},
            /* 12 DBM_ANTSIG2 */ {1,1}, /* 13 DBM_ANTNOISE2 */ {1,1}, /* 14 RXFLAGS */ {2,2},
            /* 15 TXFLAGS */ {2,2}, /* 16 RTSRETRIES */ {1,1}, /* 17 DATA_RETRIES */ {1,1},
            /* 18 XCHANNEL */ {4,8},
        };
        const size_t RTF_N = sizeof rtf / sizeof rtf[0];
        uint32_t words[8];
        int nwords = 0;
        size_t wp = 4;
        while (nwords < 8 && wp + 4 <= rlen && wp + 4 <= (size_t)cap) {
            uint32_t w = (uint32_t)f[wp] | ((uint32_t)f[wp+1] << 8) |
                         ((uint32_t)f[wp+2] << 16) | ((uint32_t)f[wp+3] << 24);
            words[nwords++] = w;
            if (!(w & 0x80000000u)) break;
            wp += 4;
        }
        size_t fbase = 4 + (size_t)nwords * 4;        /* first field-data offset */
        if (fbase > rlen) fbase = rlen;
        size_t cur = fbase;                           /* aligned running offset */
        for (int wi = 0; wi < nwords; wi++) {
            for (int bit = 0; bit < 32; bit++) {
                if (bit == 31 && wi + 1 < nwords) continue; /* ext bit */
                if (!(words[wi] & (1u << bit))) continue;
                size_t idx = (size_t)wi * 32 + (size_t)bit;
                if (idx < RTF_N) {
                    uint8_t al = rtf[idx].align, sz = rtf[idx].size;
                    cur = (cur + (al - 1)) & ~(size_t)(al - 1);   /* align */
                    if (idx == 3 && cur + 4 <= rlen && cur + 4 <= (size_t)cap) {
                        uint16_t freq = RD16LE(f + cur);
                        p->wlan_channel = freq >= 5000
                            ? (int)((freq - 5000) / 5)          /* 5 GHz */
                            : (int)((freq - 2407) / 5);         /* 2.4 GHz */
                        if (p->wlan_channel <= 0) p->wlan_channel = 0;
                    }
                    cur += sz;
                } else {
                    /* unknown/extended field: can't compute its size, stop */
                    wi = nwords; break;
                }
            }
        }
        off = rlen;
    }
    if (cap < off + 10) { p->err = "runt 802.11"; p->malformed = 1;
        snprintf(p->disp, sizeof p->disp, "BAD");
        snprintf(p->primary, sizeof p->primary, "other"); return; }

    const uint8_t *m = f + off;
    uint16_t fc = RD16LE(m);
    /* Control frames (type 1) are as short as 10 bytes (CTS/ACK); management
     * and data frames need the full 24-byte header (a bit more with QoS/4-addr,
     * which the readers below simply won't touch). */
    {
        int minlen = (((fc >> 2) & 3) == 1) ? 10 : 24;
        if (cap < off + (size_t)minlen) { p->err = "runt 802.11"; p->malformed = 1;
            snprintf(p->disp, sizeof p->disp, "BAD");
            snprintf(p->primary, sizeof p->primary, "other"); return; }
    }
    p->wlan = 1;
    p->has_l2 = 1;
    p->wlan_type = (fc >> 2) & 3;
    p->wlan_subtype = (fc >> 4) & 0xf;
    int to_ds = (fc >> 8) & 1, from_ds = (fc >> 9) & 1;

    /* address layout depends on the ToDS/FromDS bits.  Control frames (type 1)
     * only carry RA (+TA for RTS), so read addresses only when the bytes are
     * actually present to avoid reading past a 10-byte CTS/ACK. */
    size_t mlen0 = cap - off;        /* bytes available from m[0] onward */
    const uint8_t *a1 = m + 4;
    const uint8_t *a2 = mlen0 >= 16 ? m + 10 : NULL;
    const uint8_t *a3 = mlen0 >= 22 ? m + 16 : NULL;
    if (p->wlan_type == 0) {          /* management: addr3 is the BSSID */
        memcpy(p->eth_src, a2, 6);
        memcpy(p->eth_dst, a1, 6);
        mac_str(a3, p->wlan_bssid, sizeof p->wlan_bssid);
        p->etype = 0;                 /* not Ethernet */
    } else if (p->wlan_type == 1) {   /* control: only addr1 (RA) is reliable */
        memcpy(p->eth_dst, a1, 6);
        if (a2) memcpy(p->eth_src, a2, 6);
        else memset(p->eth_src, 0, 6);
        p->etype = 0;
    } else {                          /* data */
        if (a3) {
            memcpy(p->eth_src, from_ds ? a3 : a2, 6);
            memcpy(p->eth_dst, to_ds ? a3 : a1, 6);
            mac_str(a3, p->wlan_bssid, sizeof p->wlan_bssid);
        } else {
            memcpy(p->eth_src, to_ds ? a1 : a2, 6);
            memcpy(p->eth_dst, a1, 6);
        }
    }

    static const char *mt[] = { "mgmt", "ctrl", "data" };
    snprintf(p->disp, sizeof p->disp, "%s", p->wlan_type <= 2 ? mt[p->wlan_type] : "wlan");
    snprintf(p->primary, sizeof p->primary, "wlan");

    /* management frame bodies we understand */
    if (p->wlan_type == 0) {
        size_t mlen = cap - off;         /* bytes available from m[0] onward */
        size_t body = 24;                /* 802.11 header is 24 bytes */
        if (p->wlan_subtype == 8 || p->wlan_subtype == 5) {   /* beacon / probe-resp */
            size_t q = body + 12;    /* skip fixed timestamp(8) + interval(2) + cap(2) */
            if (q + 2 <= mlen) {
                p->wlan_protected = (RD16LE(m + body + 10) >> 4) & 1;   /* privacy bit */
                size_t elen = m[q + 1];
                if (q + 2 + elen <= mlen && elen <= 32) {
                    memcpy(p->wlan_ssid, m + q + 2, elen);
                    p->wlan_ssid[elen] = 0;
                }
            }
            snprintf(p->disp, sizeof p->disp, p->wlan_subtype == 8 ? "BEACON" : "PROBE-RESP");
        } else if (p->wlan_subtype == 12 || p->wlan_subtype == 10) {   /* deauth / disassoc */
            p->wlan_deauth = 1;
            uint16_t reason = (body + 2 <= mlen) ? RD16LE(m + body) : 0;
            snprintf(p->app_s, sizeof p->app_s, "deauth reason=%u", reason);
            snprintf(p->disp, sizeof p->disp, p->wlan_subtype == 12 ? "DEAUTH" : "DISASSOC");
        } else if (p->wlan_subtype == 4 || p->wlan_subtype == 0) {     /* probe-req / assoc-req */
            size_t q = body + 4;
            if (q + 2 <= mlen) {
                size_t elen = m[q + 1];
                if (q + 2 + elen <= mlen && elen <= 32) {
                    memcpy(p->wlan_ssid, m + q + 2, elen);
                    p->wlan_ssid[elen] = 0;
                }
            }
            snprintf(p->disp, sizeof p->disp, p->wlan_subtype == 4 ? "PROBE-REQ" : "ASSOC-REQ");
        } else {
            snprintf(p->disp, sizeof p->disp, "MGMT-%d", p->wlan_subtype);
        }
    }
#undef RD16LE
}

void decode(packet_t *p, const uint8_t *f, size_t cap, size_t wire,
                   const struct timespec *ts, const char *ifname, int have_dir, int out) {
    memset(p, 0, sizeof *p);
    p->caplen = cap; p->wirelen = wire;
    p->ts = *ts;
    p->have_dir = have_dir; p->outgoing = out;
    p->ip_csum = -1; p->l4_csum = -1; p->vlan = -1; p->inner_vlan = -1;
    p->stream_id = -1;
    snprintf(p->ifname, sizeof p->ifname, "%s", ifname ? ifname : "?");

    /* radiotap / raw 802.11 frames take a different path */
    if (g_linktype == 127 || g_linktype == 105) {
        decode_wlan(p, f, cap, (g_linktype == 127));
        harvest(p);
        defense_observe(p);
        return;
    }

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
        if (et == 0x88a8) p->qinq = 1;
        p->vlan = rd16(f + 14) & 0x0fff;
        et = rd16(f + 16);
        off = 18;
        /* a second (inner 802.1Q C-tag) makes this a QinQ double-tagged frame */
        if (et == 0x8100 && cap >= 22) {
            p->inner_vlan = rd16(f + 18) & 0x0fff;
            et = rd16(f + 20);
            off = 22;
        }
    }
    p->etype = et;

    if (et <= 1500) {   /* 802.3 length field */
        snprintf(p->disp, sizeof p->disp, "802.3");
        snprintf(p->primary, sizeof p->primary, "other");
        p->payload = f + off; p->plen = cap - off; p->avail = cap - off;
        defense_observe(p);   /* DTP and other L2 control frames live here */
        return;
    }
    switch (et) {
        case 0x0800: p->l3 = f + off; p->l3len = cap - off;
                     decode_ipv4(p, f + off, cap - off); break;
        case 0x86dd: p->l3 = f + off; p->l3len = cap - off;
                     decode_ipv6(p, f + off, cap - off); break;
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
    defense_observe(p);
}

