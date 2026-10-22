/* util.c - tiny helpers + name tables */

#include "ch1m3ra.h"

/* ---------- tiny helpers ---------- */

uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

uint32_t ck_add(uint32_t sum, const uint8_t *d, size_t n) {
    while (n > 1) { sum += ((uint32_t)d[0] << 8) | d[1]; d += 2; n -= 2; }
    if (n) sum += (uint32_t)d[0] << 8;
    return sum;
}
uint16_t ck_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}
/* 1 = valid (segment includes its own stored checksum), 0 = bad */
int ck_ok_incl(const uint8_t *d, size_t n) { return ck_fold(ck_add(0, d, n)) == 0; }

void lstv(char *dst, size_t sz, const char *sep, const char *fmt, va_list ap) {
    size_t used = strlen(dst);
    size_t sl = strlen(sep);
    if (used + sl + 1 >= sz) return;
    if (used) { memcpy(dst + used, sep, sl + 1); used += sl; }
    vsnprintf(dst + used, sz - used, fmt, ap);
}
/* append "val" to a comma-separated list buffer */
void lst(char *dst, size_t sz, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    lstv(dst, sz, ", ", fmt, ap);
    va_end(ap);
}
/* append with a space separator (app-layer summaries) */
void lsts(char *dst, size_t sz, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    lstv(dst, sz, " ", fmt, ap);
    va_end(ap);
}

void mac_str(const uint8_t *m, char *out, size_t sz) {
    snprintf(out, sz, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* ---------- name tables ---------- */
const char *ipproto_name(uint8_t p) {
    switch (p) {
        case 1: return "icmp";   case 2: return "igmp";   case 6: return "tcp";
        case 17: return "udp";   case 41: return "ipv6";  case 47: return "gre";
        case 50: return "esp";   case 51: return "ah";    case 58: return "icmpv6";
        case 89: return "ospf";  case 103: return "pim";  case 132: return "sctp";
        default: return NULL;
    }
}
const char *icmp4_name(uint8_t t) {
    switch (t) {
        case 0: return "echo-reply";      case 3: return "dest-unreach";
        case 4: return "src-quench";      case 5: return "redirect";
        case 8: return "echo-request";    case 9: return "router-advert";
        case 10: return "router-solicit"; case 11: return "time-exceeded";
        case 12: return "param-problem";  case 13: return "timestamp";
        case 14: return "timestamp-reply";default: return "unknown";
    }
}
const char *icmp6_name(uint8_t t) {
    switch (t) {
        case 1: return "dest-unreach";   case 2: return "pkt-too-big";
        case 3: return "time-exceeded";  case 4: return "param-problem";
        case 128: return "echo-request"; case 129: return "echo-reply";
        case 133: return "router-solicit"; case 134: return "router-advert";
        case 135: return "neigh-solicit";case 136: return "neigh-advert";
        case 137: return "redirect";     default: return "unknown";
    }
}
const char *ethertype_name(uint16_t e) {
    switch (e) {
        case 0x0800: return "IPv4";  case 0x0806: return "ARP";
        case 0x8035: return "RARP";  case 0x8100: return "802.1Q";
        case 0x86dd: return "IPv6";  case 0x888e: return "EAPOL";
        case 0x88cc: return "LLDP";  case 0x8847: return "MPLS";
        case 0x88b6: return "802.1X"; default: return NULL;
    }
}
const char *port_service(uint16_t port, int istcp) {
    struct servent *s = getservbyport(htons(port), istcp ? "tcp" : "udp");
    return s ? s->s_name : NULL;
}

/* ---------- MD5 (RFC 1321), used for JA3 TLS fingerprints ---------- */

struct md5_ctx { uint32_t a, b, c, d; uint64_t len; uint8_t buf[64]; size_t n; };

static uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void md5_block(struct md5_ctx *m, const uint8_t *p) {
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    static const int S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
    };
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8)
             | ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
    uint32_t a = m->a, b = m->b, c = m->c, d = m->d;
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16)      { f = (b & c) | (~b & d);        g = i; }
        else if (i < 32) { f = (d & b) | (~d & c);        g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;                 g = (3*i + 5) & 15; }
        else             { f = c ^ (b | ~d);              g = (7*i) & 15; }
        uint32_t tmp = d;
        d = c; c = b;
        b = b + rol(a + f + K[i] + M[g], S[i]);
        a = tmp;
    }
    m->a += a; m->b += b; m->c += c; m->d += d;
}

static void md5_init(struct md5_ctx *m) {
    m->a = 0x67452301; m->b = 0xefcdab89; m->c = 0x98badcfe; m->d = 0x10325476;
    m->len = 0; m->n = 0;
}

static void md5_update(struct md5_ctx *m, const void *data, size_t len) {
    const uint8_t *p = data;
    m->len += len;
    while (len) {
        size_t take = 64 - m->n;
        if (take > len) take = len;
        memcpy(m->buf + m->n, p, take);
        m->n += take; p += take; len -= take;
        if (m->n == 64) { md5_block(m, m->buf); m->n = 0; }
    }
}

static void md5_final(struct md5_ctx *m, uint8_t out[16]) {
    uint64_t bits = m->len * 8;
    uint8_t pad = 0x80;
    md5_update(m, &pad, 1);
    uint8_t z = 0;
    while (m->n != 56) md5_update(m, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (8*i));
    md5_update(m, lenb, 8);
    uint32_t v[4] = { m->a, m->b, m->c, m->d };
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            out[i*4 + j] = (uint8_t)(v[i] >> (8*j));
}

/* hex MD5 of a string into out (needs 33 bytes) */
void md5_hex(const char *s, char *out, size_t sz) {
    struct md5_ctx m;
    uint8_t d[16];
    md5_init(&m);
    md5_update(&m, s, strlen(s));
    md5_final(&m, d);
    static const char hx[] = "0123456789abcdef";
    size_t k = 0;
    for (int i = 0; i < 16 && k + 2 < sz; i++) {
        out[k++] = hx[d[i] >> 4];
        out[k++] = hx[d[i] & 0xf];
    }
    out[k] = 0;
}
