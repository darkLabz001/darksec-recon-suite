/* bpf.c - kernel BPF filter (-F) + offline interpreter */

#include "ch1m3ra.h"

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
    uint8_t  cmp;            /* BN_TEST: BCMP_EQ / BCMP_GE / BCMP_LE / BCMP_MASK */
    uint32_t k, val;         /* BN_TEST: packet offset, compare value */
    uint32_t mask;           /* BN_TEST/BCMP_MASK: bit mask */
};
enum { BN_TEST, BN_AND, BN_OR, BN_NOT, BN_LEN };
enum { BCMP_EQ, BCMP_GE, BCMP_LE, BCMP_MASK, BCMP_NZ };
/* BN_LEN fields: cmp = BCMP_GE/BCMP_LE, val = length */
/* BN_TEST with BCMP_MASK: k = offset, val = mask, a = sub-test whose result
 *   is ANDed with (load(k) & mask) != 0                              */

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
/* packet length test: BN_LEN with cmp = BCMP_GE / BCMP_LE */
static bnode_t *blen(int cmp, uint32_t v) {
    bnode_t *n = bnew(BN_LEN); n->cmp = (uint8_t)cmp; n->val = v; return n;
}
/* masked test: (load(cls @ k) & mask) == mval */
static bnode_t *bmask(int cls, uint32_t k, uint32_t mask, uint32_t mval) {
    bnode_t *n = btest(cls, k, mval);
    n->cmp = BCMP_MASK;
    n->mask = mask;
    return n;
}
/* masked-nonzero test: (load(cls @ k) & mask) != 0 */
static bnode_t *bnz(int cls, uint32_t k, uint32_t mask) {
    bnode_t *n = btest(cls, k, 0);
    n->cmp = BCMP_NZ;
    n->mask = mask ? mask : 0xff;
    return n;
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

/* VLAN-tagged frames: 802.1Q ethertype 0x8100 at offset 12. */
static bnode_t *n_vlan(void) { return btest(BPF_H, 12, 0x8100); }

/* ether host/src/dst: match the MAC at 6 (src) / 0 (dst). */
static bnode_t *n_ether(int side, const uint8_t *mac) {
    uint32_t hi = ((uint32_t)mac[0] << 8) | mac[1];
    uint32_t lo = ((uint32_t)mac[2] << 24) | ((uint32_t)mac[3] << 16) |
                  ((uint32_t)mac[4] << 8) | mac[5];
    bnode_t *src = band(btest(BPF_H, 6, hi), btest(BPF_W, 8, lo));
    bnode_t *dst = band(btest(BPF_H, 0, hi), btest(BPF_W, 2, lo));
    if (side == 1) return src;
    if (side == 2) return dst;
    return bor(src, dst);
}

/* tcp[tcpflags]: TCP flags byte is at L4 offset 13.
 * nz=1: (flags & mask) != 0 ; nz=0: (flags & mask) == want */
static bnode_t *n_tcpflags(uint32_t mask, uint32_t want, int nz) {
    bnode_t *v4, *v6;
    if (nz) {
        v4 = band(n_proto(0, 6), bnz(BPF_B, 47, mask));
        v6 = band(n_proto(1, 6), bnz(BPF_B, 67, mask));
    } else {
        v4 = band(n_proto(0, 6), bmask(BPF_B, 47, mask, want));
        v6 = band(n_proto(1, 6), bmask(BPF_B, 67, mask, want));
    }
    return bor(v4, v6);
}

/* ---- lexer ---- */
typedef struct { const char *s; char tok[64]; } blex_t;
static int blex(blex_t *L) {
    const char *s = L->s;
    while (*s == ' ' || *s == '\t') s++;
    if (!*s) { L->s = s; L->tok[0] = 0; return 0; }
    if (*s == '(' || *s == ')' || *s == '!') {
        if (*s == '!' && s[1] == '=') { L->tok[0] = '!'; L->tok[1] = '='; L->tok[2] = 0; L->s = s + 2; return 1; }
        L->tok[0] = *s; L->tok[1] = 0; L->s = s + 1; return 1;
    }
    if ((*s == '&' && s[1] == '&') || (*s == '|' && s[1] == '|')) {
        L->tok[0] = *s; L->tok[1] = *s; L->tok[2] = 0; L->s = s + 2; return 1;
    }
    if (*s == '&' || *s == '|' || *s == '=') {
        L->tok[0] = *s; L->tok[1] = 0; L->s = s + 1; return 1;
    }
    if (*s == '>' || *s == '<') {
        if (s[1] == '=') { L->tok[0] = *s; L->tok[1] = '='; L->tok[2] = 0; L->s = s + 2; return 1; }
        L->tok[0] = *s; L->tok[1] = 0; L->s = s + 1; return 1;
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
    if (!strcasecmp(P->cur, "ether")) {
        badv(P);
        int eside = side;
        if (P->have && (!strcasecmp(P->cur, "src") || !strcasecmp(P->cur, "dst"))) {
            eside = !strcasecmp(P->cur, "src") ? 1 : 2;
            badv(P);
        }
        if (P->have && !strcasecmp(P->cur, "host")) badv(P);
        if (!P->have || !P->cur[0]) { berr(P, "expected MAC after ether"); return NULL; }
        unsigned m[6];
        if (sscanf(P->cur, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) != 6) {
            berr(P, "bad MAC address");
            return NULL;
        }
        uint8_t mac[6];
        for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
        bnode_t *n = n_ether(eside, mac);
        badv(P);
        return n;
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

    /* vlan */
    if (!strcasecmp(P->cur, "vlan")) { badv(P); return n_vlan(); }

    /* greater/less <len>  (same as 'len >= N' / 'len <= N') */
    if (!strcasecmp(P->cur, "greater") || !strcasecmp(P->cur, "less")) {
        int cmp = !strcasecmp(P->cur, "greater") ? BCMP_GE : BCMP_LE;
        long v;
        if (!bp_number(P, P->cur, 0, 65535, &v)) return NULL;
        bnode_t *n = blen(cmp, (uint32_t)v);
        badv(P);
        return n;
    }

    /* tcp[tcpflags] ... ; also len comparisons */
    if (!strcasecmp(P->cur, "len")) {
        badv(P);                                   /* consume 'len' */
        if (P->have && (!strcmp(P->cur, ">") || !strcmp(P->cur, ">="))) {
            int cmp = !strcmp(P->cur, ">") ? BCMP_GE : BCMP_GE;
            long v;
            if (!bp_number(P, "length", 0, 65535, &v)) return NULL;
            (void)cmp;
            bnode_t *n = blen(BCMP_GE, (uint32_t)v);
            badv(P);
            return n;
        }
        if (P->have && (!strcmp(P->cur, "<") || !strcmp(P->cur, "<="))) {
            long v;
            if (!bp_number(P, "length", 0, 65535, &v)) return NULL;
            bnode_t *n = blen(BCMP_LE, (uint32_t)v);
            badv(P);
            return n;
        }
        berr(P, "expected > or < after len");
        return NULL;
    }
    if (!strncasecmp(P->cur, "tcp[", 4)) {
        /* accept tcp[tcpflags], tcp[tcpflags] & FLAG [!= 0] */
        if (strcasecmp(P->cur, "tcp[tcpflags]")) {
            berr(P, "only tcp[tcpflags] is supported");
            return NULL;
        }
        badv(P);
        uint32_t mask = 0xff;
        int nz = 1;                                /* bare tcp[tcpflags] != 0 */
        uint32_t want = 0;
        if (P->have && !strcmp(P->cur, "&")) {
            badv(P);
            if (!P->have) { berr(P, "expected flag mask after &"); return NULL; }
            /* flags: fin syn rst psh ack urg ece cwr, or a number */
            mask = 0;
            for (;;) {
                uint32_t bit;
                if      (!strcasecmp(P->cur, "fin") || !strcasecmp(P->cur, "tcp-fin")) bit = 0x01;
                else if (!strcasecmp(P->cur, "syn") || !strcasecmp(P->cur, "tcp-syn")) bit = 0x02;
                else if (!strcasecmp(P->cur, "rst") || !strcasecmp(P->cur, "tcp-rst")) bit = 0x04;
                else if (!strcasecmp(P->cur, "psh") || !strcasecmp(P->cur, "tcp-push")) bit = 0x08;
                else if (!strcasecmp(P->cur, "ack") || !strcasecmp(P->cur, "tcp-ack")) bit = 0x10;
                else if (!strcasecmp(P->cur, "urg") || !strcasecmp(P->cur, "tcp-urg")) bit = 0x20;
                else if (!strcasecmp(P->cur, "ece") || !strcasecmp(P->cur, "tcp-ece")) bit = 0x40;
                else if (!strcasecmp(P->cur, "cwr") || !strcasecmp(P->cur, "tcp-cwr")) bit = 0x80;
                else {
                    char *end = NULL; long v = strtol(P->cur, &end, 0);
                    if (!end || *end || v < 0 || v > 255) { berr(P, "bad tcp flag"); return NULL; }
                    bit = (uint32_t)v;
                }
                mask |= bit;
                badv(P);
                if (P->have && !strcmp(P->cur, "|")) { badv(P); continue; }
                break;
            }
        }
        /* optional comparison: '!= N', '== N', '= N', or nothing */
        if (P->have && (!strcmp(P->cur, "!=") || !strcmp(P->cur, "=="))) {
            int neq = !strcmp(P->cur, "!=");
            long v;
            if (!bp_number(P, "flags value", 0, 255, &v)) return NULL;
            badv(P);
            if (neq && v == 0) { nz = 1; want = 0; }          /* (f & M) != 0 */
            else               { nz = 0; want = (uint32_t)v; } /* (f & M) == v */
        } else if (P->have && !strcmp(P->cur, "=")) {
            long v;
            if (!bp_number(P, "flags value", 0, 255, &v)) return NULL;
            badv(P);
            nz = 0; want = (uint32_t)v;
        } else if (mask != 0xff || nz == 0) {
            /* '& MASK' with no comparison: any listed bit set */
            nz = 0; want = mask;
        }
        return n_tcpflags(mask, want, nz);
    }

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
        if (n->op == BN_LEN) {
            /* A = packet length.  Layout after the jump:
             *   [jf2] ja lf
             *   [jt2] ja lt
             * GE: A >= val true -> skip to jt2 (jt=1); false -> jf2 (jf=0)
             * LE: A <= val true -> jf2 is 'less-or-equal'? no: use JGT, so
             *     A > val -> lf (jt=0 -> jf2=ja lf), else lt (jf=1 -> jt2) */
            bput(BPF_LD | BPF_LEN, 0);
            bput(BPF_JMP | (n->cmp == BCMP_GE ? BPF_JGE : BPF_JGT) | BPF_K, n->val);
            if (n->cmp == BCMP_GE) { b_ins[b_n - 1].jt = 1; b_ins[b_n - 1].jf = 0; }
            else                   { b_ins[b_n - 1].jt = 0; b_ins[b_n - 1].jf = 1; }
            int jf2 = b_n;
            bput(BPF_JMP | BPF_JA, 0);          /* -> lf */
            bfix(jf2, lf);
            int jt2 = b_n;
            bput(BPF_JMP | BPF_JA, 0);          /* -> lt */
            bfix(jt2, lt);
            return;
        }
        if (n->cmp == BCMP_NZ) {
            /* A = load; A &= mask; jeq #0 -> lf else -> lt */
            bput(BPF_LD | BPF_B | BPF_ABS, n->k);
            bput(BPF_ALU | BPF_AND | BPF_K, n->mask);
            bput(BPF_JMP | BPF_JEQ | BPF_K, 0);
            b_ins[b_n - 1].jt = 0;              /* ==0: fall to 'ja lf' */
            b_ins[b_n - 1].jf = 1;              /* !=0: skip to 'ja lt' */
            int njf = b_n;
            bput(BPF_JMP | BPF_JA, 0);
            bfix(njf, lf);
            int njt = b_n;
            bput(BPF_JMP | BPF_JA, 0);
            bfix(njt, lt);
            return;
        }
        if (n->cmp == BCMP_MASK) {
            /* A = load(cls @ k); A &= mask; jeq #want */
            bput(n->cls == BPF_W ? BPF_LD | BPF_W | BPF_ABS :
                 n->cls == BPF_H ? BPF_LD | BPF_H | BPF_ABS :
                                   BPF_LD | BPF_B | BPF_ABS, n->k);
            bput(BPF_ALU | BPF_AND | BPF_K, n->mask);
            bput(BPF_JMP | BPF_JEQ | BPF_K, n->val);
            b_ins[b_n - 1].jt = 1;
            int mjf = b_n;
            bput(BPF_JMP | BPF_JA, 0);
            bfix(mjf, lf);
            int mjt = b_n;
            bput(BPF_JMP | BPF_JA, 0);
            bfix(mjt, lt);
            return;
        }
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

void bpf_compile(const char *expr) {
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

void bpf_attach(int fd) {
    struct sock_fprog fp;
    fp.len = (unsigned short)b_n;
    fp.filter = b_ins;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof fp) < 0) {
        fprintf(stderr, "ch1m3ra: cannot attach BPF filter: %s\n", strerror(errno));
        exit(1);
    }
}

/* classic-BPF interpreter for -r mode; only the forms we emit are supported */
int bpf_run(const uint8_t *data, uint32_t len) {
    uint32_t A = 0;
    unsigned pc = 0, steps = 0;
    while (pc < (unsigned)b_n) {
        if (++steps > 1000000u) return 0;        /* defensive: no loops emitted */
        const struct sock_filter *i = &b_ins[pc];
        uint8_t cl = (uint8_t)(i->code & 0x07);
        if (cl == BPF_RET) return i->k != 0;
        if (cl == BPF_LD) {
            uint32_t k = i->k;
            uint8_t mode = (uint8_t)(i->code & 0xe0);
            if (mode == BPF_LEN) { A = len; pc++; continue; }
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
        if (cl == BPF_ALU) {
            if (i->code == (BPF_ALU | BPF_AND | BPF_K)) { A &= i->k; pc++; continue; }
            return 0;
        }
        if (cl == BPF_JMP) {
            if (i->code == (BPF_JMP | BPF_JA)) { pc += i->k + 1; continue; }
            if (i->code == (BPF_JMP | BPF_JEQ | BPF_K)) {
                pc += (A == i->k ? i->jt : i->jf) + 1;
                continue;
            }
            if (i->code == (BPF_JMP | BPF_JGE | BPF_K)) {
                pc += (A >= i->k ? i->jt : i->jf) + 1;
                continue;
            }
            if (i->code == (BPF_JMP | BPF_JGT | BPF_K)) {
                pc += (A > i->k ? i->jt : i->jf) + 1;
                continue;
            }
            return 0;
        }
        return 0;                                /* anything else: not emitted */
    }
    return 0;
}

