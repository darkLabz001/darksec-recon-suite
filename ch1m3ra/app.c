/* app.c - application layer (DNS / TLS / HTTP) */

#include "ch1m3ra.h"

/* ---------- application layer (DNS / TLS / HTTP) ---------- */
const char *dns_type_name(uint16_t t) {
    switch (t) {
        case 1: return "A";     case 2: return "NS";    case 5: return "CNAME";
        case 6: return "SOA";   case 12: return "PTR";  case 15: return "MX";
        case 16: return "TXT";  case 28: return "AAAA"; case 33: return "SRV";
        case 41: return "OPT";  case 47: return "RRSIG";case 48: return "DNSKEY";
        case 52: return "TLSA"; case 64: return "SVCB"; case 65: return "HTTPS";
        case 255: return "ANY"; default: return NULL;
    }
}
const char *dns_rcode_name(int r) {
    switch (r) {
        case 0: return "NOERROR";  case 1: return "FORMERR"; case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN"; case 4: return "NOTIMP";  case 5: return "REFUSED";
        case 6: return "YXDOMAIN"; case 7: return "YXRRSET"; case 8: return "NXRRSET";
        case 9: return "NOTAUTH";  case 10: return "NOTZONE"; default: return NULL;
    }
}
const char *dns_opcode_name(int o) {
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
static const char *tls_ct_name(uint8_t c) {    switch (c) {
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
const char *tls_ver_str(uint16_t v, char *buf, size_t sz) {
    switch (v) {
        case 0x0300: return "SSL3.0";
        case 0x0301: return "TLS1.0";
        case 0x0302: return "TLS1.1";
        case 0x0303: return "TLS1.2";
        case 0x0304: return "TLS1.3";
        default: snprintf(buf, sz, "0x%04x", v); return buf;
    }
}
const char *tls_cipher_name(uint16_t c) {
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

/* --- minimal DER/ASN.1 walker for X.509 certificate fields ---
 *
 * We only need a handful of fields, so this is a tiny parser rather than a
 * full ASN.1 library: it understands SEQUENCE, SET, OID, UTC/GeneralizedTime,
 * UTF8String / PrintableString / IA5String and context-tagged (SAN) values. */

typedef struct { const uint8_t *p, *end; } der_t;

static int der_tlv(der_t *d, uint8_t *tag, const uint8_t **val, size_t *len) {
    if (d->p + 2 > d->end) return 0;
    uint8_t t = *d->p++;
    size_t l = *d->p++;
    if (l & 0x80) {
        size_t nb = l & 0x7f;
        if (nb == 0 || nb > 4 || d->p + nb > d->end) return 0;
        l = 0;
        for (size_t i = 0; i < nb; i++) l = (l << 8) | *d->p++;
    }
    if (d->p + l > d->end) return 0;
    *tag = t; *val = d->p; *len = l;
    d->p += l;
    return 1;
}

/* OID for commonName: 2.5.4.3 -> 55 04 03 */
static const uint8_t OID_CN[] = {0x55, 0x04, 0x03};

/* copy a DER string value (UTF8String/PrintableString/IA5String) as ASCII */
static void der_str(const uint8_t *v, size_t l, char *out, size_t sz) {
    size_t c = l < sz - 1 ? l : sz - 1;
    memcpy(out, v, c);
    out[c] = 0;
}

/* extract the CN from a Name (RDNSequence): find the 55 04 03 OID, take the
 * next string value.  Returns 1 on success. */
static int der_name_cn(const uint8_t *b, size_t n, char *out, size_t sz) {
    der_t d = { b, b + n };
    uint8_t tag; const uint8_t *v; size_t l;
    if (!der_tlv(&d, &tag, &v, &l)) return 0;
    if ((tag & 0x1f) != 0x10 && (tag & 0x1f) != 0x11) return 0;  /* SEQ/SET */
    der_t s = { v, v + l };
    while (s.p < s.end) {
        uint8_t t2; const uint8_t *v2; size_t l2;
        if (!der_tlv(&s, &t2, &v2, &l2)) return 0;
        /* look for the CN OID anywhere inside this RDN */
        for (size_t i = 0; i + sizeof OID_CN < l2; i++) {
            if (v2[i] == OID_CN[0] && v2[i+1] == OID_CN[1] && v2[i+2] == OID_CN[2]) {
                /* the next TLV after the OID is the string */
                der_t o = { v2 + i + 3, v2 + l2 };
                uint8_t t3; const uint8_t *v3; size_t l3;
                if (der_tlv(&o, &t3, &v3, &l3) && (t3 & 0x1f) >= 12) {
                    der_str(v3, l3, out, sz);
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* decode a UTCTime / GeneralizedTime value to YYYY-MM-DD */
static void der_time(const uint8_t *v, size_t l, char *out, size_t sz) {
    if (l >= 13 && v[0] >= '0' && v[0] <= '9') {
        /* UTCTime: YYMMDDHHMMSSZ  -> 20YY-MM-DD */
        int yy = (v[0]-'0')*10 + (v[1]-'0');
        int year = yy >= 50 ? 1900 + yy : 2000 + yy;
        snprintf(out, sz, "%04d-%02d-%02d", year,
                 (v[2]-'0')*10 + (v[3]-'0'), (v[4]-'0')*10 + (v[5]-'0'));
    } else if (l >= 15) {
        /* GeneralizedTime: YYYYMMDD... */
        snprintf(out, sz, "%c%c%c%c-%c%c-%c%c",
                 v[0],v[1],v[2],v[3],v[4],v[5],v[6],v[7]);
    } else out[0] = 0;
}

/* parse one DER certificate, filling subject/issuer/SAN/validity */
static void cert_parse(const uint8_t *b, size_t n, packet_t *p) {
    der_t d = { b, b + n };
    uint8_t tag; const uint8_t *v; size_t l;
    if (!der_tlv(&d, &tag, &v, &l)) return;         /* Certificate */
    if ((tag & 0x1f) != 0x10) return;
    der_t c = { v, v + l };
    /* tbsCertificate */
    uint8_t t2; const uint8_t *tbs; size_t tl;
    if (!der_tlv(&c, &t2, &tbs, &tl)) return;
    der_t t = { tbs, tbs + tl };

    /* optional [0] version */
    uint8_t vt; const uint8_t *vv; size_t vl;
    const uint8_t *save = t.p;
    if (der_tlv(&t, &vt, &vv, &vl) && vt == 0xa0) { /* version present */ }
    else t.p = save;

    /* serialNumber INTEGER, signatureAlgorithm SEQ */
    uint8_t st1, st2; const uint8_t *sv1, *sv2; size_t sl1, sl2;
    if (!der_tlv(&t, &st1, &sv1, &sl1)) return;    /* serial */
    if (!der_tlv(&t, &st2, &sv2, &sl2)) return;    /* sig alg */

    /* issuer Name */
    uint8_t it; const uint8_t *iv; size_t il;
    if (!der_tlv(&t, &it, &iv, &il)) return;
    if (!p->cert_issuer[0]) der_name_cn(iv, il, p->cert_issuer, sizeof p->cert_issuer);

    /* validity */
    uint8_t gt; const uint8_t *gv; size_t gl;
    if (!der_tlv(&t, &gt, &gv, &gl)) return;
    {
        der_t val = { gv, gv + gl };
        uint8_t nb; const uint8_t *nbv; size_t nbl;
        uint8_t na; const uint8_t *nav; size_t nal;
        char s1[24] = "", s2[24] = "";
        if (der_tlv(&val, &nb, &nbv, &nbl)) der_time(nbv, nbl, s1, sizeof s1);
        if (der_tlv(&val, &na, &nav, &nal)) der_time(nav, nal, s2, sizeof s2);
        if (!p->cert_valid[0]) {
            char vbuf[48];
            snprintf(vbuf, sizeof vbuf, "%.11s..%.11s", s1, s2);
            memcpy(p->cert_valid, vbuf, sizeof vbuf);
        }
    }

    /* subject Name */
    uint8_t sut; const uint8_t *suv; size_t sul;
    if (!der_tlv(&t, &sut, &suv, &sul)) return;
    if (!p->cert_subject[0]) der_name_cn(suv, sul, p->cert_subject, sizeof p->cert_subject);

    /* extensions: walk remaining TLVs looking for [3] extensions, then the
     * subjectAltName OID (2.5.29.17 -> 55 1d 11) and pull dNSName entries */
    static const uint8_t OID_SAN[] = {0x55, 0x1d, 0x11};
    while (t.p < t.end) {
        uint8_t et; const uint8_t *ev; size_t el;
        if (!der_tlv(&t, &et, &ev, &el)) break;
        if (et != 0xa3) continue;                  /* [3] EXPLICIT extensions */
        der_t ext = { ev, ev + el };
        uint8_t sq; const uint8_t *sqv; size_t sql;
        if (!der_tlv(&ext, &sq, &sqv, &sql)) continue;
        der_t list = { sqv, sqv + sql };
        while (list.p < list.end) {
            uint8_t one; const uint8_t *ov; size_t ol;
            if (!der_tlv(&list, &one, &ov, &ol)) break;
            /* find the SAN OID within this extension */
            for (size_t i = 0; i + sizeof OID_SAN < ol; i++) {
                if (ov[i] == OID_SAN[0] && ov[i+1] == OID_SAN[1] && ov[i+2] == OID_SAN[2]) {
                    /* after OID: OCTET STRING containing GeneralNames SEQUENCE */
                    der_t o = { ov + i + 3, ov + ol };
                    uint8_t oct; const uint8_t *octv; size_t octl;
                    if (!der_tlv(&o, &oct, &octv, &octl)) break;
                    der_t gn = { octv, octv + octl };
                    uint8_t gs; const uint8_t *gsv; size_t gsl;
                    if (!der_tlv(&gn, &gs, &gsv, &gsl)) break;
                    der_t names = { gsv, gsv + gsl };
                    while (names.p < names.end) {
                        uint8_t nt; const uint8_t *nv; size_t nl;
                        if (!der_tlv(&names, &nt, &nv, &nl)) break;
                        if (nt != 0x82) continue;  /* dNSName [2] IA5String */
                        size_t used = strlen(p->cert_san);
                        if (used && used + 1 < sizeof p->cert_san)
                            p->cert_san[used++] = ',';
                        if (used + nl >= sizeof p->cert_san)
                            nl = sizeof p->cert_san - used - 1;
                        memcpy(p->cert_san + used, nv, nl);
                        p->cert_san[used + nl] = 0;
                    }
                    break;
                }
            }
        }
    }
}

/* parse a Certificate handshake message body (h == 11) */
static void tls_cert_msg(packet_t *p, const uint8_t *d, size_t hs) {
    if (hs < 3) return;
    /* certificate_list<3 bytes length> then certs each <3 bytes len> */
    size_t list = ((size_t)d[0] << 16) | ((size_t)d[1] << 8) | d[2];
    size_t pos = 3;
    int idx = 0;
    while (pos + 3 <= hs && idx < 16) {
        size_t clen = ((size_t)d[pos] << 16) | ((size_t)d[pos + 1] << 8) | d[pos + 2];
        pos += 3;
        if (clen == 0 || pos + clen > hs) break;
        if (idx == 0) cert_parse(d + pos, clen, p);
        pos += clen;
        idx++;
        if (list && pos - 3 >= list) break;
    }
    p->cert_n = idx;
}

/* Build the JA3 fingerprint from a ClientHello body.
 * JA3 = MD5("SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat")
 * with every list comma-joined and the "-" placeholder for empty lists.   */
static void tls_ja3(packet_t *p, const uint8_t *d, size_t hs) {
    if (hs < 2 + 32 + 1) return;
    char out[256];
    size_t o = 0;
    uint16_t legacy = rd16(d);                 /* client_version */
    o += (size_t)snprintf(out + o, sizeof out - o, "%u,", legacy);

    size_t pos = 2 + 32;
    if (pos >= hs) return;
    size_t sid = d[pos];
    pos += 1 + sid;
    if (pos + 2 > hs) return;
    size_t ncs = rd16(d + pos);
    pos += 2;
    size_t ciphers_start = pos;
    if (pos + ncs > hs) return;
    for (size_t i = 0; i + 1 < ncs; i += 2) {
        if (i) out[o++] = '-';
        o += (size_t)snprintf(out + o, sizeof out - o, "%u", rd16(d + pos + i));
    }
    (void)ciphers_start;
    pos += ncs;
    if (pos >= hs) return;
    size_t ncomp = d[pos];
    pos += 1 + ncomp;
    if (pos + 2 > hs) return;
    size_t nextlen = rd16(d + pos);
    pos += 2;
    size_t nend = pos + nextlen < hs ? pos + nextlen : hs;

    /* extension list */
    o += (size_t)snprintf(out + o, sizeof out - o, ",");
    char curves[128] = "", fmts[64] = "";
    size_t ce = 0, fe = 0;
    int firstext = 1;
    /* JA4 also needs: sorted extension types, sorted ciphers, sigalgs, ALPN */
    uint16_t jexts[64];  size_t njext = 0;
    char     jalpn[8] = "";
    uint16_t jsig[32];   size_t njsig = 0;
    size_t q = pos;
    while (q + 4 <= nend) {
        uint16_t et = rd16(d + q), el = rd16(d + q + 2);
        q += 4;
        if (q + el > nend) break;
        if (njext < 64) jexts[njext++] = et;
        if (!firstext) out[o++] = '-';
        firstext = 0;
        o += (size_t)snprintf(out + o, sizeof out - o, "%u", et);
        if (et == 10 && el >= 2) {             /* supported_groups */
            size_t g = 2;                       /* skip 2-byte list length */
            while (g + 1 < el) {
                if (ce) curves[ce++] = '-';
                ce += (size_t)snprintf(curves + ce, sizeof curves - ce, "%u", rd16(d + q + g));
                g += 2;
            }
        } else if (et == 11 && el >= 1) {      /* ec_point_formats */
            size_t g = 1;                       /* skip 1-byte list length */
            while (g < el) {
                if (fe) fmts[fe++] = '-';
                fe += (size_t)snprintf(fmts + fe, sizeof fmts - fe, "%u", d[q + g]);
                g += 1;
            }
        } else if (et == 16 && el >= 3) {      /* ALPN: first protocol, 2 chars */
            uint8_t pl = d[q + 2];
            size_t take = pl < 2 ? pl : 2;
            if (take + 3 <= el) {
                jalpn[0] = take > 0 ? (char)d[q + 3] : 0;
                jalpn[1] = take > 1 ? (char)d[q + 4] : 0;
                jalpn[2] = 0;
            }
        } else if (et == 13 && el >= 2) {      /* signature_algorithms */
            size_t g = 2;
            while (g + 1 < el && njsig < 32) {
                jsig[njsig++] = rd16(d + q + g);
                g += 2;
            }
        } else if (et == 0xfe0d) {             /* encrypted_client_hello */
            p->ech = 1;
        }
        q += el;
    }
    snprintf(out + o, sizeof out - o, ",%s,%s",
             curves[0] ? curves : "", fmts[0] ? fmts : "");
    snprintf(p->ja3_str, sizeof p->ja3_str, "%s", out);
    md5_hex(out, p->ja3, sizeof p->ja3);

    /* --- JA4 (FoxIO): <proto><ver><sni><nciphers><nexts><alpn>_<cipher md5>_<ext+sig md5> --- */
    /* ciphers come from the earlier block; re-read them here for hashing */
    size_t cp = 2 + 32;
    if (cp < hs) {
        cp += 1 + d[cp];
        if (cp + 2 <= hs) {
            size_t csl = rd16(d + cp);
            cp += 2;
            if (cp + csl <= hs) {
                uint16_t ciph[64]; size_t nc = 0;
                for (size_t i = 0; i + 1 < csl && nc < 64; i += 2)
                    ciph[nc++] = rd16(d + cp + i);
                /* remove GREASE values (0x?a?a pattern) before sorting */
                size_t w = 0;
                for (size_t i = 0; i < nc; i++) {
                    uint16_t c = ciph[i];
                    if (!((c & 0x0f0f) == 0x0a0a && ((c >> 8) == (c & 0xff))))
                        ciph[w++] = c;
                }
                nc = w;
                for (size_t i = 0; i + 1 < nc; i++)
                    for (size_t j = i + 1; j < nc; j++)
                        if (ciph[j] < ciph[i]) { uint16_t t = ciph[i]; ciph[i] = ciph[j]; ciph[j] = t; }
                char cs[512]; size_t co = 0;
                for (size_t i = 0; i < nc; i++)
                    co += (size_t)snprintf(cs + co, sizeof cs - co, "%s%04x", i ? "," : "", ciph[i]);
                char chash[33];
                md5_hex(cs[0] ? cs : "", chash, sizeof chash);

                /* extensions: drop GREASE, sort, then append sigalg list */
                uint16_t se[64]; size_t nse = 0;
                for (size_t i = 0; i < njext; i++) {
                    uint16_t e2 = jexts[i];
                    if ((e2 & 0x0f0f) == 0x0a0a && ((e2 >> 8) == (e2 & 0xff))) continue;
                    if (nse < 64) se[nse++] = e2;
                }
                for (size_t i = 0; i + 1 < nse; i++)
                    for (size_t j = i + 1; j < nse; j++)
                        if (se[j] < se[i]) { uint16_t t = se[i]; se[i] = se[j]; se[j] = t; }
                char es[640]; size_t eo = 0;
                for (size_t i = 0; i < nse; i++)
                    eo += (size_t)snprintf(es + eo, sizeof es - eo, "%s%04x", i ? "," : "", se[i]);
                for (size_t i = 0; i < njsig; i++)
                    eo += (size_t)snprintf(es + eo, sizeof es - eo, "%s%04x", (nse || i) ? "," : "", jsig[i]);
                char ehash[33];
                md5_hex(es[0] ? es : "", ehash, sizeof ehash);

                int tls13 = (legacy == 0x0304 ||
                             (p->tls_vers[0] && strstr(p->tls_vers, "TLS1.3") && legacy >= 0x0301));
                const char *ver = tls13 ? "13" : legacy == 0x0303 ? "12"
                                : legacy == 0x0302 ? "11" : legacy == 0x0301 ? "10"
                                : legacy == 0x0300 ? "s3" : "00";
                snprintf(p->ja4, sizeof p->ja4,
                         "t%s%s%02zu%02zu%s_%.12s_%.12s",
                         ver, p->tls_sni[0] ? "d" : "i", nc, nse,
                         jalpn[0] ? jalpn : "00", chash, ehash);
            }
        }
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
            tls_ja3(p, d, hs);
        }
        if (h == 11 && hs >= 3) {
            tls_cert_msg(p, d, hs);
        }
        if (h == 1) {
            lsts(p->app_s, sizeof p->app_s, "ClientHello");
            if (p->tls_sni[0])   lsts(p->app_s, sizeof p->app_s, "SNI=%s", p->tls_sni);
            if (p->tls_alpn[0])  lsts(p->app_s, sizeof p->app_s, "ALPN=%s", p->tls_alpn);
            if (p->tls_vers[0])  lsts(p->app_s, sizeof p->app_s, "vers=%s", p->tls_vers);
            if (p->ja3[0])       lsts(p->app_s, sizeof p->app_s, "ja3=%s", p->ja3);
            if (p->ja4[0])       lsts(p->app_s, sizeof p->app_s, "ja4=%s", p->ja4);
            if (p->ech)          lsts(p->app_s, sizeof p->app_s, "ECH");
        } else if (h == 2) {
            lsts(p->app_s, sizeof p->app_s, "ServerHello");
            lsts(p->app_s, sizeof p->app_s, "ver=%s", p->tls_ver);
            if (p->tls_cipher) {
                const char *cn = tls_cipher_name(p->tls_cipher);
                if (cn) lsts(p->app_s, sizeof p->app_s, "cipher=%s", cn);
                else lsts(p->app_s, sizeof p->app_s, "cipher=0x%04x", p->tls_cipher);
            }
        } else if (h == 11) {
            lsts(p->app_s, sizeof p->app_s, "Certificate");
            if (p->cert_n) lsts(p->app_s, sizeof p->app_s, "chain=%d", p->cert_n);
            if (p->cert_subject[0]) lsts(p->app_s, sizeof p->app_s, "CN=%s", p->cert_subject);
            if (p->cert_issuer[0])  lsts(p->app_s, sizeof p->app_s, "issuer=%s", p->cert_issuer);
            if (p->cert_san[0])     lsts(p->app_s, sizeof p->app_s, "SAN=%s", p->cert_san);
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
int http_hdr(const uint8_t *b, size_t n, const char *key, char *out, size_t sz) {
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

int looks_http(const uint8_t *b, size_t n) {
    if (n >= 9 && !memcmp(b, "HTTP/1.", 7) &&
        (b[7] == '0' || b[7] == '1') && b[8] == ' ') return 1;
    if (n >= 16 && !memcmp(b, "PRI * HTTP/2.0\r\n", 16)) return 1;
    for (size_t i = 0; i < sizeof http_methods / sizeof *http_methods; i++) {
        size_t m = strlen(http_methods[i]);
        if (n > m && b[m] == ' ' && !memcmp(b, http_methods[i], m)) return 1;
    }
    return 0;
}

static void decode_h2(packet_t *p, const uint8_t *b, size_t n, int have_preface);

static void decode_http(packet_t *p, const uint8_t *b, size_t n) {
    size_t lim = n < 4096 ? n : 4096;
    size_t e = 0;
    while (e < lim && b[e] != '\r' && b[e] != '\n') e++;
    size_t c = e < sizeof p->http_line ? e : sizeof p->http_line - 1;
    memcpy(p->http_line, b, c);
    p->http_line[c] = 0;
    p->app = APP_HTTP;

    if (n >= 16 && !memcmp(b, "PRI * HTTP/2.0\r\n", 16)) {
        decode_h2(p, b, n, 1);
        if (!p->app_s[0]) snprintf(p->app_s, sizeof p->app_s, "HTTP/2 connection preface");
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

    /* DNS-over-HTTPS: POST/GET to /dns-query, or an application/dns-message body */
    char ctype[80] = "", dnsbody = 0;
    if (http_hdr(b, lim, "content-type", ctype, sizeof ctype) &&
        strstr(ctype, "application/dns-message")) dnsbody = 1;
    if (strstr(p->http_line, "/dns-query") || dnsbody) {
        p->doh = 1;
        lsts(p->app_s, sizeof p->app_s, "DoH");
    }
}

/* --- QUIC / HTTP3 (RFC 9000) ---
 *
 * A long-header packet (Initial / 0-RTT / Handshake / Retry) starts with the
 * header-form bit set.  We parse the version, connection ids and packet type,
 * and for an Initial we mine the embedded TLS ClientHello for the SNI. */
static const char *quic_version_str(uint32_t v, char *buf, size_t sz) {
    if (v == 0x00000001) return "v1";
    if (v == 0x6b3343cf) return "v2";
    if (v == 0x00000000) return "negotiation";
    if ((v & 0xff000000) == 0xff000000) {   /* greased reserved version */
        snprintf(buf, sz, "reserved(0x%08x)", v);
        return buf;
    }
    if ((v >> 8) == 0xff0000) {             /* draft-29 style: 0xff0000NN */
        snprintf(buf, sz, "draft-%u", v & 0xff);
        return buf;
    }
    snprintf(buf, sz, "0x%08x", v);
    return buf;
}

static void quic_vint(const uint8_t *b, size_t n, size_t *pos, uint64_t *out) {
    if (*pos >= n) { *out = 0; return; }
    int len = 1 << (b[*pos] >> 6);
    uint64_t v = b[*pos] & 0x3f;
    for (int i = 1; i < len && *pos + (size_t)i < n; i++) v = (v << 8) | b[*pos + i];
    size_t adv = (size_t)len <= (n - *pos) ? (size_t)len : (n - *pos);
    *pos += adv;
    *out = v;
}

/* find the TLS ClientHello inside a QUIC Initial's CRYPTO frame and pull SNI */
static void quic_initial_crypto(packet_t *p, const uint8_t *b, size_t n, size_t pos) {
    if (pos >= n) return;
    size_t token_len = b[pos];
    pos += 1 + token_len;
    uint64_t plen;
    quic_vint(b, n, &pos, &plen);            /* length */
    uint64_t pnum;
    quic_vint(b, n, &pos, &pnum);            /* packet number */
    if (pos >= n) return;
    /* walk frames; CRYPTO frame is type 0x06 */
    size_t end = pos + plen < n ? pos + plen : n;
    while (pos + 1 < end) {
        uint8_t ft = b[pos];
        if (ft == 0x06) {                    /* CRYPTO */
            pos++;
            uint64_t off, clen;
            quic_vint(b, end, &pos, &off);
            quic_vint(b, end, &pos, &clen);
            if (pos + clen > end) return;
            /* the CRYPTO payload is a TLS handshake: ClientHello */
            const uint8_t *h = b + pos;
            if (clen >= 4 && h[0] == 1) {
                size_t hl = ((size_t)h[1] << 16) | ((size_t)h[2] << 8) | h[3];
                if (hl <= clen - 4 && hl >= 35) {
                    /* legacy_version(2) random(32) sessionid(...) ciphers... */
                    const uint8_t *d = h + 4;
                    size_t hs = hl;
                    size_t q = 2 + 32;
                    if (q < hs) q += 1 + d[q];
                    if (q + 2 <= hs) { size_t cs = rd16(d + q); q += 2 + cs; }
                    if (q < hs) q += 1 + d[q];
                    if (q + 2 <= hs) {
                        size_t el = rd16(d + q);
                        q += 2;
                        size_t ee = q + el < hs ? q + el : hs;
                        /* reuse the extension walker for SNI (read-only fields) */
                        packet_t tmp;
                        memset(&tmp, 0, sizeof tmp);
                        tls_exts(&tmp, d, q, ee, 0);
                        if (tmp.tls_sni[0])
                            snprintf(p->quic_sni, sizeof p->quic_sni, "%s", tmp.tls_sni);
                    }
                }
            }
            return;
        } else if (ft == 0x00 || ft == 0x01) {       /* PADDING / PING */
            pos++;
        } else if (ft == 0x02 || ft == 0x03) {       /* ACK */
            pos++;
            uint64_t a, b2, c, d2;
            quic_vint(b, end, &pos, &a); quic_vint(b, end, &pos, &b2);
            quic_vint(b, end, &pos, &c); quic_vint(b, end, &pos, &d2);
            pos += d2;
        } else if (ft == 0x1c || ft == 0x1d) {       /* CONNECTION_CLOSE */
            return;
        } else {
            return;                                   /* unknown: stop */
        }
    }
}

static void decode_quic(packet_t *p, const uint8_t *b, size_t n) {
    if (n < 7) return;
    uint8_t first = b[0];
    if (!(first & 0x80)) return;                 /* long header only for detection */
    uint32_t ver = rd32(b + 1);                  /* version */
    size_t pos = 5;
    if (pos >= n) return;
    size_t dcil = b[pos]; pos += 1 + dcil;
    if (pos >= n) return;
    size_t scil = b[pos]; pos += 1 + scil;
    if (pos > n) return;

    /* version-negotiation packet: version == 0 with a list of versions */
    p->app = APP_QUIC;
    char vb[32];
    snprintf(p->quic_ver, sizeof p->quic_ver, "%s", quic_version_str(ver, vb, sizeof vb));
    p->quic_dcid_len = (int)(dcil < 24 ? dcil : 24);
    for (size_t i = 0; i < (size_t)p->quic_dcid_len; i++)
        snprintf(p->quic_dcid + i * 2, 3, "%02x", b[6 + i]);

    if (ver == 0) {
        snprintf(p->quic_type, sizeof p->quic_type, "version-neg");
        snprintf(p->app_s, sizeof p->app_s, "version negotiation");
        return;
    }

    /* long-header packet type comes from the two bits below the form bit
     * (QUIC v1 layout), retry has its own value */
    int t = (first & 0x30) >> 4;
    const char *tn = t == 0 ? "initial" : t == 1 ? "0-rtt"
                   : t == 2 ? "handshake" : "retry";
    if (ver == 0x6b3343cf) { /* v2 remaps the type bits */
        static const char *v2t[4] = {"retry", "initial", "0-rtt", "handshake"};
        tn = v2t[t];
    }
    snprintf(p->quic_type, sizeof p->quic_type, "%s", tn);

    if (!strcmp(tn, "initial")) quic_initial_crypto(p, b, n, pos);

    snprintf(p->app_s, sizeof p->app_s, "%s %s", p->quic_ver, tn);
    if (p->quic_sni[0]) lsts(p->app_s, sizeof p->app_s, "SNI=%s", p->quic_sni);
}

/* --- HTTP/2 (RFC 9113) frame + HPACK (RFC 7541) decode ---
 *
 * Enough to name the frame, pull the stream id, and decode the indexed /
 * literal header fields of a HEADERS block against the static table.  We do
 * not maintain the dynamic table across packets (each packet is decoded in
 * isolation), so dynamic references show as "[dyn N]". */
static const struct { const char *n, *v; } HPACK_STATIC[62] = {
    {NULL,NULL},                                    /* index 0 unused */
    {":authority",""}, {":method","GET"}, {":method","POST"},
    {":path","/"}, {":path","/index.html"}, {":scheme","http"},
    {":scheme","https"}, {":status","200"}, {":status","204"},
    {":status","206"}, {":status","304"}, {":status","400"},
    {":status","404"}, {":status","500"}, {"accept-charset",""},
    {"accept-encoding","gzip, deflate"}, {"accept-language",""},
    {"accept-ranges",""}, {"accept",""}, {"access-control-allow-origin",""},
    {"age",""}, {"allow",""}, {"authorization",""}, {"cache-control",""},
    {"content-disposition",""}, {"content-encoding",""}, {"content-language",""},
    {"content-length",""}, {"content-location",""}, {"content-range",""},
    {"content-type",""}, {"cookie",""}, {"date",""}, {"etag",""},
    {"expect",""}, {"expires",""}, {"from",""}, {"host",""}, {"if-match",""},
    {"if-modified-since",""}, {"if-none-match",""}, {"if-range",""},
    {"if-unmodified-since",""}, {"last-modified",""}, {"link",""}, {"location",""},
    {"max-forwards",""}, {"proxy-authenticate",""}, {"proxy-authorization",""},
    {"range",""}, {"referer",""}, {"refresh",""}, {"retry-after",""},
    {"server",""}, {"set-cookie",""}, {"strict-transport-security",""},
    {"transfer-encoding",""}, {"user-agent",""}, {"vary",""}, {"via",""}, {"www-authenticate",""}
};

/* decode an HPACK integer with prefix bits; returns the value, advances *p */
static uint64_t hpack_int(const uint8_t **p, const uint8_t *end, int prefix) {
    if (*p >= end) return 0;
    uint64_t mask = (1u << prefix) - 1;
    uint64_t v = **p & mask;
    (*p)++;
    if (v < mask) return v;
    int shift = 0;
    while (*p < end) {
        uint8_t b = *(*p)++;
        v += (uint64_t)(b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    return v;
}

/* decode an HPACK string (Huffman-flagged values are not de-Huffman'd here) */
static void hpack_str(const uint8_t **p, const uint8_t *end, char *out, size_t sz,
                      int *was_huff) {
    if (*p >= end) { if (sz) out[0] = 0; return; }
    int huff = (**p & 0x80) != 0;
    size_t len = (size_t)hpack_int(p, end, 7);
    if ((size_t)(end - *p) < len) len = (size_t)(end - *p);
    if (was_huff) *was_huff = huff;
    if (huff) {
        /* we don't ship a Huffman table: show the length only */
        snprintf(out, sz, "(huffman %zu)", len);
        *p += len;
        return;
    }
    size_t c = len < sz - 1 ? len : sz - 1;
    memcpy(out, *p, c);
    out[c] = 0;
    *p += len;
}

static void h2_note_header(packet_t *p, const char *name, const char *val) {
    if (!strcmp(name, ":method"))         snprintf(p->h2_method, sizeof p->h2_method, "%s", val);
    else if (!strcmp(name, ":path"))      snprintf(p->h2_path, sizeof p->h2_path, "%s", val);
    else if (!strcmp(name, ":authority")) snprintf(p->h2_authority, sizeof p->h2_authority, "%s", val);
    else if (!strcmp(name, "user-agent")) snprintf(p->h2_useragent, sizeof p->h2_useragent, "%s", val);
    p->h2_headers++;
}

static void hpack_decode(packet_t *p, const uint8_t *b, size_t n) {
    const uint8_t *cur = b, *end = b + n;
    while (cur < end) {
        uint8_t byte = *cur;
        char name[64], val[256];
        if (byte & 0x80) {                         /* indexed header field */
            uint64_t idx = hpack_int(&cur, end, 7);
            if (idx > 0 && idx < 62) {
                snprintf(name, sizeof name, "%s", HPACK_STATIC[idx].n);
                snprintf(val, sizeof val, "%s", HPACK_STATIC[idx].v);
                h2_note_header(p, name, val);
            }
        } else if ((byte & 0xc0) == 0x40) {         /* literal, incremental indexing */
            uint64_t idx = hpack_int(&cur, end, 6);
            if (idx > 0 && idx < 62) snprintf(name, sizeof name, "%s", HPACK_STATIC[idx].n);
            else hpack_str(&cur, end, name, sizeof name, NULL);
            hpack_str(&cur, end, val, sizeof val, NULL);
            h2_note_header(p, name, val);
        } else if ((byte & 0xf0) == 0x00) {         /* literal, no indexing */
            uint64_t idx = hpack_int(&cur, end, 4);
            if (idx > 0 && idx < 62) snprintf(name, sizeof name, "%s", HPACK_STATIC[idx].n);
            else hpack_str(&cur, end, name, sizeof name, NULL);
            hpack_str(&cur, end, val, sizeof val, NULL);
            h2_note_header(p, name, val);
        } else if ((byte & 0xf0) == 0x10) {         /* literal, never indexed */
            uint64_t idx = hpack_int(&cur, end, 4);
            if (idx > 0 && idx < 62) snprintf(name, sizeof name, "%s", HPACK_STATIC[idx].n);
            else hpack_str(&cur, end, name, sizeof name, NULL);
            hpack_str(&cur, end, val, sizeof val, NULL);
            h2_note_header(p, name, val);
        } else if ((byte & 0xe0) == 0x20) {         /* dynamic table size update */
            hpack_int(&cur, end, 5);
        } else break;
    }
}

static const char *h2_frame_name(uint8_t t) {
    switch (t) {
        case 0x0: return "DATA"; case 0x1: return "HEADERS"; case 0x2: return "PRIORITY";
        case 0x3: return "RST_STREAM"; case 0x4: return "SETTINGS"; case 0x5: return "PUSH_PROMISE";
        case 0x6: return "PING"; case 0x7: return "GOAWAY"; case 0x8: return "WINDOW_UPDATE";
        case 0x9: return "CONTINUATION"; default: return "UNKNOWN";
    }
}

/* decode a buffer known to start an HTTP/2 frame stream (preface optional) */
static void decode_h2(packet_t *p, const uint8_t *b, size_t n, int have_preface) {
    size_t pos = 0;
    if (have_preface && n >= 24 && !memcmp(b, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24)) {
        pos = 24;
        snprintf(p->app_s, sizeof p->app_s, "HTTP/2 preface");
        p->app = APP_HTTP;
        if (pos >= n) return;
    }
    /* parse frames (usually one, but tolerate several) */
    while (pos + 9 <= n) {
        uint32_t len = ((uint32_t)b[pos] << 16) | ((uint32_t)b[pos+1] << 8) | b[pos+2];
        uint8_t type = b[pos+3];
        uint32_t sid = (((uint32_t)b[pos+5] << 24) | ((uint32_t)b[pos+6] << 16)
                      | ((uint32_t)b[pos+7] << 8) | b[pos+8]) & 0x7fffffff;
        if (len > 16384 + 4096 || pos + 9 + len > n) break;
        p->app = APP_HTTP;
        p->h2_stream = sid;
        snprintf(p->h2_type, sizeof p->h2_type, "%s", h2_frame_name(type));
        if (type == 0x1) {                         /* HEADERS: [pad][prio] hpack */
            const uint8_t *fb = b + pos + 9;
            size_t flen = len;
            uint8_t flags = b[pos + 4];
            if (flags & 0x08) {                    /* padded */
                if (flen < 1) break;
                uint8_t pad = *fb++;
                flen -= 1;
                if (pad > flen) pad = 0;
                flen -= pad;
            }
            if (flags & 0x20) {                    /* priority */
                if (flen >= 5) { fb += 5; flen -= 5; } else flen = 0;
            }
            hpack_decode(p, fb, flen);
        }
        pos += 9 + len;
        if (type != 0x1 && p->app_s[0]) { /* keep going, but note the first frame */ }
    }
    if (!p->app_s[0]) {
        /* summarize the last frame we saw */
        if (p->h2_type[0])
            snprintf(p->app_s, sizeof p->app_s, "HTTP/2 %s stream=%u",
                     p->h2_type, p->h2_stream);
    }
    if (p->h2_method[0] || p->h2_path[0]) {
        snprintf(p->app_s, sizeof p->app_s, "HTTP/2 %.12s %.150s%.200s",
                 p->h2_method[0] ? p->h2_method : "?",
                 p->h2_authority[0] ? p->h2_authority : "",
                 p->h2_path[0] ? p->h2_path : "");
        if (p->h2_useragent[0])
            lsts(p->app_s, sizeof p->app_s, "ua=%s", p->h2_useragent);
    }
}

/* --- HTTP/2 connection tracking ---
 * A connection becomes HTTP/2 when its preface is seen; later HEADERS frames
 * on that 4-tuple are then decoded even without the preface.  A small table
 * of recent connections, evicted round-robin. */
#define H2_CONNS 64
static struct { int used; uint8_t src[16], dst[16]; uint16_t sport, dport; int fam; } h2tab[H2_CONNS];
static unsigned h2rr;

static void h2_mark(packet_t *p) {
    int fam = p->ip_ver;
    for (unsigned i = 0; i < H2_CONNS; i++)
        if (h2tab[i].used && h2tab[i].fam == fam && h2tab[i].sport == p->sport &&
            h2tab[i].dport == p->dport &&
            !memcmp(h2tab[i].src, p->src, fam == 6 ? 16 : 4) &&
            !memcmp(h2tab[i].dst, p->dst, fam == 6 ? 16 : 4))
            return;
    unsigned i = h2rr++ % H2_CONNS;
    h2tab[i].used = 1; h2tab[i].fam = fam;
    h2tab[i].sport = p->sport; h2tab[i].dport = p->dport;
    memcpy(h2tab[i].src, p->src, fam == 6 ? 16 : 4);
    memcpy(h2tab[i].dst, p->dst, fam == 6 ? 16 : 4);
}

static int h2_is(const packet_t *p) {
    int fam = p->ip_ver;
    for (unsigned i = 0; i < H2_CONNS; i++)
        if (h2tab[i].used && h2tab[i].fam == fam && h2tab[i].sport == p->sport &&
            h2tab[i].dport == p->dport &&
            !memcmp(h2tab[i].src, p->src, fam == 6 ? 16 : 4) &&
            !memcmp(h2tab[i].dst, p->dst, fam == 6 ? 16 : 4))
            return 1;
    return 0;
}

/* decide which app decoder (if any) owns this payload */
void decode_app(packet_t *p) {
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
        if (looks_http(b, n)) {
            int was_h2 = (n >= 16 && !memcmp(b, "PRI * HTTP/2.0\r\n", 16));
            decode_http(p, b, n);
            if (was_h2) h2_mark(p);
            return;
        }
        if (h2_is(p) && n >= 9) { decode_h2(p, b, n, 0); if (p->app) return; }
        if (n >= 5 && b[1] == 3 && b[0] >= 20 && b[0] <= 24) {
            decode_tls(p, b, n);
            if (p->app) {
                if (sp == 853 || dp == 853) {   /* DNS-over-TLS */
                    p->dot = 1;
                    lsts(p->app_s, sizeof p->app_s, "DoT");
                }
                return;
            }
        }
        decode_banner(p, b, n);       /* -K: cleartext service banners */
        decode_proto(p, b, n);        /* SMB2 / RDP / LDAP / Kerberos */
    } else if (p->has_udp) {
        if (sp == 443 || dp == 443) decode_quic(p, b, n);
    }
}

