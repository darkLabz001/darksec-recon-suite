/* harvest.c - credential / token / banner harvesting (-K) */

#include "ch1m3ra.h"

/* ---------- credential / token / banner harvesting (-K) ----------
 * All passive: we only read bytes that are already on the wire in cleartext
 * (or, for TLS, the metadata that is not encrypted - SNI, cert CN, ALPN).   */

static const char *b64_decode(const char *in, size_t inlen, uint8_t *out, size_t outsz) {
    static signed char tab[256];
    static int init = 0;
    if (!init) {
        for (int i = 0; i < 256; i++) tab[i] = -1;
        const char *al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) tab[(unsigned char)al[i]] = (signed char)i;
        init = 1;
    }
    size_t o = 0;
    unsigned val = 0;
    int bits = 0;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=' ) break;
        if (c == '\n' || c == '\r') continue;
        int d = tab[c];
        if (d < 0) return NULL;
        val = (val << 6) | (unsigned)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o < outsz - 1) out[o++] = (uint8_t)((val >> bits) & 0xff);
        }
    }
    out[o] = 0;
    return (const char *)out;
}

static int printable_ratio(const uint8_t *b, size_t n) {
    if (!n) return 0;
    size_t ok = 0;
    for (size_t i = 0; i < n; i++)
        if ((b[i] >= 32 && b[i] < 127) || b[i] == '\t') ok++;
    return (int)(ok * 100 / n);
}

/* decode a JWT payload (middle segment) into a short readable summary */
static void jwt_summary(const char *tok, char *out, size_t sz) {
    const char *d1 = strchr(tok, '.');
    if (!d1) return;
    const char *d2 = strchr(d1 + 1, '.');
    if (!d2) return;
    uint8_t buf[1024];
    const char *j = b64_decode(d1 + 1, (size_t)(d2 - d1 - 1), buf, sizeof buf);
    if (!j) return;
    /* pull a few interesting claims without a real JSON parser */
    const char *keys[] = {"\"sub\"", "\"name\"", "\"email\"", "\"preferred_username\"",
                          "\"iss\"", "\"aud\"", "\"role\"", "\"scope\"", NULL};
    size_t w = 0;
    out[0] = 0;
    for (int i = 0; keys[i]; i++) {
        const char *k = strstr(j, keys[i]);
        if (!k) continue;
        const char *c = strchr(k, ':');
        if (!c) continue;
        c++;
        while (*c == ' ') c++;
        if (*c == '"') c++;
        const char *e = c;
        while (*e && *e != '"' && *e != ',' && *e != '}' && e - c < 60) e++;
        if (e == c) continue;
        w += (size_t)snprintf(out + w, sz > w ? sz - w : 0, "%.*s=%.*s ",
                              (int)(strlen(keys[i]) - 2), keys[i] + 1,
                              (int)(e - c > 50 ? 50 : e - c), c);
        if (w >= sz - 2) break;
    }
}

/* HTTP Basic auth: "Authorization: Basic <b64>" -> user:pass */
static void harvest_http_auth(packet_t *p, const uint8_t *b, size_t n) {
    char v[512];
    if (!http_hdr(b, n, "authorization", v, sizeof v)) return;
    if (!strncasecmp(v, "Basic ", 6)) {
        uint8_t dec[384];
        const char *s = b64_decode(v + 6, strlen(v + 6), dec, sizeof dec);
        if (s && strchr(s, ':') && printable_ratio(dec, strlen(s))) {
            const char *c = strchr(s, ':');
            size_t ul = (size_t)(c - s);
            if (ul >= sizeof p->cred_user) ul = sizeof p->cred_user - 1;
            memcpy(p->cred_user, s, ul); p->cred_user[ul] = 0;
            snprintf(p->cred_pass, sizeof p->cred_pass, "%s", c + 1);
            snprintf(p->cred_where, sizeof p->cred_where, "HTTP Basic");
            p->cred_kind = CRED_BASIC;
        }
    } else if (!strncasecmp(v, "Bearer ", 7)) {
        snprintf(p->token, sizeof p->token, "%s", v + 7);
        snprintf(p->cred_where, sizeof p->cred_where, "HTTP Bearer");
        p->cred_kind = CRED_BEARER;
        if (strchr(p->token, '.')) jwt_summary(p->token, p->jwt_sub, sizeof p->jwt_sub);
    }
}

/* cleartext form login: look for user=/username=/login= + pass=/password= */
static void harvest_http_form(packet_t *p, const uint8_t *b, size_t n) {
    if (n > 8192) n = 8192;
    /* strcasestr needs a NUL-terminated buffer; the frame slice is not one,
     * so scan a bounded copy (otherwise we read into stale frame bytes). */
    char body[8193];
    memcpy(body, b, n);
    body[n] = 0;
    const char *uk[] = {"username=", "user=", "login=", "email=", "uname=", NULL};
    const char *pk[] = {"password=", "passwd=", "pass=", "pwd=", NULL};
    char u[128] = "", pw[160] = "";
    for (int i = 0; uk[i] && !u[0]; i++) {
        const char *k = strcasestr(body, uk[i]);
        if (k) {
            const char *c = k + strlen(uk[i]);
            size_t w = 0;
            while (*c && *c != '&' && *c != '\n' && *c != '\r' && *c != ' ' &&
                   w < sizeof u - 1) {
                unsigned char ch = (unsigned char)*c;
                u[w++] = ch; c++;
            }
            u[w] = 0;
        }
    }
    for (int i = 0; pk[i] && !pw[0]; i++) {
        const char *k = strcasestr(body, pk[i]);
        if (k) {
            const char *c = k + strlen(pk[i]);
            size_t w = 0;
            while (*c && *c != '&' && *c != '\n' && *c != '\r' && *c != ' ' &&
                   w < sizeof pw - 1) {
                pw[w++] = (unsigned char)*c; c++;
            }
            pw[w] = 0;
        }
    }
    if (u[0] || pw[0]) {
        snprintf(p->cred_user, sizeof p->cred_user, "%s", u);
        snprintf(p->cred_pass, sizeof p->cred_pass, "%s", pw);
        snprintf(p->cred_where, sizeof p->cred_where, "HTTP form");
        p->cred_kind = CRED_FORM;
    }
}

/* generic "user: pass" / "LOGIN x" line grabber for cleartext protocols */
static void grab_pair(packet_t *p, const char *data, size_t n, const char *label,
                      const char *upfx, const char *ppfx, int kind) {
    if (!n) return;
    size_t lim = n < 4095 ? n : 4095;
    char buf[4096];
    memcpy(buf, data, lim); buf[lim] = 0;
    char *line = buf, *nl;
    char user[128] = "", pass[160] = "";
    while (line && *line) {
        nl = strpbrk(line, "\r\n");
        if (nl) *nl = 0;
        if (upfx && !user[0]) {
            char *k = strcasestr(line, upfx);
            if (k) { k += strlen(upfx);
                while (*k == ' ') k++;
                snprintf(user, sizeof user, "%s", k); }
        }
        if (ppfx && !pass[0]) {
            char *k = strcasestr(line, ppfx);
            if (k) { k += strlen(ppfx);
                while (*k == ' ') k++;
                snprintf(pass, sizeof pass, "%s", k); }
        }
        line = nl ? nl + 1 : NULL;
    }
    if (user[0] || pass[0]) {
        snprintf(p->cred_user, sizeof p->cred_user, "%s", user);
        snprintf(p->cred_pass, sizeof p->cred_pass, "%s", pass);
        snprintf(p->cred_where, sizeof p->cred_where, "%s", label);
        p->cred_kind = kind;
    }
}

/* Set-Cookie / Cookie -> session id */
static void harvest_cookie(packet_t *p, const uint8_t *b, size_t n) {
    char v[400];
    if (http_hdr(b, n, "set-cookie", v, sizeof v) ||
        http_hdr(b, n, "cookie", v, sizeof v)) {
        /* keep just the first name=value pair */
        char *semi = strchr(v, ';');
        if (semi) *semi = 0;
        snprintf(p->cookie, sizeof p->cookie, "%.*s",
                 (int)(sizeof p->cookie - 1), v);
    }
}

/* service banners: SSH / SMTP / FTP / POP3 / IMAP / MySQL / Telnet */
void decode_banner(packet_t *p, const uint8_t *b, size_t n) {
    if (!n) return;
    uint16_t dp = p->dport, sp = p->sport;
    /* pick the well-known server port (either direction) */
    uint16_t port = dp;
    if (dp >= 1024 && sp < dp) port = sp;
    if (port == 22 || dp == 22) {
        if (n >= 4 && !memcmp(b, "SSH-", 4)) {
            size_t e = 0; while (e < n && b[e] != '\r' && b[e] != '\n' && e < 120) e++;
            snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
            snprintf(p->svc, sizeof p->svc, "ssh");
            st.banners++;
        }
        return;
    }
    if (port == 21 || port == 20 || dp == 21) {
        const char *s = (const char *)b;
        if (n >= 3 && !strncasecmp(s, "220", 3))
            { snprintf(p->banner, sizeof p->banner, "%.*s",
                       (int)(n < 100 ? n : 100), b);
              snprintf(p->svc, sizeof p->svc, "ftp"); st.banners++; }
        return;
    }
    if (port == 25 || port == 587 || dp == 25) {
        if (n >= 3 && !strncasecmp((const char *)b, "220", 3)) {
            size_t e = 0; while (e < n && b[e] != '\r' && b[e] != '\n' && e < 120) e++;
            snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
            snprintf(p->svc, sizeof p->svc, "smtp"); st.banners++;
        }
        return;
    }
    if (port == 110) {
        if (n >= 3 && !strncasecmp((const char *)b, "+OK", 3)) {
            size_t e = 0; while (e < n && b[e] != '\r' && b[e] != '\n' && e < 120) e++;
            snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
            snprintf(p->svc, sizeof p->svc, "pop3"); st.banners++;
        }
        return;
    }
    if (port == 143) {
        if (n >= 2 && !strncasecmp((const char *)b, "* OK", 4)) {
            size_t e = 0; while (e < n && b[e] != '\r' && b[e] != '\n' && e < 120) e++;
            snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
            snprintf(p->svc, sizeof p->svc, "imap"); st.banners++;
        }
        return;
    }
    if (port == 3306 && n >= 5) {
        /* MySQL handshake: 3-byte len, seq, protocol version 10 */
        if (b[3] == 10) {
            size_t o = 5, e = o;
            while (e < n && b[e]) e++;
            snprintf(p->banner, sizeof p->banner, "MySQL %.*s",
                     (int)(e - o > 60 ? 60 : e - o), b + o);
            snprintf(p->svc, sizeof p->svc, "mysql"); st.banners++;
        }
        return;
    }
    if (port == 23) {
        /* telnet negotiates with IAC(0xff); report the readable text after it */
        if (printable_ratio(b, n > 64 ? 64 : n) > 70) {
            size_t e = 0; while (e < n && b[e] >= 32 && b[e] < 127 && e < 80) e++;
            if (e >= 4) { snprintf(p->banner, sizeof p->banner, "%.*s", (int)e, b);
                          snprintf(p->svc, sizeof p->svc, "telnet"); st.banners++; }
        }
        return;
    }
}

/* append-only credential log shared by text/json/csv modes (-k <file>) */
static FILE *g_credfile;
const char *cred_kind_name(int k);
void credfile_close(void) {
    if (g_credfile) { fclose(g_credfile); g_credfile = NULL; }
}
static void credfile_write(const packet_t *p) {
    if (!cfg.credfile) return;
    if (!g_credfile) {
        g_credfile = fopen(cfg.credfile, "a");
        if (!g_credfile) { fprintf(stderr, "ch1m3ra: %s: %s\n", cfg.credfile, strerror(errno)); return; }
    }
    struct tm tm; localtime_r(&p->ts.tv_sec, &tm);
    char tb[32]; strftime(tb, sizeof tb, "%Y-%m-%d %H:%M:%S", &tm);
    if (p->cred_kind) {
        fprintf(g_credfile, "%s %s %s:%u -> %s:%u  [%s] user=%s pass=%s\n",
                tb, cred_kind_name(p->cred_kind), p->src_s, p->sport, p->dst_s, p->dport,
                p->cred_where, p->cred_user, p->cred_pass);
    } else if (p->token[0]) {
        fprintf(g_credfile, "%s token %s:%u -> %s:%u  %s%s%s\n", tb,
                p->src_s, p->sport, p->dst_s, p->dport, p->token,
                p->jwt_sub[0] ? "  " : "", p->jwt_sub);
    } else if (p->cookie[0]) {
        fprintf(g_credfile, "%s cookie %s:%u -> %s:%u  %s\n", tb,
                p->src_s, p->sport, p->dst_s, p->dport, p->cookie);
    }
    fflush(g_credfile);
}

/* human-readable name for a credential kind */
const char *cred_kind_name(int k) {
    switch (k) {
        case CRED_BASIC:  return "basic";
        case CRED_BEARER: return "bearer";
        case CRED_FTP:    return "ftp";
        case CRED_POP3:   return "pop3";
        case CRED_IMAP:   return "imap";
        case CRED_SMTP:   return "smtp";
        case CRED_TELNET: return "telnet";
        case CRED_FORM:   return "form";
        case CRED_SNMP:   return "snmp";
        case CRED_COOKIE: return "cookie";
        case CRED_NTLM:   return "ntlm";
        case CRED_LDAP:   return "ldap";
        case CRED_KERB:   return "kerberos";
        default:          return "none";
    }
}

/* ---------- structured protocol decoders (SMB2 / RDP / LDAP / Kerberos) ----------
 * These are binary protocols.  We do enough to (a) name the protocol for the
 * service column (-N) and (b) pull any cleartext identity material (NTLMSSP
 * domain/user, LDAP bind DN, Kerberos realm/principal) into the credential
 * path (-K).  Detection is port-guided plus a magic check. */

/* little-endian helpers for SMB2 */
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* decode a UTF-16LE range (as used by NTLMSSP) into ASCII, dropping the
 * interleaved null bytes.  Returns the number of chars written. */
static size_t utf16le_to_ascii(const uint8_t *p, size_t bytes, char *out, size_t sz) {
    size_t o = 0;
    for (size_t i = 0; i + 1 < bytes && o + 1 < sz; i += 2) {
        uint16_t c = (uint16_t)(p[i] | (p[i + 1] << 8));
        if (!c) break;
        out[o++] = (c < 0x80) ? (char)c : '?';
    }
    out[o] = 0;
    return o;
}

/* SMB2: "\xfeSMB" magic, 64-byte header, 2-byte command at offset 12.
 * SESSION_SETUP (0x0001) usually carries a GSS-API blob with an NTLMSSP token
 * on the first leg (NEGOTIATE) or the client's user/domain (AUTHENTICATE). */
static void decode_smb2(packet_t *p, const uint8_t *b, size_t n) {
    snprintf(p->proto, sizeof p->proto, "smb2");
    snprintf(p->svc, sizeof p->svc, "smb");
    if (n < 32) return;
    uint16_t cmd = (uint16_t)(b[12] | (b[13] << 8));
    static const char *cmds[] = { "NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT",
                                  "TREE_DISCONNECT", "CREATE", "CLOSE", "FLUSH", "READ",
                                  "WRITE", "LOCK", "IOCTL", "CANCEL", "ECHO", "QUERY_DIRECTORY" };
    const char *cn = cmd < sizeof cmds / sizeof *cmds ? cmds[cmd] : "CMD";
    snprintf(p->proto_s, sizeof p->proto_s, "SMB2 %s", cn);

    /* hunt for an NTLMSSP signature ("NTLMSSP\0") anywhere in the payload */
    for (size_t i = 0; i + 12 < n; i++) {
        if (memcmp(b + i, "NTLMSSP\0", 8)) continue;
        uint32_t mtype = le32(b + i + 8);
        snprintf(p->cred_where, sizeof p->cred_where, "SMB2/NTLMSSP");
        p->cred_kind = CRED_NTLM;
        if (mtype == 3 && i + 8 + 40 <= n) {          /* AUTHENTICATE: has names */
            /* NTLMSSP type 3: domain and user are SecurityBuffers at 28 and 36.
             * Both are UTF-16LE, so decode rather than copy. */
            uint16_t dlen = (uint16_t)(b[i+28] | (b[i+29] << 8));
            uint32_t doff = le32(b + i + 32);
            uint16_t ulen = (uint16_t)(b[i+36] | (b[i+37] << 8));
            uint32_t uoff = le32(b + i + 40);
            char dom[64] = "", u[64] = "";
            if (doff + dlen <= n - i)
                utf16le_to_ascii(b + i + doff, dlen, dom, sizeof dom);
            if (uoff + ulen <= n - i)
                utf16le_to_ascii(b + i + uoff, ulen, u, sizeof u);
            if (dom[0] && u[0])
                snprintf(p->cred_user, sizeof p->cred_user, "%.59s\\%.63s", dom, u);
            else if (u[0])
                snprintf(p->cred_user, sizeof p->cred_user, "%.63s", u);
            else if (dom[0])
                snprintf(p->cred_user, sizeof p->cred_user, "%.63s", dom);
        }
        break;
    }
}

/* RDP: TPKT header (0x03 0x00 len16) then X.224.  We name the connection and
 * grab the mstshash cookie if the client sent one (it often holds a username). */
static void decode_rdp(packet_t *p, const uint8_t *b, size_t n) {
    snprintf(p->proto, sizeof p->proto, "rdp");
    snprintf(p->svc, sizeof p->svc, "rdp");
    if (n < 7 || b[0] != 0x03) return;
    size_t tpkt = ((size_t)b[2] << 8) | b[3];
    if (tpkt < 7 || tpkt > n + 4) return;
    /* X.224: length indicator, then 0xD0 (DT) or 0xE0 (connection request) */
    uint8_t x = b[5];
    if (x == 0xe0)      snprintf(p->proto_s, sizeof p->proto_s, "RDP connection request");
    else if (x == 0xd0) snprintf(p->proto_s, sizeof p->proto_s, "RDP data");
    else                snprintf(p->proto_s, sizeof p->proto_s, "RDP");
    /* cookie: "Cookie: mstshash=<user>\r\n" in the connection request */
    for (size_t i = 0; i + 19 < n; i++) {
        if (!memcmp(b + i, "Cookie: mstshash=", 17)) {
            size_t s = i + 17, e = s;
            while (e < n && b[e] != '\r' && b[e] != '\n' && e - s < 100) e++;
            snprintf(p->cred_user, sizeof p->cred_user, "%.*s", (int)(e - s), b + s);
            snprintf(p->cred_where, sizeof p->cred_where, "RDP cookie");
            p->cred_kind = CRED_NTLM;
            snprintf(p->proto_s, sizeof p->proto_s, "RDP cookie user=%.*s",
                     (int)(e - s), b + s);
            break;
        }
    }
}

/* read a BER length (short or long form); returns bytes consumed, 0 on error */
static size_t ber_len(const uint8_t *b, size_t n, size_t *len) {
    if (!n) return 0;
    if (!(b[0] & 0x80)) { *len = b[0]; return 1; }
    size_t nb = b[0] & 0x7f;
    if (nb == 0 || nb > 4 || n < 1 + nb) return 0;
    size_t v = 0;
    for (size_t i = 0; i < nb; i++) v = (v << 8) | b[1 + i];
    *len = v;
    return 1 + nb;
}

/* LDAP: ASN.1 BER LDAPMessage = SEQUENCE { messageID, protocolOp, ... }.
 * A bindRequest (tag 0x60) carries the version, the bind DN (auth info). */
static void decode_ldap(packet_t *p, const uint8_t *b, size_t n) {
    snprintf(p->proto, sizeof p->proto, "ldap");
    snprintf(p->svc, sizeof p->svc, "ldap");
    if (n < 7 || b[0] != 0x30) return;
    size_t l1, c1 = ber_len(b + 1, n - 1, &l1);
    if (!c1) return;
    size_t pos = 1 + c1;
    /* messageID: INTEGER */
    if (pos >= n || b[pos] != 0x02) return;
    size_t ml = 0, mc = ber_len(b + pos + 1, n - pos - 1, &ml);
    size_t id = 0;
    for (size_t i = 0; i < ml; i++) id = (id << 8) | b[pos + 1 + mc + i];
    pos += 1 + mc + ml;
    if (pos >= n) return;
    uint8_t op = b[pos];
    p->ldap_msg = (int)id;
    if (op == 0x60) {                          /* bindRequest */
        /* SEQUENCE { version INTEGER, name LDAPDN OCTET STRING, auth } */
        size_t bl, bc = ber_len(b + pos + 1, n - pos - 1, &bl);
        size_t q = pos + 1 + bc;
        if (q < n && b[q] == 0x02) {           /* version */
            size_t vl = 0, vc = ber_len(b + q + 1, n - q - 1, &vl);
            q += 1 + vc + vl;
        }
        if (q < n && b[q] == 0x04) {           /* DN string */
            size_t dl = 0, dc = ber_len(b + q + 1, n - q - 1, &dl);
            size_t ds = q + 1 + dc;
            if (ds + dl <= n && dl < sizeof p->cred_user) {
                memcpy(p->cred_user, b + ds, dl);
                p->cred_user[dl] = 0;
                snprintf(p->cred_where, sizeof p->cred_where, "LDAP bind");
                p->cred_kind = CRED_LDAP;
            }
        }
        snprintf(p->proto_s, sizeof p->proto_s, "LDAP bindRequest%s%s",
                 p->cred_user[0] ? " dn=" : "", p->cred_user);
    } else if (op == 0x63) {
        snprintf(p->proto_s, sizeof p->proto_s, "LDAP searchRequest");
    } else if (op == 0x64) {
        snprintf(p->proto_s, sizeof p->proto_s, "LDAP searchResDone");
    } else if (op == 0x42) {
        snprintf(p->proto_s, sizeof p->proto_s, "LDAP unbindRequest");
    } else {
        snprintf(p->proto_s, sizeof p->proto_s, "LDAP msgid=%zu", id);
    }
}

/* Kerberos: ASN.1.  AS-REQ tag 0x6a, TGS-REQ 0x6c, AP-REQ 0x6e, AS-REP 0x6b.
 * The ciphertext hides ticket internals, but the outer realm (0xa3 -> 0x1b)
 * and the client principal/realm in the KDC-REQ-BODY are often cleartext. */
static void decode_kerberos(packet_t *p, const uint8_t *b, size_t n) {
    snprintf(p->proto, sizeof p->proto, "kerberos");
    snprintf(p->svc, sizeof p->svc, "kerberos");
    if (n < 8 || (b[0] != 0x6a && b[0] != 0x6b && b[0] != 0x6c &&
                  b[0] != 0x6d && b[0] != 0x6e && b[0] != 0x7e && b[0] != 0x7f)) return;
    const char *mn = b[0] == 0x6a ? "AS-REQ" : b[0] == 0x6b ? "AS-REP"
                   : b[0] == 0x6c ? "TGS-REQ" : b[0] == 0x6d ? "TGS-REP"
                   : b[0] == 0x6e ? "AP-REQ" : b[0] == 0x7e ? "AP-REP" : "KRB-ERROR";
    snprintf(p->proto_s, sizeof p->proto_s, "Kerberos %s", mn);
    /* the first visible GeneralString (tag 0x1b) is usually a realm name */
    for (size_t i = 0; i + 2 < n; i++) {
        if (b[i] != 0x1b) continue;
        size_t dl = 0, dc = ber_len(b + i + 1, n - i - 1, &dl);
        if (!dc || dl < 2 || dl > 64 || i + 1 + dc + dl > n) continue;
        const uint8_t *s = b + i + 1 + dc;
        int ok = 1;
        for (size_t k = 0; k < dl; k++)
            if (s[k] < 0x20 || s[k] >= 0x7f) { ok = 0; break; }
        if (ok) {
            snprintf(p->cred_user, sizeof p->cred_user, "%.*s", (int)dl, s);
            snprintf(p->cred_where, sizeof p->cred_where, "Kerberos realm");
            p->cred_kind = CRED_KERB;
            break;
        }
    }
}

/* port-guided protocol detection; safe to run on any TCP payload */
void decode_proto(packet_t *p, const uint8_t *b, size_t n) {
    if (n < 4) return;
    uint16_t dp = p->dport, sp = p->sport;
    int smb = (dp == 445 || sp == 445 || dp == 139 || sp == 139);
    int rdp = (dp == 3389 || sp == 3389);
    int ldap = (dp == 389 || sp == 389 || dp == 636 || sp == 636 ||
                dp == 3268 || sp == 3268);
    int krb = (dp == 88 || sp == 88 || dp == 464 || sp == 464);
    if (smb && n >= 4 && b[0] == 0xfe && b[1] == 'S' && b[2] == 'M' && b[3] == 'B') {
        decode_smb2(p, b, n);
    } else if (rdp && b[0] == 0x03) {
        decode_rdp(p, b, n);
    } else if (ldap && b[0] == 0x30) {
        decode_ldap(p, b, n);
    } else if ((krb && (b[0] == 0x6a || b[0] == 0x6b || b[0] == 0x6c || b[0] == 0x6d ||
                        b[0] == 0x6e || b[0] == 0x7e || b[0] == 0x7f)) ||
               (!krb && n >= 1 && (b[0] == 0x6a || b[0] == 0x6c) && n > 16)) {
        decode_kerberos(p, b, n);
    }
}

/* run all the -K harvesters on one packet's cleartext payload */
void harvest(packet_t *p) {
    if (!cfg.harvest) return;
    const uint8_t *b = p->payload;
    size_t n = p->avail;
    if (!b || !n) return;

    if (p->app == APP_HTTP) {
        harvest_http_auth(p, b, n);
        if (!p->cred_kind) harvest_http_form(p, b, n);
        harvest_cookie(p, b, n);
    }
    if (p->has_tcp) {
        /* cleartext login protocols by port */
        if (p->dport == 21 || p->sport == 21)
            grab_pair(p, (const char *)b, n, "FTP", "USER ", "PASS ", CRED_FTP);
        else if (p->dport == 110 || p->sport == 110)
            grab_pair(p, (const char *)b, n, "POP3", "USER ", "PASS ", CRED_POP3);
        else if (p->dport == 143 || p->sport == 143)
            grab_pair(p, (const char *)b, n, "IMAP", "LOGIN ", "LOGIN ", CRED_IMAP);
        else if (p->dport == 25 || p->dport == 587)
            grab_pair(p, (const char *)b, n, "SMTP", "AUTH ", NULL, CRED_SMTP);
        else if (p->dport == 23 || p->sport == 23)
            grab_pair(p, (const char *)b, n, "Telnet", "login:", "Password:", CRED_TELNET);
    }
    if (p->has_udp && (p->dport == 161 || p->sport == 161)) {
        /* SNMPv1/v2c community string sits in cleartext in the request */
        if (n > 8) {
            size_t cl = b[n - 1];
            (void)cl;
            /* last-but-one element is the community; do a printable scan */
            for (size_t i = 6; i + 4 < n; i++) {
                if (b[i] == 0x04) {                  /* OCTET STRING tag */
                    size_t l = b[i + 1];
                    if (l >= 1 && l <= 32 && i + 2 + l <= n &&
                        printable_ratio(b + i + 2, l) == 100) {
                        snprintf(p->cred_user, sizeof p->cred_user, "community");
                        snprintf(p->cred_pass, sizeof p->cred_pass, "%.*s", (int)l, b + i + 2);
                        snprintf(p->cred_where, sizeof p->cred_where, "SNMP");
                        p->cred_kind = CRED_SNMP;
                        break;
                    }
                }
            }
        }
    }
    if (p->cred_kind) st.creds++;
    if (p->cred_kind || p->token[0] || p->cookie[0]) credfile_write(p);
}

