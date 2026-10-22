/* print.c - printing (text / json / csv) */

#include "ch1m3ra.h"

/* ---------- printing ---------- */
static struct timespec t_first;
static int t_have_first;

/* seconds since the first displayed packet (initializes on first call) */
double rel_secs(const struct timespec *ts) {
    if (!t_have_first) { t_first = *ts; t_have_first = 1; return 0.0; }
    return (double)(ts->tv_sec - t_first.tv_sec) +
           (double)(ts->tv_nsec - t_first.tv_nsec) / 1e9;
}

const char *csum_val(int v) {
    switch (v) {
        case 1:  return "ok";
        case 0:  return "bad";
        case -2: return "none";
        default: return "unknown";
    }
}

const char *pcol(const packet_t *p) {
    if (!cfg.color) return "";
    if (p->has_tcp) return CGRN;
    if (p->has_udp) return CCYN;
    if (p->has_icmp) return p->icmp_ver == 6 ? CMAG : CYEL;
    if (p->has_arp) return CRED;
    if (p->ip_ver == 6) return CBLU;
    if (p->ip_ver == 4) return CWHT;
    return CDIM;
}
const char *csum_str(int v) {
    static char buf[32];
    const char *txt, *col = "";
    switch (v) {
        case 1:  txt = "ok";   col = CDIM; break;
        case 0:  txt = "BAD";  col = CRED; break;
        case -2: txt = "none"; col = CDIM; break;
        default: txt = "?";    col = CYEL; break;
    }
    if (cfg.color) snprintf(buf, sizeof buf, "%s%s%s", col, txt, C0);
    else snprintf(buf, sizeof buf, "%s", txt);
    return buf;
}
void fmt_ep(const packet_t *p, int is_src, char *out, size_t sz) {
    const char *ip = is_src ? p->src_s : p->dst_s;
    if (p->has_tcp || p->has_udp) {
        uint16_t port = is_src ? p->sport : p->dport;
        if (p->ip_ver == 6) snprintf(out, sz, "[%s]:%u", ip, port);
        else snprintf(out, sz, "%s:%u", ip, port);
        const char *svc = port_service(port, p->has_tcp);
        if (svc && is_src == 0) {
            size_t l = strlen(out);
            snprintf(out + l, sz - l, "(%s)", svc);
        }
    } else snprintf(out, sz, "%s", ip);
}

static void hexdump(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i += 16) {
        printf("        %s%04zx  ", CDIM, i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n) printf("%02x ", b[i + j]); else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            unsigned c = b[i + j];
            putchar((c >= 32 && c < 127) ? (int)c : '.');
        }
        printf("%s|%s\n", CDIM, C0);
    }
}

static void print_pkt(const packet_t *p) {
    char tbuf[32];
    struct tm tm;
    localtime_r(&p->ts.tv_sec, &tm);
    strftime(tbuf, sizeof tbuf, "%H:%M:%S", &tm);

    printf("%s%s.%06ld%s", CDIM, tbuf, (long)(p->ts.tv_nsec / 1000), C0);
    if (cfg.reltime) printf(" %s+%0.6f%s", CDIM, rel_secs(&p->ts), C0);
    printf(" %s%-8s%s", CDIM, p->ifname, C0);
    if (p->stream_id > 0) printf(" %s#%d%s", CDIM, p->stream_id, C0);
    printf(" %s%-7s%s ", pcol(p), p->disp, C0);

    if (p->has_arp && p->arp_ok) {
        char m[24];
        if (p->arp_op == 1) printf("who-has %s tell %s", p->arp_tpa, p->arp_spa);
        else if (p->arp_op == 2) {
            mac_str(p->arp_sha, m, sizeof m);
            printf("%s is-at %s", p->arp_spa, m);
        } else printf("%s op=%u -> %s", p->arp_spa, p->arp_op, p->arp_tpa);
    } else if (p->ip_ver) {
        char a[144], b[144];
        fmt_ep(p, 1, a, sizeof a);
        fmt_ep(p, 0, b, sizeof b);
        printf("%s%s%s %s->%s %s%s%s", CGRN, a, C0, CDIM, C0, CGRN, b, C0);
    } else if (p->wlan) {
        char a[24], b[24];
        mac_str(p->eth_src, a, sizeof a);
        mac_str(p->eth_dst, b, sizeof b);
        printf("%s%s%s %s->%s %s%s%s", CDIM, a, C0, CDIM, C0, CDIM, b, C0);
        if (p->wlan_bssid[0]) printf(" bssid=%s", p->wlan_bssid);
        if (p->wlan_ssid[0]) printf(" ssid=%s", p->wlan_ssid);
        if (p->wlan_channel) printf(" ch=%d", p->wlan_channel);
        if (p->wlan_deauth) printf(" %sDEAUTH%s", CRED, C0);
    } else if (p->has_l2) {
        char a[24], b[24], c[24];
        mac_str(p->eth_src, a, sizeof a);
        mac_str(p->eth_dst, b, sizeof b);
        snprintf(c, sizeof c, "0x%04x", p->etype);
        printf("%s%s%s %s->%s %s%s%s", CDIM, a, C0, CDIM, C0, CDIM, b, C0);
        printf(" type=%s", ethertype_name(p->etype) ? ethertype_name(p->etype) : c);
    }

    printf("  %slen=%zu%s", CDIM, p->caplen, C0);
    if (p->wirelen != p->caplen) printf("/%zu", p->wirelen);
    if (p->vlan >= 0) {
        if (p->inner_vlan >= 0)
            printf(" %sqinq=%d.%d%s", CDIM, p->vlan, p->inner_vlan, C0);
        else
            printf(" %svlan=%d%s", CDIM, p->vlan, C0);
    }
    if (p->ip_ver) printf(" %sttl=%u%s", CDIM, p->ttl, C0);
    if (p->have_dir && p->outgoing) printf(" %sTX%s", CYEL, C0);
    if (p->err) printf("  %s!%s", CYEL, C0);
    printf("\n");

    if (p->err) printf("        %s! %s%s\n", CYEL, p->err, C0);
    if (cfg.quiet) return;

    if (p->ip_ver == 4) {
        printf("        IPv4 ttl=%u", p->ttl);
        if (p->ip_id) printf(" id=0x%04x", p->ip_id);
        if (p->df) printf(" DF");
        if (p->mf) printf(" MF");
        if (p->frag_off) printf(" off=%u", p->frag_off);
        printf(" ip-csum=%s", csum_str(p->ip_csum));
        printf("\n");
    } else if (p->ip_ver == 6) {
        printf("        IPv6 hlim=%u", p->ttl);
        if (p->ext_s[0]) printf(" ext=%s", p->ext_s);
        if (p->frag_off) printf(" off=%u%s", p->frag_off, p->mf ? " MF" : "");
        printf("\n");
    }
    if (p->has_tcp) {
        printf("        seq=%u ack=%u win=%u [%s] csum=%s\n",
               p->seq, p->ack, p->win, p->flags_s, csum_str(p->l4_csum));
        if (strcmp(p->opts_s, "none")) printf("        opts: %s\n", p->opts_s);
    }
    if (p->has_udp) printf("        len=%u csum=%s\n", p->udp_len, csum_str(p->l4_csum));
    if (p->has_icmp) {
        printf("        %s code=%u csum=%s",
               p->icmp_ver == 6 ? icmp6_name(p->icmp_type) : icmp4_name(p->icmp_type),
               p->icmp_code, csum_str(p->l4_csum));
        int is_echo = (p->icmp_ver == 4 && (p->icmp_type == 0 || p->icmp_type == 8)) ||
                      (p->icmp_ver == 6 && (p->icmp_type == 128 || p->icmp_type == 129));
        if (is_echo) printf(" id=0x%04x seq=%u", p->icmp_id, p->icmp_seq);
        printf("\n");
    }
    if (p->has_arp && !p->arp_ok) {
        printf("        htype=%u ptype=0x%04x op=%u\n", p->arp_htype, p->arp_ptype, p->arp_op);
    }
    if (p->app) {
        const char *lab = p->app == APP_DNS ? "DNS" : p->app == APP_TLS ? "TLS"
                        : p->app == APP_QUIC ? "QUIC" : "HTTP";
        printf("        %s%-4s%s %s\n", CYEL, lab, C0, p->app_s);
    }
    if (p->cred_kind) {
        printf("        %sCRED%s %s", CRED, C0, p->cred_where);
        if (p->cred_user[0]) printf(" user=%s", p->cred_user);
        if (p->cred_pass[0]) printf(" pass=%s", p->cred_pass);
        printf("\n");
    }
    if (p->token[0])   printf("        %sTOKN%s %s\n", CRED, C0, p->token);
    if (p->jwt_sub[0]) printf("        %sJWT %s %s\n", CRED, C0, p->jwt_sub);
    if (p->cookie[0])  printf("        %sCOOK%s %s\n", CMAG, C0, p->cookie);
    if (p->banner[0])  printf("        %sBANR%s %s\n", CMAG, C0, p->banner);
    if (p->proto_s[0]) printf("        %sPROTO%s %s\n", CCYN, C0, p->proto_s);
    if (p->os_guess[0]) printf("        %sOS  %s %s\n", CCYN, C0, p->os_guess);
    if (p->payload && p->plen && cfg.dumpbytes > 0) {
        size_t show = p->avail;
        if (show > (size_t)cfg.dumpbytes) show = (size_t)cfg.dumpbytes;
        printf("        %spayload %zu bytes%s", CDIM, p->plen, C0);
        if (p->avail < p->plen) printf(" %s(%zu captured)%s", CYEL, p->avail, C0);
        printf(":\n");
        hexdump(p->payload, show);
        if (p->plen > show)
            printf("        %s... %zu more bytes (-B to show more)%s\n", CDIM, p->plen - show, C0);
    }
}

static void json_str(const char *s) {
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:
                if (c < 32 || c == 127) printf("\\u%04x", c);
                else putchar(c);
        }
    }
    putchar('"');
}

static void json_body(const packet_t *p) {
    printf("\"ts\":%lld.%06ld,\"rel\":%.6f",
           (long long)p->ts.tv_sec, p->ts.tv_nsec / 1000, rel_secs(&p->ts));
    printf(",\"iface\":");
    json_str(p->ifname);
    if (p->have_dir) printf(",\"dir\":\"%s\"", p->outgoing ? "out" : "in");
    printf(",\"len\":%zu,\"wire\":%zu", p->caplen, p->wirelen);
    if (p->vlan >= 0) printf(",\"vlan\":%d", p->vlan);
    if (p->inner_vlan >= 0) printf(",\"vlan.inner\":%d", p->inner_vlan);

    if (p->has_l2) {
        char m[24];
        mac_str(p->eth_src, m, sizeof m);
        printf(",\"eth.src\":"); json_str(m);
        mac_str(p->eth_dst, m, sizeof m);
        printf(",\"eth.dst\":"); json_str(m);
        const char *en = ethertype_name(p->etype);
        char eb[16];
        if (!en) { snprintf(eb, sizeof eb, "0x%04x", p->etype); en = eb; }
        printf(",\"eth.type\":"); json_str(en);
    }
    if (p->wlan) {
        static const char *wt[] = { "mgmt", "ctrl", "data" };
        printf(",\"wlan.type\":"); json_str(p->wlan_type <= 2 ? wt[p->wlan_type] : "?");
        printf(",\"wlan.subtype\":%d", p->wlan_subtype);
        if (p->wlan_bssid[0]) { printf(",\"wlan.bssid\":"); json_str(p->wlan_bssid); }
        if (p->wlan_ssid[0])  { printf(",\"wlan.ssid\":");  json_str(p->wlan_ssid); }
        if (p->wlan_channel)  printf(",\"wlan.channel\":%d", p->wlan_channel);
        if (p->wlan_deauth)   printf(",\"wlan.deauth\":true");
        if (p->wlan_type == 0) printf(",\"wlan.protected\":%s", p->wlan_protected ? "true" : "false");
    }
    if (p->ip_ver) {
        printf(",\"ip.ver\":%d,\"src\":", p->ip_ver);
        json_str(p->src_s);
        printf(",\"dst\":");
        json_str(p->dst_s);
        printf(",\"ttl\":%u", p->ttl);
        if (p->ip_ver == 4) {
            printf(",\"ip.id\":%u,\"ip.df\":%s,\"ip.mf\":%s,\"ip.off\":%d",
                   p->ip_id, p->df ? "true" : "false",
                   p->mf ? "true" : "false", p->frag_off);
            printf(",\"ip.csum\":"); json_str(csum_val(p->ip_csum));
        } else if (p->ext_s[0]) {
            printf(",\"ipv6.ext\":"); json_str(p->ext_s);
        }
    }
    if (p->has_arp) {
        printf(",\"arp.op\":%u", p->arp_op);
        if (p->arp_ok) {
            char m[24];
            printf(",\"arp.spa\":"); json_str(p->arp_spa);
            printf(",\"arp.tpa\":"); json_str(p->arp_tpa);
            mac_str(p->arp_sha, m, sizeof m);
            printf(",\"arp.sha\":"); json_str(m);
        }
    }

    printf(",\"proto\":"); json_str(p->l4name[0] ? p->l4name : p->primary);
    if (p->has_tcp || p->has_udp) printf(",\"sport\":%u,\"dport\":%u", p->sport, p->dport);
    if (p->has_tcp) {
        printf(",\"seq\":%u,\"ack\":%u,\"win\":%u,\"flags\":",
               p->seq, p->ack, p->win);
        json_str(p->flags_s);
        printf(",\"tcp.csum\":"); json_str(csum_val(p->l4_csum));
        if (strcmp(p->opts_s, "none")) { printf(",\"tcp.opts\":"); json_str(p->opts_s); }
    }
    if (p->has_udp) {
        printf(",\"udp.len\":%u,\"udp.csum\":", p->udp_len);
        json_str(csum_val(p->l4_csum));
    }
    if (p->has_icmp) {
        printf(",\"icmp.type\":%u,\"icmp.code\":%u,\"icmp.name\":",
               p->icmp_type, p->icmp_code);
        json_str(p->icmp_ver == 6 ? icmp6_name(p->icmp_type) : icmp4_name(p->icmp_type));
    }
    if (p->stream_id > 0) printf(",\"stream\":%d", p->stream_id);

    if (p->app == APP_DNS) {
        printf(",\"app\":\"dns\",\"dns.qname\":"); json_str(p->dns_name);
        const char *tn = dns_type_name(p->dns_qtype);
        char tb[16];
        if (!tn) { snprintf(tb, sizeof tb, "TYPE%u", p->dns_qtype); tn = tb; }
        printf(",\"dns.qtype\":"); json_str(tn);
        printf(",\"dns.qr\":\"%s\"", p->dns_qr ? "response" : "query");
        if (p->dns_qr) {
            const char *rc = dns_rcode_name(p->dns_rcode);
            char rb[16];
            if (!rc) { snprintf(rb, sizeof rb, "rcode%d", p->dns_rcode); rc = rb; }
            printf(",\"dns.rcode\":"); json_str(rc);
            printf(",\"dns.answers\":%d", p->dns_an);
        }
        if (p->dns_first[0]) { printf(",\"dns.first\":"); json_str(p->dns_first); }
    } else if (p->app == APP_TLS) {
        printf(",\"app\":\"tls\",\"tls.type\":"); json_str(p->tls_type);
        printf(",\"tls.version\":"); json_str(p->tls_ver);
        if (p->tls_sni[0])  { printf(",\"tls.sni\":");  json_str(p->tls_sni); }
        if (p->tls_alpn[0]) { printf(",\"tls.alpn\":"); json_str(p->tls_alpn); }
        if (p->tls_cipher) {
            const char *cn = tls_cipher_name(p->tls_cipher);
            char cb[16];
            if (!cn) { snprintf(cb, sizeof cb, "0x%04x", p->tls_cipher); cn = cb; }
            printf(",\"tls.cipher\":"); json_str(cn);
        }
        if (p->cert_n) printf(",\"tls.cert.chain\":%d", p->cert_n);
        if (p->cert_subject[0]) { printf(",\"tls.cert.subject\":"); json_str(p->cert_subject); }
        if (p->cert_issuer[0])  { printf(",\"tls.cert.issuer\":");  json_str(p->cert_issuer); }
        if (p->cert_san[0])     { printf(",\"tls.cert.san\":");     json_str(p->cert_san); }
        if (p->cert_valid[0])   { printf(",\"tls.cert.valid\":");   json_str(p->cert_valid); }
        if (p->ja3[0]) { printf(",\"tls.ja3\":"); json_str(p->ja3);
                         printf(",\"tls.ja3_str\":"); json_str(p->ja3_str); }
        if (p->ja4[0]) { printf(",\"tls.ja4\":"); json_str(p->ja4); }
        if (p->ech) printf(",\"tls.ech\":true");
        if (p->dot) printf(",\"dot\":true");
    } else if (p->app == APP_QUIC) {
        printf(",\"app\":\"quic\"");
        if (p->quic_ver[0])  { printf(",\"quic.version\":"); json_str(p->quic_ver); }
        if (p->quic_type[0]) { printf(",\"quic.type\":");    json_str(p->quic_type); }
        if (p->quic_sni[0])  { printf(",\"quic.sni\":");     json_str(p->quic_sni); }
        if (p->quic_dcid[0]) { printf(",\"quic.dcid\":");    json_str(p->quic_dcid); }
    } else if (p->app == APP_HTTP) {
        printf(",\"app\":\"http\",\"http.line\":"); json_str(p->http_line);
        if (p->http_code) printf(",\"http.code\":%d", p->http_code);
        if (p->http_host[0]) { printf(",\"http.host\":"); json_str(p->http_host); }
        if (p->doh) printf(",\"doh\":true");
        if (p->h2_type[0])     { printf(",\"h2.type\":");      json_str(p->h2_type); }
        if (p->h2_stream)      printf(",\"h2.stream\":%u", p->h2_stream);
        if (p->h2_method[0])   { printf(",\"h2.method\":");    json_str(p->h2_method); }
        if (p->h2_path[0])     { printf(",\"h2.path\":");      json_str(p->h2_path); }
        if (p->h2_authority[0]){ printf(",\"h2.authority\":"); json_str(p->h2_authority); }
        if (p->h2_useragent[0]){ printf(",\"h2.ua\":");        json_str(p->h2_useragent); }
    }

    /* --- harvested credentials / tokens / banners --- */
    if (p->cred_kind) {
        printf(",\"cred\":{\"kind\":\"%s\"", cred_kind_name(p->cred_kind));
        printf(",\"where\":"); json_str(p->cred_where);
        if (p->cred_user[0]) { printf(",\"user\":"); json_str(p->cred_user); }
        if (p->cred_pass[0]) { printf(",\"pass\":"); json_str(p->cred_pass); }
        printf("}");
    }
    if (p->token[0])      { printf(",\"token\":");   json_str(p->token); }
    if (p->jwt_sub[0])    { printf(",\"jwt\":");     json_str(p->jwt_sub); }
    if (p->cookie[0])     { printf(",\"cookie\":");  json_str(p->cookie); }
    if (p->banner[0]) {
        printf(",\"banner\":"); json_str(p->banner);
        if (p->svc[0]) { printf(",\"service\":"); json_str(p->svc); }
    }
    if (p->os_guess[0])   { printf(",\"os\":");      json_str(p->os_guess); }
    if (p->proto[0]) {
        printf(",\"proto\":");
        json_str(p->proto);
        if (p->proto_s[0]) { printf(",\"proto.detail\":"); json_str(p->proto_s); }
        if (p->ldap_msg) printf(",\"ldap.msgid\":%d", p->ldap_msg);
    }

    if (p->err) { printf(",\"error\":"); json_str(p->err); }
    if (p->malformed) printf(",\"malformed\":true");

    if (p->payload && p->avail && cfg.dumpbytes > 0) {
        size_t show = p->avail;
        if (show > (size_t)cfg.dumpbytes) show = (size_t)cfg.dumpbytes;
        fputs(",\"payload\":\"", stdout);
        for (size_t i = 0; i < show; i++) printf("%02x", p->payload[i]);
        putchar('"');
    }
}

static void print_json(const packet_t *p) {
    putchar('{');
    json_body(p);
    printf("}\n");
}

static void csv_str(const char *s) {
    putchar('"');
    for (; *s; s++) {
        if (*s == '"') fputs("\"\"", stdout);
        else if ((unsigned char)*s < 32 || *s == 127) putchar(' ');
        else putchar(*s);
    }
    putchar('"');
}

static void print_csv(const packet_t *p) {
    static int header_done = 0;
    if (!header_done) {
        printf("ts,rel,iface,dir,proto,src,sport,dst,dport,len,vlan,info,user,pass,where,banner,os\n");
        header_done = 1;
    }
    printf("%lld.%06ld,%.6f,", (long long)p->ts.tv_sec,
           p->ts.tv_nsec / 1000, rel_secs(&p->ts));
    csv_str(p->ifname);
    putchar(',');
    if (p->have_dir) fputs(p->outgoing ? "out" : "in", stdout);
    putchar(',');
    csv_str(p->l4name[0] ? p->l4name : p->primary);
    putchar(',');
    csv_str(p->ip_ver ? p->src_s : "");
    putchar(',');
    if (p->has_tcp || p->has_udp) printf("%u", p->sport);
    putchar(',');
    csv_str(p->ip_ver ? p->dst_s : "");
    putchar(',');
    if (p->has_tcp || p->has_udp) printf("%u", p->dport);
    putchar(',');
    printf("%zu,", p->caplen);
    if (p->vlan >= 0) {
        if (p->inner_vlan >= 0) printf("%d.%d", p->vlan, p->inner_vlan);
        else printf("%d", p->vlan);
    }
    putchar(',');

    char info[480];
    info[0] = 0;
    if (p->app_s[0]) snprintf(info, sizeof info, "%s", p->app_s);
    else if (p->has_tcp) snprintf(info, sizeof info, "%s", p->flags_s);
    else if (p->has_icmp)
        snprintf(info, sizeof info, "%s code=%u",
                 p->icmp_ver == 6 ? icmp6_name(p->icmp_type) : icmp4_name(p->icmp_type),
                 p->icmp_code);
    else if (p->has_arp && p->arp_ok)
        snprintf(info, sizeof info, "op=%u %s -> %s", p->arp_op, p->arp_spa, p->arp_tpa);
    if (p->err) lst(info, sizeof info, "%s", p->err);
    csv_str(info);
    putchar(',');
    /* harvested / recon columns (empty when the feature is off) */
    csv_str(p->cred_user);
    putchar(',');
    csv_str(p->cred_pass);
    putchar(',');
    csv_str(p->cred_where);
    putchar(',');
    csv_str(p->banner);
    putchar(',');
    csv_str(p->os_guess);
    putchar('\n');
}

/* ---------- ndjson: like json but with a schema version up front ---------- */

void print_ndjson(const packet_t *p) {
    printf("{\"schema\":1,");
    json_body(p);
    printf("}\n");
}

/* ---------- zeek: one TSV line per packet in the "conn"-ish schema ---------- */

void print_zeek_headers(void) {
    if (strcmp(cfg.outfmt, "zeek")) return;
    printf("#separator \\x09\n");
    printf("#set_separator\\x09,\n");
    printf("#empty_field\\x09(empty)\n");
    printf("#unset_field\\x09-\n");
    printf("#path\\x09ch1m3ra\n");
    printf("#open\\x09%ld\n", (long)time(NULL));
    printf("#fields\\x09ts\\tuid\\tid.orig_h\\tid.orig_p\\tid.resp_h\\tid.resp_p"
           "\\tproto\\tservice\\tduration\\torig_bytes\\tresp_bytes\\tconn_state"
           "\\thistory\\torig_pkts\\tresp_pkts\\tinfo\n");
    printf("#types\\x09time\\tstring\\taddr\\tport\\taddr\\tport\\tstring\\tstring"
           "\\tinterval\\tcount\\tcount\\tstring\\tstring\\tcount\\tcount\\tstring\n");
}

void print_zeek(const packet_t *p) {
    char ts[32];
    snprintf(ts, sizeof ts, "%.6f", (double)p->ts.tv_sec + (double)p->ts.tv_nsec / 1e9);
    char sp[8], dp[8], info[256];
    snprintf(sp, sizeof sp, "%u", p->sport);
    snprintf(dp, sizeof dp, "%u", p->dport);
    if (!p->ip_ver) { snprintf(sp, sizeof sp, "-"); snprintf(dp, sizeof dp, "-"); }

    const char *proto = p->l4name[0] ? p->l4name : p->primary;
    char uid[32];
    if (p->stream_id >= 0) snprintf(uid, sizeof uid, "S%ld", (long)p->stream_id);
    else snprintf(uid, sizeof uid, "P%llu", (unsigned long long)st.shown);

    info[0] = 0;
    if (p->app == APP_DNS && p->dns_name[0]) snprintf(info, sizeof info, "%s", p->dns_name);
    else if (p->app == APP_TLS && p->tls_sni[0]) snprintf(info, sizeof info, "%s", p->tls_sni);
    else if (p->app == APP_HTTP && p->http_line[0]) snprintf(info, sizeof info, "%.120s", p->http_line);
    else if (p->app == APP_QUIC && p->quic_sni[0]) snprintf(info, sizeof info, "%s", p->quic_sni);

    const char *orig = p->ip_ver ? p->src_s : "-";
    const char *resp = p->ip_ver ? p->dst_s : "-";

    printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t-\t%zu\t0\t-\t-\t1\t0\t%s\n",
           ts, uid, orig, sp, resp, dp, proto,
           (p->app == APP_DNS ? "dns" : p->app == APP_TLS ? "ssl" :
            p->app == APP_HTTP ? "http" : p->app == APP_QUIC ? "quic" : "-"),
           p->caplen, info[0] ? info : "-");
}

/* dispatch to the selected output format */
void print_record(const packet_t *p) {
    if (!strcmp(cfg.outfmt, "json")) print_json(p);
    else if (!strcmp(cfg.outfmt, "ndjson")) print_ndjson(p);
    else if (!strcmp(cfg.outfmt, "csv")) print_csv(p);
    else if (!strcmp(cfg.outfmt, "zeek")) print_zeek(p);
    else print_pkt(p);
}

void print_stats(void) {
    fprintf(stderr, "\n%s--- stats ---%s\n", CWHT, C0);
    fprintf(stderr, "packets %llu (%llu bytes)  shown %llu  filtered %llu  malformed %llu\n",
            st.cap, st.bytes, st.shown, st.filtered, st.bad);
    for (int i = 0; i < 8; i++)
        if (st.b[i]) fprintf(stderr, "  %s %llu\n", bucket_name(i), st.b[i]);
    if (st.a[0] || st.a[1] || st.a[2])
        fprintf(stderr, "  dns %llu  tls %llu  http %llu\n", st.a[0], st.a[1], st.a[2]);
    if (st.a[3]) fprintf(stderr, "  quic %llu\n", st.a[3]);
    if (cfg.harvest && (st.creds || st.banners))
        fprintf(stderr, "  harvested: %llu credential(s), %llu banner(s)\n",
                st.creds, st.banners);
    if (cfg.names && st.names) fprintf(stderr, "  names learned: %llu\n", st.names);
    frag_stats(stderr);
    streams_stats(stderr);
    finger_stats(stderr);
    talkers_stats(stderr);
    names_stats(stderr);
    defense_stats(stderr);
}

