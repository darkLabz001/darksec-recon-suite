/* filter.c - filtering */

#include "ch1m3ra.h"

/* ---------- filtering ---------- */
int proto_match(const packet_t *p, const char *req) {
    if (!strcasecmp(req, "all")) return 1;
    if (!strcasecmp(req, "tcp")) return p->has_tcp;
    if (!strcasecmp(req, "udp")) return p->has_udp;
    if (!strcasecmp(req, "icmp")) return p->has_icmp && p->icmp_ver == 4;
    if (!strcasecmp(req, "icmpv6") || !strcasecmp(req, "icmp6"))
        return p->has_icmp && p->icmp_ver == 6;
    if (!strcasecmp(req, "arp")) return p->has_arp;
    if (!strcasecmp(req, "ip") || !strcasecmp(req, "ipv4")) return p->ip_ver == 4;
    if (!strcasecmp(req, "ipv6")) return p->ip_ver == 6;
    if (!strcasecmp(req, "frag")) return p->frag_off > 0 || p->mf;
    if (!strcasecmp(req, "dns")) return p->app == APP_DNS;
    if (!strcasecmp(req, "tls") || !strcasecmp(req, "https")) return p->app == APP_TLS;
    if (!strcasecmp(req, "http")) return p->app == APP_HTTP;
    if (p->l4name[0] && !strcasecmp(p->l4name, req)) return 1;
    return !strcasecmp(p->primary, req);
}

int pass_filter(const packet_t *p) {
    if (cfg.proto && !proto_match(p, cfg.proto)) return 0;
    if (cfg.host) {
        int hit = strstr(p->src_s, cfg.host) != NULL || strstr(p->dst_s, cfg.host) != NULL;
        if (!hit && p->arp_ok)
            hit = strstr(p->arp_spa, cfg.host) != NULL || strstr(p->arp_tpa, cfg.host) != NULL;
        /* also match decoded names: DNS question, TLS SNI, HTTP Host */
        if (!hit && p->dns_name[0])   hit = strstr(p->dns_name, cfg.host) != NULL;
        if (!hit && p->tls_sni[0])    hit = strstr(p->tls_sni, cfg.host) != NULL;
        if (!hit && p->http_host[0])  hit = strstr(p->http_host, cfg.host) != NULL;
        if (!hit) return 0;
    }
    if (cfg.port >= 0) {
        if (!((p->has_tcp || p->has_udp) &&
              (p->sport == (uint16_t)cfg.port || p->dport == (uint16_t)cfg.port)))
            return 0;
    }
    return 1;
}

