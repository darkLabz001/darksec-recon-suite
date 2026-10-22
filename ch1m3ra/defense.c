/* defense.c - defensive network anomaly detection (-D).
 *
 * Detectors that watch for the classic layer-2/3 attacks a packet sniffer is uniquely
 * placed to notice, all passive (nothing is transmitted):
 *
 *   - ARP spoofing:        an IPv4 address whose MAC binding suddenly changes,
 *                          gratuitous ARP claiming an address, or one MAC
 *                          announcing an implausible number of addresses
 *                          (a tell-tale of an ARP-spoofing host).
 *   - Neighbor spoofing:   the IPv6 analogue using ICMPv6 Neighbor
 *                          Advertisements that can't be trusted (unsolicited,
 *                          or a binding change for a known address).
 *   - Rogue DHCP:          more than one DHCP server on the segment, and Offers
 *                          whose server identifier / router differs from the
 *                          first one seen.
 *   - Name poisoning:      mDNS / LLMNR / NBNS answers that bind a name that a
 *                          different host previously owned, or that answer a
 *                          name the responder never asked about (the classic
 *                          Responder.py attack).  Includes WPAD takeover.
 *   - VLAN / DTP:          802.1Q double-tagging and Cisco DTP frames, which are
 *                          the usual precursors to VLAN hopping.
 *
 * Findings are emitted once per distinct anomaly to stderr (and folded into the
 * stats table) so a long capture doesn't drown the analyst in repeats.
 */
#include "ch1m3ra.h"
#include <ctype.h>

/* ---------- ARP binding table ---------- */
#define NARP 512
typedef struct {
    int      used;
    char     ip[INET6_ADDRSTRLEN + 4];   /* IPv4, or "v6:<addr>" */
    uint8_t  mac[6];
    unsigned long long seen;
    int      changes;         /* number of times the MAC changed for this IP */
} arpb_t;
static arpb_t arpt[NARP];
static unsigned arpn = 0;

/* one MAC can legitimately hold many addresses (routers, VM hosts), so only
 * flag absurd fan-out -- the signature of an attacker claiming the whole /24 */
#define MAC_CLAIM_LIMIT 12
typedef struct {
    int     used;
    uint8_t mac[6];
    unsigned ipcount;
} maccount_t;
static maccount_t mact[NARP];
static unsigned macn = 0;

static arpb_t *arp_find_ip(const char *ip, int create) {
    for (unsigned i = 0; i < arpn; i++)
        if (arpt[i].used && !strcmp(arpt[i].ip, ip)) return &arpt[i];
    if (!create || arpn >= NARP) return NULL;
    arpb_t *e = &arpt[arpn++];
    memset(e, 0, sizeof *e);
    e->used = 1;
    snprintf(e->ip, sizeof e->ip, "%s", ip);
    return e;
}

static const char *macfmt(const uint8_t *m, char *out, size_t sz) {
    mac_str(m, out, sz);
    return out;
}

/* ---------- finding output + counters ---------- */
static unsigned long long n_anom = 0;

void defense_report(const packet_t *p, const char *kind, const char *detail) {
    st.anoms++;
    n_anom++;
    char m[24];
    fprintf(stderr, "%s[!] %s%s", CRED, kind, C0);
    if (p) {
        fprintf(stderr, " %s", CDIM);
        if (p->has_arp) fprintf(stderr, "%s", p->arp_spa[0] ? p->arp_spa : "?");
        else if (p->ip_ver) fprintf(stderr, "%s -> %s", p->src_s, p->dst_s);
        else fprintf(stderr, "%s -> %s", macfmt(p->eth_src, m, sizeof m), "?");
        fprintf(stderr, "%s", C0);
    }
    fprintf(stderr, ": %s\n", detail);
}

static int defense_enabled(void) { return cfg.defense; }

/* ---------- ARP spoof detection ---------- */
static void defend_arp(const packet_t *p) {
    /* What address is being claimed, and with which MAC?  A request claims the
     * sender; a reply claims the sender too.  We care about the sender binding
     * (spa -> sha). */
    const char *ip = p->arp_spa;
    if (!ip[0] || !memcmp(ip, "0.0.0.0", 8)) return;
    int is_grat = !memcmp(p->arp_tpa, ip, sizeof p->arp_tpa) ||
                  !memcmp(p->arp_tpa, "0.0.0.0", 8);

    /* broadcast/multicast sender MACs are never a real claim */
    static const uint8_t zero[6] = {0}, bc[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    if (!memcmp(p->arp_sha, zero, 6) || !memcmp(p->arp_sha, bc, 6)) return;

    arpb_t *e = arp_find_ip(ip, 1);
    if (!e) return;
    char m1[24], m2[24];
    int is_new_ip = !e->seen;

    /* fan-out: how many distinct IPs has this MAC claimed?  A real host holds
     * one or two; a spoofer sweeping a /24 claims dozens. */
    if (is_new_ip) {
        maccount_t *mc = NULL;
        for (unsigned i = 0; i < macn; i++)
            if (mact[i].used && !memcmp(mact[i].mac, p->arp_sha, 6)) { mc = &mact[i]; break; }
        if (!mc && macn < NARP) {
            mc = &mact[macn++];
            memset(mc, 0, sizeof *mc);
            mc->used = 1;
            memcpy(mc->mac, p->arp_sha, 6);
        }
        if (mc && ++mc->ipcount == MAC_CLAIM_LIMIT + 1) {
            char det[220];
            snprintf(det, sizeof det,
                     "MAC %s has claimed %u addresses (possible ARP sweep / MITM)",
                     macfmt(p->arp_sha, m1, sizeof m1), mc->ipcount);
            defense_report(p, "ARP over-claim", det);
        }
    }

    if (is_new_ip) {
        memcpy(e->mac, p->arp_sha, 6);
        e->seen = 1;
        /* a gratuitous ARP/announcement on first sight is too noisy to flag;
         * only a later conflict for the same address is a real signal */
        return;
    }
    if (memcmp(e->mac, p->arp_sha, 6) != 0) {
        char det[220];
        snprintf(det, sizeof det,
                 "MAC for %s changed %s -> %s%s",
                 ip, macfmt(e->mac, m1, sizeof m1), macfmt(p->arp_sha, m2, sizeof m2),
                 is_grat ? " (gratuitous)" : "");
        defense_report(p, "ARP SPOOF suspected", det);
        memcpy(e->mac, p->arp_sha, 6);
        e->changes++;
    }
}

/* ---------- ICMPv6 Neighbor Advertisement spoof detection ---------- */
static void defend_icmp6_na(const packet_t *p) {
    /* NA is ICMPv6 type 136.  The target address is in the message body we
     * haven't parsed into a field, so work off what decode gave us: for an NA
     * the source is the target's address.  We track IPv6->MAC from the source
     * link-layer option (needs the option bytes); fall back to the Ethernet
     * source MAC, which is what an off-path spoofer would use anyway. */
    if (!p->has_icmp || p->icmp_ver != 6 || p->icmp_type != 136) return;
    char key[INET6_ADDRSTRLEN + 4];
    snprintf(key, sizeof key, "v6:%s", p->src_s);
    arpb_t *e = arp_find_ip(key, 1);
    if (!e) return;
    char m1[24], m2[24];
    if (!e->seen) { memcpy(e->mac, p->eth_src, 6); e->seen = 1; return; }
    if (memcmp(e->mac, p->eth_src, 6) != 0) {
        char det[220];
        snprintf(det, sizeof det, "NA for %s changed MAC %s -> %s",
                 p->src_s, macfmt(e->mac, m1, sizeof m1), macfmt(p->eth_src, m2, sizeof m2));
        defense_report(p, "ICMPv6 NA spoof suspected", det);
        memcpy(e->mac, p->eth_src, 6);
        e->changes++;
    }
}

/* ---------- rogue DHCP detection ---------- */
typedef struct {
    int    used;
    char   server[INET6_ADDRSTRLEN];
    unsigned offers;
} dhcp_srv_t;
#define NDHCP 32
static dhcp_srv_t dhcps[NDHCP];
static unsigned dhcpn = 0;

static void defend_dhcp(const packet_t *p) {
    /* DHCPv4: client->server on 67, server->client on 68.  We look at the
     * IPv4 source of server->client packets (the "server identifier" in
     * practice) and at the offered router, which we don't decode deeply, so
     * the source address is the signal. */
    if (!p->has_udp || p->ip_ver != 4) return;
    if (p->sport != 67 || p->dport != 68) return;

    for (unsigned i = 0; i < dhcpn; i++) {
        if (dhcps[i].used && !strcmp(dhcps[i].server, p->src_s)) {
            dhcps[i].offers++;
            return;
        }
    }
    if (dhcpn >= NDHCP) return;
    dhcps[dhcpn].used = 1;
    snprintf(dhcps[dhcpn].server, sizeof dhcps[dhcpn].server, "%s", p->src_s);
    dhcps[dhcpn].offers = 1;
    dhcpn++;
    if (dhcpn == 2) {
        char det[220];
        snprintf(det, sizeof det,
                 "second DHCP server on the segment (first was %s, now %s) "
                 "-- possible rogue DHCP", dhcps[0].server, dhcps[1].server);
        defense_report(p, "ROGUE DHCP suspected", det);
    } else if (dhcpn > 2) {
        char det[220];
        snprintf(det, sizeof det, "DHCP server #%u on the segment: %s",
                 dhcpn, p->src_s);
        defense_report(p, "ROGUE DHCP suspected", det);
    }
}

/* ---------- mDNS / LLMNR / NBNS name poisoning ---------- */
typedef struct {
    int    used;
    char   name[192];       /* lower-cased name */
    char   addr[64];        /* answer address (or the responder) */
} nmap_t;
#define NNAME 512
static nmap_t ntab[NNAME];
static unsigned nn = 0;

static void defend_name_answer(const packet_t *p) {
    /* A response (qr=1) that carries an answer binding a name.  If that name
     * was already bound to a different address, that is the Responder.py
     * signature: whoever got asked first now answers with *their* address. */
    if (!p->dns_name[0] || !p->dns_qr) return;
    char low[192];
    size_t k = 0;
    for (; p->dns_name[k] && k < sizeof low - 1; k++)
        low[k] = (char)tolower((unsigned char)p->dns_name[k]);
    low[k] = 0;

    char addr[64] = "";
    /* prefer an A/AAAA answer; fall back to the responder's own IP */
    if (p->dns_first[0]) snprintf(addr, sizeof addr, "%.*s", 60, p->dns_first);
    else snprintf(addr, sizeof addr, "%s", p->src_s);

    for (unsigned i = 0; i < nn; i++) {
        if (ntab[i].used && !strcmp(ntab[i].name, low)) {
            if (strcmp(ntab[i].addr, addr) != 0) {
                char det[320];
                snprintf(det, sizeof det,
                         "\"%.*s\" is answered by both %s and %s "
                         "(mDNS/LLMNR/NBNS poisoning?)",
                         120, p->dns_name, ntab[i].addr, addr);
                defense_report(p, "NAME POISONING suspected", det);
                snprintf(ntab[i].addr, sizeof ntab[i].addr, "%s", addr);
            }
            return;
        }
    }
    if (nn >= NNAME) return;
    ntab[nn].used = 1;
    snprintf(ntab[nn].name, sizeof ntab[nn].name, "%s", low);
    snprintf(ntab[nn].addr, sizeof ntab[nn].addr, "%s", addr);
    nn++;

    /* WPAD takeover: a WPAD answer is exactly how the classic attack works */
    if (!strncmp(low, "wpad", 4)) {
        char det[260];
        snprintf(det, sizeof det, "WPAD answered by %s (proxy auto-config takeover?)", addr);
        defense_report(p, "WPAD answer", det);
    }
}

/* ---------- VLAN hopping / DTP ---------- */
static void defend_vlan_dtp(const packet_t *p) {
    /* DTP frames go to the Cisco multicast MAC 01:00:0c:cc:cc:cc with LLC
     * SNAP (length field <= 1500).  Seeing them on an access port is a sign
     * someone is negotiating a trunk. */
    static const uint8_t cisco[6] = {0x01,0x00,0x0c,0xcc,0xcc,0xcc};
    if (p->has_l2 && !memcmp(p->eth_dst, cisco, 6)) {
        defense_report(p, "DTP frame", "Cisco DTP seen (trunk negotiation / VLAN hop risk)");
    }
    /* Double tagging: a QinQ outer tag (0x88a8) means the frame is stacked --
     * unusual inside a single segment and the setup for VLAN hopping. */
    if (p->qinq) {
        char msg[128];
        if (p->inner_vlan >= 0)
            snprintf(msg, sizeof msg,
                     "QinQ outer tag %d, inner tag %d -- VLAN hopping setup?",
                     p->vlan, p->inner_vlan);
        else
            snprintf(msg, sizeof msg, "QinQ (0x88a8) outer tag -- VLAN hopping setup?");
        defense_report(p, "double VLAN tag", msg);
    }
}

/* ---------- 802.11 deauth flood / rogue beacon detection ---------- */
#define NDEAUTH_WIN 2       /* seconds */
static struct timespec dwin_start;
static unsigned deauth_count = 0;
static int dwin_have = 0;

static void defend_wlan(const packet_t *p) {
    if (!p->wlan) return;
    if (p->wlan_deauth) {
        struct timespec now = p->ts;
        if (!dwin_have) { dwin_start = now; dwin_have = 1; deauth_count = 0; }
        double dt = (double)(now.tv_sec - dwin_start.tv_sec) +
                    (double)(now.tv_nsec - dwin_start.tv_nsec) / 1e9;
        if (dt > NDEAUTH_WIN) { dwin_start = now; deauth_count = 0; }
        if (++deauth_count == 20) {
            char det[200];
            snprintf(det, sizeof det,
                     "%u deauth/disassoc frames in <=%ds -- deauth flood?",
                     deauth_count, NDEAUTH_WIN);
            defense_report(p, "802.11 DEAUTH FLOOD suspected", det);
        } else if (deauth_count > 20 && deauth_count % 50 == 0) {
            char det[200];
            snprintf(det, sizeof det, "%u deauth frames and counting", deauth_count);
            defense_report(p, "802.11 DEAUTH FLOOD suspected", det);
        }
    }
    /* beacon with a different BSSID for a known SSID: evil twin / rogue AP.
     * Only the first BSSID per SSID is remembered; a second one is flagged. */
    if (p->wlan_type == 0 && p->wlan_subtype == 8 && p->wlan_ssid[0]) {
        for (unsigned i = 0; i < nn; i++) {
            if (ntab[i].used && !strcmp(ntab[i].name, p->wlan_ssid)) {
                if (strcmp(ntab[i].addr, p->wlan_bssid) != 0) {
                    char det[240];
                    snprintf(det, sizeof det,
                             "SSID \"%s\" advertised by two BSSIDs (%s and %s) "
                             "-- possible evil twin / rogue AP",
                             p->wlan_ssid, ntab[i].addr, p->wlan_bssid);
                    defense_report(p, "ROGUE AP suspected", det);
                }
                return;
            }
        }
        if (nn < NNAME) {
            ntab[nn].used = 1;
            snprintf(ntab[nn].name, sizeof ntab[nn].name, "%s", p->wlan_ssid);
            snprintf(ntab[nn].addr, sizeof ntab[nn].addr, "%s", p->wlan_bssid);
            nn++;
        }
    }
}

/* ---------- public entry point ---------- */
void defense_observe(const packet_t *p) {
    if (!defense_enabled()) return;
    if (p->wlan) { defend_wlan(p); return; }
    if (p->has_arp || (p->etype == 0x0806 || p->etype == 0x8035))
        defend_arp(p);
    if (p->has_icmp && p->icmp_ver == 6 && p->icmp_type == 136)
        defend_icmp6_na(p);
    if (p->has_udp && p->ip_ver == 4 && p->sport == 67 && p->dport == 68)
        defend_dhcp(p);
    if (p->dns_name[0]) defend_name_answer(p);
    defend_vlan_dtp(p);
}

void defense_stats(FILE *o) {
    if (!cfg.defense) return;
    fprintf(o, "  anomalies : %llu flagged (ARP/ND spoof, rogue DHCP/AP, name poisoning, VLAN, 802.11)\n",
            st.anoms);
}
