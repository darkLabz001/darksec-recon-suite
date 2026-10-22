/* globals.c - shared globals (config, stats, signal, buckets, TUI hooks) */

#include "ch1m3ra.h"

cfg_t cfg = { .iface=NULL, .rfile=NULL, .wfile=NULL, .host=NULL, .proto=NULL,
          .port=-1, .count=0, .snaplen=65535, .dumpbytes=96,
          .quiet=0, .color=-1, .nopromisc=0, .follow=-1,
          .outfmt="text", .reltime=0, .bfilter=NULL, .ring=0, .tui=0,
          .harvest=0, .finger=0, .talkers=0, .names=0, .credfile=NULL,
          .evasion=0, .arp_poison=NULL, .syn_scan=NULL, .dhcp_starve=NULL,
          .replay=NULL, .rewrite_src=NULL,
          .syn_ports_a=0, .syn_ports_b=0, .active=0 };
volatile sig_atomic_t g_stop = 0;
void on_sigint(int s) { (void)s; g_stop = 1; }
stats_t st;
int bucket(const packet_t *p) {
    if (!strcmp(p->primary, "tcp"))    return 0;
    if (!strcmp(p->primary, "udp"))    return 1;
    if (!strcmp(p->primary, "icmp"))   return 2;
    if (!strcmp(p->primary, "icmpv6")) return 3;
    if (!strcmp(p->primary, "arp"))    return 4;
    if (!strcmp(p->primary, "ip"))     return 5;
    if (!strcmp(p->primary, "ipv6"))   return 6;
    return 7;
}
const char *bucket_name(int i) {
    static const char *n[8] = {"tcp","udp","icmp","icmpv6","arp","ip","ipv6","other"};
    return n[i];
}

int  tui_active;

cap_t cap;
uint32_t g_linktype;
