#!/usr/bin/env python3
"""Generate tests/defense.pcap - frames that trigger each -D detector.

Included: two ARP bindings for the same IP (spoof), a MAC claiming many IPs,
an ICMPv6 NA that changes MAC, two DHCP servers, an mDNS name answered by two
different hosts, a WPAD answer, a Cisco DTP frame, and a QinQ double tag.
"""
import struct, sys, time

def eth(dst, src, etype):
    return dst + src + struct.pack("!H", etype)

def ipv4(src, dst, proto, payload, ttl=64):
    ihl_ver = 0x45
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", ihl_ver, 0, total, 0x1234, 0, ttl, proto, 0,
                      bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return hdr + payload

def csum(data):
    if len(data) % 2: data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp(src, dst, sport, dport, payload):
    pseudo = bytes(map(int, src.split("."))) + bytes(map(int, dst.split("."))) + \
             struct.pack("!BBH", 0, 17, len(payload) + 8)
    uh = struct.pack("!HHHH", sport, dport, len(payload) + 8, 0)
    c = csum(pseudo + uh + payload)
    return struct.pack("!HHHH", sport, dport, len(payload) + 8, c) + payload

def arp(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sha + \
           bytes(map(int, spa.split("."))) + tha + bytes(map(int, tpa.split(".")))

def icmp6_na(src_addr, src_mac, tgt_addr):
    # IPv6 + ICMPv6 Neighbor Advertisement (type 136)
    def v6(a):
        out = b""
        # very small textual->binary helper for our fixed addresses
        import socket
        return socket.inet_pton(socket.AF_INET6, a)
    payload = struct.pack("!BBHII", 136, 0, 0, 0x60000000, v6(tgt_addr) and 0)
    payload = struct.pack("!BBH", 136, 0, 0) + struct.pack("!I", 0x60000000) + v6(tgt_addr)
    return payload

def dns_response(qname, ans_ip):
    tid = 0x1234
    hdr = struct.pack("!HHHHHH", tid, 0x8400, 1, 1, 0, 0)
    q = b""
    for lbl in qname.split("."):
        q += bytes([len(lbl)]) + lbl.encode()
    q += b"\0" + struct.pack("!HH", 1, 1)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(map(int, ans_ip.split(".")))
    return hdr + q + ans

frames = []

# 1. ARP spoof: same IP 10.0.0.1 from two MACs
frames.append(eth(b"\xff"*6, bytes.fromhex("aabbcc000001"), 0x0806) +
              arp(1, bytes.fromhex("aabbcc000001"), "10.0.0.1", b"\0"*6, "10.0.0.2"))
frames.append(eth(b"\xff"*6, bytes.fromhex("deadbeef0001"), 0x0806) +
              arp(2, bytes.fromhex("deadbeef0001"), "10.0.0.1", bytes.fromhex("aabbcc000001"), "10.0.0.2"))

# 2. ARP over-claim: one MAC claims 14 distinct IPs
evil = bytes.fromhex("001122334455")
for i in range(14):
    frames.append(eth(b"\xff"*6, evil, 0x0806) +
                  arp(1, evil, "10.0.1.%d" % (i + 1), b"\0"*6, "10.0.1.1"))

# 3. IPv6 NA spoof: 2001:db8::1 advertised from two MACs
import socket
na_payload = struct.pack("!BBH", 136, 0, 0) + struct.pack("!I", 0x60000000) + \
             socket.inet_pton(socket.AF_INET6, "2001:db8::1")
ip6a = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
ip6ff = socket.inet_pton(socket.AF_INET6, "ff02::1")
def ipv6(src, dst, payload, nh=58):
    return struct.pack("!IHBB", 0x60000000, len(payload), nh, 255) + src + dst + payload
for mac in (bytes.fromhex("aabbcc000010"), bytes.fromhex("aabbcc000099")):
    frames.append(eth(b"\x33\x33\x00\x00\x00\x01", mac, 0x86dd) +
                  ipv6(ip6a, ip6ff, na_payload))

# 4. Two DHCP servers offering to the same client
def dhcp_offer(srv):
    # minimal BOOTP + magic cookie; ch1m3ra keys on src/dst ports + IPv4 src
    bootp = struct.pack("!BBBBIHH", 2, 1, 6, 0, 0x3903F326, 0, 0) + b"\0"*202
    return bootp + b"\x63\x82\x53\x63\x35\x02\x02\xff"
for srv in ("10.0.0.254", "192.168.99.99"):
    frames.append(eth(bytes.fromhex("aabbcc0000ff"), bytes.fromhex("aabbcc00abcd"), 0x0800) +
                  ipv4(srv, "255.255.255.255", 17, udp(srv, "255.255.255.255", 67, 68, dhcp_offer(srv))))

# 5. mDNS name poisoning: printer.local answered by two hosts, plus WPAD
def mdns(ans_ip, src_ip, src_mac):
    return eth(b"\x01\x00\x5e\x00\x00\xfb", src_mac, 0x0800) + \
           ipv4(src_ip, "224.0.0.251", 17, udp(src_ip, "224.0.0.251", 5353, 5353,
                dns_response("printer.local", ans_ip)))
frames.append(mdns("10.0.0.10", "10.0.0.10", bytes.fromhex("aabbcc000010")))
frames.append(mdns("10.0.0.66", "10.0.0.66", bytes.fromhex("aabbcc000066")))
frames.append(eth(b"\x01\x00\x5e\x00\x00\xfb", bytes.fromhex("aabbcc000042"), 0x0800) +
              ipv4("10.0.0.42", "224.0.0.251", 17, udp("10.0.0.42", "224.0.0.251", 5353, 5353,
                   dns_response("wpad.local", "10.0.0.42"))))

# 6. Cisco DTP frame (dst 01:00:0c:cc:cc:cc, LLC/SNAP length frame)
frames.append(eth(bytes.fromhex("01000ccccccc"), bytes.fromhex("aabbcc000010"), 0x00ff) +
              b"\xaa\xaa\x03\x00\x00\x0c\x20\x04" + b"\x00"*20)

# 7. QinQ double tag (outer 0x88a8)
frames.append(eth(b"\xff"*6, bytes.fromhex("aabbcc000010"), 0x88a8) +
              struct.pack("!H", 100) + struct.pack("!H", 0x8100) + struct.pack("!H", 200) +
              struct.pack("!H", 0x0800) + ipv4("10.0.0.1", "10.0.0.2", 1, b"\x08\x00\x00\x00") )

# write pcap
out = sys.argv[1] if len(sys.argv) > 1 else "tests/defense.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    t = 1700000000
    for i, fr in enumerate(frames):
        f.write(struct.pack("<IIII", t + i, 0, len(fr), len(fr)))
        f.write(fr)
print("wrote %s (%d frames)" % (out, len(frames)))
