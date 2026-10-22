#!/usr/bin/env python3
"""Generate test frames with correct checksums for ch1m3ra's test suite."""
import struct, socket, sys

def cksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def eth(dst, src, etype, payload, vlan=None):
    f = dst + src
    f += struct.pack('!HHH', 0x8100, vlan, etype) if vlan is not None else struct.pack('!H', etype)
    return f + payload

def ipv4(src, dst, proto, payload, ttl=64, ident=0x1234, frag=0, bad_csum=False):
    tot = 20 + len(payload)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, ident, frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    c = 0x0000 if bad_csum else cksum(hdr)
    hdr = hdr[:10] + struct.pack('!H', c) + hdr[12:]
    return hdr + payload

def pseudo4(src, dst, proto, seg):
    return socket.inet_aton(src) + socket.inet_aton(dst) + bytes([0, proto]) + struct.pack('!H', len(seg))

def tcp4(src, dst, sport, dport, seq, ack, flags, win=64240, opts=b'', payload=b''):
    doff = (20 + len(opts)) // 4
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, doff << 4, flags, win, 0, 0) + opts
    seg = hdr + payload
    c = cksum(pseudo4(src, dst, 6, seg) + seg)
    return seg[:16] + struct.pack('!H', c) + seg[18:]

def udp4(src, dst, sport, dport, payload):
    ln = 8 + len(payload)
    hdr = struct.pack('!HHHH', sport, dport, ln, 0) + payload
    c = cksum(pseudo4(src, dst, 17, hdr) + hdr)
    return hdr[:6] + struct.pack('!H', c) + hdr[8:]

def icmp4(typ, code, ident, seq, data):
    body = struct.pack('!BBHHH', typ, code, 0, ident, seq) + data
    c = cksum(body)
    return body[:2] + struct.pack('!H', c) + body[4:]

def pseudo6(src, dst, proto, seg):
    return (socket.inet_pton(socket.AF_INET6, src) +
            socket.inet_pton(socket.AF_INET6, dst) +
            struct.pack('!I', len(seg)) + bytes([0, 0, 0, proto]))

def ipv6(src, dst, nxt, payload, hlim=64):
    hdr = struct.pack('!IHBB', 0x60000000, len(payload), nxt, hlim) + \
          socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
    return hdr + payload

def tcp6(src, dst, sport, dport, seq, ack, flags, payload=b''):
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    seg = hdr + payload
    c = cksum(pseudo6(src, dst, 6, seg) + seg)
    return seg[:16] + struct.pack('!H', c) + seg[18:]

frames = []
M1 = bytes.fromhex('aabbccddeeff')
M2 = bytes.fromhex('112233445566')
BC = b'\xff' * 6
LOCAL = '192.168.1.50'
DNS = '8.8.8.8'

# 1. ARP request
arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + M1 + socket.inet_aton(LOCAL) + b'\0'*6 + socket.inet_aton('192.168.1.1')
frames.append(eth(BC, M1, 0x0806, arp))

# 2. ARP reply
arp2 = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) + M2 + socket.inet_aton('192.168.1.1') + M1 + socket.inet_aton(LOCAL)
frames.append(eth(M1, M2, 0x0806, arp2))

# 3. TCP SYN with options (MSS, SACK-perm, TS, NOP, WS)
opts = b'\x02\x04\x05\xb4\x04\x02\x08\x0a' + struct.pack('!II', 111111, 0) + b'\x01\x03\x03\x07'
frames.append(eth(BC, M1, 0x0800,
    ipv4(LOCAL, DNS, 6, tcp4(LOCAL, DNS, 51344, 443, 1000, 0, 0x02, opts=opts))))

# 4. TCP PSH/ACK with HTTP payload
http = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
frames.append(eth(BC, M1, 0x0800,
    ipv4(LOCAL, DNS, 6, tcp4(LOCAL, DNS, 51344, 443, 1001, 5000, 0x18, payload=http), ident=0x1235)))

# 5. TCP ACK with BAD checksum
seg = tcp4(DNS, LOCAL, 443, 51344, 5000, 1041, 0x10)
bad = seg[:16] + struct.pack('!H', cksum(seg[:16] + b'') ^ 0xffff) + seg[18:]
frames.append(eth(M1, M2, 0x0800, ipv4(DNS, LOCAL, 6, bad, ident=0x1236)))

# 6. UDP DNS query for example.com
qname = b'\x07example\x03com\x00'
dns = struct.pack('!HHHHHH', 0x33f7, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)
frames.append(eth(BC, M1, 0x0800, ipv4(LOCAL, DNS, 17, udp4(LOCAL, DNS, 53325, 53, dns), ident=0x1237)))

# 7. ICMP echo request
frames.append(eth(BC, M1, 0x0800,
    ipv4(LOCAL, DNS, 1, icmp4(8, 0, 0x4242, 1, bytes(range(32))), ident=0x1238)))

# 8. ICMP echo reply
frames.append(eth(M1, M2, 0x0800,
    ipv4(DNS, LOCAL, 1, icmp4(0, 0, 0x4242, 1, bytes(range(32))), ident=0x1239)))

# 9. IPv6 TCP SYN with hop-by-hop ext header (kernel -F port tests can't see
#    through ext headers by design - see README; the src/dst host test can)
hbh = bytes([6, 0]) + b'\x01\x04\x00\x00\x00\x00'   # next=TCP, len=0, PadN
frames.append(eth(BC, M1, 0x86dd,
    ipv6('2001:db8::1', '2001:db8::2', 0, hbh + tcp6('2001:db8::1', '2001:db8::2', 40000, 443, 777, 0, 0x02))))

# 9b. IPv6 TCP SYN, plain (no extension header) so -F 'ip6 and tcp port N' matches
frames.append(eth(BC, M1, 0x86dd,
    ipv6('2001:db8::3', '2001:db8::4', 6, tcp6('2001:db8::3', '2001:db8::4', 40001, 8443, 888, 0, 0x02))))

# 10. ICMPv6 echo request
body = struct.pack('!BBHHH', 128, 0, 0, 0x1234, 1) + b'v6payload'
c = cksum(pseudo6('fe80::1', 'fe80::2', 58, body) + body)
icmp6 = body[:2] + struct.pack('!H', c) + body[4:]
frames.append(eth(BC, M1, 0x86dd, ipv6('fe80::1', 'fe80::2', 58, icmp6)))

# 11. VLAN-tagged UDP
frames.append(eth(BC, M1, 0x0800,
    ipv4('10.0.0.5', '10.0.0.6', 17, udp4('10.0.0.5', '10.0.0.6', 5353, 5353, b'\x00\x01')), vlan=42))

# 12. Truncated IPv4 (6 bytes after eth header)
frames.append(eth(BC, M1, 0x0800, b'\x45\x00\x00\x14\x12\x34'))

# 13. Unknown ethertype (EAPOL)
frames.append(eth(BC, M1, 0x888e, b'\x01\x00\x00\x00'))

# 14. Non-first IPv4 fragment (offset 1480 bytes, MF set) - offset lives in the IP header field:
#     13-bit offset field = offset/8, MF = bit 13
frames.append(eth(BC, M1, 0x0800,
    ipv4(LOCAL, '10.1.1.1', 6, b'fragmented-l4-data-here', ident=0x7777,
         frag=(1 << 13) | 185)))

# 15. Bad IPv4 header checksum
frames.append(eth(BC, M1, 0x0800,
    ipv4(LOCAL, DNS, 17, b'', ident=0x2222, bad_csum=True)))

# ---- app-layer frames ----

def tls_rec(ct, ver, body):
    """TLS record: content type, version, length, body"""
    return bytes([ct]) + struct.pack('!HH', ver, len(body)) + body

# 16. DNS response with one A answer (answer name compressed to offset 12)
qname = b'\x07example\x03com\x00'
q = qname + struct.pack('!HH', 1, 1)
ans = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + socket.inet_aton('93.184.216.34')
dnsr = struct.pack('!HHHHHH', 0x33f7, 0x8180, 1, 1, 0, 0) + q + ans
frames.append(eth(BC, M2, 0x0800,
    ipv4(DNS, LOCAL, 17, udp4(DNS, LOCAL, 53, 53325, dnsr), ident=0x1240)))

# 17. TLS ClientHello with SNI, ALPN and supported_versions extensions
sni = b'example.com'
sni_data = struct.pack('!H', 3 + len(sni)) + b'\x00' + struct.pack('!H', len(sni)) + sni
protos = b'\x02h2' + bytes([len(b'http/1.1')]) + b'http/1.1'
alpn_data = struct.pack('!H', len(protos)) + protos
sv_data = bytes([4]) + struct.pack('!HH', 0x0304, 0x0303)
exts = (struct.pack('!HH', 0, len(sni_data)) + sni_data +
        struct.pack('!HH', 16, len(alpn_data)) + alpn_data +
        struct.pack('!HH', 43, len(sv_data)) + sv_data)
ch = (struct.pack('!H', 0x0303) + b'\x11' * 32 + b'\x00' +
      struct.pack('!H', 4) + struct.pack('!HH', 0x1301, 0xc02f) +
      b'\x01\x00' + struct.pack('!H', len(exts)) + exts)
hello = bytes([1]) + len(ch).to_bytes(3, 'big') + ch
frames.append(eth(BC, M1, 0x0800,
    ipv4(LOCAL, DNS, 6,
         tcp4(LOCAL, DNS, 51346, 443, 7000, 8000, 0x18, payload=tls_rec(22, 0x0301, hello)),
         ident=0x1241)))

# 18. TLS application-data record (encrypted; only the record header decodes)
frames.append(eth(BC, M2, 0x0800,
    ipv4(DNS, LOCAL, 6,
         tcp4(DNS, LOCAL, 443, 51346, 8000, 7043, 0x18, payload=tls_rec(23, 0x0303, b'\xde\xad\xbe\xef' * 8)),
         ident=0x1242)))

# 19. HTTP/1.1 response
resp = b'HTTP/1.1 200 OK\r\nServer: test\r\nContent-Length: 5\r\n\r\nhello'
frames.append(eth(BC, M2, 0x0800,
    ipv4(DNS, LOCAL, 6,
         tcp4(DNS, LOCAL, 80, 51347, 5000, 6000, 0x18, payload=resp),
         ident=0x1243)))

# 20-22. TCP stream split over 3 frames, second segment deliberately
#        arrives BEFORE the segment it follows (out-of-order reassembly test)
full = b'GET /reasm HTTP/1.1\r\nHost: reasm.test\r\n\r\nBODY!!'
seg_a, seg_b = full[:25], full[25:]
frames.append(eth(BC, M1, 0x0800,                       # SYN, starts the stream
    ipv4(LOCAL, '10.2.2.2', 6, tcp4(LOCAL, '10.2.2.2', 52000, 80, 9999, 0, 0x02), ident=0x1244)))
frames.append(eth(BC, M1, 0x0800,                       # segment 2 (gap!)
    ipv4(LOCAL, '10.2.2.2', 6, tcp4(LOCAL, '10.2.2.2', 52000, 80,
         10000 + len(seg_a), 0, 0x18, payload=seg_b), ident=0x1245)))
frames.append(eth(BC, M1, 0x0800,                       # segment 1 fills the gap
    ipv4(LOCAL, '10.2.2.2', 6, tcp4(LOCAL, '10.2.2.2', 52000, 80,
         10000, 0, 0x18, payload=seg_a), ident=0x1246)))

out = sys.stdout.buffer
out.write(bytes.fromhex('d4c3b2a1'))          # magic LE usec
out.write(struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1))
for i, f in enumerate(frames):
    sec = 1700000000 + i
    usec = (i * 137) % 1000000
    out.write(struct.pack('<IIII', sec, usec, len(f), len(f)))
    out.write(f)
print(f"wrote {len(frames)} frames", file=sys.stderr)
