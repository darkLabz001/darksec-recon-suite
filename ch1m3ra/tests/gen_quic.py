#!/usr/bin/env python3
"""Generate a pcap with a QUIC v1 Initial packet carrying a TLS ClientHello
(so the -QUIC decoder's SNI extraction can be exercised).  Also emits a QUIC
version-negotiation packet.  No external deps.

Usage: gen_quic.py [out.pcap]
"""
import struct, sys

LINKTYPE_ETHERNET = 1
QUIC_V1 = 0x00000001

def varint(v):
    if v < 0x40: return bytes([v])
    if v < 0x4000: return struct.pack("!H", 0x4000 | v)
    if v < 0x40000000: return struct.pack("!I", 0x80000000 | v)
    return struct.pack("!Q", 0xc000000000000000 | v)

def tls_client_hello(sni):
    def ext(t, body): return struct.pack("!HH", t, len(body)) + body
    server_name = struct.pack("!H", 3 + len(sni)) + b"\x00" + struct.pack("!H", len(sni)) + sni.encode()
    exts = ext(0x0000, server_name) + ext(0x0010, b"\x02h2")
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00"          # version, random, no session id
            + struct.pack("!H", 2) + b"\x13\x01"          # one cipher
            + b"\x01\x00"                                  # compression
            + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + struct.pack("!I", len(body))[1:] + body

def quic_initial(dcid, scid, payload):
    first = 0xc0 | 0x00                                    # long header, Initial
    hdr = bytes([first]) + struct.pack("!I", QUIC_V1)
    hdr += bytes([len(dcid)]) + dcid
    hdr += bytes([len(scid)]) + scid
    hdr += varint(0)                                       # token length 0
    # crypto frame: type 0x06, offset 0, length, ClientHello
    ch = tls_client_hello("quic.example.test")
    frame = b"\x06" + varint(0) + varint(len(ch)) + ch
    # pad so total length field matches
    body = frame + b"\x00" * 20
    pn = b"\x00\x00\x00\x01"                               # 4-byte packet number
    length = len(pn) + len(body)
    return hdr + varint(length) + pn + body

def quic_version_neg(dcid, scid, versions):
    first = 0xc0
    hdr = bytes([first]) + struct.pack("!I", 0)            # version 0
    hdr += bytes([len(dcid)]) + dcid
    hdr += bytes([len(scid)]) + scid
    return hdr + b"".join(struct.pack("!I", v) for v in versions)

def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

def ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x5555, 0, 64, proto, 0, src, dst)
    s = 0
    for i in range(0, 20, 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    c = (~s) & 0xffff
    hdr = hdr[:10] + struct.pack("!H", c) + hdr[12:]
    return hdr + payload

def ether(etype):
    return bytes.fromhex("aa0000000001") + bytes.fromhex("bb0000000002") + struct.pack("!H", etype)

def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        t = 1700000000  # fixed epoch, like the other generators
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t, i * 1000, len(fr), len(fr)))
            f.write(fr)

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/quic.pcap"
    src = bytes([192, 0, 2, 30]); dst = bytes([192, 0, 2, 40])
    dcid = bytes.fromhex("8394c8f03e515708")
    scid = bytes.fromhex("a1b2c3d4")

    frames = [
        ether(0x0800) + ipv4(src, dst, 17, udp(55555, 443, quic_initial(dcid, scid, b""))),
        ether(0x0800) + ipv4(dst, src, 17, udp(443, 55555, quic_version_neg(dcid, scid, [QUIC_V1]))),
    ]
    write_pcap(path, frames)
    sys.stderr.write(f"wrote {path}: {len(frames)} frames\n")

if __name__ == "__main__":
    main()
