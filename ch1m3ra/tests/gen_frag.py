#!/usr/bin/env python3
"""Generate a pcap with fragmented IPv4 and IPv6 datagrams plus a normal
packet, used to exercise the -A fragment reassembly path.

Outputs a classic little-endian libpcap file to the path in argv[1].
"""
import struct, sys, time

LINKTYPE_ETHERNET = 1

def ether(dst, src, etype):
    return dst + src + struct.pack("!H", etype)

def ipv4(src, dst, proto, payload, ident=0, frag_off=0, mf=0, ihl=5):
    ver_ihl = (4 << 4) | ihl
    flags_frag = ((mf & 1) << 13) | ((frag_off // 8) & 0x1fff)
    total = ihl * 4 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, ident,
                      flags_frag, 64, proto, 0, src, dst)
    # checksum
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + (hdr[i + 1] if i + 1 < len(hdr) else 0)
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    csum = (~s) & 0xffff
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload

def ipv6(src, dst, nxt, payload, frag_id=None, frag_off=0, mf=0):
    if frag_id is None:
        return struct.pack("!IHBB16s16s", 6 << 28, len(payload), nxt, 64, src, dst) + payload
    # insert a fragment header
    fr = struct.pack("!BBHI", nxt, 0, ((frag_off // 8) << 3) | (mf & 1), frag_id)
    base_next = 44
    return (struct.pack("!IHBB16s16s", 6 << 28, len(fr) + len(payload), base_next,
                        64, src, dst) + fr + payload)

def udp(sport, dport, payload):
    ln = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, ln, 0) + payload

def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        t = int(time.time())
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t, i * 1000, len(fr), len(fr)))
            f.write(fr)

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/frag.pcap"
    macs = bytes.fromhex("aa0000000001") + bytes.fromhex("bb0000000002")
    frames = []

    # 1) IPv4 fragmented UDP: 3 fragments (IPv4 min MTU-ish split)
    s = bytes([192, 0, 2, 1]); d = bytes([192, 0, 2, 2])
    body = b"HELLO-FRAGMENTED-WORLD-" + bytes(range(40, 140))   # 120 bytes
    f1 = body[:48]; f2 = body[48:96]; f3 = body[96:]
    frames.append(ether(macs[:6], macs[6:], 0x0800) +
                  ipv4(s, d, 17, udp(40000, 40001, f1), ident=0x1111, frag_off=0, mf=1))
    frames.append(ether(macs[:6], macs[6:], 0x0800) +
                  ipv4(s, d, 17, f2, ident=0x1111, frag_off=48, mf=1))
    frames.append(ether(macs[:6], macs[6:], 0x0800) +
                  ipv4(s, d, 17, f3, ident=0x1111, frag_off=96, mf=0))

    # 2) IPv6 fragmented UDP: 2 fragments
    s6 = bytes.fromhex("20010db8000000000000000000000001")
    d6 = bytes.fromhex("20010db8000000000000000000000002")
    body6 = b"V6-FRAGMENTED-PAYLOAD-" + bytes(range(10, 90))    # 100 bytes
    g1 = body6[:48]; g2 = body6[48:]
    frames.append(ether(macs[:6], macs[6:], 0x86dd) +
                  ipv6(s6, d6, 17, udp(50000, 50001, g1), frag_id=0x2222, frag_off=0, mf=1))
    frames.append(ether(macs[:6], macs[6:], 0x86dd) +
                  ipv6(s6, d6, 17, g2, frag_id=0x2222, frag_off=48, mf=0))

    # 3) Normal (unfragmented) packet for contrast
    frames.append(ether(macs[:6], macs[6:], 0x0800) +
                  ipv4(s, d, 17, udp(1234, 53, b"\x00\x01normal"), ident=0x3333))

    write_pcap(path, frames)
    sys.stderr.write(f"wrote {path}: {len(frames)} frames\n")

if __name__ == "__main__":
    main()
