#!/usr/bin/env python3
"""Generate a pcap that deterministically exercises the flow metrics:

  * a clean handshake + data/ACK so an RTT can be measured
  * a retransmitted segment (same seq sent twice)
  * an out-of-order segment (a gap then the missing piece)
  * a zero-window advertisement
  * two UDP flows (so udp flow tracking has something to show)

Usage: gen_metrics.py [out.pcap]
"""
import struct, sys, time

LINKTYPE_ETHERNET = 1


def tcp(sport, dport, seq, ack, flags, win=64240, payload=b""):
    off_flags = (5 << 12) | flags
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, win, 0, 0)
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ipv4(src, dst, proto, payload, ident=1):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0, 64, proto, 0, src, dst)
    s = 0
    for i in range(0, 20, 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    hdr = hdr[:10] + struct.pack("!H", (~s) & 0xffff) + hdr[12:]
    return hdr + payload


def ether(etype):
    return bytes.fromhex("aa0000000001") + bytes.fromhex("bb0000000002") + struct.pack("!H", etype)


def write_pcap(path, frames, times):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for fr, (sec, usec) in zip(frames, times):
            f.write(struct.pack("<IIII", sec, usec, len(fr), len(fr)))
            f.write(fr)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/metrics.pcap"
    C = bytes([192, 0, 2, 10])     # client
    S = bytes([192, 0, 2, 20])     # server
    CP, SP = 40000, 80
    # fixed base time for reproducible RTT
    base = 1700001000
    frames, times = [], []

    def add(payload, proto, src, dst, ts_us, ident):
        frames.append(ether(0x0800) + ipv4(src, dst, proto, payload, ident))
        times.append((base + ts_us // 1000000, ts_us % 1000000))

    # --- TCP: handshake ---
    add(tcp(CP, SP, 1000, 0, 0x02), 6, C, S, 0, 1)              # SYN
    add(tcp(SP, CP, 5000, 1001, 0x12), 6, S, C, 500, 2)         # SYN/ACK
    add(tcp(CP, SP, 1001, 5001, 0x10), 6, C, S, 1000, 3)        # ACK

    # data segment from client (seq 1001, 20 bytes), then ACK 200us later
    add(tcp(CP, SP, 1001, 5001, 0x18, payload=b"A" * 20), 6, C, S, 1500, 4)
    add(tcp(SP, CP, 5001, 1021, 0x10), 6, S, C, 1700, 5)        # ACK -> RTT ~0.2ms

    # --- retransmit: client resends seq 1001 (same bytes) ---
    add(tcp(CP, SP, 1001, 5001, 0x18, payload=b"A" * 20), 6, C, S, 5000, 6)
    add(tcp(SP, CP, 5001, 1021, 0x10), 6, S, C, 5200, 7)

    # --- out-of-order: client sends seq 1061 first, then the missing 1021..1060 ---
    add(tcp(CP, SP, 1061, 5001, 0x18, payload=b"B" * 20), 6, C, S, 6000, 8)
    add(tcp(CP, SP, 1021, 5001, 0x18, payload=b"C" * 40), 6, C, S, 6200, 9)
    add(tcp(SP, CP, 5001, 1081, 0x10), 6, S, C, 6400, 10)

    # --- zero window: server advertises win=0 ---
    add(tcp(SP, CP, 5001, 1081, 0x10, win=0), 6, S, C, 7000, 11)
    add(tcp(CP, SP, 1081, 5001, 0x10), 6, C, S, 7200, 12)

    # --- FIN teardown ---
    add(tcp(CP, SP, 1081, 5001, 0x11), 6, C, S, 8000, 13)
    add(tcp(SP, CP, 5001, 1082, 0x11), 6, S, C, 8300, 14)
    add(tcp(CP, SP, 1082, 5002, 0x10), 6, C, S, 8600, 15)

    # --- UDP flows ---
    add(udp(53000, 53, b"\x00\x01" + b"\x00" * 20), 17, C, S, 9000, 16)
    add(udp(53, 53000, b"\x00\x01" + b"\x00" * 40), 17, S, C, 9200, 17)
    add(udp(53001, 123, b"\x1b" + b"\x00" * 47), 17, C, S, 9500, 18)

    write_pcap(path, frames, times)
    sys.stderr.write(f"wrote {path}: {len(frames)} frames\n")


if __name__ == "__main__":
    main()
