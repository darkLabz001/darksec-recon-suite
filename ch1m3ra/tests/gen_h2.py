#!/usr/bin/env python3
"""Generate a pcap with HTTP/2 traffic: the connection preface, followed by a
HEADERS frame carrying an HPACK-encoded request (indexed + literal-with-index
+ literal-no-index fields).  Exercises the -HTTP/2 frame + HPACK decoder.

Usage: gen_h2.py [out.pcap]
"""
import struct, sys, time

LINKTYPE_ETHERNET = 1
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def hpack_int(value, prefix, first_byte_mask):
    """Encode an HPACK integer with the given prefix length."""
    max_prefix = (1 << prefix) - 1
    if value < max_prefix:
        return bytes([first_byte_mask | value])
    out = bytearray([first_byte_mask | max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def lit_indexed(index, name, value):
    """Literal header field with incremental indexing, name from the static table."""
    out = hpack_int(index, 6, 0x40)
    vb = value.encode()
    out += hpack_int(len(vb), 7, 0x00) + vb
    return out


def lit_noindex(index, name, value):
    """Literal header field without indexing, name from the static table."""
    out = hpack_int(index, 4, 0x00)
    vb = value.encode()
    out += hpack_int(len(vb), 7, 0x00) + vb
    return out


def indexed(index):
    return hpack_int(index, 7, 0x80)


def h2_frame(ftype, flags, stream, payload):
    return (struct.pack("!I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack("!I", stream) + payload)


def headers_block(stream, payload, flags=0x04):     # END_HEADERS
    return h2_frame(0x1, flags, stream, payload)


def tcp(sport, dport, payload, seq=1):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 5 << 4, 0x18, 65535, 0, 0)
    return hdr + payload


def ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x6666, 0, 64, proto, 0, src, dst)
    s = 0
    for i in range(0, 20, 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    hdr = hdr[:10] + struct.pack("!H", (~s) & 0xffff) + hdr[12:]
    return hdr + payload


def ether(etype):
    return bytes.fromhex("aa0000000001") + bytes.fromhex("bb0000000002") + struct.pack("!H", etype)


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        t = int(time.time())
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t, i * 1000, len(fr), len(fr)))
            f.write(fr)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/h2.pcap"
    src = bytes([192, 0, 2, 50])
    dst = bytes([192, 0, 2, 60])

    # HPACK request: :method GET (idx 2), :scheme https (idx 7), :path /api/v1
    # (literal w/ idx 4), :authority h2.example.test (literal w/ idx 1),
    # user-agent (literal no-index, idx 58 / static name)
    block = indexed(2) + indexed(7)
    block += lit_indexed(4, ":path", "/api/v1/items")
    block += lit_indexed(1, ":authority", "h2.example.test")
    block += lit_noindex(58, "user-agent", "curl/8.0")

    frames = [
        ether(0x0800) + ipv4(src, dst, 6, tcp(40000, 443, PREFACE, seq=1)),
        ether(0x0800) + ipv4(src, dst, 6, tcp(40000, 443, headers_block(1, block), seq=25)),
    ]
    write_pcap(path, frames)
    sys.stderr.write(f"wrote {path}: {len(frames)} frames\n")


if __name__ == "__main__":
    main()
