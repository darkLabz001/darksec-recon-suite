#!/usr/bin/env python3
"""Generate a small pcap that exercises the -K credential harvesters.

Frames (all Ethernet/IPv4/TCP, hand-built so we don't need scapy):
  1. HTTP GET with Authorization: Basic YWRtaW46c2VjcmV0   (admin:secret)
  2. HTTP POST form with username=bob&password=hunter2
  3. HTTP 200 with Set-Cookie: SID=deadbeefcafe
  4. HTTP GET with Authorization: Bearer <jwt>
  5. FTP control: "USER alice\r\n" then "PASS s3cr3t\r\n"
  6. SSH banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n"
"""
import struct, sys

MAGIC = 0xa1b2c3d4

def cksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(s):
    return bytes(int(x) for x in s.split("."))

def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))

def tcp_frame(src_ip, dst_ip, smac, dmac, sport, dport, seq, ack, flags, payload=b""):
    tcp_len = 20 + len(payload)
    ip_len = 20 + tcp_len
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack(">H", ip_len)
    ip[6] = 0x40
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = ip4(src_ip)
    ip[16:20] = ip4(dst_ip)
    ip[10:12] = struct.pack(">H", cksum(bytes(ip)))
    tcp = bytearray(tcp_len)
    tcp[0:2] = struct.pack(">H", sport)
    tcp[2:4] = struct.pack(">H", dport)
    tcp[4:8] = struct.pack(">I", seq)
    tcp[8:12] = struct.pack(">I", ack)
    tcp[12] = 0x50
    tcp[13] = flags
    tcp[14:16] = struct.pack(">H", 0xffff)
    if payload:
        tcp[20:] = payload
    pseudo = ip4(src_ip) + ip4(dst_ip) + bytes([0, 6]) + struct.pack(">H", tcp_len)
    tcp[16:18] = struct.pack(">H", cksum(pseudo + bytes(tcp)))
    eth = dmac + smac + b"\x08\x00"
    return eth + bytes(ip) + bytes(tcp)

def main():
    frames = []

    def add(payload, sport=40000, dport=80, seq=1000, flags=0x18):
        frames.append(tcp_frame("192.168.1.50", "10.0.0.9",
                                mac("aa:bb:cc:dd:ee:ff"), mac("11:22:33:44:55:66"),
                                sport, dport, seq, 1, flags, payload))

    # 1. HTTP Basic
    add(b"GET /admin HTTP/1.1\r\nHost: app.local\r\n"
        b"Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n", sport=40001)
    # 2. HTTP form POST
    add(b"POST /login HTTP/1.1\r\nHost: app.local\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"username=bob&password=hunter2&submit=1", sport=40002, seq=2000)
    # 3. Set-Cookie
    add(b"HTTP/1.1 200 OK\r\nSet-Cookie: SID=deadbeefcafe; Path=/; HttpOnly\r\n\r\n",
        sport=40003, seq=3000, flags=0x18)
    # 4. Bearer JWT (payload {"sub":"42","name":"admin"})
    jwt = ("eyJhbGciOiJIUzI1NiJ9."
           "eyJzdWIiOiI0MiIsIm5hbWUiOiJhZG1pbiJ9."
           "c2lnbmF0dXJl")
    add(b"GET /api HTTP/1.1\r\nHost: api.local\r\n"
        b"Authorization: Bearer " + jwt.encode() + b"\r\n\r\n", sport=40004, seq=4000)
    # 5. FTP USER / PASS
    add(b"USER alice\r\n", sport=41000, dport=21, seq=5000)
    add(b"PASS s3cr3t\r\n", sport=41001, dport=21, seq=6000)
    # 6. SSH banner
    add(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
        sport=41002, dport=22, seq=7000)

    out = sys.argv[1] if len(sys.argv) > 1 else "tests/creds.pcap"
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", MAGIC, 2, 4, 0, 0, 65535, 1))
        ts = 1700000000
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", ts + i, i * 1000, len(fr), len(fr)))
            f.write(fr)
    print(f"wrote {out}: {len(frames)} frames")

if __name__ == "__main__":
    main()
