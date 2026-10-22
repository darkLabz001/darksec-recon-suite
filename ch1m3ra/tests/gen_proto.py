#!/usr/bin/env python3
"""Generate a pcap exercising the SMB2 / RDP / LDAP / Kerberos decoders:

  * SMB2 SESSION_SETUP carrying an NTLMSSP AUTHENTICATE with domain/user
  * RDP connection request with a "Cookie: mstshash=" username
  * LDAP bindRequest with a cleartext DN
  * Kerberos AS-REQ with a cleartext realm

Usage: gen_proto.py [out.pcap]
"""
import struct, sys, time

LINKTYPE_ETHERNET = 1


def tcp(sport, dport, payload, seq=1):
    off_flags = (5 << 12) | 0x018
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, 1, off_flags, 64240, 0, 0)
    return hdr + payload


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


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        t = int(time.time())
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t, i * 1000, len(fr), len(fr)))
            f.write(fr)


def smb2_session_setup(domain, user):
    """Build a minimal SMB2 header + SESSION_SETUP with an NTLMSSP type-3 token."""
    hdr = bytearray(b"\xfeSMB")
    hdr += struct.pack("<H", 64)            # StructureSize
    hdr += struct.pack("<H", 0)             # CreditCharge
    hdr += struct.pack("<I", 0)             # Status
    hdr += struct.pack("<H", 0x0001)        # Command = SESSION_SETUP
    hdr += struct.pack("<H", 0)             # CreditRequest
    hdr += struct.pack("<I", 0)             # Flags
    hdr += struct.pack("<I", 0)             # NextCommand
    hdr += struct.pack("<Q", 1)             # MessageId
    hdr += struct.pack("<I", 0)             # Reserved
    hdr += struct.pack("<I", 0)             # TreeId
    hdr += struct.pack("<Q", 0)             # SessionId
    hdr += b"\x00" * 16                     # Signature
    assert len(hdr) == 64

    # NTLMSSP AUTHENTICATE (type 3): fixed header is 64 bytes for the message
    # plus security buffers.  Layout: offset 28=domain len, 32=domain off,
    # 36=user len, 40=user off.
    dom = domain.encode("utf-16-le")
    usr = user.encode("utf-16-le")
    payload_off = 64
    dom_off = payload_off
    usr_off = dom_off + len(dom)
    nt = b"\x00" * 24
    nt_off = usr_off + len(usr)
    tm = b"\x00" * 24
    tm_off = nt_off + len(nt)
    ws = b"\x00" * 16
    ws_off = tm_off + len(tm)

    tok = bytearray(b"NTLMSSP\x00")
    tok += struct.pack("<I", 3)             # message type
    # security buffers, in protocol order:
    tok += struct.pack("<HHI", len(nt), len(nt), nt_off)      # LM response  @12
    tok += struct.pack("<HHI", len(nt), len(nt), nt_off)      # NT response  @20
    tok += struct.pack("<HHI", len(dom), len(dom), dom_off)   # domain       @28
    tok += struct.pack("<HHI", len(usr), len(usr), usr_off)   # user         @36
    tok += struct.pack("<HHI", len(ws), len(ws), ws_off)      # workstation  @44
    tok += struct.pack("<HHI", 0, 0, 0)                       # session key  @52
    tok += struct.pack("<I", 0)             # flags @60
    # fixed part is 64 bytes; pad to that, then append the security buffers
    while len(tok) < payload_off:
        tok += b"\x00"
    tok += dom + usr + nt + tm + ws
    return bytes(hdr) + bytes(tok)


def rdp_conn_request(user):
    cookie = ("Cookie: mstshash=%s\r\n" % user).encode()
    # X.224 Connection Request: LI(1)=len, type=0xE0
    x224 = bytes([len(cookie) + 6 + 2]) + bytes([0xE0]) + b"\x00\x00\x00\x01\x00"
    body = x224 + cookie
    tpkt = bytes([0x03, 0x00]) + struct.pack("!H", len(body) + 4) + body
    return tpkt


def ldap_bind(dn):
    def ber_len(n):
        if n < 0x80:
            return bytes([n])
        out = b""
        while n:
            out = bytes([n & 0xff]) + out
            n >>= 8
        return bytes([0x80 | len(out)]) + out

    def tlv(tag, value):
        return bytes([tag]) + ber_len(len(value)) + value

    bind_body = tlv(0x02, b"\x03") + tlv(0x04, dn.encode()) + tlv(0x80, b"secret")
    bind_op = tlv(0x60, bind_body)
    msg = tlv(0x02, b"\x01") + bind_op
    return tlv(0x30, msg)


def kerberos_asreq(realm):
    def ber_len(n):
        if n < 0x80:
            return bytes([n])
        out = b""
        while n:
            out = bytes([n & 0xff]) + out
            n >>= 8
        return bytes([0x80 | len(out)]) + out

    def tlv(tag, value):
        return bytes([tag]) + ber_len(len(value)) + value

    # minimal AS-REQ: SEQUENCE { pvno, msg-type, padata, req-body }
    # req-body contains the realm (GeneralString) which is what we want to see
    realm_tlv = tlv(0x1b, realm.encode())     # GeneralString
    req_body = tlv(0x30, tlv(0xa1, tlv(0x1b, b"\x00\x00")) + realm_tlv)
    asreq = tlv(0x6a, tlv(0x02, b"\x05") + tlv(0x02, b"\x0a") + req_body)
    return asreq


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/proto.pcap"
    src = bytes([192, 0, 2, 70])
    dst = bytes([192, 0, 2, 80])

    frames = [
        ether(0x0800) + ipv4(src, dst, 6, tcp(49001, 445, smb2_session_setup("CORP", "alice")), 1),
        ether(0x0800) + ipv4(src, dst, 6, tcp(49002, 3389, rdp_conn_request("bob")), 2),
        ether(0x0800) + ipv4(src, dst, 6, tcp(49003, 389, ldap_bind("cn=carol,dc=example,dc=test")), 3),
        ether(0x0800) + ipv4(src, dst, 6, tcp(49004, 88, kerberos_asreq("EXAMPLE.TEST")), 4),
    ]
    write_pcap(path, frames)
    sys.stderr.write(f"wrote {path}: {len(frames)} frames\n")


if __name__ == "__main__":
    main()
