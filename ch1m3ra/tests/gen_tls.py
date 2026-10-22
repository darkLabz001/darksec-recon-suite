#!/usr/bin/env python3
"""Generate a pcap containing a TLS 1.2 Certificate handshake message with a
throwaway self-signed X.509 certificate, to exercise certificate extraction.

A minimal DER certificate is built by hand (no cryptography dependency) with a
known subject/issuer CN and a subjectAltName dNSName.

Usage: gen_tls.py [out.pcap]
"""
import struct, sys, time

LINKTYPE_ETHERNET = 1

def der(tag, body):
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    l = len(body)
    lb = b""
    while l:
        lb = bytes([l & 0xff]) + lb
        l >>= 8
    return bytes([tag, 0x80 | len(lb)]) + lb + body

def seq(*parts):  return der(0x30, b"".join(parts))
def set_(*parts): return der(0x31, b"".join(parts))
def oid(enc):     return der(0x06, enc)
def utf8(s):      return der(0x0c, s.encode())
def printable(s): return der(0x13, s.encode())
def ia5(s):       return der(0x16, s.encode())
def integer(v):   return der(0x02, v)
def utctime(s):   return der(0x17, s.encode())
def bitstring(b): return der(0x03, b"\x00" + b)
def null():       return b"\x05\x00"
def octet(b):     return der(0x04, b)
def ctx(tagnum, body, constructed=True):
    t = 0xa0 | tagnum if constructed else 0x80 | tagnum
    return der(t, body)

OID_CN = oid(bytes([0x55, 0x04, 0x03]))
OID_SAN = oid(bytes([0x55, 0x1d, 0x11]))
OID_RSA = oid(bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]))
OID_SHA256RSA = oid(bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]))

def rdn(oidv, s): return set_(seq(oidv, s))

def make_cert():
    version = ctx(0, integer(b"\x02"))              # v3
    serial = integer(b"\x01\x02\x03\x04")
    sigalg = seq(OID_SHA256RSA, null())
    issuer = seq(rdn(OID_CN, printable("Test Issuer CA")))
    validity = seq(utctime("240101000000Z"), utctime("340101000000Z"))
    subject = seq(rdn(OID_CN, printable("www.example.test")))
    spki = seq(seq(OID_RSA, null()), bitstring(b"\x00" * 64))
    san = ctx(3, seq(seq(OID_SAN, octet(seq(
        der(0x82, b"www.example.test"),
        der(0x82, b"api.example.test"),
    )))))
    tbs = seq(version, serial, sigalg, issuer, validity, subject, spki, san)
    cert = seq(tbs, sigalg, bitstring(b"\x00" * 64))
    return cert

def client_hello(server_name="ja3.example.test",
                 ciphers=(0x1301, 0xc02b, 0xc02f),
                 groups=(0x001d, 0x0017, 0x0018),
                 point_formats=(0,),
                 versions=(0x0304, 0x0303),
                 ech=False):
    def ext(t, body): return struct.pack("!HH", t, len(body)) + body
    sni = struct.pack("!H", 3 + len(server_name)) + b"\x00" + struct.pack("!H", len(server_name)) + server_name.encode()
    exts = b""
    exts += ext(0x0000, sni)
    exts += ext(0x000a, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", g) for g in groups))
    exts += ext(0x000b, bytes([len(point_formats)]) + bytes(point_formats))
    exts += ext(0x002b, bytes([2 * len(versions)]) + b"".join(struct.pack("!H", v) for v in versions))
    exts += ext(0x0010, struct.pack("!H", 3) + b"\x02h2")
    if ech:
        exts += ext(0xfe0d, b"\x00" * 8)
    body = (b"\x03\x03" + b"\x22" * 32 + b"\x00"
            + struct.pack("!H", 2 * len(ciphers)) + b"".join(struct.pack("!H", c) for c in ciphers)
            + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + struct.pack("!I", len(body))[1:] + body

def ja3_of(ch):
    """Compute the JA3 string + md5 the same way the C code does, for tests."""
    import hashlib
    d = ch[4:]
    legacy = struct.unpack("!H", d[0:2])[0]
    pos = 2 + 32
    pos += 1 + d[pos]
    ncs = struct.unpack("!H", d[pos:pos+2])[0]; pos += 2
    ciphers = [struct.unpack("!H", d[pos+i:pos+i+2])[0] for i in range(0, ncs, 2)]
    pos += ncs
    ncomp = d[pos]; pos += 1 + ncomp
    extlen = struct.unpack("!H", d[pos:pos+2])[0]; pos += 2
    nend = pos + extlen
    exts, curves, fmts = [], [], []
    q = pos
    while q + 4 <= nend:
        et, el = struct.unpack("!HH", d[q:q+4]); q += 4
        exts.append(et)
        if et == 10:
            g = 2
            while g + 1 < el:
                curves.append(struct.unpack("!H", d[q+g:q+g+2])[0]); g += 2
        elif et == 11:
            g = 1
            while g < el:
                fmts.append(d[q+g]); g += 1
        q += el
    s = "%d,%s,%s,%s,%s" % (legacy,
                            "-".join(str(x) for x in ciphers),
                            "-".join(str(x) for x in exts),
                            "-".join(str(x) for x in curves),
                            "-".join(str(x) for x in fmts))
    return s, hashlib.md5(s.encode()).hexdigest()

def ja4_of(ch, sni_present=True):
    """Compute the JA4 string the same way the C code does (FoxIO spec)."""
    import hashlib
    d = ch[4:]
    legacy = struct.unpack("!H", d[0:2])[0]
    pos = 2 + 32
    pos += 1 + d[pos]
    ncs = struct.unpack("!H", d[pos:pos+2])[0]; pos += 2
    ciphers = [struct.unpack("!H", d[pos+i:pos+i+2])[0] for i in range(0, ncs, 2)]
    pos += ncs
    ncomp = d[pos]; pos += 1 + ncomp
    extlen = struct.unpack("!H", d[pos:pos+2])[0]; pos += 2
    nend = pos + extlen
    exts, sigs, alpn = [], [], ""
    tls13 = False
    q = pos
    while q + 4 <= nend:
        et, el = struct.unpack("!HH", d[q:q+4]); q += 4
        exts.append(et)
        if et == 16 and el >= 3:
            pl = d[q+2]
            take = min(pl, 2)
            alpn = d[q+3:q+3+take].decode("latin1")
        elif et == 13 and el >= 2:
            g = 2
            while g + 1 < el:
                sigs.append(struct.unpack("!H", d[q+g:q+g+2])[0]); g += 2
        elif et == 43 and el >= 3:      # supported_versions
            g = 1
            while g + 1 < el:
                if struct.unpack("!H", d[q+g:q+g+2])[0] == 0x0304:
                    tls13 = True
                g += 2
        q += el
    grease = lambda v: (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)
    ciphers = sorted(c for c in ciphers if not grease(c))
    exts = sorted(e for e in exts if not grease(e))
    cs = ",".join("%04x" % c for c in ciphers)
    es = ",".join(["%04x" % e for e in exts] + ["%04x" % s for s in sigs])
    chash = hashlib.md5(cs.encode()).hexdigest()[:12]
    ehash = hashlib.md5(es.encode()).hexdigest()[:12]
    ver = "13" if (legacy == 0x0304 or tls13) else {0x0303:"12",0x0302:"11",0x0301:"10",0x0300:"s3"}.get(legacy, "00")
    return "t%s%s%02d%02d%s_%s_%s" % (ver, "d" if sni_present else "i",
                                      len(ciphers), len(exts), alpn or "00", chash, ehash)

def tls_record(ctype, payload):
    return bytes([ctype, 0x03, 0x03]) + struct.pack("!H", len(payload)) + payload

def handshake(htype, body):
    return bytes([htype]) + struct.pack("!I", len(body))[1:] + body

def tcp(sport, dport, payload, seq=1):
    off_flags = (5 << 12) | 0x018            # data offset 5, PSH+ACK
    return struct.pack("!HHIIHHHH", sport, dport, seq, 1, off_flags, 65535, 0, 0) + payload

def ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x4444, 0, 64, proto, 0, src, dst)
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
        t = int(time.time())
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t, i * 1000, len(fr), len(fr)))
            f.write(fr)

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/tls.pcap"
    src = bytes([192, 0, 2, 10]); dst = bytes([192, 0, 2, 20])

    cert = make_cert()
    # certificate_list: 3-byte total length, then each cert with 3-byte length
    certlist = struct.pack("!I", len(cert))[1:] + struct.pack("!I", len(cert))[1:] + cert
    hs = handshake(11, certlist)
    rec = tls_record(22, hs)

    frames = [ether(0x0800) + ipv4(src, dst, 6, tcp(44444, 443, rec))]

    # a TLS 1.3 ClientHello so JA3 + SNI + ECH can be exercised
    ch = client_hello(server_name="ja3.example.test", ech=True)
    ja3s, ja3h = ja3_of(ch)
    rec2 = tls_record(22, ch)          # client_hello() already includes the handshake header
    frames.append(ether(0x0800) + ipv4(dst, src, 6, tcp(443, 44444, rec2, seq=2)))

    # DNS-over-HTTPS: POST /dns-query with an application/dns-message body
    doh = (b"POST /dns-query HTTP/1.1\r\nHost: doh.example.test\r\n"
           b"Content-Type: application/dns-message\r\nContent-Length: 12\r\n\r\n"
           b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    frames.append(ether(0x0800) + ipv4(src, dst, 6, tcp(34567, 443, doh, seq=3)))

    # DNS-over-TLS: a TLS record on port 853
    frames.append(ether(0x0800) + ipv4(src, dst, 6, tcp(45678, 853,
                  tls_record(22, client_hello(server_name="dot.example.test")), seq=4)))

    write_pcap(path, frames)
    sys.stderr.write(f"wrote {path}: cert {len(cert)} bytes, record {len(rec)} bytes, "
                     f"ja3={ja3h} ja4={ja4_of(ch)}\n")
    print(ja3h)          # line 1: expected JA3 for the shell test suite
    print(ja4_of(ch))    # line 2: expected JA4
if __name__ == "__main__":
    main()
