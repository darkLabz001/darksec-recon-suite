#!/usr/bin/env python3
"""Generate tests/wlan.pcap - radiotap + 802.11 frames (DLT 127).

Beacons for two BSSIDs on the same SSID (evil twin), a probe request/response,
and a burst of deauthentication frames (deauth flood).  Parsed with -D and the
802.11 decoder; no monitor-mode hardware needed because this is an offline pcap.
"""
import struct, sys

# --- a minimal radiotap header: present=CHANNEL, one 4-byte channel field ---
def radiotap(chan_freq):
    present = (1 << 3)          # only CHANNEL present
    fields = struct.pack("<HH", chan_freq, 0)   # channel freq + flags
    hdrlen = 8 + len(fields)
    return struct.pack("<BBHI", 0, 0, hdrlen, present) + fields

def radiotap2(chan_freq):
    """Like a real adapter: two present words (ext bit set on the first), with
    FLAGS + RATE + CHANNEL + dBm signal, so the multi-word walker is exercised."""
    word0 = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 31)  # flags,rate,chan,dbm_antsig,ext
    word1 = 0                                                     # no further fields
    fields = struct.pack("<BBHHb", 0x00, 2, chan_freq, 0, -50)    # flags,rate,chan(+flags),dbm
    hdrlen = 4 + 4 + 4 + len(fields)   # ver+pad+len, word0, word1, fields
    return struct.pack("<BBHII", 0, 0, hdrlen, word0, word1) + fields

def cts(ra, chan_freq=2412):
    """802.11 control CTS: FC + duration + RA only (10-byte header)."""
    fc = 0x00c4   # type 1 (control), subtype 12 (CTS)
    hdr = struct.pack("<HH", fc, 0) + mac(ra)
    return radiotap2(chan_freq) + hdr

def ack(ra, chan_freq=2412):
    """802.11 control ACK: FC + duration + RA only (10-byte header)."""
    fc = 0x00d4   # type 1 (control), subtype 13 (ACK)
    hdr = struct.pack("<HH", fc, 0) + mac(ra)
    return radiotap2(chan_freq) + hdr

def mac(s):
    return bytes.fromhex(s.replace(":", ""))

def beacon(bssid, ssid, chan_freq=2412):
    # FC: version 0, type mgmt (0), subtype beacon (8) -> 0x0080
    fc = 0x0080
    dur = 0
    hdr = struct.pack("<HH", fc, dur) + b"\xff"*6 + mac(bssid) + mac(bssid) + \
          struct.pack("<H", 0)          # seq
    fixed = struct.pack("<QHH", 0, 100, 0x0011)   # timestamp, interval, cap (privacy)
    ssid_ie = bytes([0, len(ssid)]) + ssid.encode()
    return radiotap(chan_freq) + hdr + fixed + ssid_ie

def deauth(src, dst, bssid):
    fc = 0x00c0   # mgmt, subtype 12 (deauth)
    hdr = struct.pack("<HH", fc, 0) + mac(dst) + mac(src) + mac(bssid) + struct.pack("<H", 0)
    return radiotap(2412) + hdr + struct.pack("<H", 7)   # reason: class3 frame from nonassoc

def probe_req(src, ssid):
    fc = 0x0040   # mgmt, subtype 4 (probe request)
    hdr = struct.pack("<HH", fc, 0) + b"\xff"*6 + mac(src) + b"\xff"*6 + struct.pack("<H", 0)
    return radiotap(2412) + hdr + bytes([0, len(ssid)]) + ssid.encode()

def probe_resp(bssid, ssid, dst):
    fc = 0x0050   # mgmt, subtype 5 (probe response)
    hdr = struct.pack("<HH", fc, 0) + mac(dst) + mac(bssid) + mac(bssid) + struct.pack("<H", 0)
    fixed = struct.pack("<QHH", 0, 100, 0x0011)
    return radiotap(2412) + hdr + fixed + bytes([0, len(ssid)]) + ssid.encode()

frames = []
# one legit AP
frames.append(beacon("aa:bb:cc:00:00:01", "HomeNet"))
# an evil twin: same SSID, different BSSID
frames.append(beacon("de:ad:be:ef:00:02", "HomeNet"))
# probe request + response
frames.append(probe_req("aa:bb:cc:11:22:33", "HomeNet"))
frames.append(probe_resp("aa:bb:cc:00:00:01", "HomeNet", "aa:bb:cc:11:22:33"))
# deauth flood: 25 frames toward a client, all within the same instant
for i in range(25):
    frames.append(deauth("de:ad:be:ef:00:02", "aa:bb:cc:11:22:33", "aa:bb:cc:00:00:01"))
# control frames (short 10-byte headers) with a two-word radiotap bitmap
frames.append(cts("aa:bb:cc:00:00:01"))
frames.append(ack("aa:bb:cc:11:22:33"))

out = sys.argv[1] if len(sys.argv) > 1 else "tests/wlan.pcap"
# indexes 4..28 are the deauth burst; keep those inside one second
DEAUTH_START = 4
with open(out, "wb") as f:
    # classic pcap with linktype 127 (IEEE802_11_RADIO)
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
    t = 1700000200
    for i, fr in enumerate(frames):
        ind = DEAUTH_START <= i < DEAUTH_START + 25
        ts = t + (0 if ind else i)
        usec = i if ind else 0
        f.write(struct.pack("<IIII", ts, usec, len(fr), len(fr)))
        f.write(fr)
print("wrote %s (%d frames)" % (out, len(frames)))
