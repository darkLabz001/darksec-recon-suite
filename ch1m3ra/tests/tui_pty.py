#!/usr/bin/env python3
"""Drive the ch1m3ra TUI under a pty and verify the panes, prompt, search,
detail view, colors and scrolling.

Usage: python3 tests/tui_pty.py <binary> <pcap>
Exits 0 on success, prints the observed screen markers on failure.
"""
import os, pty, select, sys, time, re, fcntl, termios, struct

BIN = sys.argv[1] if len(sys.argv) > 1 else "./ch1m3ra"
PCAP = sys.argv[2] if len(sys.argv) > 2 else "tests/sample.pcap"

pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    os.execv(BIN, [BIN, "-r", PCAP, "-U", "-O", "-Y", "-N", "-K"])

# give the TUI a realistic window so the full header/histogram/footer fit
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))

def drain(t=0.6):
    out = b""
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    return out.decode("utf-8", "replace")

screen = drain(1.5)

def send(s):
    os.write(fd, s.encode())

# detail view: scroll back one row (the newest is the EOF marker) then Enter
send("j"); screen += drain(0.3)
send("\r"); screen += drain(0.5)
send("\r"); screen += drain(0.4)

# cycle panes: packets -> hits -> hosts -> talkers -> packets
send("p"); screen += drain(0.4)
send("p"); screen += drain(0.4)
send("p"); screen += drain(0.4)
send("p"); screen += drain(0.4)

# ':' command prompt
send(":")
screen += drain(0.3)
send("proto icmp")
screen += drain(0.3)
send("\r")
screen += drain(0.5)

# clear it
send(":")
send("filter")
send("\r")
screen += drain(0.5)

# search: '/' then a query, jump to a match
send("/")
screen += drain(0.2)
send("443")
screen += drain(0.3)
send("\r")
screen += drain(0.5)

# mouse wheel up (SGR): ESC [ < 64 ; x ; y M  -> pane scrolls back
send("\x1b[<64;10;5M"); screen += drain(0.5)
send("\x1b[<65;10;5M"); screen += drain(0.3)   # wheel down -> back to tail

send("q")
time.sleep(0.3)
try:
    os.waitpid(pid, os.WNOHANG)
except Exception:
    pass
os.close(fd)

# assertions: markers that must appear somewhere in the captured stream
checks = {
    "pane hosts":     "hosts (passive OS fingerprint)",
    "pane talkers":   "top conversations (by bytes)",
    "pane hits":      "hits: creds/tokens/banners/os",
    "column header":  "SUMMARY",
    "cmd prompt":     "\x1b[1;37m:",
    "proto result":   "proto=icmp",
    "clear result":   "filters cleared",
    "sparkline pps":  "pps ",
    "row colour":     "\x1b[96m",          # UDP rows use bright cyan (header does not)
    "search status":  "match(es)",
    "scroll marker":  "SCROLLED",
    "detail pane":    "L4",                # the decode pane labels layers
    "detail hexdump": "payload",
    "metric row":     "malformed",
    "side panel":     "PROTOCOL MIX",
    "top talkers":    "TOP TALKERS",
}
bad = [k for k, v in checks.items() if v not in screen]
if bad:
    sys.stderr.write("TUI pty check: missing %s\n" % ", ".join(bad))
    sys.stderr.write(re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", screen)[-2500:])
    sys.exit(1)
print("TUI pty check: OK (%d bytes)" % len(screen))
