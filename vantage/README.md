# vantage

**A fast, precise port scanner written from scratch in Go.**

`vantage` is a modern take on the classic port scanner. It pairs three scan
engines with an adaptive concurrency controller, dual-stack aware probing,
protocol-aware service detection, TLS and favicon fingerprinting, and a
streaming output pipeline — all in a single static binary with **zero
third-party dependencies**.

```
$ vantage -s --ja3 -p 443,8443 example.com
93.184.216.34:443    open       https        nginx       1.25.3        12.4ms
93.184.216.34:8443   closed
```

---

## Highlights

| Capability | What vantage does |
| --- | --- |
| **Graphical interface** | A built in browser dashboard (`vantage gui`) that starts scans, follows them live over Server-Sent Events and exports the results. |
| **Three engines** | TCP connect (unprivileged, default), raw TCP SYN (half open, `CAP_NET_RAW`), and UDP with per-service payloads. |
| **Adaptive concurrency** | An AIMD controller modelled on TCP congestion control grows the in-flight window on healthy targets and shrinks it multiplicatively when errors appear. |
| **Rate limiting** | A token bucket with a configurable burst keeps a scan inside a fixed probes-per-second budget. |
| **Dual stack** | IPv4 and IPv6 targets are probed as one logical host, raced using the RFC 8305 Happy Eyeballs delay. |
| **Service detection** | 48 protocol probers exchange real protocol handshakes, and 65 fingerprint rules turn banners into product, version and CPE. |
| **OS detection** | A raw SYN probe fingerprints the remote TCP/IP stack — initial TTL, TCP window, MSS and the ordered TCP options — and matches it against a database to guess the operating system. |
| **TLS fingerprints** | JA3 and JA3S are computed from the real ClientHello and ServerHello, along with certificate metadata. |
| **Favicon hashing** | Shodan-style MurmurHash3 favicon fingerprints identify web software. |
| **Bounded memory** | The pipeline is streaming: a full 65 535 port scan peaks at ~46 MiB of resident memory. |
| **Machine friendly output** | `text`, `json`, `jsonl`, `csv`, `greppable` and Go `template` formats, all written incrementally. |

---

## Install

The project requires **Go 1.27** or newer and has no external dependencies.

```sh
git clone https://github.com/darkLabz001/darksec-recon-suite
cd darksec-recon-suite/vantage
make build          # writes ./bin/vantage
sudo make install   # optional, installs into /usr/local/bin
```

Or build directly:

```sh
go build -o vantage ./cmd/vantage
```

---

## Quick start

```sh
# Scan the 1000 most common ports on a host.
vantage 192.168.1.1

# Scan a /24 on the well known ports, with service detection.
vantage -s -p 1-1024 192.168.1.0/24

# Full sweep of every TCP port, rate limited to 5000 probes per second.
vantage -p 1-65535 --rate 5000 10.0.0.0/8

# Half open SYN scan (needs CAP_NET_RAW or root).
sudo vantage --engine syn -p 1-1024 10.0.0.1

# UDP scan of the most common UDP services.
vantage --engine udp --top-ports 44 192.168.1.1

# Machine readable output.
vantage --format jsonl -o scan.jsonl 10.0.0.0/24

# Detect the operating system of each host (needs CAP_NET_RAW).
sudo vantage --os -p 22,443 10.0.0.5
```

---

## Graphical interface

`vantage gui` starts a local web server and opens a browser dashboard, so a
scan can be configured, followed and exported without the command line.

```sh
vantage gui                      # http://127.0.0.1:8787
vantage gui --listen :9090       # bind another address
vantage gui --no-open            # don't open a browser automatically
```

The dashboard provides:

* a **scan form** — targets, ports (or the top-N list), engine, service
  detection, JA3/favicon fingerprinting, timeout, rate and concurrency;
* a **live results table** that fills in as each port is answered, with
  expandable rows for the banner, CPE and fingerprints;
* **progress counters** for open, closed and filtered ports;
* **JSON and CSV export** of the accumulated results.

The interface talks to the scanner over a small HTTP API (`/api/scan`,
`/api/stop`, `/api/events`, `/api/export`) and pushes every result to the
page with Server-Sent Events, so the table updates in real time. When the
SYN engine is unavailable the dashboard says so, because the process is not
running with `CAP_NET_RAW`.

---

## Targets

| Syntax | Meaning |
| --- | --- |
| `192.168.1.1` | a single address |
| `192.168.1.0/24` | a CIDR block (network and broadcast are skipped) |
| `192.168.1.10-192.168.1.60` | an inclusive address range |
| `192.168.1.*` | a wildcard block |
| `example.com` | a hostname, requires `--resolve` |
| `@targets.txt` | read specifications from a file |
| `-` | read specifications from standard input |

Targets are repeatable and each one may hold a comma separated list. The
`--exclude-cidr` flag removes blocks from the final list, and `--max-hosts`
caps how many addresses a single specification may expand to (default
1 048 576).

---

## Ports

```
80            a single port
1-1024        an inclusive range
80,443,8080   a list
T:80,443      force TCP
U:53,67       force UDP
-             every port
```

A protocol prefix applies to the item that carries it and to every item that
follows it, until another prefix appears. In the UDP engine a bare
specification such as `-p 53` means a UDP port, while `-p U:53` is always
explicit.

`--top-ports N` scans the N most frequently used ports from the bundled
list (5 206 TCP and 44 UDP entries), and `--exclude-ports` removes ports
from whatever set was selected.

---

## Service detection

`--detect-services` (or `-s`) identifies what is running behind an open
port. Detection happens in two layers:

1. **Protocol probing.** The scanner speaks the protocol it expects. An SSH
   port receives an `SSH-2.0-…` banner, a Redis port receives `PING`, an
   LDAP port receives a search request, and so on. The registry covers 48
   protocols: `http`, `https`, `ssh`, `ftp`, `smtp`, `dns`, `ntp`, `snmp`,
   `redis`, `memcached`, `mysql`, `postgres`, `mongodb`, `ldap`, `rdp`,
   `smb`, `rpcbind`, `nfs`, `docker`, `elasticsearch`, `kafka`, `mqtt`,
   `amqp`, `cassandra`, `openvpn`, `bgp`, `vnc`, `xmpp`, `zookeeper` and
   more.

2. **Fingerprinting.** Sixty-five regular expressions turn the banner into
   a product name, a version and a CPE identifier. A banner that no rule
   matches still keeps its raw text.

```sh
vantage -s -p 22,80,443,3306 10.0.0.5 --format json
```

```json
{
  "ip": "10.0.0.5",
  "port": 3306,
  "protocol": "tcp",
  "state": "open",
  "service": "mysql",
  "product": "MySQL",
  "version": "8.0.36",
  "cpe": "cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*",
  "confidence": 0.9,
  "method": "probe",
  "rtt_ms": 3.21
}
```

Ports with no known protocol mapping fall back to the probes named by
`--fallback-probes` (HTTP by default). `--probe http,redis` restricts
detection to specific protocols, and `--fingerprint-rules rules.json` adds
your own rules:

```json
{
  "rules": [
    {
      "name": "acme-http",
      "service": "http",
      "pattern": "AcmeServer/([0-9.]+)",
      "product": "AcmeServer",
      "version_group": 1,
      "cpe": "cpe:2.3:a:acme:acmeserver:%s:*:*:*:*:*:*:*"
    }
  ]
}
```

### TLS and favicon fingerprints

`--ja3` computes the JA3 hash of the ClientHello the scanner sends and the
JA3S hash of the ServerHello it receives, and records the negotiated
version, cipher suite, ALPN protocols, certificate subject, issuer, validity
window, subject alternative names, key type and signature algorithm.

`--favicon` requests `/favicon.ico` from HTTP services and reports the
MurmurHash3 fingerprint of the icon, which identifies web software even when
the banner is hidden.

### Operating system detection

`--os` fingerprints the remote operating system by looking at how its TCP/IP
stack answers a crafted SYN. The reply carries several signals that are
distinctive per OS:

* the **initial TTL** (Linux and macOS use 64, Windows 128, Cisco and
  Solaris 255);
* the **TCP window size**;
* the **MSS** and the ordered list of **TCP options** (window scale, SACK,
  timestamps).

The observed signature is matched against a built-in database and the best
guess is reported with a confidence percentage and the raw values, so the
guess can be verified by eye:

```sh
sudo vantage --os -p 22,443 10.0.0.5
```

```
10.0.0.5:22                open       ssh
OS: 10.0.0.5 Linux (95% confidence) - Linux 5.x/6.x (Ubuntu, Debian, Arch, Fedora)
```

OS detection needs `CAP_NET_RAW` (it crafts and reads raw packets), and runs
once per host on the first open TCP port. The database is a curated starting
point of well known signatures; the JSON output always includes the full
fingerprint so the guess is not a black box.

---

## Output formats

| Format | Description |
| --- | --- |
| `text` | an aligned, optionally colourised table (the default) |
| `json` | a single, pretty printed JSON array |
| `jsonl` | one JSON document per line |
| `csv` | comma separated values with a header row |
| `greppable` | compact `ip:port service version` lines |
| `template` | any Go `text/template`, supplied with `--template` |

Every format is written incrementally, so a scan of a large network never
has to hold its results in memory.

```sh
vantage --format template \
  --template '{{.Addr}}:{{.Port}} {{.Service}} {{.Product}} {{.Version}}' \
  -p 80,443 10.0.0.0/24
```

The text format shows one line per open port:

```
203.0.113.7:443                open            https          nginx          1.25.3          12.4ms
```

Add `--all` to include closed and filtered ports, and `--no-color` to
disable ANSI colouring (colour is disabled automatically when writing to a
file).

---

## Configuration file

`--config config.json` supplies defaults; command line flags always win.

```json
{
  "timeout": "2s",
  "concurrency": 512,
  "rate": 2000,
  "ports": "1-1024",
  "engine": "connect",
  "detect": true,
  "ja3": true,
  "favicon": true,
  "probe_timeout": "5s",
  "format": "jsonl",
  "output": "scan.jsonl"
}
```

Durations accept either a Go duration string (`"2s"`) or a number of
nanoseconds.

---

## Performance

Measured on this machine with Go 1.27 against the loopback interface, which
is the fastest possible target:

| Workload | Probes | Wall clock | Rate |
| --- | --- | --- | --- |
| Full TCP range, one host | 65 535 | 1.66 s | ~39 500/s |
| Top 1000 ports, /24 | 253 952 | 5.90 s | ~43 000/s |
| Top 1000 ports, /22 | 1 022 000 | 23.4 s | ~43 600/s |
| Full TCP range, one host, JSON output | 65 535 | 1.7 s | 46 MiB peak RSS |

Loopback numbers are an upper bound; real networks are limited by the round
trip time and by the remote host's willingness to answer. The adaptive
controller reacts to that automatically: it starts small, grows while the
target keeps answering, and backs off quickly when probes start failing.

Reproduce the numbers with:

```sh
make bench-sweep   # the loopback sweeps above
make bench         # the Go micro benchmarks
```

---

## Architecture

The scanner is built as a set of small packages with a single dependency
direction, from the leaves upwards:

```
target   → ports   → engine   → proto   → detect   → output
                             ↘ ratelimit ↗

gui (web dashboard) ── engine ── output
```

* `internal/target` expands target specifications into hosts.
* `internal/ports` parses port specifications into deduplicated sets.
* `internal/engine` holds the shared pipeline and the three engines.
* `internal/proto` holds the protocol probers and the TLS machinery.
* `internal/detect` holds the fingerprint rules and the favicon hashing.
* `internal/osdetect` holds the operating system fingerprinting.
* `internal/output` renders results.
* `internal/ratelimit` implements the token bucket.
* `internal/gui` serves the embedded dashboard and drives the engines over HTTP.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a detailed walk
through the pipeline, the concurrency model and the detection flow.

---

## Development

```sh
make build      # build the binary into ./bin
make test       # run the test suite
make race       # run the test suite under the race detector
make lint       # gofmt and go vet
make cover      # produce a coverage profile
make bench      # run the Go benchmarks
make all        # lint, test and build
```

The test suite is hermetic: it starts loopback listeners instead of
touching the network, so it runs anywhere. Statement coverage sits at 76 %,
with the core packages (CLI, output, ports, rate limiting) above 90 %.

---

## Legal and ethical use

`vantage` is a tool for people who are authorised to test the systems they
point it at. Scanning systems you do not own or have permission to test is
illegal in many jurisdictions. Use it on your own infrastructure, on
infrastructure you have written permission to assess, or inside a lab.

## License

MIT.
