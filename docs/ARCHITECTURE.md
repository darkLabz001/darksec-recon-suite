# Architecture

This document describes how `vantage` is put together, from the packages
down to the individual probe. It is aimed at someone who wants to change the
scanner rather than simply run it.

---

## 1. Package layout

```
github.com/darkLabz001/darksec-recon-suite/vantage
├── cmd/vantage             the entry point
└── internal
    ├── target              target specifications → hosts
    ├── ports               port specifications → port sets
    ├── engine              the scan pipeline and the three engines
    │   ├── scanner.go      shared machinery: pipeline, gate, controller
    │   ├── connect.go      TCP connect engine
    │   ├── syn.go          raw TCP SYN engine
    │   ├── synpacket.go    packet construction and checksum helpers
    │   ├── udp.go          UDP engine
    │   ├── udppayload.go   per-service UDP request payloads
    │   ├── limiter.go      the concurrency gate and the AIMD controller
    │   └── result.go       the Result type
    ├── proto               protocol probers and TLS machinery
    ├── detect              fingerprint rules, service detection, favicon hashing
    ├── output              result rendering
    ├── ratelimit           the token bucket
    ├── stats               live progress reporting
    ├── cli                 flag parsing and the scan driver
    ├── gui                 the browser dashboard and its HTTP API
    │   └── assets          the embedded single page application
    └── version             build information
```

Dependencies flow in one direction only. `engine` knows about `ports`,
`target`, `proto`, `detect` and `ratelimit`; `detect` knows about `proto`;
`cli` knows about everything. Nothing below `cli` knows that a command line
exists, which keeps the packages testable in isolation.

---

## 2. The scan pipeline

All three engines share one pipeline. The engine specific part is a single
function that turns a job into a result.

```
targets ──► host list ──┐
                        ├──► job queue ──► worker pool ──► result channel ──► writer
ports ───► port list ───┘                     │
                                              └── rate limiter → concurrency gate
```

### 2.1 Jobs

A job is a (`target.Host`, `port`) pair. The host may carry both an IPv4 and
an IPv6 address, in which case the job expands into one probe per family.

### 2.2 Ordering

`engine.Order` selects how jobs are sequenced:

* `OrderHost` finishes every port of a host before moving on. It is the
  friendliest choice for a single target.
* `OrderPort` probes one port across every host before moving to the next
  port. It spreads the load evenly over a large network, which keeps a
  firewall's per-host limits out of the picture.
* `OrderAuto` picks between them: port ordering for more than a handful of
  hosts, host ordering otherwise.

### 2.3 Workers and the gate

Workers pull jobs from a bounded queue. Before each probe a worker:

1. waits for a token from the rate limiter, if a rate is configured;
2. acquires a permit from the concurrency gate;
3. runs the probe;
4. releases the permit.

The gate is a resizable counting semaphore built on `sync.Cond`. Unlike a
buffered channel it can change its limit while permits are outstanding,
which is what makes the adaptive controller possible. Waiting on the gate is
context aware: a `context.AfterFunc` callback broadcasts to the waiters
when the scan is cancelled, so a shutdown never has to wait for a permit.

### 2.4 The AIMD controller

The controller behaves like TCP congestion control:

* it samples the outcome of every probe (round trip time and success);
* every 64 samples it computes the error ratio;
* an error ratio above 20 % multiplies the window by 0.75 (multiplicative
  decrease);
* an error ratio below 5 % with a healthy round trip time adds 10 % to the
  window (additive increase);
* the window is always clamped to `[MinConcurrency, MaxConcurrency]`.

This gives a scanner that starts politely, ramps up when the target keeps
answering, and backs off within a single window when the target starts
dropping packets — which is the behaviour that avoids IDS alerts and
resets.

The controller's window is applied to the gate with `setLimit`, so the
change takes effect for the probes that follow without disturbing the ones
in flight.

### 2.5 Rate limiting

`internal/ratelimit` implements a token bucket with a burst of `rate/10`
tokens (at least one). The bucket starts full, so a scan may fire a short
spike before it settles into the configured rate. `--rate 0` disables
limiting entirely.

### 2.6 Bounded memory

Nothing in the pipeline accumulates per-probe state:

* the job queue is bounded;
* the result channel is bounded (1 024 entries);
* the writer renders each result as it arrives.

The only format that would otherwise buffer is JSON, which needs a closing
bracket; it is written incrementally as a streaming array instead, so even
the JSON format keeps the memory profile flat.

---

## 3. The engines

### 3.1 TCP connect (`--engine connect`)

The default engine. It opens a TCP connection and classifies the outcome:

| Outcome | State |
| --- | --- |
| the connection is established | `open` |
| the peer answers with a RST | `closed` |
| the connection times out or the network is unreachable | `filtered` |

It needs no privileges, which makes it the safe choice for shared hosts and
for untrusted networks.

### 3.2 TCP SYN (`--engine syn`)

A half open scan. The scanner crafts the SYN packet itself, computes the
TCP checksum, sends it and waits for a SYN/ACK. A RST means `closed`,
silence means `filtered`, and a SYN/ACK is completed with a RST so that the
target does not keep the connection in its backlog.

It needs `CAP_NET_RAW`, which in practice means root:

```sh
sudo setcap cap_net_raw+ep ./vantage
```

The engine refuses to start when the raw socket cannot be opened and says
so, rather than silently degrading.

### 3.3 UDP (`--engine udp`)

UDP has no handshake, so "open" is inferred from a response. The engine
sends a per-service payload — a `version.bind` query for DNS, an SNMP
`getRequest` for SNMP, a NTP mode 6 packet, an SSDP `M-SEARCH`, and so on —
and treats any answer as an open port.

The classification is deliberately conservative:

* an ICMP port unreachable becomes `closed`;
* an answer becomes `open`;
* a timeout becomes `filtered`.

Because the response itself identifies the service, the UDP engine records
the service directly (for example the DNS version from the `version.bind`
TXT record) instead of running the generic detector.

---

## 4. Service detection

Detection runs only on open ports and only when `--detect-services` is
given.

### 4.1 Choosing the probers

`internal/proto` keeps a registry of protocol probers. Each prober knows
how to talk its protocol and what a response looks like.

`proto.Candidates(port)` returns the protocols that plausibly live on a
port, based on a port to protocol table. A port with no entry falls back to
the universal probes — HTTP and, when the port suggests TLS, HTTPS.

Two details matter:

* protocols that only exist over UDP are not offered for TCP ports;
* a protocol without a registered prober is dropped from the candidate list
  rather than silently doing nothing.

### 4.2 The probers

A prober receives a connection and a deadline and returns an observation:

```go
type Observation struct {
    Service string      // the canonical service name
    Product string      // the software implementation
    Version string      // the detected version
    Extra   string      // vendor or build details
    Banner  string      // the raw banner, trimmed
    Raw     []byte      // every byte read during the probe
    HTTP    *HTTPInfo   // populated for HTTP and HTTPS
    TLS     *TLSInfo    // populated for services negotiated over TLS
    JA3     string      // the fingerprint of the ClientHello we sent
    JA3S    string      // the fingerprint of the ServerHello we received
}
```

Probers are deliberately cheap. A probe is at most a few hundred bytes in
each direction and never waits for the peer to close the connection; the
reader stops at the first complete response or at the deadline.

### 4.3 Fingerprinting

`internal/detect` holds 65 rules. Each rule is a regular expression with a
canonical service name, a product name, an optional capture group for the
version and a CPE template.

The precedence for extracting the product is:

1. the rule's static product name;
2. the capture group selected by `ProductGroup`;
3. the whole match.

The version comes from the group selected by `VersionGroup`, and the `%s` in
the CPE template is replaced with it.

Rules are applied to the raw bytes the service sent, so the same database
works for protocol probers and for the generic banner fallback.

### 4.4 The generic banner fallback

When no prober recognises the service, the scanner reads whatever the
service sends first — the classic greeting — and runs the fingerprint rules
over it. The banner is kept even when nothing matches, because an
unrecognised banner is often the most interesting part of a scan.

### 4.5 TLS fingerprints

`--ja3` makes the scanner perform a real TLS handshake and compute:

* **JA3** — the MD5 of the canonicalised ClientHello the scanner sends;
* **JA3S** — the MD5 of the canonicalised ServerHello it receives.

The canonical form lists the cipher suites, the extensions, the elliptic
curve groups and the point formats in the order they appear on the wire, and
drops the GREASE values that TLS stacks insert to defeat middlebox caches.
The result is hashed with MD5, exactly as the JA3 specification defines. The handshake also yields the negotiated version, the
cipher suite, the ALPN protocols and the full certificate metadata.

### 4.6 Favicon hashing

`--favicon` requests `/favicon.ico` from an HTTP service, base64 encodes
the body, hashes it with MurmurHash3 and renders the result as a base64
encoded signed decimal — the exact format Shodan publishes.

---

## 5. Output

`internal/output` renders results in six formats. A `Writer` is created
once and every result is handed to it as it arrives.

* `text` — an aligned table with optional ANSI colour.
* `json` — a streaming, pretty printed array.
* `jsonl` — one document per line, for log shippers.
* `csv` — a header row followed by one row per result.
* `greppable` — `ip:port service product version`.
* `template` — any Go `text/template` over the result structure.

The CLI always drains the result channel completely before it flushes the
writer, so no result is lost when a scan ends.

---

## 6. Cancellation and shutdown

The CLI installs a `signal.NotifyContext` handler for `SIGINT` and
`SIGTERM`. Cancelling the context:

* stops the job producer;
* wakes every worker waiting on the gate;
* aborts the in-flight probes through their deadlines;
* stops the progress renderer, which prints a final line.

Because the results already collected are still written, an interrupted scan
produces a valid, if partial, output file.

---

## 7. The graphical interface

`internal/gui` turns the same engine API into a browser dashboard. It is
reachable through `vantage gui`, which is dispatched from `cli.Run` before
the flag parser runs, because the subcommand has a flag surface of its own
(`--listen`, `--open`, `--no-open`).

### 7.1 The embedded application

The front end — a single page of vanilla HTML, CSS and JavaScript — is
embedded into the binary with `go:embed`, so the whole interface ships in
the one static executable and needs no build step or web server of its own.
The binary serves it with `net/http` over an `http.FileServer` rooted at the
embedded assets directory.

### 7.2 The API

| Route | Purpose |
| --- | --- |
| `GET /` | the application |
| `GET /api/info` | the build version and whether the SYN engine is available |
| `GET /api/state` | the current scan counters and the accumulated results |
| `POST /api/scan` | start a scan from a JSON description |
| `POST /api/stop` | cancel the running scan |
| `GET /api/events` | a Server-Sent Events stream of results and stats |
| `GET /api/export?format=json|csv|jsonl` | download the accumulated results |

A `manager` owns at most one scan. Starting a new one cancels the previous,
clears the accumulator and broadcasts a `start` event with the total probe
count. Each result is appended to the accumulator and pushed to every
connected client as a `result` event, while a ticker emits `stats` events
with the live counters. When the engine returns the manager broadcasts a
`done` event carrying either an error or a stopped flag.

### 7.3 Live updates over SSE

Results are pushed to the browser with Server-Sent Events rather than
polling. Each client registers a buffered channel with a `hub`; a slow
client's channel is dropped rather than allowed to stall the scan. A client
that connects mid-scan is replayed the `start` event and the current stats,
and can always pull the full result set from `/api/state` or `/api/export`.

Export reuses `internal/output`, so the CSV and JSON downloads are byte
compatible with the command line `--format` writers.

---

## 8. Testing strategy

The test suite never touches the network beyond loopback. It starts local
listeners that speak a real protocol — an HTTP server, an SSH banner, a
Redis `PONG` — and asserts on what the scanner reports.

| Package | What it covers |
| --- | --- |
| `ports` | specification parsing, ranges, prefixes, exclusions, the top lists |
| `target` | CIDR, range and wildcard expansion, exclusions, file input |
| `proto` | every prober against a local listener, the JA3/JA3S computation |
| `detect` | rule matching, CPE filling, HTTP detection, custom rule loading |
| `engine` | the engines, the ordering, the gate, the controller, the limiter |
| `output` | every format, the templates, the empty scan |
| `cli` | flag parsing, the configuration file, the port set, an end to end scan |
| `gui` | the handlers, the scan lifecycle, the port list, an end to end scan |
| `ratelimit` | the token bucket with an injected clock |
| `stats` | the counters, the progress bar, the summary |

The suite is run under the race detector in CI, and the CLI tests exercise
the whole pipeline end to end against a loopback listener.
