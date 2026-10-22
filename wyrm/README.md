# wyrm

**A WPA3 and WPA2 wireless security auditor written from scratch in Go.**

`wyrm` reads wireless traffic and tells you what is wrong with it. It
decodes 802.11 management frames, RSN information elements, the SAE
handshake and EAP-pwd on its own, validates Dragonfly groups and commit
elements against the published curves, and reports on downgrade paths,
evil twins, handshake leakage, side channels, flooding and the layer 2
risks that come with an open network — all in a single static binary with
**zero third-party dependencies**.

```
$ wyrm check capture.pcap
wyrm 1.0.0 - wireless security audit
source : capture.pcap
window : 2026-10-22T03:46:57-04:00 to 2026-10-22T03:47:00-04:00 (4s)

SUMMARY
  verdict      : C (medium)
  findings     : 2  (critical 0, high 0, medium 2, low 0, info 0)
  access points: 1
  clients      : 3
  packets      : 412
```

---

## Highlights

| Capability | What wyrm does |
| --- | --- |
| **Graphical interface** | A built in browser dashboard (`wyrm gui`) that configures a capture, follows it live over Server-Sent Events and exports the report. |
| **No dependencies** | The 802.11, pcap, pcapng, SAE and EAP decoders are written from scratch in the standard library. No libpcap, no cgo, no scapy. |
| **Pure Go captures** | Classic pcap and pcapng are read and written in process; live capture uses `tcpdump` over a pipe and the stream is parsed while it is written. |
| **Monitor mode** | Monitor mode and channel hopping are driven through raw `nl80211` netlink, so no `iw` and no `airmon-ng` are needed. |
| **SAE validation** | Commit and confirm frames are decoded exactly the way the wire format is laid out, and the commit scalar and element are checked against the group. |
| **Dragonfly groups** | Every SAE and EAP-pwd group is rated: the group order, the safe-prime property and the curve validity are all checked. |
| **Downgrade analysis** | Transition mode, OWE transition mode, missing downgrade protection, evil twins, open networks and captured handshakes are reported separately. |
| **Machine friendly output** | `text`, `json` and a self contained `html` report, all written to a file with `wyrm report`. |

---

## Install

The project requires **Go 1.27** or newer and has no external dependencies.

```sh
git clone https://github.com/darkLabz001/darksec-recon-suite
cd darksec-recon-suite/wyrm
make build          # writes ./bin/wyrm
sudo make install   # optional, installs into /usr/local/bin
```

The desktop launcher and the icon are installed with:

```sh
make install-desktop
```

Or build directly:

```sh
go build -o wyrm ./cmd/wyrm
```

---

## Quick start

```sh
# Audit a capture that was made somewhere else.
wyrm analyze capture.pcap

# List the findings with the evidence and the remedy.
wyrm check capture.pcap

# Write a report that can be shared.
wyrm report capture.pcap -o report.html

# List the networks that are around (needs root).
sudo wyrm survey -i wlp4s0 -c 1,6,11 --duration 60

# Watch a network for two minutes and report the findings.
sudo wyrm watch -i wlp4s0 --monitor --duration 120

# The wireless interfaces of the host.
wyrm iface
```

A bare path is treated as `analyze`, so `wyrm capture.pcap` works too.

---

## Graphical interface

```sh
wyrm gui
```

The dashboard is served on `127.0.0.1:8788` and opened in the browser. It
lists the wireless interfaces of the host, lets the channels, the filter
and the length of the capture be chosen, shows the access points and the
findings as they arrive, and exports the report.

`--listen` changes the address and `--no-open` stops the browser from
being opened. The server only ever binds to the loopback address unless
it is told otherwise.

---

## What is audited

Every finding carries an identifier, a severity, the evidence that led to
it and the remedy that closes it.

### `downgrade` — the transition mode and the handshake

| Finding | What it means |
| --- | --- |
| `WYM-DWN-001` | The network is open. |
| `WYM-DWN-002` | The network uses WEP or TKIP. |
| `WYM-DWN-003` | The network offers WPA1. |
| `WYM-DWN-004` | The network has no downgrade protection. |
| `WYM-DWN-005` | The network runs in WPA3 transition mode. |
| `WYM-DWN-006` | The network runs in OWE transition mode. |
| `WYM-DWN-007` | Management frame protection is not required. |
| `WYM-DWN-008` | The network does not exclude the older password methods. |
| `WYM-DWN-009` | The network hides its name. |
| `WYM-DWN-010` | Several access points serve the same name. |
| `WYM-DWN-011` | An evil twin serves the same name with different security. |
| `WYM-DWN-012` | A WPA2 four way handshake was captured. |
| `WYM-DWN-013` | A PMKID was captured. |

An access point that serves the same name as another one is only called an
evil twin when the two disagree about the security; when they agree it is
reported as a plain duplicate, because that is a roaming setup and not an
attack.

### `dragonfly` — SAE and the side channels

| Finding | What it means |
| --- | --- |
| `WYM-DFL-001` | The SAE handshake used a weak finite cyclic group. |
| `WYM-DFL-002` | The SAE handshake used an unknown finite cyclic group. |
| `WYM-DFL-003` | The SAE commit failed validation. |
| `WYM-DFL-004` | The SAE handshake used a single commit. |
| `WYM-DFL-005` | The network authenticates with SAE-PK. |

A single commit is the shape of a timing side channel: the answer arrives
faster than the password is checked, which is what the Dragonblood paper
describes. The commit is validated against the group it names, so a commit
that does not sit on the curve or is not in the right subgroup is caught.

### `eap` — the EAP-pwd method

| Finding | What it means |
| --- | --- |
| `WYM-EAP-001` | The network authenticates with EAP-pwd. |
| `WYM-EAP-002` | The EAP-pwd server sent an invalid group element. |
| `WYM-EAP-003` | EAP-pwd used a weak finite cyclic group. |
| `WYM-EAP-004` | EAP-pwd used an unknown finite cyclic group. |
| `WYM-EAP-005` | The EAP-pwd exchange looks like a reflection. |

EAP-pwd is vulnerable to a reflection attack and to a man in the middle
because the password is exposed to the chosen prime attack. A station that
answers with the element it was given is the signature of a reflection.

### `mgmt` — flooding and the channel switch announcement

| Finding | What it means |
| --- | --- |
| `WYM-MGT-002` | Channel switch announcements were seen. |
| `WYM-MGT-003` | Management frame disassociations were seen. |
| `WYM-MGT-004` | The access point accepts forged management frames. |

A channel switch announcement that is not protected is a way to move a
network onto a channel of the attacker's choosing, and a flood of
disassociation frames is a way to keep the clients off the network.

### `lan` — the open network

| Finding | What it means |
| --- | --- |
| `WYM-LAN-001` | An address was claimed by two hardware addresses. |
| `WYM-LAN-002` | More than one DHCP server answered. |
| `WYM-LAN-003` | The group key is shared by every station of the network. |
| `WYM-LAN-004` | The open network lets any station impersonate a client. |

On a network without a password every station can answer for every address,
so the address mappings, the name servers and the gateway are all open to
being rewritten.

---

## The wire formats

The decoders follow the published formats rather than an approximation of
them.

* **AKM and cipher suites** are taken from the IEEE 802.11 RSN
  information element: the suite selector is the OUI `00:0F:AC` followed by
  one type octet, so PSK is `02`, 802.1X is `01`, SAE is `08`, FT-SAE is
  `09`, OWE is `12`, SAE with a group dependent password is `18` and PASN
  is `15`. CCMP is `04`, TKIP is `02` and GCMP is `08`.
* **The SAE commit frame** is laid out as the algorithm, the transaction
  sequence, the status, the group identifier, the anti-clogging token, the
  commit scalar and the commit element, with the extension elements
  following them. The token comes **before** the scalar, and the group
  identifier is present for the statuses that carry one.
* **The SAE groups** are the ones of the standard: the finite cyclic groups
  1, 2, 5, 14, 15, 16, 17 and 18, and the elliptic curves 19 (P-256), 20
  (P-384), 21 (P-521), 25 (P-192), 26 (P-224) and the Brainpool curves 27
  to 30. The groups 22, 23 and 24 are the ones that were left out of the
  standard.
* **SAE-PK** is looked for in the extended capabilities, where bit 88 is
  "SAE-PK Passwords Used Exclusively", and in the RSN extension element
  (element 244), where the flags sit in the high four bits of the first
  octet. The transition disable KDE and the OWE transition mode are read
  from the vendor specific elements of the Wi-Fi Alliance.

---

## Output formats

```sh
wyrm analyze capture.pcap                  # text, on the terminal
wyrm analyze capture.pcap --format json    # JSON, on the terminal
wyrm report capture.pcap -o report.json    # JSON, in a file
wyrm report capture.pcap -o report.html    # a self contained page
wyrm report capture.pcap -o report.txt     # text, in a file
```

The JSON document carries the summary, the statistics, every access point
with its security, every client, every finding, the SAE exchanges, the
handshakes, the EAP-pwd exchanges and the address mappings.

The HTML report is a single file with no external references, so it can be
sent on its own.

---

## Privileges

A raw wireless capture needs root. `wyrm` asks for it in the least
obtrusive way it can:

```sh
sudo wyrm watch -i wlp4s0 --duration 60
wyrm watch -i wlp4s0 --duration 60 --sudo-password secret
WYRM_SUDO_PASSWORD=secret wyrm watch -i wlp4s0 --duration 60
```

The password is only used to run the capture through `sudo` and is never
written to a file.

Monitor mode takes the interface off the network, so the connection that is
using it will drop. It is never switched on without `--monitor` being
given, and the tool says so before it does.

---

## Architecture

```
wyrm/
├── cmd/wyrm/           the entry point
└── internal/
    ├── dot11/          the 802.11 MAC header, the information elements and the RSN
    ├── pcap/           the classic pcap and the pcapng readers and writers
    ├── dh/             the finite cyclic groups, the curves and the validation
    ├── sae/            the SAE commit and confirm frames
    ├── eap/            the 802.1X encapsulation, EAPOL-Key and EAP-pwd
    ├── lan/            Ethernet, ARP, DHCP and DNS
    ├── capture/        the interfaces, the channels and the live capture
    ├── audit/          the model, the analyser, the checks and the score
    ├── report/         the JSON, the text and the HTML reports
    ├── gui/            the dashboard server and its assets
    ├── cli/            the command line interface
    └── version/        the build information
```

The packages do not depend on each other in a cycle: the decoders know
nothing about the audit, and the audit knows nothing about the interface.

---

## Development

```sh
make test          # run the test suite
make race          # run it under the race detector
make cover         # write a coverage profile
make lint          # gofmt and go vet
make fmt           # format the tree
make build         # build ./bin/wyrm
```

The decoders are checked against fixtures that were taken from the
published formats, and the capture readers are checked against files that
`tcpdump` wrote, with the packet counts compared against `tshark`.

---

## Legal and ethical use

`wyrm` is a tool for people who are authorised to test the networks they
point it at. Use it on your own infrastructure, on infrastructure you have
written permission to assess, or inside a lab.

Capturing wireless traffic that is not your own, or interfering with a
network that you are not authorised to test, is a criminal offence in most
jurisdictions.

---

## License

MIT.
