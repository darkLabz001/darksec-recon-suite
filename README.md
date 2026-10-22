# darksec recon suite

A reconnaissance toolkit built from scratch. Four tools, one repo.

| Tool | What it does | Language |
| --- | --- | --- |
| [`vantage`](vantage) | Fast, precise port scanner with service and OS detection | Go |
| [`sunder`](sunder) | Subdomain enumeration with a live terminal UI | Python |
| [`ch1m3ra`](ch1m3ra) | Cyberpunk packet sniffer, decoder and active toolset | C |
| [`wyrm`](wyrm) | WPA3/WPA2 wireless security auditor | Go |

## vantage

A modern port scanner with three engines (TCP connect, raw SYN, UDP),
adaptive concurrency, rate limiting, protocol-aware service detection, JA3/JA3S
and favicon fingerprinting, operating system detection and a browser
dashboard. See [`vantage/README.md`](vantage/README.md).

```sh
cd vantage && make build
./bin/vantage -s -p 1-1024 10.0.0.0/24
```

## sunder

Subdomain enumeration with a terminal UI: passive intel and active DNS,
streaming every hit into a live results table. See
[`sunder/README.md`](sunder/README.md).

```sh
cd sunder && pip install -e .
sunder example.com
```

## ch1m3ra

A packet sniffer written from scratch in C — no libpcap, no scapy. Raw
`AF_PACKET` capture, kernel BPF filtering, fragment reassembly, flow tracking,
TLS/QUIC/HTTP2 decode, JA3/JA4 fingerprinting, pcap/pcapng output and an
interactive TUI. See [`ch1m3ra/README.md`](ch1m3ra/README.md).

```sh
cd ch1m3ra && make
sudo ./ch1m3ra -i eth0
```

## wyrm

A WPA3/WPA2 wireless security auditor with no third-party dependencies.
It parses 802.11, RSN and SAE traffic, validates Dragonfly groups, inspects
EAP-pwd, flags downgrade and transition-mode issues, and reports on the
risks present on a capture or a live survey. A local browser dashboard is
included for live work. See [`wyrm/README.md`](wyrm/README.md).

```sh
cd wyrm && make build
./bin/wyrm analyze capture.pcap
./bin/wyrm gui
```

## Legal and ethical use

These are tools for people authorised to test the systems they point them at.
Use them on your own infrastructure, on infrastructure you have written
permission to assess, or inside a lab.

## License

MIT.
