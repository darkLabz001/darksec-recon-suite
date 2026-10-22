<h1 align="center">
  sunder
</h1>
<p align="center">
  split a domain into every shadow it casts — subdomain enumeration with a terminal UI
</p>

---

## About

`sunder` is a terminal TUI for subdomain enumeration and host reconnaissance. Give it
a domain (or an IP, or a list of both) and it splits the target apart using passive
intel and active DNS, streaming every hit into a live results table.

## ⚠️ LEGAL DISCLAIMER

This tool is intended for **educational and ethical use only**. You are responsible
for making sure you have explicit permission to scan any target you point sunder at.
Only enumerate domains you own or have written authorisation to test.

## Features

| Source          | What it does                                                    |
| --------------- | --------------------------------------------------------------- |
| `crt.sh`        | certificate transparency logs — names people got TLS certs for   |
| `wayback`      | the Wayback Machine CDX index — hosts seen in archived URLs      |
| `hackertarget`  | passive DNS host search (free tier, no key needed)               |
| `dns brute`     | resolves a wordlist against the domain via public resolvers      |
| `dns records`   | apex NS/MX/TXT/SPF/DMARC/CAA/SOA + an AXFR zone transfer attempt |
| `flag admin`    | fingerprints admin panels from the probe response (free)         |
| `takeover`      | dangling CNAMEs + dead-service error pages                       |
| `cert expiry`   | live TLS cert intel: issuer, expiry countdown, SAN count         |

On top of that:

- **Wildcard DNS detection** — brute-force hits that only match a wildcard are flagged
  so you don't chase false positives
- **DNS resolution** — A/AAAA + CNAME records for every hit
- **HTTP probing** — status code + page title for every live host
- **Admin panel flagging** — the probe response is fingerprinted for admin
  surfaces: phpMyAdmin, Grafana, Jenkins, Kibana, WordPress logins, cPanel,
  `/admin` paths, password forms, and more. Flagged rows light up with a
  `⚡ PANEL` cell and a highlighted hostname
- **Subdomain takeover detection** — CNAMEs pointing at heroku, GitHub Pages,
  S3, Azure, fastly, shopify, zendesk and ~25 more services are matched against
  dangling (no A record) and dead-service page bodies; findings show
  `⚠ <service> (dangling|confirmed)` in red
- **TLS certificate intel** — every https host gets its live leaf cert parsed:
  issuer, expiry countdown (red badge under 30 days, warnings under 14) and
  SAN count
- **Tech + security header audit** — server/php/cloudflare/WAF detection from
  response headers, plus missing HSTS/CSP/XCTO/XFO notes, per host
- **DNS records tab** — the apex record set in a dedicated tab, plus an AXFR
  zone transfer attempt against every nameserver (open transfers get a big red
  warning)
- **Filter + sort + detail** — filter-as-you-type with tokens
  (`live`, `flagged`, `admin`, `takeover`, `expiring`), click any column header
  to sort, press `enter` on a row for the full detail view
- **Clickable links** — the detail view's URL opens in your browser on click,
  or press `o` on any selected row
- **IP targets** — IPs get PTR reverse lookup, RDAP registration data and Team Cymru
  ASN info instead (IPs can't have subdomains, so sunder tells you what the address is)
- **Multi-target** — mix domains and IPs in one run, or feed a whole file with `@file.txt`
- **Export** — save results as `.json`, `.csv`, `.txt` or a self-contained
  `.html` report with the banner baked in
- **Themes** — cycle color themes live with `t`, or start with `--theme nord`

## Installation

```bash
git clone <this repo> && cd sunder
uv venv && uv pip install -e .
make link                  # puts `sunder` on your PATH (~/.local/bin)
sunder                     # TUI
```

Or with plain venv:

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
```

## Usage

```bash
sunder                          # start the TUI
sunder example.com 10.0.0.5     # headless, prints a table + apex records
sunder @targets.txt -o out.json # headless from a file, export json
sunder --tui example.com        # TUI with the input prefilled
sunder -o report.html example.com   # HTML report instead
sunder --theme dracula          # pick a TUI theme up front
```

Inside the TUI:

- type targets in the input bar — `example.com, 10.0.0.5` — or `@targets.txt`
- optionally point the *wordlist file* field at a bigger DNS brute list
- toggle sources with the checkboxes, then hit **enter**
- filter results in the filter box — free text, or `live` / `flagged` /
  `admin` / `takeover` / `expiring`
- click a column header to sort, press `enter` on a row for the detail view

| Key     | Action                                   |
| ------- | ---------------------------------------- |
| `enter` | start the scan (or open row detail)      |
| `o`     | open the selected host in your browser   |
| `s`     | save/export findings (json/csv/txt/html) |
| `c`     | clear results + log                      |
| `l`     | jump to log tab                          |
| `r`     | jump to records tab                      |
| `h`     | jump to help tab                         |
| `t`     | cycle color theme                        |
| `q`     | quit                                     |

## Development

```bash
make install
make run
make smoke     # headless UI smoke test
```
