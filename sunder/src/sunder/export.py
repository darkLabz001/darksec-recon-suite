"""Export findings to .json / .csv / plain text / standalone .html report."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from . import __version__
from .logo import SLIM, TAGLINE
from .models import Finding


def _as_dict(finding: Finding) -> dict:
    return {
        "target": finding.target,
        "host": finding.host,
        "kind": finding.kind,
        "sources": sorted(finding.sources),
        "ips": finding.ips,
        "resolved": finding.resolved,
        "status": finding.status,
        "url": finding.url,
        "title": finding.title,
        "note": finding.note,
        "panel": finding.panel,
        "cname": finding.cname,
        "takeover": finding.takeover,
        "cert_days": finding.cert_days,
        "cert_issuer": finding.cert_issuer,
        "cert_sans": finding.cert_sans,
        "tech": finding.tech,
        "security": finding.sec,
    }


def save(findings: list[Finding], path: str) -> int:
    """Write findings out, format chosen by extension. Returns rows written."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    suffix = target.suffix.lower()

    if suffix == ".json":
        target.write_text(json.dumps([_as_dict(f) for f in findings], indent=2) + "\n")
    elif suffix == ".csv":
        with target.open("w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                [
                    "target", "host", "kind", "sources", "ips", "status", "panel",
                    "takeover", "cert_days", "cert_issuer", "tech", "security",
                    "url", "title", "note",
                ]
            )
            for f in findings:
                writer.writerow(
                    [
                        f.target,
                        f.host,
                        f.kind,
                        ",".join(sorted(f.sources)),
                        ",".join(f.ips),
                        f.status if f.status is not None else "",
                        f.panel,
                        f.takeover,
                        f.cert_days if f.cert_days is not None else "",
                        f.cert_issuer,
                        f.tech,
                        f.sec,
                        f.url,
                        f.title,
                        f.note,
                    ]
                )
    elif suffix in (".html", ".htm"):
        target.write_text(_render_html(findings))
    else:
        lines = ["# host\tips\tstatus\tflags\tcert\ttech\ttitle/note\tsources"]
        for f in findings:
            flags = " · ".join(x for x in (f"⚠{f.takeover}" if f.takeover else "", f.panel) if x)
            cert = f"{f.cert_days}d {f.cert_issuer}" if f.cert_days is not None else ""
            lines.append(
                "\t".join(
                    [
                        f.host,
                        ",".join(f.ips),
                        str(f.status) if f.status is not None else "",
                        flags,
                        cert,
                        f.tech,
                        f.title or f.note,
                        ",".join(sorted(f.sources)),
                    ]
                )
            )
        target.write_text("\n".join(lines) + "\n")

    return len(findings)


# ------------------------------------------------------------------ html -- #

_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #0b0f14; color: #c9d5e0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
header { padding: 1.5rem 2rem 0.5rem; border-bottom: 2px solid #1b2733; }
pre.banner { margin: 0; color: #22d3ee; font-size: 6px; line-height: 1.1;
  overflow-x: auto; text-shadow: 0 0 12px #22d3ee55; }
.tagline { color: #556270; margin-top: .5rem; }
.stats { display: flex; gap: 1.5rem; padding: 1rem 2rem; flex-wrap: wrap; }
.stat { background: #101922; border: 1px solid #1b2733; border-radius: 8px;
  padding: .6rem 1rem; }
.stat b { display: block; font-size: 1.4rem; color: #22d3ee; }
.stat.warn b { color: #ffd166; }
.stat.bad b { color: #ff6b6b; }
main { padding: 0 2rem 3rem; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { text-align: left; color: #22d3ee; border-bottom: 2px solid #35485a;
  padding: .5rem .6rem; position: sticky; top: 0; background: #0b0f14; }
td { padding: .4rem .6rem; border-bottom: 1px solid #16202a; vertical-align: top; }
tr:nth-child(even) td { background: #0e141c; }
a { color: #22d3ee; text-decoration: none; }
a:hover { text-decoration: underline; }
.pill { display: inline-block; border-radius: 999px; padding: 0 .55rem;
  font-weight: 700; white-space: nowrap; }
.panel { background: #ffd16633; color: #ffd166; border: 1px solid #ffd16677; }
.takeover { background: #ff6b6b33; color: #ff6b6b; border: 1px solid #ff6b6b77; }
.cert { color: #ff6b6b; font-weight: 700; }
.wild { color: #89a; }
.muted { color: #556270; }
footer { padding: 1rem 2rem 2rem; color: #556270; font-size: 12px; }
"""


def _render_html(findings: list[Finding]) -> str:
    esc = html.escape
    live = sum(1 for f in findings if f.status and f.status < 400)
    panels = [f for f in findings if f.panel]
    takeovers = [f for f in findings if f.takeover]
    expiring = [f for f in findings if f.cert_days is not None and f.cert_days <= 30]

    stats = [
        (str(len(findings)), "findings", ""),
        (str(live), "live (<400)", ""),
        (str(len(panels)), "admin panels", "warn"),
        (str(len(takeovers)), "takeovers", "bad"),
        (str(len(expiring)), "certs ≤30d", "bad"),
    ]

    rows = []
    for f in sorted(findings, key=lambda x: ((x.takeover or x.panel or "") == "", x.host)):
        pills = ""
        if f.takeover:
            pills += f'<span class="pill takeover">⚠ {esc(f.takeover)}</span> '
        if f.panel:
            pills += f'<span class="pill panel">⚡ {esc(f.panel)}</span>'
        if f.kind == "wildcard":
            pills += ' <span class="pill wild">wildcard</span>'

        cert = ""
        if f.cert_days is not None:
            cls = "cert" if f.cert_days <= 30 else "muted"
            days = f"{f.cert_days}d" if f.cert_days >= 0 else f"{f.cert_days}d (expired)"
            cert = f'<span class="{cls}">cert {esc(days)}</span><br><span class="muted">{esc(f.cert_issuer)}</span>'

        url = f.url or (f"https://{f.host}/" if f.status else "")
        host_cell = f'<a href="{esc(url)}">{esc(f.host)}</a>' if url else esc(f.host)

        rows.append(
            "<tr>"
            f"<td>{esc(f.target)}</td>"
            f"<td>{host_cell}<br><span class='muted'>{esc(f.source_str)}</span></td>"
            f"<td>{esc(', '.join(f.ips))}</td>"
            f"<td>{f.status if f.status is not None else '—'}</td>"
            f"<td>{pills or '—'}</td>"
            f"<td>{cert}</td>"
            f"<td>{esc(f.tech)}<br><span class='muted'>{esc(f.sec)}</span></td>"
            f"<td>{esc(f.title or f.note)}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sunder report</title>
<style>{_CSS}</style>
</head>
<body>
<header>
<pre class="banner">{esc(SLIM)}</pre>
<div class="tagline">{esc(TAGLINE)}</div>
</header>
<div class="stats">
{''.join(f'<div class="stat {cls}"><b>{value}</b>{label}</div>' for value, label, cls in stats)}
</div>
<main>
<table>
<thead><tr>
<th>target</th><th>host</th><th>ip</th><th>http</th><th>flags</th><th>cert</th><th>tech / security</th><th>title</th>
</tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</main>
<footer>generated by sunder v{esc(__version__)} — authorized testing only</footer>
</body>
</html>
"""
