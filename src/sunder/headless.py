"""Non-TUI mode for scripting: rich console output, same engine."""

from __future__ import annotations

import asyncio
import time

from rich.console import Console
from rich.table import Table

from . import export
from .engine import Engine, Options
from .logo import SLIM, TAGLINE, gradient
from .models import Finding, Target

LEVEL_COLORS = {
    "run": "dim",
    "ok": "green",
    "warn": "yellow",
    "err": "red",
}


def run(targets: list[Target], opts: Options, output: str | None) -> int:
    console = Console()
    console.print(gradient(SLIM))
    console.print(f"  [dim]{TAGLINE}[/]\n")

    findings: dict[str, Finding] = {}
    records_out: list[tuple[str, dict[str, list[str]], tuple[str, int] | None]] = []

    def on_log(source: str, level: str, message: str) -> None:
        color = LEVEL_COLORS.get(level, "white")
        console.print(
            f"[dim]{time.strftime('%H:%M:%S')}[/] [{color}][{source:<10}][/] {message}"
        )

    def on_finding(finding: Finding) -> None:
        findings[f"{finding.target}|{finding.host}"] = finding

    def on_records(
        domain: str, records: dict[str, list[str]], axfr: tuple[str, int] | None
    ) -> None:
        records_out.append((domain, records, axfr))

    engine = Engine(opts, on_log=on_log, on_finding=on_finding, on_records=on_records)
    asyncio.run(engine.run(targets))

    for domain, records, axfr in records_out:
        rtable = Table(title=f"apex records — {domain}", header_style="bold cyan")
        rtable.add_column("TYPE", style="cyan", no_wrap=True)
        rtable.add_column("VALUE", overflow="ellipsis")
        for key, values in records.items():
            for i, value in enumerate(values):
                rtable.add_row(key if i == 0 else "", value)
        if axfr:
            rtable.add_row("AXFR", f"[bold red]OPEN on {axfr[0]} — {axfr[1]} entries[/]")
        console.print()
        console.print(rtable)

    rows = sorted(findings.values(), key=lambda f: (f.target, f.kind == "ip", f.host))

    table = Table(title=f"{len(rows)} findings", header_style="bold cyan")
    table.add_column("TARGET", max_width=16, no_wrap=True, overflow="ellipsis")
    table.add_column("HOST", max_width=38, no_wrap=True, overflow="ellipsis")
    table.add_column("SOURCE", max_width=18, no_wrap=True, overflow="ellipsis")
    table.add_column("IP", max_width=30, no_wrap=True, overflow="ellipsis")
    table.add_column("HTTP", max_width=6, justify="right")
    table.add_column("FLAGS", max_width=24, no_wrap=True, overflow="ellipsis")
    table.add_column("TITLE / ORG", max_width=40, no_wrap=True, overflow="ellipsis")
    for f in rows:
        flags = " · ".join(
            x
            for x in (
                f"[bold red]⚠ {f.takeover}[/]" if f.takeover else "",
                f"[bold yellow]⚡ {f.panel}[/]" if f.panel else "",
            )
            if x
        )
        title = f.title or f.note
        if f.cert_days is not None and f.cert_days <= 30:
            badge = "expired" if f.cert_days < 0 else f"{f.cert_days}d"
            title = f"[bold red]cert {badge}[/] {title}"
        table.add_row(
            f.target,
            f.host,
            f.source_str,
            ", ".join(f.ips),
            str(f.status) if f.status is not None else "",
            flags,
            title,
        )
    console.print()
    console.print(table)

    if output:
        count = export.save(list(findings.values()), output)
        console.print(f"\n[green]saved {count} findings → {output}[/]")
    return len(rows)
