"""The sunder TUI: splash screen, target input, live results, log, export."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import ClassVar

from rich.table import Table as RichTable
from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    Label,
    LoadingIndicator,
    Markdown,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from . import __version__, export
from .engine import Engine, Options
from .logo import SLIM, SPINNER_FRAMES, TAGLINE, gradient
from .models import Finding, Target, classify

SPLIT_RE = re.compile(r"[,\s;]+")

SOURCE_TOGGLES = [
    ("crtsh", "crt.sh"),
    ("wayback", "wayback"),
    ("hackertarget", "hackertarget"),
    ("bruteforce", "dns brute"),
    ("records", "dns records"),
    ("resolve", "resolve dns"),
    ("probe", "http probe"),
    ("admin", "flag admin"),
    ("takeover", "takeover"),
    ("cert", "cert expiry"),
]

LEVEL_COLORS = {
    "run": "#5b7f99",
    "ok": "#7fd77f",
    "warn": "#ffd166",
    "err": "#ff6b6b",
}

SORT_GETTERS = {
    "c-target": lambda f: f.target,
    "c-host": lambda f: f.host,
    "c-src": lambda f: f.source_str,
    "c-ip": lambda f: f.ips[0] if f.ips else "",
    "c-http": lambda f: f.status or -1,
    "c-flag": lambda f: (f.takeover or f.panel),
    "c-title": lambda f: f.title or f.note,
}

HELP_TEXT = """\
[b bold #22d3ee]WHAT THIS DOES[/]

  sunder takes a domain (or IP, or a pile of both) and splits it apart into
  every subdomain it can find, using a mix of passive intel and active DNS:

  [b]crt.sh[/]         certificate transparency logs — names people issued TLS certs for
  [b]wayback[/]        the wayback machine index — hosts seen in archived URLs
  [b]hackertarget[/]   passive DNS host search (free tier)
  [b]dns brute[/]      resolve a wordlist against the domain (queries public resolvers only)
  [b]dns records[/]    apex NS/MX/TXT/SPF/DMARC/CAA/SOA + an AXFR zone transfer attempt
  [b]resolve dns[/]    A/AAAA + CNAME lookup for every hit
  [b]http probe[/]     https/http status + page title for live hosts
  [b]flag admin[/]     fingerprint admin panels and login surfaces from the
                       probe response — phpmyadmin, grafana, jenkins, wordpress
                       logins, /admin paths, password forms, and more
  [b]takeover[/]       dangling CNAMEs and dead-service pages (heroku, github
                       pages, s3, azure, fastly, shopify …) flagged as claimable
  [b]cert expiry[/]    live TLS cert intel: issuer, expiry countdown, SAN count

  Every live host also gets a tech fingerprint and security header audit
  (server/php/cloudflare detection, missing HSTS/CSP/XCTO/XFO).

  IP targets get a different treatment: PTR reverse lookup, RDAP registration
  data and Team Cymru ASN info. IPs cannot have subdomains, so sunder shows
  what the address actually is instead.

[b bold #22d3ee]INPUT[/]

  type targets in the bar, separated by commas or spaces:
      [i]example.com, 10.0.0.5, sub.example.org[/]
  or load a file (one target per line, # comments allowed):
      [i]@targets.txt[/]
  a wordlist file can be supplied for the brute phase — anything else uses the
  embedded high-signal list.

[b bold #22d3ee]FILTER[/]

  the filter box accepts free text (matches host, ip, title, flags) or one of
  these tokens: [b]live[/] · [b]flagged[/] · [b]admin[/] · [b]takeover[/] · [b]expiring[/]
  click any column header to sort by it.

[b bold #22d3ee]KEYS[/]

  [b]enter[/]    start the scan (or open the selected row's detail view)
  [b]o[/]        open the selected host in your browser
  [b]s[/]        save/export findings (json, csv, txt or html)
  [b]c[/]        clear results and log
  [b]l[/]        jump to the log tab
  [b]r[/]        jump to the records tab
  [b]h[/]        jump to this help tab
  [b]t[/]        cycle color theme
  [b]q[/]        quit

[bold #ffd166]Only scan targets you own or have explicit permission to test.[/]
"""


class SplashScreen(Screen):
    """Full-bleed gradient banner before the main interface."""

    def compose(self) -> ComposeResult:
        yield Static(gradient(SLIM), id="splash-banner")
        yield Static(TAGLINE, id="splash-tagline")
        yield Static("press [b #22d3ee]enter[/] to begin   ·   [b]q[/] to bail", id="splash-hint")

    def on_mount(self) -> None:
        self._blink = 0
        self.set_interval(0.6, self._pulse)

    def _pulse(self) -> None:
        self._blink += 1
        hint = self.query_one("#splash-hint", Static)
        hint.styles.opacity = 1.0 if self._blink % 2 else 0.35

    async def on_key(self, event: events.Key) -> None:
        if event.key == "q":
            self.app.exit()
        elif event.key in ("enter", "space"):
            event.stop()
            self.app.pop_screen()


class SaveModal(ModalScreen[str | None]):
    def __init__(self, default_name: str) -> None:
        super().__init__()
        self.default_name = default_name

    def compose(self) -> ComposeResult:
        with Vertical(id="save-dialog"):
            yield Label("export findings", id="save-title")
            yield Input(value=self.default_name, id="save-path")
            yield Label("extension picks the format: .json / .csv / .txt / .html", id="save-hint")
            with Horizontal(id="save-buttons"):
                yield Button("save", variant="primary", id="save-go")
                yield Button("cancel", id="save-cancel")

    def on_mount(self) -> None:
        self.query_one("#save-path", Input).focus()

    def _accept(self) -> None:
        value = self.query_one("#save-path", Input).value.strip()
        self.dismiss(value or None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "save-path":
            self._accept()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-go":
            self._accept()
        else:
            self.dismiss(None)

    async def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            self.dismiss(None)


class DetailScreen(ModalScreen[None]):
    """Everything sunder knows about one host, with a clickable link."""

    BINDINGS: ClassVar = [
        ("escape", "dismiss_it", "Close"),
        ("enter", "dismiss_it", "Close"),
        ("q", "dismiss_it", "Close"),
        ("o", "open_it", "Open"),
    ]

    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def _url(self) -> str:
        return self.finding.url or f"https://{self.finding.host}/"

    def compose(self) -> ComposeResult:
        f = self.finding
        rows: list[tuple[str, str]] = [
            ("target", f.target),
            ("kind", f.kind),
            ("sources", f.source_str),
            ("ips", ", ".join(f.ips)),
            ("http", f"{f.status} ({f.scheme})" if f.status is not None else ""),
            ("panel", f.panel),
            ("takeover", f.takeover),
            ("cname", f.cname),
            (
                "cert",
                f"{f.cert_issuer} · {f.cert_days}d left · {f.cert_sans} SANs"
                if f.cert_days is not None
                else "",
            ),
            ("tech", f.tech),
            ("security", f.sec),
            ("title", f.title),
        ]
        body = "\n".join(f"**{key}:** {value}" for key, value in rows if value)
        with Vertical(id="detail-dialog"):
            yield Label(f.host, id="detail-title")
            yield Markdown(body, id="detail-body", open_links=False)
            yield Markdown(f"[→ open {self._url()}]({self._url()})", id="detail-link", open_links=False)
            yield Label("enter/o open in browser  ·  esc close", id="detail-hint")

    def action_dismiss_it(self) -> None:
        self.dismiss()

    def action_open_it(self) -> None:
        self.app.open_url(self._url())
        self.notify(f"opening {self._url()}")

    def on_markdown_link_clicked(self, event: Markdown.LinkClicked) -> None:
        event.stop()
        self.app.open_url(event.href)
        self.notify(f"opening {event.href}")


class MainScreen(Screen):
    BINDINGS: ClassVar = [
        ("enter", "start_scan", "Scan"),
        ("o", "open_row", "Open"),
        ("s", "save", "Save"),
        ("c", "clear", "Clear"),
        ("l", "show_log", "Log"),
        ("r", "show_records", "Records"),
        ("h", "show_help", "Help"),
        ("t", "cycle_theme", "Theme"),
        ("q", "quit_app", "Quit"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(
        self,
        prefill: list[str] | None = None,
        options: Options | None = None,
        theme: str | None = None,
    ) -> None:
        super().__init__()
        self.prefill = prefill or []
        self.options = options or Options()
        self.theme_name = theme

    # ------------------------------------------------------------------ #

    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Static(gradient(SLIM), id="logo")
            with Vertical(id="topbar-right"):
                yield Static(f"v{__version__}  ·  {TAGLINE}", id="tagline")
                yield Static("split a domain, find what lives under it.", id="subtag")
        with Horizontal(id="inputbar"):
            yield Input(
                placeholder="example.com, 10.0.0.5, @targets.txt …", id="target"
            )
            yield Button("SCAN", variant="primary", id="scan")
        with Horizontal(id="optionbar"):
            for key, label in SOURCE_TOGGLES:
                yield Checkbox(label, value=getattr(self.options, key), id=f"src-{key}")
            yield Input(placeholder="wordlist file (optional)", id="wordlist")
        with TabbedContent(id="tabs"):
            with TabPane("results", id="tab-results"):
                yield Input(
                    placeholder="filter…  (live / flagged / admin / takeover / expiring / text)",
                    id="filter",
                )
                yield DataTable(id="results")
            yield TabPane("records", RichLog(wrap=False, id="records"), id="tab-records")
            yield TabPane("log", RichLog(wrap=True, highlight=True, id="log"), id="tab-log")
            yield TabPane("help", Static(HELP_TEXT, id="help"), id="tab-help")
        with Horizontal(id="statusbar"):
            yield LoadingIndicator(id="spinner")
            yield Static("idle — enter a target above", id="status")

    # ------------------------------------------------------------------ #

    def on_mount(self) -> None:
        table = self.query_one("#results", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("TARGET", key="c-target", width=16)
        table.add_column("SUBDOMAIN", key="c-host", width=42)
        table.add_column("SOURCE", key="c-src", width=20)
        table.add_column("IP", key="c-ip", width=28)
        table.add_column("HTTP", key="c-http", width=6)
        table.add_column("FLAGS", key="c-flag", width=24)
        table.add_column("TITLE / ORG", key="c-title", width=40)

        self._rowmap: dict[str, object] = {}
        self.findings: list[Finding] = []
        self._sort: tuple[str | None, bool] = (None, False)
        self._scanning = False
        self._tick = 0
        self._ntargets = 0
        self._start = 0.0
        self._status_timer = None
        self._engine: Engine | None = None

        if self.prefill:
            self.query_one("#target", Input).value = ", ".join(self.prefill)
        self.query_one("#target", Input).focus()

        # Restore anything the user disabled via CLI flags.
        for key, _ in SOURCE_TOGGLES:
            self.query_one(f"#src-{key}", Checkbox).value = getattr(self.options, key)

        if self.theme_name:
            try:
                self.app.theme = self.theme_name
            except Exception:
                pass

    # ------------------------------------------------------------------ #

    def _log(self, source: str, level: str, message: str) -> None:
        log = self.query_one("#log", RichLog)
        color = LEVEL_COLORS.get(level, "#9fb3c8")
        stamp = time.strftime("%H:%M:%S")
        log.write(
            f"[dim]{stamp}[/] [{color}][{source:<10}][/] {message}"
        )

    def _on_records(
        self, domain: str, records: dict[str, list[str]], axfr: tuple[str, int] | None
    ) -> None:
        table = RichTable(
            show_header=False, box=None, title=domain, title_style="bold cyan", padding=(0, 2)
        )
        table.add_column(style="cyan", no_wrap=True)
        table.add_column()
        for key, values in records.items():
            for i, value in enumerate(values):
                table.add_row(key if i == 0 else "", value)
        if axfr:
            table.add_row("AXFR", f"[bold red]OPEN on {axfr[0]} — {axfr[1]} entries[/]")
        self.query_one("#records", RichLog).write(table)

    # ------------------------------------------------------------------ #

    @staticmethod
    def _host_cell(finding: Finding) -> Text | str:
        if finding.takeover:
            return Text(finding.host, style="bold #ff6b6b")
        if finding.panel:
            return Text(finding.host, style="bold #ffd166")
        return finding.host

    @staticmethod
    def _flag_cell(finding: Finding) -> Text | str:
        text = Text()
        if finding.takeover:
            text.append(f"⚠ {finding.takeover}", style="bold #ff6b6b")
        if finding.panel:
            if text.plain:
                text.append(" · ")
            text.append(f"⚡ {finding.panel}", style="bold #ffd166")
        return text if text.plain else "—"

    @staticmethod
    def _title_cell(finding: Finding) -> Text | str:
        base = finding.title or finding.note or ""
        if finding.cert_days is not None and finding.cert_days <= 30:
            label = " ⛔cert expired" if finding.cert_days < 0 else f" ⏳cert {finding.cert_days}d"
            text = Text(base)
            text.append(label, style="bold #ff6b6b")
            return text
        return base

    def _add_row(self, finding: Finding) -> object:
        table = self.query_one("#results", DataTable)
        row = table.add_row(
            finding.target,
            self._host_cell(finding),
            finding.source_str,
            ", ".join(finding.ips) or "—",
            "—",
            self._flag_cell(finding),
            self._title_cell(finding),
            key=finding.host,
        )
        self._rowmap[finding.host] = row
        return row

    def _on_finding(self, finding: Finding) -> None:
        row = self._rowmap.get(finding.host)
        if row is None:
            self.findings.append(finding)
            self._add_row(finding)
        else:
            table = self.query_one("#results", DataTable)
            table.update_cell(row, "c-host", self._host_cell(finding), update_width=True)
            table.update_cell(row, "c-src", finding.source_str)
            table.update_cell(row, "c-ip", ", ".join(finding.ips) or "—", update_width=True)
            table.update_cell(row, "c-http", str(finding.status) if finding.status is not None else "—")
            table.update_cell(row, "c-flag", self._flag_cell(finding))
            table.update_cell(row, "c-title", self._title_cell(finding), update_width=True)

    # ------------------------------------------------------------------ #

    def _visible_findings(self) -> list[Finding]:
        text = self.query_one("#filter", Input).value.strip().lower()
        rows = self.findings
        if text == "live":
            rows = [f for f in rows if f.status and f.status < 400]
        elif text == "flagged":
            rows = [f for f in rows if f.panel or f.takeover]
        elif text == "admin":
            rows = [f for f in rows if f.panel]
        elif text == "takeover":
            rows = [f for f in rows if f.takeover]
        elif text == "expiring":
            rows = [f for f in rows if f.cert_days is not None and f.cert_days <= 30]
        elif text:
            rows = [
                f
                for f in rows
                if text
                in f"{f.target} {f.host} {' '.join(f.ips)} {f.title} {f.panel} {f.takeover}".lower()
            ]

        key, reverse = self._sort
        if key and key in SORT_GETTERS:
            getter = SORT_GETTERS[key]
            rows = sorted(rows, key=lambda f: (getter(f) is None, getter(f)), reverse=reverse)
        return rows

    def _rebuild_table(self) -> None:
        table = self.query_one("#results", DataTable)
        table.clear()
        self._rowmap.clear()
        for finding in self._visible_findings():
            self._add_row(finding)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self._rebuild_table()

    def _sort_by(self, column: str) -> None:
        if column not in SORT_GETTERS:
            return
        if self._sort[0] == column:
            self._sort = (column, not self._sort[1])
        else:
            self._sort = (column, False)
        self._rebuild_table()

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        column = (
            str(event.column_key.value)
            if hasattr(event.column_key, "value")
            else str(event.column_key)
        )
        self._sort_by(column)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        host = str(event.row_key.value)
        finding = next((f for f in self.findings if f.host == host), None)
        if finding:
            self.app.push_screen(DetailScreen(finding))

    # ------------------------------------------------------------------ #

    def _parse_targets(self, raw: str) -> tuple[list[Target], list[str]]:
        text = raw.strip()
        if text.startswith("@"):
            path = Path(text[1:]).expanduser()
            if not path.is_file():
                self.notify(f"no such file: {path}", severity="error")
                return [], []
            text = path.read_text(errors="ignore")

        # Strip comments (# ...) before splitting on separators.
        text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
        parts = [p for p in SPLIT_RE.split(text) if p]
        targets: list[Target] = []
        bad: list[str] = []
        seen: set[str] = set()
        for part in parts:
            target = classify(part)
            if target is None:
                bad.append(part)
            elif target.normalized not in seen:
                seen.add(target.normalized)
                targets.append(target)
        return targets, bad

    def _load_wordlist(self) -> list[str] | None:
        path = self.query_one("#wordlist", Input).value.strip()
        if not path:
            return None
        p = Path(path).expanduser()
        if not p.is_file():
            self.notify(f"wordlist not found: {path} — using embedded list", severity="warning")
            return None
        words = []
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
        return list(dict.fromkeys(words))

    def _build_options(self) -> Options:
        opts = Options()
        for key, _ in SOURCE_TOGGLES:
            setattr(opts, key, self.query_one(f"#src-{key}", Checkbox).value)
        words = self._load_wordlist()
        if words:
            opts.wordlist = words
        return opts

    def action_start_scan(self) -> None:
        # Enter on a focused table opens details instead of scanning.
        if isinstance(self.focused, DataTable):
            self.action_open_detail()
            return

        raw = self.query_one("#target", Input).value
        targets, bad = self._parse_targets(raw)
        if bad:
            self._log("input", "warn", f"skipping garbage: {', '.join(bad)}")
            self.notify(f"{len(bad)} invalid input(s) ignored", severity="warning")
        if not targets:
            self.notify("give me at least one domain or IP", severity="error")
            return
        if self._scanning:
            self.notify("already scanning — wait for it to finish", severity="warning")
            return

        self.query_one("#results", DataTable).clear()
        self._rowmap.clear()
        self.findings.clear()
        self.query_one("#records", RichLog).clear()
        self._ntargets = len(targets)
        self._start = time.monotonic()
        self._scanning = True
        self.query_one("#spinner", LoadingIndicator).display = True
        self._log("engine", "run", f"scan started on {len(targets)} target(s): "
                 + ", ".join(t.normalized for t in targets))
        self._status_timer = self.set_interval(0.4, self._refresh_status)
        self.run_work_scan(targets, self._build_options())

    @work(exclusive=True, group="scan")
    async def run_work_scan(self, targets: list[Target], opts: Options) -> None:
        engine = Engine(
            opts, on_log=self._log, on_finding=self._on_finding, on_records=self._on_records
        )
        self._engine = engine
        try:
            await engine.run(targets)
            self._log("engine", "ok", f"done — {len(self.findings)} findings")
            self.notify(f"scan complete — {len(self.findings)} findings", timeout=6000)
        except Exception as exc:
            self._log("engine", "err", f"scan failed: {type(exc).__name__}: {exc}")
            self.notify(f"scan failed: {exc}", severity="error")
        finally:
            self._scanning = False
            if self._status_timer:
                self._status_timer.stop()
            self.query_one("#spinner", LoadingIndicator).display = False
            self._refresh_status()

    # ------------------------------------------------------------------ #

    def _refresh_status(self) -> None:
        found = len(self.findings)
        resolved = sum(1 for f in self.findings if f.resolved)
        live = sum(1 for f in self.findings if f.status and f.status < 400)
        panels = sum(1 for f in self.findings if f.panel)
        takeovers = sum(1 for f in self.findings if f.takeover)
        elapsed = (time.monotonic() - self._start) if self._start else 0.0

        if self._scanning:
            frame = SPINNER_FRAMES[self._tick % len(SPINNER_FRAMES)]
            self._tick += 1
            state = f"[#22d3ee]{frame} scanning[/]"
        else:
            state = "[#7fd77f]✓ done[/]" if self._start else "idle"

        flags = ""
        if panels:
            flags += f"  ·  [#ffd166]⚡ {panels} panel{'s' if panels != 1 else ''}[/]"
        if takeovers:
            flags += f"  ·  [#ff6b6b]⚠ {takeovers} takeover{'s' if takeovers != 1 else ''}[/]"

        self.query_one("#status", Static).update(
            f" {state}  ·  targets {self._ntargets}  ·  found [b]{found}[/b]"
            f"  ·  resolved {resolved}  ·  live {live}{flags}  ·  {elapsed:.0f}s"
        )

    # ------------------------------------------------------------------ #

    def _cursor_finding(self) -> Finding | None:
        table = self.query_one("#results", DataTable)
        if not table.rows:
            return None
        row_keys = list(table.rows)
        index = min(table.cursor_row, len(row_keys) - 1)
        host = str(row_keys[index].value)
        return next((f for f in self.findings if f.host == host), None)

    def action_open_row(self) -> None:
        finding = self._cursor_finding()
        if not finding:
            self.notify("no row selected", severity="warning")
            return
        url = finding.url or f"https://{finding.host}/"
        self.app.open_url(url)
        self.notify(f"opening {url}")

    def action_open_detail(self) -> None:
        finding = self._cursor_finding()
        if finding:
            self.app.push_screen(DetailScreen(finding))

    def action_cycle_theme(self) -> None:
        themes = sorted(self.app.available_themes)
        current = self.app.theme
        index = themes.index(current) if current in themes else -1
        nxt = themes[(index + 1) % len(themes)]
        self.app.theme = nxt
        self.notify(f"theme: {nxt}")

    def action_save(self) -> None:
        if not self.findings:
            self.notify("nothing to save yet", severity="warning")
            return
        default = f"sunder-{time.strftime('%Y%m%d-%H%M%S')}.json"
        self.app.push_screen(SaveModal(default), self._save_done)

    def _save_done(self, path: str | None) -> None:
        if not path:
            return
        try:
            count = export.save(self.findings, path)
        except OSError as exc:
            self.notify(f"could not write {path}: {exc}", severity="error")
            return
        self._log("export", "ok", f"wrote {count} findings to {path}")
        self.notify(f"saved {count} findings → {path}", timeout=6000)

    def action_clear(self) -> None:
        self.query_one("#results", DataTable).clear()
        self.query_one("#log", RichLog).clear()
        self.query_one("#records", RichLog).clear()
        self._rowmap.clear()
        self.findings.clear()
        self._ntargets = 0
        self._start = 0.0
        self._refresh_status()

    def action_show_log(self) -> None:
        self._show_tab("tab-log")

    def action_show_records(self) -> None:
        self._show_tab("tab-records")

    def action_show_help(self) -> None:
        self._show_tab("tab-help")

    def _show_tab(self, pane_id: str) -> None:
        self.query_one("#tabs", TabbedContent).active = pane_id

    def action_quit_app(self) -> None:
        self.app.exit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "target":
            self.action_start_scan()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan":
            self.action_start_scan()


class SunderApp(App):
    TITLE = "sunder"
    SUB_TITLE = "subdomain enumeration"
    HEADER = False

    CSS = """
    Screen {
        background: #0b0f14;
        color: #c9d5e0;
    }

    #topbar {
        layout: horizontal;
        height: 3;
        background: #0e141c;
        padding: 0 2;
    }
    #logo { height: 3; width: auto; content-align: left middle; }
    #topbar-right { height: 3; padding: 0 2; }
    #tagline { color: #22d3ee; text-style: bold; }
    #subtag { color: #556270; }

    #inputbar {
        layout: horizontal;
        height: 3;
        padding: 0 2;
        background: #0e141c;
    }
    Input#target {
        width: 1fr;
        background: #0d151d;
        border: none;
        border-bottom: tall #22d3ee;
    }
    Button#scan { width: 14; margin: 0 1; }

    #optionbar {
        layout: horizontal;
        height: 3;
        padding: 0 2;
        background: #0e141c;
    }
    Checkbox { background: #0e141c; margin: 0 1 0 0; }
    Input#wordlist {
        width: 30;
        background: #0d151d;
        border: none;
        border-bottom: tall #35485a;
    }

    #tabs { height: 1fr; }
    TabbedContent { background: #0b0f14; }
    TabPane { background: #0b0f14; padding: 0 1; }
    Input#filter {
        height: 3;
        background: #0d151d;
        border: none;
        border-bottom: tall #35485a;
    }
    DataTable#results { height: 1fr; background: #0b0f14; }
    RichLog#log { background: #0a1016; border: round #1b2733; }
    RichLog#records { background: #0a1016; border: round #1b2733; }
    Static#help { padding: 1 2; }

    #statusbar {
        layout: horizontal;
        height: 3;
        background: #12202b;
        padding: 0 1;
    }
    LoadingIndicator { display: none; height: 3; width: 4; }
    #status { height: 3; content-align: left middle; color: #89a; }

    #splash-banner {
        width: 100%;
        height: auto;
        content-align: center middle;
        margin: 2 0 0 0;
    }
    #splash-tagline {
        width: 100%;
        height: 3;
        content-align: center middle;
        color: #7c8aa0;
    }
    #splash-hint {
        width: 100%;
        height: 3;
        content-align: center middle;
    }

    SaveModal { align: center middle; background: #0b0f14cc; }
    #save-dialog {
        width: 70;
        height: 11;
        background: #101922;
        border: round #22d3ee;
        padding: 1 2;
    }
    #save-title { text-style: bold; color: #22d3ee; }
    #save-hint { color: #556270; }
    #save-buttons { height: 3; margin-top: 1; }
    #save-buttons Button { margin-right: 1; }

    DetailScreen { align: center middle; background: #0b0f14aa; }
    #detail-dialog {
        width: 94;
        max-width: 100%;
        height: auto;
        max-height: 92%;
        background: #101922;
        border: round #22d3ee;
        padding: 1 2;
    }
    #detail-title { text-style: bold; color: #22d3ee; }
    #detail-body { background: #101922; height: auto; max-height: 20; }
    #detail-link { background: #101922; color: #22d3ee; }
    #detail-hint { color: #556270; }
    """

    BINDINGS: ClassVar = [
        ("ctrl+q", "quit", "Quit"),
    ]

    def __init__(
        self,
        prefill: list[str] | None = None,
        options: Options | None = None,
        theme: str | None = None,
    ) -> None:
        super().__init__()
        self.prefill = prefill
        self.options = options or Options()
        self._requested_theme = theme
        if theme and theme in self.available_themes:
            self.theme = theme

    def on_mount(self) -> None:
        if "nord" in self.available_themes:
            self.theme = "nord"
        if self._requested_theme and self._requested_theme in self.available_themes:
            self.theme = self._requested_theme
        self.push_screen(MainScreen(self.prefill, self.options))
        self.push_screen(SplashScreen())
