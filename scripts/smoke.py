"""Headless interaction test: splash -> scan -> tabs -> save -> @file parsing.

    .venv/bin/python scripts/smoke.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sunder.app import DetailScreen, MainScreen, SaveModal, SunderApp  # noqa: E402
from sunder.fingerprint import analyze_headers, detect_panel  # noqa: E402
from sunder.resolver import probe_host  # noqa: E402
from sunder.takeover import body_service, cname_service  # noqa: E402
from textual.widgets import DataTable, Input, Markdown, Static, TabbedContent  # noqa: E402


def test_fingerprints() -> None:
    cases = [
        # (url, title, body) -> expected panel
        ("https://x.tld/admin/", "Welcome", "", "admin path"),
        ("https://x.tld/login", "phpMyAdmin 5.2.1", "", "phpmyadmin"),
        ("https://x.tld/wp-login.php", "Log In", "", "wordpress"),
        ("https://x.tld/wp-admin/", "Log In", "", "wordpress"),
        ("https://x.tld/", "Grafana", "", "grafana"),
        ("https://x.tld/", "Login - Jenkins", "", "jenkins"),
        ("https://x.tld/dash/", "Admin Dashboard", "", "admin page"),
        ("https://x.tld/auth", "Sign in", '<input type="password">', "admin login"),
        ("https://x.tld/manager/html", "Tomcat", "", "tomcat manager"),
        ("https://x.tld/cpanel/", "", "", "cpanel"),
        # things that must NOT be flagged
        ("https://x.tld/", "My Blog", "", ""),
        ("https://x.tld/pricing", "Acme — Administration services for families", "", ""),
        ("https://x.tld/", "Customer Portal", '<input type="password">', ""),
    ]
    for url, title, body, expected in cases:
        got = detect_panel(url=url, title=title, body=body)
        assert got == expected, f"detect_panel({url!r}, {title!r}) = {got!r}, want {expected!r}"
    # "Administration services" must not trip the generic admin regex
    assert detect_panel(url="https://x.tld/", title="Acme — Administration services") == ""
    print(f"fingerprint ok: {len(cases)} cases")


def test_takeover() -> None:
    cname_cases = [
        ("dead-site.herokuapp.com", "heroku"),
        ("x.github.io", "github pages"),
        ("b.s3-website-us-east-1.amazonaws.com", "s3"),
        ("dangling.azurewebsites.net", "azure"),
        ("site.fastly.net", "fastly"),
        ("shop.myshopify.com", "shopify"),
        ("www.example.com", None),
        ("EXAMPLE.COM.", None),
        ("", None),
        (None, None),
    ]
    for cname, expected in cname_cases:
        got = cname_service(cname)  # type: ignore[arg-type]
        assert got == expected, f"cname_service({cname!r}) = {got!r}, want {expected!r}"

    body_cases = [
        ("There isn't a GitHub Pages site here.", "github pages"),
        ("NoSuchBucket: The specified bucket does not exist", "s3/aws"),
        ("<h1>No such app</h1>", "heroku"),
        ("Welcome to nginx!", None),
        ("", None),
    ]
    for body, expected in body_cases:
        got = body_service(body)
        assert got == expected, f"body_service({body!r}) = {got!r}, want {expected!r}"
    print(f"takeover ok: {len(cname_cases) + len(body_cases)} cases")


def test_header_audit() -> None:
    tech, sec = analyze_headers(
        {"server": "nginx/1.24.0", "set-cookie": "PHPSESSID=1"}, https=True
    )
    assert "nginx/1.24.0" in tech and "php" in tech, tech
    assert "server version exposed" in sec, sec
    assert "no-hsts" in sec and "no-csp" in sec, sec

    tech, sec = analyze_headers(
        {"server": "cloudflare", "cf-ray": "abc", "strict-transport-security": "max-age=1",
         "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff",
         "x-frame-options": "DENY"},
        https=True,
    )
    assert "cloudflare" in tech, tech
    assert sec == "", f"expected clean audit, got {sec!r}"

    # HSTS is meaningless over plain http — must not be flagged there.
    _, sec = analyze_headers({}, https=False)
    assert "no-hsts" not in sec, sec
    print("header audit ok")


async def test_records_live() -> None:
    from sunder.records import apex_records, try_axfr
    from sunder.resolver import make_resolver

    resolver = make_resolver()
    records = await apex_records("example.com", resolver)
    assert records.get("NS"), records
    assert records.get("MX") is not None, records  # key may be absent, but MX query must not crash
    axfr = await try_axfr("example.com", records["NS"], resolver)
    assert axfr is None or (isinstance(axfr, tuple) and len(axfr) == 2), axfr
    print(f"records ok: {sorted(records)} (axfr={'open' if axfr else 'closed'})")


async def test_probe_pipeline() -> None:
    """Serve fake admin pages locally and probe them for real."""
    import http.server
    import threading

    PAGES = {
        "/": "<html><head><title>Admin Panel</title></head><body>"
             "<form><input type='password'></form></body></html>",
        "/blog": "<html><head><title>Daily Blog</title></head><body>hi</body></html>",
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = PAGES.get(self.path.rstrip("/") or "/").encode()
            if not body:
                body = PAGES["/blog"].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        import httpx

        async with httpx.AsyncClient() as client:
            result = await probe_host(client, f"127.0.0.1:{port}")
        assert result.status == 200, result
        assert result.title == "Admin Panel", result.title
        assert result.panel == "admin page", result.panel
        print(f"probe pipeline ok: port {port} -> {result.panel!r}")
    finally:
        server.shutdown()


async def main() -> None:
    test_fingerprints()
    test_takeover()
    test_header_audit()
    await test_probe_pipeline()
    await test_records_live()

    app = SunderApp()
    async with app.run_test(size=(140, 42)) as pilot:
        await pilot.pause(0.5)
        assert app.screen.__class__.__name__ == "SplashScreen", app.screen
        await pilot.press("enter")  # dismiss splash
        await pilot.pause(0.5)
        screen = app.screen
        assert isinstance(screen, MainScreen), screen

        # @file parsing (no scan, just the parser)
        Path("/tmp/sunder-targets.txt").write_text(
            "# comment\nexample.com\n\nexample.com, https://www.example.com:443/x\nnot a target!!\n"
        )
        targets, bad = screen._parse_targets("@/tmp/sunder-targets.txt")
        names = [t.normalized for t in targets]
        assert names == ["example.com", "www.example.com"], names
        assert bad == ["not", "a", "target!!"], bad
        print(f"parse ok: {names} (skipped {bad})")

        # Real scan through the input bar.
        screen.query_one("#target", Input).value = "example.com"
        await pilot.press("enter")
        await pilot.pause(2.0)
        for _ in range(60):
            await pilot.pause(2.0)
            table = screen.query_one("#results", DataTable)
            if len(table.rows) > 0 and not screen._scanning:
                break
        table = screen.query_one("#results", DataTable)
        assert len(table.rows) > 0, "no findings streamed into the table"
        print(f"scan ok: {len(table.rows)} rows")

        # The records tab must have received apex records from the engine.
        # RichLog defers writes until it has a size, so open the tab first.
        screen.set_focus(None)
        await pilot.press("r")
        await pilot.pause(0.4)
        tabs = screen.query_one("#tabs", TabbedContent)
        assert tabs.active == "tab-records", tabs.active
        records_log = screen.query_one("#records")
        assert len(records_log.lines) > 0, "records tab is empty"
        print(f"records tab ok: {len(records_log.lines)} lines")
        tabs.active = "tab-results"
        await pilot.pause(0.4)

        # Filter: token "live" shows only sub-400 hosts, free text matches host.
        expected_live = sum(1 for f in screen.findings if f.status and f.status < 400)
        filt = screen.query_one("#filter", Input)
        filt.value = "live"
        await pilot.pause(0.4)
        assert len(table.rows) == expected_live, (len(table.rows), expected_live)
        filt.value = "___no_such_host___"
        await pilot.pause(0.4)
        assert len(table.rows) == 0, len(table.rows)
        filt.value = ""
        await pilot.pause(0.4)
        assert len(table.rows) == len(screen.findings), (
            len(table.rows),
            len(screen.findings),
        )
        print(f"filter ok (live={expected_live})")

        # Sorting: header-click path rebuilds rows in sorted order, toggle reverses.
        screen.set_focus(None)
        screen._sort_by("c-host")
        await pilot.pause(0.3)
        hosts = [str(k.value) for k in table.rows]
        assert hosts == sorted(hosts), hosts[:5]
        screen._sort_by("c-host")  # second click flips direction
        await pilot.pause(0.3)
        hosts_rev = [str(k.value) for k in table.rows]
        assert hosts_rev == list(reversed(hosts)), (hosts_rev[:3], hosts[:3])
        screen._sort = (None, False)
        screen._rebuild_table()
        await pilot.pause(0.3)
        print("sort ok")

        # Detail view: enter on a focused row opens exactly one DetailScreen.
        screen.set_focus(table)
        await pilot.pause(0.3)
        await pilot.press("enter")
        await pilot.pause(0.5)
        details = [s for s in app.screen_stack if isinstance(s, DetailScreen)]
        assert len(details) == 1, f"expected 1 detail screen, got {len(details)}"
        assert isinstance(app.screen, DetailScreen), app.screen
        assert screen.findings, "no findings for detail view"
        body = app.screen.query_one("#detail-body", Markdown).source
        assert "**target:**" in body and details[0].finding.host, body[:200]
        await pilot.press("escape")
        await pilot.pause(0.4)
        assert isinstance(app.screen, MainScreen), app.screen
        print("detail ok")

        # Takeover cell styling + status bar counts.
        from sunder.models import Finding

        fake_take = Finding(
            target="example.com",
            host="claimme.example.com",
            sources={"crt.sh"},
            resolved=True,
            cname="claimme.herokuapp.com",
            takeover="heroku (dangling)",
        )
        screen._on_finding(fake_take)
        await pilot.pause(0.3)
        screen._refresh_status()
        status = str(screen.query_one("#status", Static).content)
        assert "1 takeover" in status, status
        flag = screen._flag_cell(fake_take)
        assert "⚠ heroku (dangling)" in flag.plain, flag.plain
        spans = flag.spans
        assert spans, "flag cell has no style spans"
        style = str(spans[0].style)
        assert "bold" in style and ("red" in style or "ff6b6b" in style), style
        print("takeover highlight ok")

        # Theme cycling.
        screen.set_focus(None)
        theme_before = app.theme
        await pilot.press("t")
        await pilot.pause(0.4)
        assert app.theme != theme_before, (theme_before, app.theme)
        print(f"theme ok: {theme_before} -> {app.theme}")

        # Tab keybindings (input must not have focus for single-key bindings).
        screen.set_focus(None)
        await pilot.press("l")
        await pilot.pause(0.3)
        tabs = screen.query_one("#tabs", TabbedContent)
        assert tabs.active == "tab-log", tabs.active
        await pilot.press("h")
        await pilot.pause(0.3)
        assert tabs.active == "tab-help", tabs.active
        print("tab bindings ok")

        # Save modal via the "s" key.
        import os

        if os.path.exists("/tmp/sunder-smoke-out.json"):
            os.remove("/tmp/sunder-smoke-out.json")
        await pilot.press("s")
        await pilot.pause(0.5)
        assert isinstance(app.screen, SaveModal), app.screen
        app.screen.query_one("#save-path", Input).value = "/tmp/sunder-smoke-out.json"
        await pilot.press("enter")
        await pilot.pause(0.5)
        assert Path("/tmp/sunder-smoke-out.json").is_file(), "export file missing"
        print("save ok")

        # HTML report via the same save path (extension picks the format).
        from sunder.export import save as export_save

        count = export_save(screen.findings, "/tmp/sunder-smoke-out.html")
        html_text = Path("/tmp/sunder-smoke-out.html").read_text()
        assert count == len(screen.findings)
        assert "<html" in html_text and "sunder report" in html_text
        assert screen.findings[0].host in html_text
        print("html export ok")

        print("smoke ok")


if __name__ == "__main__":
    asyncio.run(main())
