"""Capture SVG screenshots of the TUI for visual inspection.

    .venv/bin/python scripts/shots.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sunder.app import SunderApp  # noqa: E402
from textual.widgets import DataTable, Input  # noqa: E402


async def main() -> None:
    app = SunderApp()
    async with app.run_test(size=(140, 42)) as pilot:
        await pilot.pause(1.0)
        app.save_screenshot("/tmp/sunder-splash.svg")

        await pilot.press("enter")
        await pilot.pause(0.5)

        app.screen.query_one("#target", Input).value = "example.com"
        await pilot.press("enter")

        for _ in range(90):
            await pilot.pause(2.0)
            table = app.screen.query_one("#results", DataTable)
            if len(table.rows) > 0 and not app.screen._scanning:
                break

        await pilot.pause(0.5)
        app.save_screenshot("/tmp/sunder-main.svg")

        # Apex records tab (real data from the engine's AXFR/records job).
        app.screen._show_tab("tab-records")
        await pilot.pause(0.6)
        app.save_screenshot("/tmp/sunder-records.svg")
        app.screen._show_tab("tab-results")

        # Inject fake flagged findings so takeover/panel/cert styling gets captured.
        from sunder.models import Finding

        fake = Finding(
            target="example.com",
            host="db-admin.example.com",
            sources={"crt.sh", "brute"},
            ips=["104.20.23.154"],
            resolved=True,
            status=200,
            url="https://db-admin.example.com/phpmyadmin/",
            title="phpMyAdmin 5.2.1",
            panel="phpmyadmin",
        )
        app.screen._on_finding(fake)
        dangling = Finding(
            target="example.com",
            host="claimme.example.com",
            sources={"crt.sh"},
            resolved=True,
            cname="claimme.herokuapp.com",
            takeover="heroku (dangling)",
            note="dangling cname",
        )
        app.screen._on_finding(dangling)
        expiring = Finding(
            target="example.com",
            host="legacy.example.com",
            sources={"wayback"},
            ips=["104.20.23.154"],
            resolved=True,
            status=200,
            url="https://legacy.example.com/",
            title="Legacy Portal",
            cert_days=9,
            cert_issuer="Let's Encrypt",
            tech="nginx, php",
            sec="no-csp",
        )
        app.screen._on_finding(expiring)
        await pilot.pause(0.5)
        app.save_screenshot("/tmp/sunder-flagged.svg")

        # Detail modal with the clickable link.
        table = app.screen.query_one("#results", DataTable)
        app.screen.set_focus(table)
        await pilot.pause(0.3)
        for _ in range(7):
            await pilot.press("down")  # land on the takeover row
        await pilot.press("enter")
        await pilot.pause(0.6)
        app.save_screenshot("/tmp/sunder-detail.svg")
        await pilot.press("escape")
        await pilot.pause(0.4)

        # Filter active on "flagged".
        app.screen.query_one("#filter", Input).value = "flagged"
        await pilot.pause(0.5)
        app.save_screenshot("/tmp/sunder-filter.svg")
        app.screen.query_one("#filter", Input).value = ""
        await pilot.pause(0.3)

        app.screen._show_tab("tab-log")
        await pilot.pause(0.5)
        app.save_screenshot("/tmp/sunder-log.svg")

        app.screen._show_tab("tab-help")
        await pilot.pause(0.5)
        app.save_screenshot("/tmp/sunder-help.svg")

        app.screen.action_save()
        await pilot.pause(0.5)
        app.save_screenshot("/tmp/sunder-save.svg")

        print("shots saved")


if __name__ == "__main__":
    asyncio.run(main())
