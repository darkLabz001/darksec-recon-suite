"""Probe tab switching and layout geometry."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sunder.app import MainScreen, SunderApp  # noqa: E402
from textual.widgets import TabbedContent  # noqa: E402


async def main() -> None:
    app = SunderApp()
    async with app.run_test(size=(140, 42)) as pilot:
        await pilot.pause(0.5)
        await pilot.press("enter")
        await pilot.pause(0.5)
        screen = app.screen
        assert isinstance(screen, MainScreen)

        tabs = screen.query_one("#tabs", TabbedContent)
        print("active:", tabs.active)
        for name in ["tab-results", "tab-log", "tab-help"]:
            tabs.active = name
            await pilot.pause(0.3)
            visible = [p.id for p in screen.query("TabPane") if p.display and p.visible]
            print(f"set {name}: active={tabs.active} visible={visible}")

        for sel in ["#topbar", "#logo", "#tagline", "#subtag", "#status", "#optionbar", "#inputbar"]:
            w = screen.query_one(sel)
            print(f"{sel:12} size={w.size} display={w.display}")


if __name__ == "__main__":
    asyncio.run(main())
