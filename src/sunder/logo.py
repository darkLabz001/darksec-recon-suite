from __future__ import annotations

from rich.style import Style
from rich.text import Text

# Full-fat banner for the splash screen (ANSI Shadow style).
BANNER = """\
███████╗██╗   ██╗███████╗██████╗ ███╗   ██╗███████╗███████╗
██╔════╝██║   ██║██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝
███████╗██║   ██║█████╗  ██████╔╝██╔██╗ ██║█████╗  ███████╗
╚════██║██║   ██║██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ╚════██║
███████║╚██████╔╝███████╗██║  ██║██║ ╚████║███████╗███████║
╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"""

# Slim variant for the main screen header (figlet "small" font, 3 rows).
SLIM = """\
 ___ _   _ _  _ ___  ___ ___
/ __| | | | \\| |   \\| __| _ \\
\\__ \\ |_| | .` | |) | _||   /
|___/\\___/|_|\\_|___/|___|_|_\\"""

TAGLINE = "split a domain into every shadow it casts"

CYAN = (34, 211, 238)
PURPLE = (168, 85, 247)


def _lerp(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))  # type: ignore[return-value]


def gradient(text: str, start=CYAN, end=PURPLE) -> Text:
    """Render text with a smooth diagonal cyan->purple gradient."""
    lines = text.split("\n")
    height = max(len(lines) - 1, 1)
    width = max(max((len(line) for line in lines), default=1) - 1, 1)

    out = Text(no_wrap=True)
    for y, line in enumerate(lines):
        for x, char in enumerate(line):
            if char == " ":
                out.append(" ")
                continue
            t = (x / width) * 0.65 + (y / height) * 0.35
            r, g, b = _lerp(start, end, t)
            out.append(char, style=Style(color=f"#{r:02x}{g:02x}{b:02x}", bold=True))
        if y != len(lines) - 1:
            out.append("\n")
    return out


SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
