from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import Options
from .models import classify
from .wordlist import DEFAULT_SUBDOMAINS

SOURCE_FLAGS = {
    "crtsh": "no-crtsh",
    "wayback": "no-wayback",
    "hackertarget": "no-hackertarget",
    "bruteforce": "no-bruteforce",
    "records": "no-records",
    "axfr": "no-axfr",
    "resolve": "no-resolve",
    "probe": "no-probe",
    "admin": "no-admin",
    "takeover": "no-takeover",
    "cert": "no-cert",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sunder",
        description="Split a domain into every shadow it casts — subdomain enumeration "
        "with a terminal UI. With no arguments the TUI starts; pass targets to run "
        "headless.",
    )
    parser.add_argument("targets", nargs="*", help="domains, IPs, or @file.txt")
    parser.add_argument("--tui", action="store_true", help="force the TUI (targets prefill the input)")
    parser.add_argument("-w", "--wordlist", help="file of subdomain names for the DNS brute-force phase")
    parser.add_argument("-o", "--output", help="export findings (.json / .csv / .txt / .html)")
    parser.add_argument(
        "--theme", help="TUI color theme (nord, dracula, catppuccin-mocha, gruvbox, …)"
    )
    parser.add_argument("--max-hosts", type=int, default=4000, help="cap hosts resolved per target")
    for key, flag in SOURCE_FLAGS.items():
        parser.add_argument(f"--{flag}", action="store_true", help=f"disable {key}")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    return parser


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return list(DEFAULT_SUBDOMAINS)
    p = Path(path).expanduser()
    if not p.is_file():
        sys.exit(f"sunder: wordlist not found: {p}")
    words = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line)
    return list(dict.fromkeys(words))


def main() -> None:
    args = build_parser().parse_args()

    if args.version:
        from . import __version__

        print(f"sunder {__version__}")
        return

    opts = Options(wordlist=load_wordlist(args.wordlist), max_hosts=args.max_hosts)
    for key in SOURCE_FLAGS:
        if getattr(args, f"no_{key}"):
            setattr(opts, key, False)

    if args.targets and not args.tui:
        from .headless import run

        targets, bad = [], []
        for raw in args.targets:
            t = classify(raw)
            (targets if t else bad).append(t or raw)
        for junk in bad:
            print(f"sunder: skipping invalid target: {junk}", file=sys.stderr)
        if not targets:
            sys.exit("sunder: no valid targets")
        run(targets, opts, args.output)
        return

    from .app import SunderApp

    SunderApp(prefill=args.targets, options=opts, theme=args.theme).run()
