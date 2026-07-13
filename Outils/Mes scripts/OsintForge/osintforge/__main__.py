"""Entry point.

    python -m osintforge                 # interactive TUI
    python -m osintforge <target>        # one-shot scan, prints a table
    python -m osintforge <target> --json out.json
    python -m osintforge --config path/to/config.yaml
"""

from __future__ import annotations

import argparse
import sys


def _force_utf8() -> None:
    """Windows consoles default to cp1252 and choke on emoji/box chars. Force UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main() -> int:
    _force_utf8()
    parser = argparse.ArgumentParser(prog="osintforge", description="OsintForge — OSINT scanner")
    parser.add_argument("target", nargs="?", help="username / email / name / phone / domain / image path")
    parser.add_argument("--config", help="path to config.yaml")
    parser.add_argument("--json", help="write findings to this JSON file (one-shot mode)")
    parser.add_argument("--no-verify", action="store_true", help="skip deep-verify of candidate profiles")
    args = parser.parse_args()

    if not args.target:
        from .tui import main as tui_main
        tui_main(args.config)
        return 0

    # One-shot non-interactive scan. Use rich's console for all output so emoji
    # and box-drawing render on any terminal (Windows cp1252 can't encode via print()).
    from rich.console import Console
    from .config import load_config
    from .detect import detect_input, input_icon
    from .engines import get_all_engines
    from .pipeline import detect_engines, engines_for, run_scan
    from .store import Store
    from .tui import display_findings, display_stats, display_discarded
    from .reporting import export_json

    console = Console()
    cfg = load_config(args.config)
    if args.no_verify:
        cfg.verify.enabled = False
    store = Store(cfg.db_path)
    it = detect_input(args.target)
    console.print(f"{input_icon(it)} type detecte: [bold]{it.value}[/bold]")
    engines = engines_for(it, detect_engines(get_all_engines()))
    if not engines:
        console.print("[red]Aucun moteur disponible pour ce type.[/red]")
        return 1
    findings, discarded, _ = run_scan(args.target, it, engines, cfg, store)
    display_discarded(discarded)
    display_findings(findings, f"Resultats — {args.target}")
    display_stats(findings)
    if args.json:
        p = export_json(findings, args.target, ".", discarded)
        console.print(f"\nJSON: {p}")
    store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
