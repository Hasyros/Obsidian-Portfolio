"""Rich terminal UI for OsintForge."""

from __future__ import annotations

import time
import webbrowser

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.table import Table

from .config import load_config
from .detect import detect_input, input_icon
from .engines import get_all_engines
from .engines.base import LIVE, NEEDS_SETUP, ASSISTED
from .models import Finding, Discarded, FindingKind, Confidence, Status, InputType
from .pipeline import detect_engines, engines_for, run_scan
from .reporting import export_all
from .store import Store
from .variants import generate_variants

console = Console()
APP_VERSION = "1.0.0"

BANNER = r"""[bold cyan]
   ____       _       _   _____
  / __ \     (_)     | | |  __ \
 | |  | |___ _ _ __ __| || |__) |__  _ __ __ _  ___
 | |  | / __| | '_ \_  _||  ___/ _ \| '__/ _` |/ _ \
 | |__| \__ \ | | | || |_ | |  | (_) | | | (_| |  __/
  \____/|___/_|_| |_| \__||_|   \___/|_|  \__, |\___|
[/bold cyan][bold white]        OSINT · Forge[/bold white][dim]  v%s  ·  findings typés · deep-verify[/dim]  \___/
""" % APP_VERSION

MENU = [
    ("1", "Scan auto", "Detection auto + moteurs adaptes + verify", "bold green"),
    ("2", "Selectif", "Choisir les moteurs", "bold green"),
    ("V", "Variantes", "Scanner des variantes d'un pseudo", "bold green"),
    ("3", "Resultats", "Tableau courant", "bold cyan"),
    ("4", "Revue", "Confirmer / rejeter", "bold magenta"),
    ("5", "Export", "JSON + CSV + HTML + Maltego", "bold green"),
    ("6", "Filtrer", "Type, confiance, source...", "bold blue"),
    ("O", "Ouvrir", "Ouvrir les liens HIGH dans le navigateur", "bold cyan"),
    ("7", "Deep test", "Verifier une URL", "bold magenta"),
    ("G", "Geo/OSM", "Overpass Turbo autour de coordonnees", "bold yellow"),
    ("8", "Moteurs", "Statut de tous", "bold white"),
    ("9", "Historique", "Scans precedents", "bold blue"),
    ("C", "Comparer", "Comparer 2 scans", "bold magenta"),
    ("S", "Stats", "Statistiques globales", "bold cyan"),
    ("R", "Reset", "Nouvelle session", "bold white"),
    ("0", "Quitter", "", "bold red"),
]

_KIND_LABEL = {
    FindingKind.PROFILE: "profil", FindingKind.ACCOUNT: "compte",
    FindingKind.BREACH: "fuite", FindingKind.ARCHIVE: "archive",
    FindingKind.INFO: "info", FindingKind.LINK: "lien",
    FindingKind.DORK: "dork", FindingKind.ERROR: "erreur",
}
_STATUS_STYLE = {"live": "[green]LIVE[/green]", "setup": "[yellow]SETUP[/yellow]",
                 "assisted": "[blue]ASSIST[/blue]"}


def display_engines(es):
    t = Table(title="[bold]Moteurs OSINT[/bold]", box=box.ROUNDED, border_style="cyan", padding=(0, 1))
    t.add_column("", width=3, justify="right")
    t.add_column("Moteur", style="bold", width=15)
    t.add_column("Modes", width=26)
    t.add_column("Description", style="dim")
    t.add_column("Etat", width=8, justify="center")
    for i, (e, ok) in enumerate(es, 1):
        try:
            st = e.status()
        except Exception:
            st = NEEDS_SETUP
        t.add_row(str(i), e.name, ", ".join(e.modes), e.desc,
                  _STATUS_STYLE.get(st, "[dim]?[/dim]"))
    console.print(t)
    console.print("  [dim]LIVE = auto · SETUP = binaire/cle manquant · ASSIST = genere liens/commandes[/dim]")


def display_findings(findings: list[Finding], title="Resultats"):
    if not findings:
        console.print("  [dim]Vide.[/dim]")
        return
    from rich.text import Text
    t = Table(title=title, box=box.ROUNDED, border_style="bright_black",
              padding=(0, 1), title_style="bold white")
    t.add_column("#", style="dim", width=3, justify="right")
    t.add_column("Conf", width=5, justify="center")
    t.add_column("HT", width=2)
    t.add_column("Type", width=7, style="dim")
    t.add_column("Site", style="bold", width=22, overflow="fold")
    # URL folds instead of truncating (fully copyable) and is a real terminal
    # hyperlink (Ctrl+clic to open in most terminals, e.g. Windows Terminal).
    t.add_column("URL / Info", style="cyan", overflow="fold", ratio=1, min_width=30)
    t.add_column("Source", style="blue", width=14, no_wrap=True)
    cm = {"high": "[green]HIGH[/green]", "medium": "[yellow]MED[/yellow]", "low": "[red]LOW[/red]"}
    for i, r in enumerate(findings, 1):
        if r.url:
            site_cell = Text(r.title, style="bold")
            site_cell.stylize(f"link {r.url}")
            url_cell = Text(r.url, style="cyan")
            url_cell.stylize(f"link {r.url}")
        else:
            site_cell = Text(r.title, style="bold")
            url_cell = Text(r.note or "", style="dim")
        t.add_row(str(i), cm.get(r.confidence.value, "?"),
                  "[green]HT[/green]" if r.high_trust else "",
                  _KIND_LABEL.get(r.kind, "?"), site_cell, url_cell, (r.source or "?")[:14])
    console.print()
    console.print(t)
    console.print("  [dim]Astuce: Ctrl+clic sur un lien pour l'ouvrir · "
                  "menu O = ouvrir les HIGH · menu 5 = export HTML cliquable[/dim]")


def display_stats(findings: list[Finding]):
    hi = sum(1 for r in findings if r.confidence == Confidence.HIGH)
    md = sum(1 for r in findings if r.confidence == Confidence.MEDIUM)
    lo = sum(1 for r in findings if r.confidence == Confidence.LOW)
    ht = sum(1 for r in findings if r.high_trust)
    acc = sum(1 for r in findings if r.kind in (FindingKind.PROFILE, FindingKind.ACCOUNT))
    br = sum(1 for r in findings if r.kind == FindingKind.BREACH)
    console.print(f"\n  [green]HIGH {hi}[/green]  [yellow]MED {md}[/yellow]  [red]LOW {lo}[/red]  "
                  f"Total {len(findings)}  [green]HT {ht}[/green]  "
                  f"[bold]Comptes {acc}[/bold]  [red]Fuites {br}[/red]")


def display_discarded(discarded: list[Discarded]):
    if not discarded:
        return
    t = Table(title=f"[red]{len(discarded)} candidats elimines[/red]", box=box.SIMPLE,
              border_style="red", padding=(0, 1))
    t.add_column("#", style="dim", width=3)
    t.add_column("Site", width=22, style="dim")
    t.add_column("Raison", style="red", width=32)
    t.add_column("Source", style="dim", width=14)
    for i, d in enumerate(discarded, 1):
        t.add_row(str(i), d.title, d.reason, d.source)
    console.print()
    console.print(t)


def _open_links(findings: list[Finding], high_only: bool = True):
    targets = [r for r in findings if r.url.startswith("http")
               and (not high_only or r.confidence == Confidence.HIGH)]
    if not targets:
        console.print("  [dim]Aucun lien a ouvrir.[/dim]")
        return
    if len(targets) > 15 and not Confirm.ask(f"  {len(targets)} liens, continuer ?", default=True):
        return
    for i, r in enumerate(targets):
        console.print(f"  [{i+1}/{len(targets)}] {r.title}: {r.url}")
        webbrowser.open(r.url)
        time.sleep(0.3)
    console.print(f"  [green]{len(targets)} liens ouverts.[/green]")


def _review(findings: list[Finding]) -> list[Finding]:
    console.print(Rule("[bold magenta] REVUE [/bold magenta]"))
    console.print("[dim]  y=confirmer  n=rejeter  s=passer  o=ouvrir  YY=tous HIGH  q=quitter[/dim]")
    i = 0
    while i < len(findings):
        r = findings[i]
        cs = {"high": "green", "medium": "yellow", "low": "red"}[r.confidence.value]
        console.print(f"\n  [{cs}]{r.confidence.value.upper()}[/{cs}] "
                      f"{'[green]HT[/green] ' if r.high_trust else ''}[bold]{r.title}[/bold] "
                      f"[dim]({_KIND_LABEL.get(r.kind,'?')})[/dim]")
        if r.url:
            console.print(f"  [cyan]{r.url}[/cyan]")
        if r.note:
            console.print(f"  [dim]{r.note}[/dim]  [blue]{r.source}[/blue]")
        try:
            ch = Prompt.ask(f"  [{i+1}/{len(findings)}]", default="y")
        except (KeyboardInterrupt, EOFError):
            break
        if ch in ("y", ""):
            r.status = Status.CONFIRMED
        elif ch == "n":
            r.status = Status.REJECTED
        elif ch == "o" and r.url:
            webbrowser.open(r.url)
            continue
        elif ch == "YY":
            for x in findings:
                if x.confidence == Confidence.HIGH and x.status == Status.PENDING:
                    x.status = Status.CONFIRMED
        elif ch == "q":
            break
        i += 1
    return findings


def _geo_menu():
    console.print(Rule("[bold yellow] GEO / OSM [/bold yellow]"))
    raw = Prompt.ask("  Coordonnees 'lat,lon' (ou Entree pour annuler)", default="")
    if "," not in raw:
        return
    try:
        lat, lon = (float(x) for x in raw.split(",", 1))
    except ValueError:
        console.print("  [red]Format invalide.[/red]")
        return
    from .engines.geo_overpass import overpass_for_coords
    findings = overpass_for_coords(lat, lon)
    display_findings(findings, "Geo / OSM")
    if Confirm.ask("  Ouvrir les liens ?", default=True):
        _open_links(findings, high_only=False)


def _scan_and_show(query, it, engines, cfg, store, state):
    findings, discarded, _ = run_scan(query, it, engines, cfg, store)
    if not findings and not discarded:
        return
    state["query"], state["findings"], state["discarded"] = query, findings, discarded
    console.print(Rule("[bold green] RESULTATS [/bold green]"))
    display_discarded(discarded)
    display_findings(findings, f"Resultats — {query}")
    display_stats(findings)
    highs = [r for r in findings if r.confidence == Confidence.HIGH and r.url.startswith("http")]
    if highs:
        console.print()
        console.print("  [bold]1[/bold]—Revue  [bold]2[/bold]—Auto (Y HIGH, N LOW)  [bold]O[/bold]—Ouvrir HIGH")
        a = Prompt.ask("  ", default="")
        if a == "1":
            _review(findings)
        elif a == "2":
            for r in findings:
                if r.confidence == Confidence.HIGH:
                    r.status = Status.CONFIRMED
                elif r.confidence == Confidence.LOW:
                    r.status = Status.REJECTED
            console.print("  [green]Auto applique.[/green]")
        elif a.upper() == "O":
            _open_links(findings)


def main(config_path: str | None = None):
    import sys
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    cfg = load_config(config_path)
    store = Store(cfg.db_path)

    console.clear()
    console.print(Align.center(Panel(BANNER, border_style="cyan", box=box.DOUBLE_EDGE, padding=(0, 2))))

    all_engines = get_all_engines()
    es = detect_engines(all_engines)
    console.print()
    display_engines(es)

    state = {"query": None, "findings": [], "discarded": []}

    while True:
        console.print()
        if state["query"]:
            console.print(Align.center(f"[bold white on blue]  {state['query']}  [/bold white on blue]"))
        t = Table(box=box.SIMPLE_HEAD, border_style="bright_black", padding=(0, 2),
                  title="[bold yellow]MENU[/bold yellow]")
        t.add_column("", style="bold yellow", width=4, justify="center")
        t.add_column("", width=14)
        t.add_column("", style="dim")
        for n, nm, d, c in MENU:
            t.add_row(n, f"[{c}]{nm}[/{c}]", d)
        console.print(Align.center(t))
        console.print()

        try:
            ch = Prompt.ask("[bold yellow]>[/bold yellow]", default="1").strip()
        except (KeyboardInterrupt, EOFError):
            break
        chu = ch.upper()

        if ch == "1":
            q = Prompt.ask("  [bold]Cible (username, email, nom, telephone, domaine, image)[/bold]").strip()
            if not q:
                continue
            it = detect_input(q)
            console.print(f"\n  {input_icon(it)} Detecte: [bold]{it.value.upper()}[/bold]")
            engines = engines_for(it, es)
            if not engines:
                console.print("  [red]Aucun moteur disponible pour ce type.[/red]")
                continue
            console.print(f"  [dim]Moteurs: {', '.join(e.name for e in engines)}[/dim]")
            _scan_and_show(q, it, engines, cfg, store, state)

        elif ch == "2":
            q = Prompt.ask("  [bold]Cible[/bold]").strip()
            if not q:
                continue
            it = detect_input(q)
            console.print(f"  Detecte: {it.value}")
            for i, (e, ok) in enumerate(es, 1):
                active = it.value in e.modes
                mark = "[green]OK[/green]" if ok and active else "[dim]--[/dim]"
                console.print(f"  {mark} {i:2d} {e.name} [dim][{','.join(e.modes)}][/dim]")
            sel = Prompt.ask("  Moteurs (ex: 1,3,5)")
            chosen = []
            for s in sel.split(","):
                try:
                    e, ok = es[int(s.strip()) - 1]
                    if ok and it.value in e.modes:
                        chosen.append(e)
                except Exception:
                    pass
            if chosen:
                _scan_and_show(q, it, chosen, cfg, store, state)

        elif chu == "V":
            q = Prompt.ask("  [bold]Username de base[/bold]").strip()
            if not q:
                continue
            variants = [q] + generate_variants(q)
            console.print(f"  [dim]{len(variants)} variantes: {', '.join(variants[:8])}...[/dim]")
            if not Confirm.ask(f"  Scanner {len(variants)} variantes ?", default=True):
                continue
            engines = engines_for(InputType.USERNAME, es)
            all_f: list[Finding] = []
            for i, v in enumerate(variants):
                console.print(f"\n  [bold]--- {i+1}/{len(variants)}: {v} ---[/bold]")
                f, _, _ = run_scan(v, InputType.USERNAME, engines, cfg, store)
                for r in f:
                    if v != q:
                        r.note = (f"Variante: {v} | " + r.note) if r.note else f"Variante: {v}"
                all_f.extend(f)
            seen, dedup = set(), []
            for r in all_f:
                k = (r.url or r.title).rstrip("/").lower()
                if k not in seen:
                    seen.add(k)
                    dedup.append(r)
            state.update(query=f"{q} (+variantes)", findings=dedup, discarded=[])
            display_findings(dedup, f"Variantes de {q}")
            display_stats(dedup)

        elif ch == "3":
            if state["findings"]:
                display_findings(state["findings"], f"Resultats — {state['query']}")
                display_stats(state["findings"])
            else:
                console.print("  [yellow]Aucun scan.[/yellow]")

        elif ch == "4":
            if state["findings"]:
                _review(state["findings"])
            else:
                console.print("  [yellow]Aucun scan.[/yellow]")

        elif ch == "5":
            if not state["findings"]:
                console.print("  [yellow]Aucun scan.[/yellow]")
                continue
            out_dir = Prompt.ask("  Dossier", default=cfg.output_dir)
            paths = export_all(state["findings"], state["query"], out_dir, state["discarded"])
            for fmt, p in paths.items():
                console.print(f"  [green]{fmt.upper()}: {p}[/green]")

        elif ch == "6":
            if not state["findings"]:
                console.print("  [yellow]Aucun scan.[/yellow]")
                continue
            console.print("  [bold]1[/bold]=Type [bold]2[/bold]=Confiance [bold]3[/bold]=Source "
                          "[bold]4[/bold]=HT [bold]5[/bold]=Mot-cle")
            fc = Prompt.ask("  ", default="0")
            f = state["findings"]
            if fc == "1":
                k = Prompt.ask("  Type", choices=[x.value for x in FindingKind])
                f = [r for r in f if r.kind.value == k]
            elif fc == "2":
                lvl = Prompt.ask("  Confiance", choices=["high", "medium", "low"])
                f = [r for r in f if r.confidence.value == lvl]
            elif fc == "3":
                s = Prompt.ask("  Source").lower()
                f = [r for r in f if s in r.source.lower()]
            elif fc == "4":
                f = [r for r in f if r.high_trust]
            elif fc == "5":
                kw = Prompt.ask("  Mot-cle").lower()
                f = [r for r in f if kw in r.title.lower() or kw in r.url.lower()]
            display_findings(f, f"Filtre — {len(f)}")

        elif chu == "O":
            if state["findings"]:
                sub = Prompt.ask("  [bold]1[/bold]=HIGH seulement  [bold]2[/bold]=tous liens", default="1")
                _open_links(state["findings"], high_only=(sub != "2"))
            else:
                console.print("  [yellow]Aucun scan.[/yellow]")

        elif ch == "7":
            url = Prompt.ask("  URL")
            q = Prompt.ask("  Username/cible", default="")
            from .verify import verify_one
            from urllib.parse import urlparse
            site = urlparse(url).netloc.replace("www.", "").split(".")[0].capitalize()
            probe = Finding(source="manual", title=site, url=url, kind=FindingKind.PROFILE)
            with console.status("[cyan]Deep verify...[/cyan]"):
                passed, res = verify_one(q or site, probe)
            if passed:
                console.print(f"  [green]VALIDE — HTTP {res.http_status}[/green]")
                display_findings([res])
            else:
                console.print(f"  [red]ELIMINE — {res.reason}[/red]")

        elif chu == "G":
            _geo_menu()

        elif ch == "8":
            es = detect_engines(all_engines)
            display_engines(es)

        elif ch == "9":
            scans = store.list_scans(20)
            if not scans:
                console.print("  [dim]Aucun scan en base.[/dim]")
            else:
                t = Table(title="Historique", box=box.ROUNDED, border_style="blue")
                for col in ("ID", "Cible", "Type", "Date", "Trouves", "Elimines"):
                    t.add_column(col)
                for s in scans:
                    t.add_row(str(s.scan_id), s.query, s.input_type, s.timestamp,
                              str(s.total_found), str(s.total_discarded))
                console.print(t)
                sid = Prompt.ask("  Charger scan ID (Entree=annuler)", default="")
                if sid.isdigit():
                    loaded = store.get_findings(int(sid))
                    if loaded:
                        state.update(query=f"Scan #{sid}", findings=loaded,
                                     discarded=store.get_discarded(int(sid)))
                        display_findings(loaded, f"Scan #{sid}")
                        display_stats(loaded)

        elif chu == "C":
            a = Prompt.ask("  Ancien scan ID")
            b = Prompt.ask("  Nouveau scan ID")
            if a.isdigit() and b.isdigit():
                d = store.compare(int(a), int(b))
                console.print(f"\n  Ancien: {d['old_total']} | Nouveau: {d['new_total']}")
                for r in d["added"][:12]:
                    console.print(f"    [green]+[/green] {r.title} — {r.url}")
                for r in d["removed"][:12]:
                    console.print(f"    [red]-[/red] {r.title} — {r.url}")
                for c in d["changed"][:12]:
                    console.print(f"    [yellow]~[/yellow] {c['title']}: {c['old']} -> {c['new']}")

        elif chu == "S":
            st = store.stats()
            console.print(f"\n  [bold cyan]Statistiques[/bold cyan]")
            console.print(f"  Scans: {st['total_scans']} · Findings: {st['total_findings']} · "
                          f"Sites uniques: {st['unique_sites']} · Cibles: {st['unique_queries']}")

        elif chu == "R":
            state.update(query=None, findings=[], discarded=[])
            console.print("  [dim]Reset.[/dim]")

        elif ch == "0":
            console.print(Align.center(Panel("[bold cyan]Merci d'avoir utilise OsintForge ![/bold cyan]",
                                             border_style="cyan", box=box.DOUBLE_EDGE)))
            store.close()
            break
