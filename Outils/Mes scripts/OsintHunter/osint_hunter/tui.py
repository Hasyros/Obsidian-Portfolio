"""Rich TUI — interactive terminal interface."""

import webbrowser

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.table import Table

from .cache import Cache
from .config import Config, load_config
from .correlation import CorrelationReport
from .database import Database
from .detection import detect_input, input_icon
from .engines import get_all_engines
from .export import export_all
from .models import (
    SiteResult, DiscardedResult, Confidence, Status, InputType,
)
from .scanner import detect_engines, engines_for_mode, do_scan

console = Console()

APP_VERSION = "5.0.0"

SPLASH = r"""[bold yellow]
           ▄██▀▀▀▀▀▀▀▀▀▀▀▀▀██▄
          ██  ████████████████ ██
        █  ██████████████████████ █
        █▌ ▀████████████████████▀▐█
         ██      ▀▀████████▀▀     ██
             ▀██  ▄██▀▀██▄  ██▀
              █▌ ██ ▄▀▄ ██ ▐█
              █▌ █  █●█  █ ▐█
              █▌ ██ ▀▄▀ ██ ▐█
              ██  ▀██▄██▀  ██
              █▌  ▄▀▀▀▀▀▄  ▐█
              ██ █▀▀▀▀▀▀▀█ ██
               ██▄        ▄██
                ▀▀██▄▄▄▄██▀▀
[/bold yellow]"""

TITLE = f"""[bold white]
  ██████╗ ███████╗██╗███╗  ██╗████████╗
 ██╔═══██╗██╔════╝██║████╗ ██║╚══██╔══╝
 ██║   ██║███████╗██║██╔██╗██║   ██║
 ██║   ██║╚════██║██║██║╚████║   ██║
 ╚██████╔╝███████║██║██║ ╚███║   ██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚══╝   ╚═╝
[/bold white][bold cyan]  H·U·N·T·E·R  v{APP_VERSION}  DEEP VERIFY + CORRELATION[/bold cyan]"""

MENU = [
    ("1", "Scan auto", "Detection auto + tous moteurs + deep verify + correlation", "bold green"),
    ("2", "Selectif", "Choisir les moteurs", "bold green"),
    ("V", "Variantes", "Scanner des variantes du pseudo (leet, case...)", "bold green"),
    ("3", "Resultats", "Tableau courant", "bold cyan"),
    ("4", "Revue", "Confirmer/rejeter", "bold magenta"),
    ("5", "Export", "JSON + CSV + HTML", "bold green"),
    ("6", "Filtrer", "Confiance, source, HT...", "bold blue"),
    ("O", "Ouvrir HIGH", "Ouvrir toutes les pages HIGH dans le navigateur", "bold cyan"),
    ("7", "Deep test", "Verifier une URL", "bold magenta"),
    ("8", "Moteurs", "Statut de tous", "bold white"),
    ("9", "Historique", "Scans precedents (DB)", "bold blue"),
    ("C", "Comparer", "Comparer 2 scans", "bold magenta"),
    ("S", "Stats", "Statistiques globales", "bold cyan"),
    ("R", "Reset", "Nouvelle session", "bold white"),
    ("0", "Quitter", "", "bold red"),
]


def display_engines(es):
    t = Table(title="[bold]Moteurs OSINT[/bold]", box=box.ROUNDED, border_style="cyan", padding=(0, 1))
    t.add_column("", width=3)
    t.add_column("Moteur", style="bold", width=14)
    t.add_column("Modes", width=22)
    t.add_column("Description", style="dim")
    t.add_column("", width=10, justify="center")
    for i, (e, ok) in enumerate(es, 1):
        t.add_row(
            str(i), e.name, ", ".join(e.modes), e.desc,
            "[bold green]OK[/bold green]" if ok else "[dim]--[/dim]",
        )
    console.print(t)


def display_discarded(d):
    if not d:
        return
    t = Table(title=f"[red]{len(d)} eliminees[/red]", box=box.SIMPLE, border_style="red", padding=(0, 1))
    t.add_column("#", style="dim", width=4)
    t.add_column("Site", width=20, style="dim")
    t.add_column("Raison", style="red", width=45)
    t.add_column("Src", style="dim", width=12)
    for i, r in enumerate(d, 1):
        t.add_row(str(i), r.site_name, r.reason, r.source)
    console.print()
    console.print(t)


def display_results(results, title="Resultats"):
    if not results:
        console.print("  [dim]Vide.[/dim]")
        return
    t = Table(title=title, box=box.ROUNDED, border_style="bright_black", padding=(0, 1), title_style="bold white")
    t.add_column("#", style="dim", width=4, justify="right")
    t.add_column("Conf.", width=6, justify="center")
    t.add_column("HT", width=3)
    t.add_column("Site", style="bold", width=20)
    t.add_column("URL", style="cyan", max_width=42, no_wrap=True)
    t.add_column("HTTP", width=4, justify="center")
    t.add_column("User?", width=5, justify="center")
    t.add_column("Source", style="blue", width=12, no_wrap=True)
    cm = {"high": "[green]HIGH[/green]", "medium": "[yellow]MED[/yellow]", "low": "[red]LOW[/red]"}
    for i, r in enumerate(results, 1):
        url_display = r.url[:39] + ("..." if len(r.url) > 42 else "")
        uib = "[green]Y[/green]" if r.username_in_body else ("[red]N[/red]" if r.username_in_body is not None else "-")
        t.add_row(
            str(i),
            cm.get(r.confidence.value, "?"),
            "[green]HT[/green]" if r.high_trust else "",
            r.site_name,
            url_display,
            str(r.http_status or "-"),
            uib,
            (r.source or "?")[:12],
        )
    console.print()
    console.print(t)
    console.print("  [dim]HT = high-trust (page creee uniquement si le compte existe)[/dim]")


def display_stats(results, query):
    hi = sum(1 for r in results if r.confidence == Confidence.HIGH)
    md = sum(1 for r in results if r.confidence == Confidence.MEDIUM)
    lo = sum(1 for r in results if r.confidence == Confidence.LOW)
    ht = sum(1 for r in results if r.high_trust)
    console.print(
        f"\n  [green]HIGH {hi}[/green]  [yellow]MED {md}[/yellow]  "
        f"[red]LOW {lo}[/red]  Total {len(results)}  [green]HT {ht}[/green]"
    )


def display_correlation(corr: CorrelationReport):
    if not corr or not corr.links:
        return
    console.print(Rule("[bold magenta] CORRELATIONS [/bold magenta]"))
    for link in corr.links:
        color = {"avatar": "magenta", "bio": "yellow", "link": "blue", "email": "green"}.get(link.link_type, "white")
        console.print(
            f"  [{color}][{link.link_type}][/{color}] "
            f"[bold]{link.source}[/bold] <-> [bold]{link.target}[/bold] "
            f"[dim]{link.detail} ({link.confidence:.0%})[/dim]"
        )
    if corr.emails_found:
        console.print(f"\n  [cyan]Emails detectes:[/cyan]")
        for email in corr.emails_found:
            console.print(f"    {email}")
    if corr.avatar_clusters:
        console.print(f"\n  [magenta]Clusters d'avatars similaires:[/magenta]")
        for cluster in corr.avatar_clusters:
            console.print(f"    {', '.join(cluster)}")


def interactive_review(results):
    console.print(Rule("[bold magenta] REVUE [/bold magenta]"))
    console.print("[dim]  y/Entree=Y  n=N  s=passer  o=ouvrir  a=annoter  YY=Y tous HIGH  NN=N tous LOW  TT=Y HT  q=quitter[/dim]")
    i = 0
    while i < len(results):
        r = results[i]
        cs = {"high": "green", "medium": "yellow", "low": "red"}[r.confidence.value]
        console.print(
            f"\n  [{cs}]{r.confidence.value.upper()}[/{cs}]"
            f"{'[green]HT[/green]' if r.high_trust else ''} "
            f"[bold]{r.site_name}[/bold] — [cyan]{r.url}[/cyan]"
        )
        console.print(f"  HTTP {r.http_status or '-'} | User:{'Y' if r.username_in_body else 'N'} | {r.page_size}B | Source:{r.source}")
        if r.note:
            console.print(f"  [yellow]{r.note}[/yellow]")
        try:
            ch = Prompt.ask(f"  [{i + 1}/{len(results)}]", default="y")
        except (KeyboardInterrupt, EOFError):
            break
        if ch in ("y", ""):
            r.status = Status.CONFIRMED
            console.print("  [green]Confirmed[/green]")
        elif ch == "n":
            r.status = Status.REJECTED
            console.print("  [red]Rejected[/red]")
        elif ch == "s":
            pass
        elif ch == "a":
            r.note = Prompt.ask("  Note")
            continue
        elif ch == "o":
            webbrowser.open(r.url)
            continue
        elif ch == "YY":
            for x in results:
                if x.confidence == Confidence.HIGH and x.status == Status.PENDING:
                    x.status = Status.CONFIRMED
        elif ch == "NN":
            for x in results:
                if x.confidence == Confidence.LOW and x.status == Status.PENDING:
                    x.status = Status.REJECTED
        elif ch == "TT":
            for x in results:
                if x.high_trust and x.confidence in (Confidence.HIGH, Confidence.MEDIUM) and x.status == Status.PENDING:
                    x.status = Status.CONFIRMED
        elif ch == "q":
            break
        i += 1
    return results


def display_history(db: Database):
    scans = db.list_scans(20)
    if not scans:
        console.print("  [dim]Aucun scan en base.[/dim]")
        return
    t = Table(title="[bold]Historique des scans[/bold]", box=box.ROUNDED, border_style="blue")
    t.add_column("ID", width=5, justify="right")
    t.add_column("Cible", width=25)
    t.add_column("Type", width=10)
    t.add_column("Date", width=20)
    t.add_column("Trouves", width=8, justify="center")
    t.add_column("Elimines", width=8, justify="center")
    t.add_column("Moteurs", style="dim")
    for s in scans:
        t.add_row(
            str(s.scan_id), s.query, s.input_type, s.timestamp,
            f"[green]{s.total_found}[/green]",
            f"[red]{s.total_discarded}[/red]",
            s.engines_used[:40],
        )
    console.print()
    console.print(t)


def _open_all_high(results: list[SiteResult], only_ht: bool = False):
    """Open all HIGH-confidence result URLs in the browser."""
    targets = [
        r for r in results
        if r.confidence == Confidence.HIGH
        and r.url.startswith("http")
        and not r.site_name.startswith("[")
        and (not only_ht or r.high_trust)
    ]
    if not targets:
        console.print("  [dim]Aucun resultat HIGH a ouvrir.[/dim]")
        return
    console.print(f"\n  [bold cyan]Ouverture de {len(targets)} pages HIGH...[/bold cyan]")
    if len(targets) > 20:
        from rich.prompt import Confirm
        if not Confirm.ask(f"  {len(targets)} pages, continuer ?", default=True):
            return
    import time
    for i, r in enumerate(targets):
        console.print(f"  [{i + 1}/{len(targets)}] {r.site_name}: {r.url}")
        webbrowser.open(r.url)
        if i < len(targets) - 1:
            time.sleep(0.3)  # Small delay to avoid overwhelming the browser
    console.print(f"  [green]{len(targets)} pages ouvertes.[/green]")


def main(config_path: str | None = None):
    cfg = load_config(config_path)
    db = Database(cfg.db_path)
    cache = Cache(ttl=cfg.cache_ttl)

    console.clear()
    sp = Table.grid(padding=1)
    sp.add_column(justify="center", width=36)
    sp.add_column(justify="center")
    sp.add_row(
        SPLASH,
        TITLE + "\n\n[dim]"
        "Auto: Username / Email / Nom / Telephone\n"
        f"20 moteurs | Deep Verify | Breaches | Correlation | HT\n"
        f"v{APP_VERSION}[/dim]",
    )
    console.print(Align.center(Panel(sp, border_style="yellow", box=box.DOUBLE_EDGE, padding=(1, 2))))

    all_engines = get_all_engines()
    es = detect_engines(all_engines)
    console.print()
    display_engines(es)

    # Session state
    cu: str | None = None
    cr: list[SiteResult] = []
    cd: list[DiscardedResult] = []
    cc: CorrelationReport | None = None

    while True:
        console.print()
        if cu:
            console.print(Align.center(f"[bold white on blue]  {cu}  [/bold white on blue]"))
        t = Table(box=box.SIMPLE_HEAD, border_style="bright_black", padding=(0, 2), title="[bold yellow]MENU[/bold yellow]")
        t.add_column("", style="bold yellow", width=4, justify="center")
        t.add_column("", width=16)
        t.add_column("", style="dim")
        for n, nm, d, c in MENU:
            t.add_row(n, f"[{c}]{nm}[/{c}]", d)
        console.print(Align.center(t))
        console.print()

        try:
            ch = Prompt.ask("[bold yellow]>[/bold yellow]", default="1")
        except (KeyboardInterrupt, EOFError):
            break

        if ch == "1":
            q = Prompt.ask("  [bold]Cible (username, email, nom prenom, ou telephone)[/bold]")
            if not q.strip():
                continue
            it = detect_input(q)
            icon = input_icon(it)
            console.print(f"\n  {icon} Detecte: [bold]{it.value.upper()}[/bold]")
            engs = engines_for_mode(it, es)
            if not engs:
                console.print("  [red]Aucun moteur disponible.[/red]")
                continue
            console.print(f"  [dim]Moteurs: {', '.join(e.name for e in engs)}[/dim]")
            valid, discarded, correlation, _scan_id = do_scan(q, it, engs, cfg, cache, db)
            if valid:
                cu = q
                cr = valid
                cd = discarded
                cc = correlation
                console.print(Rule("[bold green] RESULTATS [/bold green]"))
                if discarded:
                    console.print(f"\n  [bold red]{len(discarded)} eliminees par deep verify[/bold red]")
                    display_discarded(discarded)
                console.print(f"\n  [bold green]{len(valid)} resultats valides[/bold green]")
                display_results(valid, title=f"Resultats — {q}")
                display_stats(valid, q)
                display_correlation(correlation)

                ht = [r for r in valid if r.high_trust and r.confidence in (Confidence.HIGH, Confidence.MEDIUM)]
                if ht:
                    console.print(Rule("[bold green] HIGH-TRUST [/bold green]"))
                    for r in ht:
                        console.print(f"  [green]HT[/green] {r.site_name:20s} [cyan]{r.url}[/cyan]")

                # Action choice
                console.print()
                console.print(
                    "  [bold]1[/bold]—Revue  [bold]2[/bold]—Auto (Y HIGH+HT, N LOW)  "
                    "[bold]3[/bold]—Pending  [bold]O[/bold]—Ouvrir tous HIGH"
                )
                a = Prompt.ask("  ", default="1")
                if a == "1":
                    cr = interactive_review(cr)
                elif a == "2":
                    ok = ko = 0
                    for r in cr:
                        if r.confidence == Confidence.HIGH or (r.high_trust and r.confidence == Confidence.MEDIUM):
                            r.status = Status.CONFIRMED
                            ok += 1
                        elif r.confidence == Confidence.LOW:
                            r.status = Status.REJECTED
                            ko += 1
                    console.print(f"  [green]Y {ok}[/green] | [red]N {ko}[/red]")
                elif a.upper() == "O":
                    _open_all_high(cr)

        elif ch == "2":
            q = Prompt.ask("  [bold]Cible[/bold]")
            if not q.strip():
                continue
            it = detect_input(q)
            console.print(f"  Detecte: {it.value}")
            for i, (e, ok) in enumerate(es, 1):
                act = it.value in e.modes
                console.print(f"  {'[green]OK[/green]' if ok and act else '[dim]--[/dim]'} {i:2d} {e.name} [{','.join(e.modes)}]")
            sel = Prompt.ask("  Moteurs (ex: 1,3,5)")
            selected = []
            for s in sel.split(","):
                try:
                    e, ok = es[int(s.strip()) - 1]
                    if ok:
                        selected.append(e)
                except Exception:
                    pass
            if not selected:
                continue
            valid, discarded, correlation, _scan_id = do_scan(q, it, selected, cfg, cache, db)
            if valid:
                cu = q
                cr = valid
                cd = discarded
                cc = correlation
                display_results(cr, f"Resultats — {q}")
                display_stats(cr, q)

        elif ch.upper() == "V":
            q = Prompt.ask("  [bold]Username de base[/bold]")
            if not q.strip():
                continue
            from .variants import generate_variants, display_variants_menu
            vs = generate_variants(q)
            queries = display_variants_menu(vs)
            if not queries:
                continue
            it = InputType.USERNAME
            engs = engines_for_mode(it, es)
            if not engs:
                console.print("  [red]Aucun moteur disponible.[/red]")
                continue
            console.print(f"\n  [bold magenta]Scan de {len(queries)} variante(s)...[/bold magenta]")
            all_valid: list[SiteResult] = []
            all_discarded: list[DiscardedResult] = []
            for i, variant in enumerate(queries):
                console.print(f"\n  [bold]--- Variante {i + 1}/{len(queries)}: {variant} ---[/bold]")
                v, d, _, _ = do_scan(variant, it, engs, cfg, cache, db)
                # Tag results with the variant they came from
                for r in v:
                    if variant != q:
                        r.note = f"Variante: {variant}" + (f" | {r.note}" if r.note else "")
                all_valid.extend(v)
                all_discarded.extend(d)
            if all_valid:
                # Dedup by URL across variants
                seen_urls: set[str] = set()
                deduped: list[SiteResult] = []
                for r in all_valid:
                    norm = r.url.rstrip("/").lower()
                    if norm not in seen_urls:
                        seen_urls.add(norm)
                        deduped.append(r)
                cu = f"{q} (+{len(queries) - 1} variantes)"
                cr = deduped
                cd = all_discarded
                cc = None
                console.print(Rule("[bold green] RESULTATS COMBINES [/bold green]"))
                console.print(f"  [bold green]{len(deduped)} resultats uniques sur {len(all_valid)} total[/bold green]")
                display_results(deduped, f"Variantes de {q}")
                display_stats(deduped, q)

        elif ch.upper() == "O":
            if cr:
                console.print("  [bold]1[/bold]=Tous HIGH  [bold]2[/bold]=HIGH + HT seulement")
                sub = Prompt.ask("  ", default="1")
                _open_all_high(cr, only_ht=(sub == "2"))
            else:
                console.print("  [yellow]Aucun scan.[/yellow]")

        elif ch == "3":
            if cr:
                display_results(cr, f"Resultats — {cu}")
                display_stats(cr, cu)
                display_correlation(cc)
            else:
                console.print("  [yellow]Aucun scan.[/yellow]")

        elif ch == "4":
            if cr:
                cr = interactive_review(cr)
            else:
                console.print("  [yellow]Aucun scan.[/yellow]")

        elif ch == "5":
            if cr:
                out_dir = Prompt.ask("  Dossier", default=cfg.output_dir)
                paths = export_all(cr, cu, out_dir, cd, cc)
                for fmt, p in paths.items():
                    console.print(f"  [green]{fmt.upper()}: {p}[/green]")
            else:
                console.print("  [yellow]Aucun scan.[/yellow]")

        elif ch == "6":
            if not cr:
                console.print("  [yellow]Aucun scan.[/yellow]")
                continue
            console.print("  [bold]1[/bold]=Confiance [bold]2[/bold]=Statut [bold]3[/bold]=Source [bold]4[/bold]=HT [bold]5[/bold]=Mot-cle [bold]6[/bold]=Categorie")
            fc = Prompt.ask("  ", default="0")
            f = cr
            if fc == "1":
                lvl = Prompt.ask(" ", choices=["high", "medium", "low"])
                f = [r for r in cr if r.confidence.value == lvl]
            elif fc == "2":
                st = Prompt.ask(" ", choices=["confirmed", "rejected", "pending"])
                f = [r for r in cr if r.status.value == st]
            elif fc == "3":
                s = Prompt.ask("  Source")
                f = [r for r in cr if s.lower() in r.source.lower()]
            elif fc == "4":
                f = [r for r in cr if r.high_trust]
            elif fc == "5":
                kw = Prompt.ask("  ").lower()
                f = [r for r in cr if kw in r.site_name.lower() or kw in r.url.lower()]
            elif fc == "6":
                cat = Prompt.ask("  Categorie (social/dev/media/forum/gaming/commerce/blog/messaging/photo/breach)")
                f = [r for r in cr if cat in r.tags]
            if f:
                display_results(f, f"Filtre — {len(f)}")
            else:
                console.print("  [dim]Aucun resultat.[/dim]")

        elif ch == "7":
            url = Prompt.ask("  URL")
            un = Prompt.ask("  Username")
            from .verify import verify_one
            from urllib.parse import urlparse
            with console.status("[cyan]Deep verify...[/cyan]"):
                passed, res = verify_one(un, urlparse(url).netloc.split(".")[0].capitalize(), url)
            if passed:
                console.print(f"  [green]VALIDE — HTTP {res.http_status}[/green]")
                display_results([res])
            else:
                console.print(f"  [red]ELIMINE — {res.reason}[/red]")

        elif ch == "8":
            es = detect_engines(all_engines)
            display_engines(es)

        elif ch == "9":
            display_history(db)
            sid = Prompt.ask("  Charger scan ID (ou Entree pour annuler)", default="")
            if sid.isdigit():
                loaded = db.get_scan_results(int(sid))
                if loaded:
                    cu = f"Scan #{sid}"
                    cr = loaded
                    cd = db.get_scan_discarded(int(sid))
                    cc = None
                    display_results(cr, f"Scan #{sid}")
                    display_stats(cr, cu)
                else:
                    console.print("  [red]Scan introuvable.[/red]")

        elif ch.upper() == "C":
            display_history(db)
            old_id = Prompt.ask("  Ancien scan ID")
            new_id = Prompt.ask("  Nouveau scan ID")
            if old_id.isdigit() and new_id.isdigit():
                diff = db.compare_scans(int(old_id), int(new_id))
                console.print(f"\n  [bold]Comparaison scan #{old_id} vs #{new_id}[/bold]")
                console.print(f"  Ancien: {diff['old_total']} | Nouveau: {diff['new_total']}")
                if diff["added"]:
                    console.print(f"\n  [green]+{len(diff['added'])} nouveaux comptes:[/green]")
                    for r in diff["added"][:10]:
                        console.print(f"    [green]+[/green] {r.site_name} — {r.url}")
                if diff["removed"]:
                    console.print(f"\n  [red]-{len(diff['removed'])} comptes supprimes:[/red]")
                    for r in diff["removed"][:10]:
                        console.print(f"    [red]-[/red] {r.site_name} — {r.url}")
                if diff["changed"]:
                    console.print(f"\n  [yellow]~{len(diff['changed'])} confiance modifiee:[/yellow]")
                    for c in diff["changed"][:10]:
                        console.print(f"    [yellow]~[/yellow] {c['site']} : {c['old_confidence']} -> {c['new_confidence']}")

        elif ch.upper() == "S":
            stats = db.stats()
            console.print(f"\n  [bold cyan]Statistiques globales[/bold cyan]")
            console.print(f"  Scans: {stats['total_scans']}")
            console.print(f"  Resultats: {stats['total_results']}")
            console.print(f"  Sites uniques: {stats['unique_sites']}")
            console.print(f"  Cibles uniques: {stats['unique_queries']}")

        elif ch.upper() == "R":
            cu = None
            cr = []
            cd = []
            cc = None
            cache.clear()
            console.print("  [dim]Reset.[/dim]")

        elif ch == "0":
            console.print(Align.center(
                Panel("[bold yellow]Merci ![/bold yellow]", border_style="yellow", box=box.DOUBLE_EDGE)
            ))
            db.close()
            break
