"""CLI — argparse non-interactive mode."""

import argparse
import sys

from rich.console import Console

from .cache import Cache
from .config import load_config
from .database import Database
from .detection import detect_input
from .engines import get_all_engines
from .export import export_all
from .models import Confidence
from .scanner import detect_engines, engines_for_mode, do_scan

console = Console()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint-hunter",
        description="OSINT Hunter v5.0 — Multi-engine OSINT scanner with deep verify & correlation",
    )
    sub = p.add_subparsers(dest="command", help="Commande")

    # scan
    scan = sub.add_parser("scan", help="Lancer un scan")
    scan.add_argument("query", help="Cible (username, email, nom prenom, telephone)")
    scan.add_argument("-t", "--type", choices=["username", "email", "name", "phone"],
                      help="Forcer le type d'input")
    scan.add_argument("-e", "--engines", help="Moteurs (noms separes par virgule)")
    scan.add_argument("-o", "--output", default="./reports", help="Dossier de sortie")
    scan.add_argument("-f", "--format", default="all", choices=["json", "csv", "html", "all"],
                      help="Format d'export")
    scan.add_argument("--no-verify", action="store_true", help="Desactiver deep verify")
    scan.add_argument("--no-correlation", action="store_true", help="Desactiver correlation")
    scan.add_argument("--no-cache", action="store_true", help="Desactiver le cache")
    scan.add_argument("--proxy", help="Proxy URL (ex: socks5://127.0.0.1:9050)")
    scan.add_argument("-c", "--config", help="Chemin du fichier config.yaml")
    scan.add_argument("--json-stdout", action="store_true", help="Sortir les resultats en JSON sur stdout")

    # history
    hist = sub.add_parser("history", help="Voir l'historique des scans")
    hist.add_argument("-n", "--limit", type=int, default=20, help="Nombre de scans")
    hist.add_argument("-c", "--config", help="Chemin du fichier config.yaml")

    # compare
    comp = sub.add_parser("compare", help="Comparer deux scans")
    comp.add_argument("old_id", type=int, help="ID ancien scan")
    comp.add_argument("new_id", type=int, help="ID nouveau scan")
    comp.add_argument("-c", "--config", help="Chemin du fichier config.yaml")

    # engines
    eng = sub.add_parser("engines", help="Lister les moteurs disponibles")

    # stats
    st = sub.add_parser("stats", help="Statistiques globales")
    st.add_argument("-c", "--config", help="Chemin du fichier config.yaml")

    # interactive (default)
    sub.add_parser("interactive", help="Mode interactif (TUI)")

    # api
    api = sub.add_parser("api", help="Lancer le serveur API FastAPI")
    api.add_argument("--host", default=None, help="Host")
    api.add_argument("--port", type=int, default=None, help="Port")
    api.add_argument("-c", "--config", help="Chemin du fichier config.yaml")

    return p


def run_cli():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command or args.command == "interactive":
        from .tui import main as tui_main
        config_path = getattr(args, "config", None)
        tui_main(config_path)
        return

    cfg = load_config(getattr(args, "config", None))

    if args.command == "scan":
        if args.proxy:
            cfg.proxy.enabled = True
            cfg.proxy.url = args.proxy
        if args.no_cache:
            cfg.cache_ttl = 0

        from .models import InputType
        if args.type:
            it = InputType(args.type)
        else:
            it = detect_input(args.query)

        console.print(f"[bold]Cible:[/bold] {args.query} ({it.value})")

        all_engines = get_all_engines()
        es = detect_engines(all_engines)
        if args.engines:
            names = {n.strip().lower() for n in args.engines.split(",")}
            engs = [e for e, ok in es if ok and e.name.lower() in names]
        else:
            engs = engines_for_mode(it, es)

        if not engs:
            console.print("[red]Aucun moteur disponible.[/red]")
            sys.exit(1)

        console.print(f"[dim]Moteurs: {', '.join(e.name for e in engs)}[/dim]")

        db = Database(cfg.db_path)
        cache = Cache(ttl=cfg.cache_ttl)

        valid, discarded, correlation, _scan_id = do_scan(
            args.query, it, engs, cfg, cache, db,
            skip_verify=args.no_verify,
            skip_correlation=args.no_correlation,
        )

        if valid:
            if args.json_stdout:
                import json
                data = [r.to_dict() for r in valid]
                print(json.dumps(data, indent=2, ensure_ascii=False))
            else:
                from .tui import display_results, display_stats
                display_results(valid, f"Resultats — {args.query}")
                display_stats(valid, args.query)

                # Export
                from .export import export_json, export_csv, export_html
                fmt = args.format
                if fmt in ("json", "all"):
                    p = export_json(valid, args.query, args.output, discarded, correlation)
                    console.print(f"[green]JSON: {p}[/green]")
                if fmt in ("csv", "all"):
                    p = export_csv(valid, args.query, args.output)
                    console.print(f"[green]CSV: {p}[/green]")
                if fmt in ("html", "all"):
                    p = export_html(valid, args.query, args.output, discarded, correlation)
                    console.print(f"[green]HTML: {p}[/green]")
        else:
            console.print("[yellow]Aucun resultat.[/yellow]")

        db.close()

    elif args.command == "history":
        db = Database(cfg.db_path)
        from .tui import display_history
        display_history(db)
        db.close()

    elif args.command == "compare":
        db = Database(cfg.db_path)
        diff = db.compare_scans(args.old_id, args.new_id)
        console.print(f"[bold]Scan #{args.old_id} vs #{args.new_id}[/bold]")
        console.print(f"Ancien: {diff['old_total']} | Nouveau: {diff['new_total']}")
        console.print(f"[green]+{len(diff['added'])} nouveaux[/green] | [red]-{len(diff['removed'])} supprimes[/red] | [yellow]~{len(diff['changed'])} modifies[/yellow]")
        for r in diff["added"][:20]:
            console.print(f"  [green]+[/green] {r.site_name} — {r.url}")
        for r in diff["removed"][:20]:
            console.print(f"  [red]-[/red] {r.site_name} — {r.url}")
        for c in diff["changed"][:20]:
            console.print(f"  [yellow]~[/yellow] {c['site']}: {c['old_confidence']} -> {c['new_confidence']}")
        db.close()

    elif args.command == "engines":
        all_engines = get_all_engines()
        es = detect_engines(all_engines)
        from .tui import display_engines
        display_engines(es)

    elif args.command == "stats":
        db = Database(cfg.db_path)
        stats = db.stats()
        console.print(f"Scans: {stats['total_scans']}")
        console.print(f"Resultats: {stats['total_results']}")
        console.print(f"Sites uniques: {stats['unique_sites']}")
        console.print(f"Cibles uniques: {stats['unique_queries']}")
        db.close()

    elif args.command == "api":
        from .api import create_app
        import uvicorn
        app = create_app(cfg)
        host = args.host or cfg.api_server.host
        port = args.port or cfg.api_server.port
        if host not in ("127.0.0.1", "localhost", "::1") and not cfg.api_server.api_key:
            console.print(
                "[bold yellow]ATTENTION:[/bold yellow] l'API est exposee hors localhost "
                "SANS cle API. Definir api_server.api_key (ou OSINT_API_KEY) pour la proteger."
            )
        console.print(f"[bold green]API demarree sur http://{host}:{port}[/bold green]")
        console.print(f"[dim]Docs: http://{host}:{port}/docs[/dim]")
        uvicorn.run(app, host=host, port=port)
