#!/usr/bin/env python3
"""
SQLi Auto-Auditor v2 - Outil d'audit automatise pour les injections SQL
Integre: interception de redirections, probing pre-scan, test des headers,
bypass WAF, analyse JS, detection auth bypass.

Usage autorise uniquement dans le cadre de tests de penetration avec accord prealable.
"""

import sys
import os
import time
import argparse
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from core.scanner import WebScanner, Crawler
from core.analyzer import Analyzer
from core.prober import SQLiProber
from core.sqlmap_runner import SQLMapRunner
from core.reporter import Reporter

console = Console()

BANNER = r"""
[bold cyan]
  ___  ___  _    _     _         _           _         _ _ _
 / __|/ _ \| |  (_)   /_\ _  _ | |_ ___    /_\ _  _  __| (_) |_ ___  _ _
 \__ \ (_) | |__| |  / _ \ || ||  _/ _ \  / _ \ || |/ _` | |  _/ _ \| '_|
 |___/\__\_\____|_| /_/ \_\_,_| \__\___/ /_/ \_\_,_|\__,_|_|\__\___/|_|
[/bold cyan]
[bold white]v2.0[/bold white] [dim]- Redirect interception | Header injection | WAF bypass | Pre-scan probing[/dim]
[yellow]Usage strictement reserve aux tests autorises.[/yellow]
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="SQLi Auto-Auditor v2 - Scan automatise et test d'injection SQL"
    )
    parser.add_argument("url", nargs="?", help="URL cible a auditer")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Profondeur de crawl (defaut: 3)")
    parser.add_argument("-m", "--max-pages", type=int, default=50, help="Nombre max de pages (defaut: 50)")
    parser.add_argument("-o", "--output", default="output", help="Dossier de sortie (defaut: output)")
    parser.add_argument("--level", type=int, default=2, choices=[1, 2, 3, 4, 5], help="Niveau sqlmap (defaut: 2)")
    parser.add_argument("--risk", type=int, default=2, choices=[1, 2, 3], help="Risque sqlmap (defaut: 2)")
    parser.add_argument("--no-sqlmap", action="store_true", help="Scan + probe uniquement, sans lancer sqlmap")
    parser.add_argument("--no-probe", action="store_true", help="Desactiver le probing pre-scan")
    parser.add_argument("--recon", action="store_true", help="Lancer la reconnaissance avant le scan")
    parser.add_argument("--osint", action="store_true", help="Lancer l'OSINT avant le scan")
    parser.add_argument("--full", action="store_true", help="Mode complet: recon + osint + scan + ai")
    parser.add_argument("--sqlmap-path", help="Chemin vers sqlmap")
    parser.add_argument("--no-crawl", action="store_true", help="Scanner uniquement la page fournie")
    parser.add_argument("--cookie", help="Cookie de session (ex: 'PHPSESSID=abc123')")
    parser.add_argument("--header", action="append", help="Header supplementaire (ex: 'Authorization: Bearer xxx')")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Desactiver la verification SSL (par defaut: verification active)")
    parser.add_argument("--top", type=int, default=10, help="Nombre de points a tester avec sqlmap (defaut: 10)")
    parser.add_argument("--sqlmap-args", help="Arguments supplementaires pour sqlmap (entre guillemets)")
    parser.add_argument("--probe-top", type=int, default=20, help="Nombre de points a prober (defaut: 20)")
    return parser.parse_args()


def validate_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


def build_headers(header_args):
    headers = {}
    if header_args:
        for h in header_args:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


def build_cookies(cookie_str):
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(";"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                cookies[key.strip()] = value.strip()
    return cookies


def main():
    console.print(BANNER)
    args = parse_args()

    target_url = args.url
    if not target_url:
        target_url = Prompt.ask("[bold]Entrez l'URL cible")

    target_url = validate_url(target_url)
    if not target_url:
        console.print("[bold red]URL invalide.[/bold red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold]Cible:[/bold] {target_url}\n"
        f"[bold]Profondeur:[/bold] {args.depth} | [bold]Max pages:[/bold] {args.max_pages}\n"
        f"[bold]Probing:[/bold] {'Oui' if not args.no_probe else 'Non'}\n"
        f"[bold]SQLMap:[/bold] {'Desactive' if args.no_sqlmap else f'Level {args.level} / Risk {args.risk}'}\n"
        f"[bold]Nouveautes v2:[/bold] Interception redirections, test headers, bypass WAF, probing",
        title="Configuration",
        border_style="cyan",
    ))

    if not Confirm.ask("\n[bold]Avez-vous l'autorisation de tester cette cible ?[/bold]", default=False):
        console.print("[yellow]Audit annule. Obtenez une autorisation ecrite avant de tester.[/yellow]")
        sys.exit(0)

    os.makedirs(args.output, exist_ok=True)
    custom_headers = build_headers(args.header)
    cookies = build_cookies(args.cookie)

    # ═══════════════════════════════════════════
    # PHASE 0 : Recon & OSINT (optionnel)
    # ═══════════════════════════════════════════
    if args.recon or args.full:
        console.print("\n[bold blue]== PHASE 0a : Reconnaissance avancee ==[/bold blue]")
        from core.recon import FullRecon
        recon = FullRecon(target_url, args.output)
        recon.run_full(skip_nuclei=not args.full)

    if args.osint or args.full:
        console.print("\n[bold blue]== PHASE 0b : OSINT ==[/bold blue]")
        from core.osint import FullOSINT
        osint = FullOSINT(target_url, args.output)
        osint.run_full()

    scanner = WebScanner(
        verify_ssl=not args.no_ssl_verify,
        custom_headers=custom_headers,
        cookies=cookies,
    )
    reporter = Reporter(target_url, args.output)

    # ═══════════════════════════════════════════
    # PHASE 1 : Reconnaissance
    # ═══════════════════════════════════════════
    console.print("\n[bold cyan]== PHASE 1 : Reconnaissance ==[/bold cyan]")

    console.print("  Verification robots.txt...")
    robot_paths = scanner.check_robots_txt(target_url)
    if robot_paths:
        console.print(f"  [green]{len(robot_paths)} chemins dans robots.txt[/green]")
        for p in robot_paths[:10]:
            console.print(f"    {p}")

    console.print("  Verification sitemap.xml...")
    sitemap_urls = scanner.check_sitemap(target_url)
    if sitemap_urls:
        console.print(f"  [green]{len(sitemap_urls)} URLs dans sitemap.xml[/green]")

    # ═══════════════════════════════════════════
    # PHASE 2 : Scan en profondeur + interception redirections
    # ═══════════════════════════════════════════
    console.print("\n[bold cyan]== PHASE 2 : Scan en profondeur (interception redirections active) ==[/bold cyan]")

    if args.no_crawl:
        console.print("  Mode page unique...")
        scan_results = [scanner.scan_page(target_url)]
    else:
        console.print(f"  Crawl en cours (profondeur: {args.depth}, max: {args.max_pages} pages)...")
        crawler = Crawler(scanner, max_depth=args.depth, max_pages=args.max_pages)
        scan_results = crawler.crawl(target_url)

        extra_urls = [u for u in (robot_paths + sitemap_urls) if u not in crawler.visited]
        for extra_url in extra_urls[:20]:
            if len(crawler.visited) >= args.max_pages:
                break
            console.print(f"  [dim]Scan bonus[/dim] {extra_url}")
            result = scanner.scan_page(extra_url)
            scan_results.append(result)

    # Show redirect chains found
    total_redirects = sum(len(r.redirect_chain) for r in scan_results if not r.error)
    redirect_params = sum(
        len(step.location_params)
        for r in scan_results if not r.error
        for step in r.redirect_chain
    )
    if total_redirects > 0:
        console.print(f"\n  [bold yellow]Redirections interceptees: {total_redirects} etapes, {redirect_params} parametres captures[/bold yellow]")

    reporter.set_scan_results(scan_results)
    reporter.print_scan_summary()

    # ═══════════════════════════════════════════
    # PHASE 3 : Analyse des points d'injection
    # ═══════════════════════════════════════════
    console.print("\n[bold cyan]== PHASE 3 : Analyse des points d'injection (headers + cookies + redirections) ==[/bold cyan]")

    analyzer = Analyzer(scan_results, args.output, target_url=target_url)
    injection_points = analyzer.analyze()

    reporter.set_injection_points(injection_points)
    reporter.print_injection_points()
    reporter.print_injection_details(limit=15)

    if not injection_points:
        console.print("\n[yellow]Aucun point d'injection trouve. Rapport genere.[/yellow]")
        reporter.generate_report()
        sys.exit(0)

    # ═══════════════════════════════════════════
    # PHASE 4 : Probing pre-scan (detection rapide)
    # ═══════════════════════════════════════════
    confirmed_points = []
    if not args.no_probe:
        console.print("\n[bold cyan]== PHASE 4 : Probing SQLi (detection rapide avant sqlmap) ==[/bold cyan]")
        console.print(f"  Test des {min(args.probe_top, len(injection_points))} points prioritaires...\n")

        prober = SQLiProber(session=scanner.session, verify_ssl=not args.no_ssl_verify)

        # Probe top injection points
        testable = [ip for ip in injection_points if ip.method not in ("HEADER", "COOKIE")]
        for ip in testable[:args.probe_top]:
            result = prober.probe_injection_point(ip)
            if result.error_vulnerable or result.boolean_vulnerable or result.time_vulnerable:
                confirmed_points.append(ip)
                ip.score += 50  # Big bonus for confirmed vulnerability
                ip.reasons.append("CONFIRME par probing pre-scan!")

        # Probe login forms for auth bypass
        login_forms = [
            form
            for r in scan_results if not r.error
            for form in r.forms if form.is_login_form
        ]
        for form in login_forms:
            console.print(f"\n  [yellow]Test auth bypass: {form.full_action}[/yellow]")
            bypassed, detail = prober.probe_auth_bypass(form, session=scanner.session)
            if bypassed:
                console.print(f"  [bold red]AUTH BYPASS DETECTE: {detail}[/bold red]")
                for ip in injection_points:
                    if ip.url == form.full_action and ip.source in ("login_form", "form"):
                        ip.score += 60
                        ip.reasons.append(f"AUTH BYPASS: {detail}")
                        confirmed_points.append(ip)

        # Re-sort after probing
        injection_points.sort(key=lambda x: x.score, reverse=True)

        if confirmed_points:
            console.print(f"\n  [bold red]{len(confirmed_points)} point(s) confirme(s) vulnerable(s) par probing![/bold red]")
        else:
            console.print(f"\n  [dim]Aucune vulnerabilite confirmee par probing (sqlmap ira plus loin).[/dim]")
    else:
        console.print("\n[dim]Probing desactive (--no-probe)[/dim]")

    # ═══════════════════════════════════════════
    # PHASE 5 : Generation des requetes
    # ═══════════════════════════════════════════
    console.print("\n[bold cyan]== PHASE 5 : Generation des fichiers de requetes ==[/bold cyan]")

    request_files = analyzer.generate_request_files()
    reporter.set_request_files(request_files)

    console.print(f"  [green]{len(request_files)} fichiers de requetes generes dans {args.output}/[/green]")
    for rf in request_files:
        source_tag = f" [{rf.get('source', '')}]" if rf.get('source') else ""
        console.print(f"    {rf['file']} ({rf['method']}) -> {', '.join(rf['params'][:5])}{source_tag}")

    # ═══════════════════════════════════════════
    # PHASE 6 : Execution SQLMap
    # ═══════════════════════════════════════════
    if args.no_sqlmap:
        console.print("\n[yellow]SQLMap desactive (--no-sqlmap).[/yellow]")
        console.print(f"  Utilisez manuellement:")
        console.print(f"    sqlmap -r {args.output}/request_XXX.txt --batch")
        console.print(f"    sqlmap -r {args.output}/request_XXX_headers.txt --batch --level 3")
    else:
        console.print("\n[bold cyan]== PHASE 6 : Execution SQLMap (avec retry WAF bypass) ==[/bold cyan]")

        extra_sqlmap = args.sqlmap_args.split() if args.sqlmap_args else []
        if args.cookie:
            extra_sqlmap.extend(["--cookie", args.cookie])

        sqlmap = SQLMapRunner(
            output_dir=args.output,
            sqlmap_path=args.sqlmap_path,
            extra_args=extra_sqlmap,
            scheme=urlparse(target_url).scheme,   # https -> sqlmap tape en https
        )

        if not sqlmap.is_available():
            console.print("[bold red]sqlmap non trouve ![/bold red]")
            console.print("  Installez sqlmap: pip install sqlmap  OU  git clone https://github.com/sqlmapproject/sqlmap.git")
            console.print("  Ou specifiez le chemin: --sqlmap-path /chemin/vers/sqlmap")
            console.print(f"\n  Les fichiers de requetes sont disponibles dans {args.output}/")
            console.print(f"  Utilisez: sqlmap -r {args.output}/request_XXX.txt --batch")
        else:
            console.print(f"  sqlmap detecte: {sqlmap.sqlmap_path}")

            # Prioritize confirmed points, then by score
            top_targets = request_files[:args.top]

            # Test confirmed vulnerable points first
            if confirmed_points:
                console.print(f"\n  [bold]Test prioritaire des {len(confirmed_points)} point(s) confirme(s)...[/bold]")

            confirmed_endpoints = set()  # Track endpoints already confirmed vulnerable

            for idx, target in enumerate(top_targets, 1):
                # Skip if same endpoint already confirmed (avoid WAF ban)
                target_parsed = urlparse(target["url"])
                endpoint_key = (target_parsed.netloc, target_parsed.path)
                if endpoint_key in confirmed_endpoints:
                    console.print(f"  [dim]Skip cible {idx} ({target_parsed.path}) - deja confirme vulnerable[/dim]")
                    continue

                # Anti-WAF delay between targets (skip for first)
                if idx > 1:
                    console.print(f"  [dim]Pause anti-WAF (5s)...[/dim]")
                    time.sleep(5)

                console.print(Panel(
                    f"Cible {idx}/{len(top_targets)}: {target['method']} {target['url'][:80]}\n"
                    f"Parametres: {', '.join(target['params'][:5])}\n"
                    f"Source: {target.get('source', 'unknown')} | Score: {target['max_score']}",
                    border_style="cyan",
                ))

                if target["method"] == "HEADER":
                    result = sqlmap.run_headers_test(target["url"], level=max(args.level, 3), risk=args.risk)
                elif target["method"] == "COOKIE":
                    result = sqlmap.run_with_request_file(
                        target["file"], level=max(args.level, 2), risk=args.risk,
                    )
                else:
                    result = sqlmap.run_with_request_file(
                        target["file"],
                        params=target["params"],
                        level=args.level,
                        risk=args.risk,
                    )

                # Mark endpoint as confirmed if vulnerable
                if result and result.get("vulnerable"):
                    confirmed_endpoints.add(endpoint_key)
                    console.print(f"  [bold green]Endpoint confirme vulnerable, skip des doublons[/bold green]")
                    remaining = len(top_targets) - idx
                    if remaining > 0 and not Confirm.ask(
                        f"\n  [bold]Vulnerabilite trouvee ! Continuer le scan des {remaining} cible(s) restante(s) ?[/bold]",
                        default=False,
                    ):
                        console.print("  [dim]Scan stoppe. Passez au portail interactif pour exploiter.[/dim]")
                        break

            # Complementary: sqlmap --forms --crawl
            console.print("\n  [cyan]Scan complementaire: sqlmap --forms --crawl[/cyan]")
            sqlmap.run_forms_crawl(
                target_url,
                crawl_depth=min(args.depth, 3),
                level=args.level,
                risk=args.risk,
            )

            summary = sqlmap.get_summary()
            reporter.set_sqlmap_summary(summary)
            reporter.print_sqlmap_summary()

    # ═══════════════════════════════════════════
    # PHASE 7 : Rapport
    # ═══════════════════════════════════════════
    console.print("\n[bold cyan]== PHASE 7 : Generation du rapport ==[/bold cyan]")
    json_path, html_path = reporter.generate_report()

    # ═══════════════════════════════════════════
    # PHASE 8 : Analyse IA (si mode full)
    # ═══════════════════════════════════════════
    if args.full:
        console.print("\n[bold red]== PHASE 8 : Analyse IA ==[/bold red]")
        from core.ai_agent import AIAnalyzer
        ai = AIAnalyzer(args.output)
        ai.analyze()
        ai.save_analysis()

    vuln_count = len(confirmed_points)
    console.print(Panel(
        f"[bold green]Audit termine ![/bold green]\n\n"
        f"Cible: {target_url}\n"
        f"Points d'injection identifies: {len(injection_points)}\n"
        f"Confirmes par probing: [{'bold red' if vuln_count else 'green'}]{vuln_count}[/{'bold red' if vuln_count else 'green'}]\n"
        f"Fichiers de requetes: {len(request_files)}\n"
        f"Rapport JSON: {json_path}\n"
        f"Rapport HTML: {html_path}\n\n"
        f"[dim]Techniques: redirections, headers, cookies, JS, forms, auth bypass, WAF bypass[/dim]\n"
        f"[dim]Options: --recon (reconnaissance) | --osint (OSINT) | --full (tout)[/dim]",
        title="Termine",
        border_style="green",
    ))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrompu par l'utilisateur. Sortie propre.[/yellow]")
        console.print("[dim]Les fichiers de requetes/rapports deja generes restent dans le dossier de sortie.[/dim]")
        sys.exit(130)
