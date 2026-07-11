import os
import html
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class Reporter:
    def __init__(self, target_url, output_dir="output"):
        self.target_url = target_url
        self.output_dir = output_dir
        self.scan_results = []
        self.injection_points = []
        self.request_files = []
        self.sqlmap_summary = {}
        self.start_time = datetime.now()

    def set_scan_results(self, results):
        self.scan_results = results

    def set_injection_points(self, points):
        self.injection_points = points

    def set_request_files(self, files):
        self.request_files = files

    def set_sqlmap_summary(self, summary):
        self.sqlmap_summary = summary

    def print_scan_summary(self):
        total_pages = len(self.scan_results)
        total_forms = sum(len(r.forms) for r in self.scan_results if not r.error)
        total_links = len(set(
            link for r in self.scan_results if not r.error for link in r.links
        ))
        total_js = sum(len(r.js_files) for r in self.scan_results if not r.error)
        total_js_endpoints = len(set(
            ep for r in self.scan_results if not r.error for ep in r.js_endpoints
        ))
        total_params = sum(len(r.url_parameters) for r in self.scan_results if not r.error)
        total_comments = sum(len(r.comments) for r in self.scan_results if not r.error)
        total_hidden = sum(len(r.hidden_inputs) for r in self.scan_results if not r.error)

        table = Table(title="Resultats du Scan", show_header=False, border_style="cyan")
        table.add_column("Metrique", style="bold")
        table.add_column("Valeur", justify="right")

        table.add_row("Pages scannees", str(total_pages))
        table.add_row("Formulaires trouves", str(total_forms))
        table.add_row("Liens internes", str(total_links))
        table.add_row("Fichiers JavaScript", str(total_js))
        table.add_row("Endpoints JS decouverts", str(total_js_endpoints))
        table.add_row("Parametres URL", str(total_params))
        table.add_row("Inputs caches", str(total_hidden))
        table.add_row("Commentaires HTML", str(total_comments))

        console.print()
        console.print(table)

        techs = set()
        for r in self.scan_results:
            if not r.error:
                techs.update(r.technologies)
        if techs:
            console.print("\n[bold]Technologies detectees:[/bold]")
            for tech in techs:
                console.print(f"  [cyan]{tech}[/cyan]")

    def print_injection_points(self):
        if not self.injection_points:
            console.print("\n[yellow]Aucun point d'injection identifie.[/yellow]")
            return

        table = Table(title=f"Points d'Injection ({len(self.injection_points)})", border_style="red")
        table.add_column("#", style="dim", width=4)
        table.add_column("Priorite", width=10)
        table.add_column("Score", justify="right", width=6)
        table.add_column("Methode", width=7)
        table.add_column("Parametre", style="bold")
        table.add_column("URL", max_width=50)
        table.add_column("Source")

        for idx, ip in enumerate(self.injection_points, 1):
            priority_style = {
                "CRITIQUE": "bold red",
                "HAUT": "red",
                "MOYEN": "yellow",
                "BAS": "dim",
            }.get(ip.priority, "dim")

            table.add_row(
                str(idx),
                f"[{priority_style}]{ip.priority}[/{priority_style}]",
                str(ip.score),
                ip.method,
                ip.param_name,
                ip.url[:50] + "..." if len(ip.url) > 50 else ip.url,
                ip.source,
            )

        console.print()
        console.print(table)

    def print_injection_details(self, limit=10):
        console.print(f"\n[bold]Details des {min(limit, len(self.injection_points))} premiers points:[/bold]")
        for idx, ip in enumerate(self.injection_points[:limit], 1):
            priority_style = {
                "CRITIQUE": "bold red",
                "HAUT": "red",
                "MOYEN": "yellow",
                "BAS": "dim",
            }.get(ip.priority, "dim")

            console.print(f"\n  [{priority_style}]#{idx} [{ip.priority}] Score: {ip.score}[/{priority_style}]")
            console.print(f"  URL: {ip.url}")
            console.print(f"  Methode: {ip.method} | Parametre: [bold]{ip.param_name}[/bold] = {ip.param_value}")
            console.print(f"  Source: {ip.source} | Page: {ip.page_url}")
            if ip.reasons:
                console.print(f"  Raisons:")
                for reason in ip.reasons:
                    console.print(f"    - {reason}")

    def print_sqlmap_summary(self):
        if not self.sqlmap_summary:
            return

        s = self.sqlmap_summary
        style = "bold red" if s.get("vulnerable", 0) > 0 else "bold green"

        panel_text = (
            f"Tests executes: {s.get('total_tests', 0)}\n"
            f"[{style}]Vulnerables: {s.get('vulnerable', 0)}[/{style}]\n"
            f"Non vulnerables: {s.get('clean', 0)}\n"
            f"Erreurs: {s.get('errors', 0)}"
        )

        console.print()
        console.print(Panel(panel_text, title="Resultats SQLMap", border_style="red"))

        for detail in s.get("details", []):
            if detail.get("vulnerable"):
                console.print(f"\n  [bold red]VULNERABLE:[/bold red] {detail.get('file', detail.get('url', '?'))}")
                for vuln in detail.get("vulnerabilities", []):
                    console.print(f"    [red]{vuln}[/red]")

    def generate_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        duration = datetime.now() - self.start_time

        report = {
            "target": self.target_url,
            "scan_date": self.start_time.isoformat(),
            "duration_seconds": duration.total_seconds(),
            "pages_scanned": len(self.scan_results),
            "injection_points": [
                {
                    "url": ip.url,
                    "method": ip.method,
                    "param": ip.param_name,
                    "value": ip.param_value,
                    "score": ip.score,
                    "priority": ip.priority,
                    "source": ip.source,
                    "reasons": ip.reasons,
                }
                for ip in self.injection_points
            ],
            "request_files": self.request_files,
            "sqlmap_results": self.sqlmap_summary,
            "technologies": list(set(
                tech
                for r in self.scan_results if not r.error
                for tech in r.technologies
            )),
            "forms_found": [
                form.to_dict()
                for r in self.scan_results if not r.error
                for form in r.forms
            ],
        }

        json_path = os.path.join(self.output_dir, "report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        html_path = os.path.join(self.output_dir, "report.html")
        self._generate_html_report(report, html_path)

        console.print(f"\n[bold green]Rapports generes:[/bold green]")
        console.print(f"  JSON: {json_path}")
        console.print(f"  HTML: {html_path}")

        return json_path, html_path

    def _generate_html_report(self, data, path):
        # Toutes les valeurs issues de la CIBLE (URLs, params, headers Server,
        # actions de formulaires...) sont ECHAPPEES : une cible malveillante ne
        # doit pas pouvoir injecter de HTML/JS dans le rapport (self-XSS a l'ouverture).
        esc = lambda v: html.escape(str(v))

        vuln_count = data.get("sqlmap_results", {}).get("vulnerable", 0)
        status_color = "#e74c3c" if vuln_count > 0 else "#27ae60"
        status_text = f"{vuln_count} VULNERABILITE(S)" if vuln_count > 0 else "AUCUNE VULNERABILITE"
        target_esc = esc(data.get("target", ""))

        injection_rows = ""
        for ip in data["injection_points"]:
            p = ip["priority"]
            color = {"CRITIQUE": "#e74c3c", "HAUT": "#e67e22", "MOYEN": "#f39c12", "BAS": "#95a5a6"}.get(p, "#95a5a6")
            injection_rows += f"""
            <tr>
                <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;">{esc(p)}</span></td>
                <td>{esc(ip['score'])}</td>
                <td><code>{esc(ip['method'])}</code></td>
                <td><strong>{esc(ip['param'])}</strong></td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;">{esc(ip['url'])}</td>
                <td>{esc(ip['source'])}</td>
            </tr>"""

        forms_rows = ""
        for form in data.get("forms_found", []):
            inputs_list = ", ".join(
                f"<code>{esc(inp['name'])}</code> ({esc(inp['type'])})"
                for inp in form.get("inputs", []) if inp.get("name")
            )
            forms_rows += f"""
            <tr>
                <td><code>{esc(form.get('method', 'GET'))}</code></td>
                <td>{esc(form.get('full_action', ''))}</td>
                <td>{inputs_list}</td>
            </tr>"""

        tech_list = "".join(f"<li>{esc(t)}</li>" for t in data.get("technologies", []))

        html_out = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport Audit SQLi - {target_esc}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 5px; }}
        h2 {{ color: #00d4ff; margin: 30px 0 15px; border-bottom: 1px solid #333; padding-bottom: 5px; }}
        .header {{ background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .status {{ display: inline-block; background: {status_color}; color: #fff; padding: 5px 15px;
                   border-radius: 4px; font-weight: bold; font-size: 1.1em; margin-top: 10px; }}
        .meta {{ color: #888; margin-top: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
        th {{ background: #16213e; color: #00d4ff; }}
        tr:hover {{ background: #16213e44; }}
        code {{ background: #2a2a4a; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
        .card {{ background: #16213e; padding: 15px; border-radius: 8px; margin: 10px 0; }}
        ul {{ padding-left: 20px; }}
        li {{ margin: 4px 0; }}
        .footer {{ text-align: center; color: #555; margin-top: 40px; padding: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Rapport d'Audit SQL Injection</h1>
            <div class="meta">
                Cible: <strong>{target_esc}</strong><br>
                Date: {data['scan_date']}<br>
                Duree: {data['duration_seconds']:.1f}s |
                Pages: {data['pages_scanned']} |
                Points d'injection: {len(data['injection_points'])}
            </div>
            <div class="status">{status_text}</div>
        </div>

        <h2>Technologies Detectees</h2>
        <div class="card">
            <ul>{tech_list if tech_list else '<li>Aucune technologie identifiee</li>'}</ul>
        </div>

        <h2>Points d'Injection ({len(data['injection_points'])})</h2>
        <table>
            <tr><th>Priorite</th><th>Score</th><th>Methode</th><th>Parametre</th><th>URL</th><th>Source</th></tr>
            {injection_rows if injection_rows else '<tr><td colspan="6">Aucun point identifie</td></tr>'}
        </table>

        <h2>Formulaires Decouverts ({len(data.get('forms_found', []))})</h2>
        <table>
            <tr><th>Methode</th><th>Action</th><th>Champs</th></tr>
            {forms_rows if forms_rows else '<tr><td colspan="3">Aucun formulaire</td></tr>'}
        </table>

        <div class="footer">
            Genere par SQLi Auto-Auditor | Usage autorise uniquement
        </div>
    </div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_out)
