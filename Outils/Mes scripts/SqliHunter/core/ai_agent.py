"""
AI Analysis Agent - Correlation intelligente des resultats de scan.
Analyse les donnees collectees, priorise les vecteurs d'attaque,
suggere les prochaines etapes et genere des strategies d'exploitation.
"""

import os
import json
import re
from datetime import datetime
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class AIAnalyzer:
    """
    Agent IA d'analyse qui correle toutes les donnees collectees
    et fournit des recommandations intelligentes.
    """

    def __init__(self, output_dir="output"):
        self.output_dir = output_dir
        self.data = {
            "recon": {},
            "osint": {},
            "sqli": {},
            "nosqli": [],
            "xss": [],
            "loot": {},
        }
        self.attack_surface = []
        self.recommendations = []
        self.risk_score = 0

    def load_all_data(self):
        """Load all scan results from output directory."""
        # Recon
        recon_path = os.path.join(self.output_dir, "recon_results.json")
        if os.path.exists(recon_path):
            with open(recon_path, "r", encoding="utf-8") as f:
                self.data["recon"] = json.load(f)

        # OSINT
        osint_path = os.path.join(self.output_dir, "osint_results.json")
        if os.path.exists(osint_path):
            with open(osint_path, "r", encoding="utf-8") as f:
                self.data["osint"] = json.load(f)

        # SQLi report
        report_path = os.path.join(self.output_dir, "report.json")
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                self.data["sqli"] = json.load(f)

        # Loot data
        loot_dir = os.path.join(self.output_dir, "loot")
        if os.path.exists(loot_dir):
            for fname in os.listdir(loot_dir):
                if fname.endswith(".json"):
                    with open(os.path.join(loot_dir, fname), "r", encoding="utf-8") as f:
                        self.data["loot"][fname] = json.load(f)

    def analyze(self):
        """Run full AI analysis on collected data."""
        self.load_all_data()

        console.print(Panel(
            "[bold]Agent IA - Analyse de la surface d'attaque[/bold]\n"
            "[dim]Correlation des donnees | Priorisation | Recommandations[/dim]",
            border_style="cyan",
        ))

        self._analyze_attack_surface()
        self._analyze_vulnerabilities()
        self._analyze_data_exposure()
        self._generate_recommendations()
        self._calculate_risk_score()
        self._display_results()

        return {
            "attack_surface": self.attack_surface,
            "recommendations": self.recommendations,
            "risk_score": self.risk_score,
        }

    def _analyze_attack_surface(self):
        """Map the complete attack surface."""
        console.print("\n  [bold]Phase 1: Cartographie de la surface d'attaque[/bold]")

        recon = self.data.get("recon", {})
        osint = self.data.get("osint", {})

        # Subdomains
        subdomains = recon.get("subdomains", [])
        if subdomains:
            self.attack_surface.append({
                "category": "subdomains",
                "count": len(subdomains),
                "items": subdomains[:20],
                "risk": "MEDIUM",
                "note": "Chaque sous-domaine est un point d'entree potentiel",
            })
            console.print(f"    [cyan]{len(subdomains)} sous-domaines[/cyan]")

        # Open ports
        ports = recon.get("ports", [])
        critical_ports = [p for p in ports if p.get("port") in (21, 22, 23, 3306, 5432, 6379, 27017, 9200, 5601, 5984, 11211)]
        if ports:
            self.attack_surface.append({
                "category": "ports",
                "count": len(ports),
                "critical": len(critical_ports),
                "items": ports,
                "risk": "HIGH" if critical_ports else "LOW",
                "note": f"{len(critical_ports)} ports critiques exposes" if critical_ports else "Ports standards",
            })
            console.print(f"    [cyan]{len(ports)} ports ouverts ({len(critical_ports)} critiques)[/cyan]")

        # Exposed services
        techs = recon.get("technologies", {})
        exposed = {k: v for k, v in techs.items() if k.startswith("EXPOSED:")}
        if exposed:
            self.attack_surface.append({
                "category": "exposed_services",
                "count": len(exposed),
                "items": list(exposed.keys()),
                "risk": "CRITICAL",
                "note": "Services administratifs exposes sur Internet",
            })
            console.print(f"    [bold red]{len(exposed)} services exposes[/bold red]")

        # Directories found
        dirs = recon.get("directories", [])
        sensitive_dirs = [d for d in dirs if d.get("status") == 200 and
                         any(kw in d.get("path", "").lower() for kw in
                             (".env", ".git", "admin", "config", "backup", "phpmy", "kibana", "elastic", "debug", "phpinfo"))]
        if dirs:
            self.attack_surface.append({
                "category": "directories",
                "count": len(dirs),
                "sensitive": len(sensitive_dirs),
                "items": sensitive_dirs[:10],
                "risk": "HIGH" if sensitive_dirs else "LOW",
                "note": f"{len(sensitive_dirs)} chemins sensibles accessibles" if sensitive_dirs else "",
            })
            console.print(f"    [cyan]{len(dirs)} chemins decouverts ({len(sensitive_dirs)} sensibles)[/cyan]")

        # Wayback URLs
        wayback = recon.get("wayback_urls", [])
        if wayback:
            interesting = [u for u in wayback if any(kw in u.lower() for kw in
                          ("admin", "login", "config", "api", "upload", "backup", "test", "debug", ".sql", ".bak", ".env"))]
            self.attack_surface.append({
                "category": "wayback",
                "count": len(wayback),
                "interesting": len(interesting),
                "items": interesting[:15],
                "risk": "MEDIUM" if interesting else "LOW",
                "note": f"{len(interesting)} URLs historiques interessantes",
            })
            console.print(f"    [cyan]{len(wayback)} URLs Wayback ({len(interesting)} interessantes)[/cyan]")

    def _analyze_vulnerabilities(self):
        """Analyze all discovered vulnerabilities."""
        console.print("\n  [bold]Phase 2: Analyse des vulnerabilites[/bold]")

        sqli = self.data.get("sqli", {})

        # SQLi findings
        sqli_results = sqli.get("sqlmap_results", {})
        vuln_count = sqli_results.get("vulnerable", 0)
        if vuln_count > 0:
            details = sqli_results.get("details", [])
            techniques = set()
            for d in details:
                for v in d.get("vulnerabilities", []):
                    for technique in ("boolean-based", "error-based", "time-based", "UNION", "stacked"):
                        if technique.lower() in v.lower():
                            techniques.add(technique)

            self.attack_surface.append({
                "category": "sqli",
                "count": vuln_count,
                "techniques": list(techniques),
                "risk": "CRITICAL",
                "note": f"SQL Injection confirmee via {', '.join(techniques)}",
            })
            console.print(f"    [bold red]{vuln_count} SQLi confirmes (techniques: {', '.join(techniques)})[/bold red]")

        # Injection points
        injection_points = sqli.get("injection_points", [])
        confirmed = [p for p in injection_points if "CONFIRME" in " ".join(p.get("reasons", []))]
        if confirmed:
            console.print(f"    [red]{len(confirmed)} points d'injection confirmes[/red]")

        # Security headers
        osint = self.data.get("osint", {})
        sec_headers = osint.get("security_headers", {})
        if sec_headers:
            score = sec_headers.get("score", 0)
            missing = sec_headers.get("missing", [])
            issues = sec_headers.get("issues", [])
            if score < 50:
                self.attack_surface.append({
                    "category": "security_config",
                    "score": score,
                    "missing_headers": missing,
                    "issues": issues[:5],
                    "risk": "HIGH" if score < 30 else "MEDIUM",
                    "note": f"Score securite: {score}% - Headers manquants: {', '.join(missing[:3])}",
                })
                console.print(f"    [yellow]Score securite headers: {score}%[/yellow]")

        # Nuclei findings
        nuclei = self.data.get("recon", {}).get("nuclei", [])
        if nuclei:
            critical = [n for n in nuclei if n.get("severity") in ("critical", "high")]
            self.attack_surface.append({
                "category": "nuclei",
                "count": len(nuclei),
                "critical": len(critical),
                "items": nuclei[:10],
                "risk": "CRITICAL" if critical else "MEDIUM",
                "note": f"{len(critical)} vulnerabilites critiques/hautes (Nuclei)",
            })
            console.print(f"    [red]{len(nuclei)} findings Nuclei ({len(critical)} critiques)[/red]")

        # Shodan CVEs
        shodan = osint.get("shodan", {})
        vulns = shodan.get("vulns", [])
        if vulns:
            self.attack_surface.append({
                "category": "cves",
                "count": len(vulns),
                "items": vulns[:10],
                "risk": "CRITICAL",
                "note": f"{len(vulns)} CVEs connues (Shodan)",
            })
            console.print(f"    [bold red]{len(vulns)} CVEs connues[/bold red]")

    def _analyze_data_exposure(self):
        """Analyze extracted data for sensitive information."""
        console.print("\n  [bold]Phase 3: Analyse de l'exposition des donnees[/bold]")

        for fname, loot in self.data.get("loot", {}).items():
            entries = loot.get("entries", [])

            cred_entries = [e for e in entries if e.get("category") in ("credentials", "dump", "query")]
            file_entries = [e for e in entries if e.get("category") == "file"]

            # Check for credentials in dumps
            cred_count = 0
            for entry in cred_entries:
                data = entry.get("data", [])
                for row in data if isinstance(data, list) else []:
                    if isinstance(row, dict):
                        for key, val in row.items():
                            if any(kw in key.lower() for kw in ("password", "pass", "pwd", "secret", "token", "key", "hash")):
                                cred_count += 1

            if cred_count > 0:
                console.print(f"    [bold red]{cred_count} champs de credentials/secrets trouves dans le loot[/bold red]")

            if file_entries:
                console.print(f"    [yellow]{len(file_entries)} fichiers serveur lus[/yellow]")

            # Check for specific high-value data
            for entry in entries:
                title = entry.get("title", "").lower()
                if any(kw in title for kw in ("passwd", "shadow", "config", "credential", "id_rsa", "private key")):
                    console.print(f"    [bold red]Donnee critique: {entry.get('title', '')}[/bold red]")

    def _generate_recommendations(self):
        """Generate prioritized recommendations based on all findings."""
        console.print("\n  [bold]Phase 4: Generation des recommandations[/bold]")

        # Build recommendations based on findings
        for finding in self.attack_surface:
            cat = finding["category"]
            risk = finding["risk"]

            if cat == "sqli" and risk == "CRITICAL":
                self.recommendations.append({
                    "priority": 1,
                    "risk": "CRITICAL",
                    "title": "Exploitation SQL Injection",
                    "actions": [
                        "Utiliser le portail interactif [S] pour extraire les donnees",
                        "Tester --os-shell pour acces systeme",
                        "Extraire /etc/passwd et /etc/shadow via --file-read",
                        "Dump toutes les bases avec --dump-all --exclude-sysdbs",
                        "Chercher les credentials: --search -C password,secret,token",
                        f"Techniques detectees: {', '.join(finding.get('techniques', []))}",
                    ],
                })

            elif cat == "exposed_services" and risk == "CRITICAL":
                services = finding.get("items", [])
                actions = []
                for svc in services:
                    svc_name = svc.replace("EXPOSED: ", "")
                    if "Kibana" in svc_name:
                        actions.append("Kibana expose -> Acceder aux dashboards, indices Elasticsearch, logs applicatifs")
                    elif "Elasticsearch" in svc_name:
                        actions.append("Elasticsearch expose -> GET /_cat/indices pour lister les index, puis GET /index/_search pour extraire les donnees")
                    elif "Git" in svc_name:
                        actions.append("Repository Git expose -> Utiliser git-dumper pour recuperer le code source")
                    elif "phpMyAdmin" in svc_name:
                        actions.append("phpMyAdmin expose -> Tenter les credentials par defaut, puis acces BDD complet")
                    elif "CouchDB" in svc_name:
                        actions.append("CouchDB expose -> GET /_all_dbs puis GET /dbname/_all_docs pour extraire les donnees")
                    elif "Grafana" in svc_name:
                        actions.append("Grafana expose -> Verifier CVE-2021-43798 (path traversal), acceder aux datasources")
                    else:
                        actions.append(f"{svc_name} expose -> Tester les credentials par defaut")

                self.recommendations.append({
                    "priority": 1,
                    "risk": "CRITICAL",
                    "title": "Services administratifs exposes",
                    "actions": actions,
                })

            elif cat == "cves":
                cves = finding.get("items", [])[:5]
                self.recommendations.append({
                    "priority": 2,
                    "risk": "HIGH",
                    "title": "CVEs connues a exploiter",
                    "actions": [
                        f"Rechercher les exploits pour: {', '.join(cves[:5])}",
                        "Utiliser searchsploit ou exploit-db.com",
                        "Verifier si Metasploit a des modules pour ces CVEs",
                    ],
                })

            elif cat == "ports" and finding.get("critical", 0) > 0:
                critical_ports = [p for p in finding.get("items", []) if p.get("port") in (21, 22, 23, 3306, 5432, 6379, 27017, 9200, 5601)]
                actions = []
                for p in critical_ports:
                    port = p["port"]
                    service = p.get("service", "")
                    if port == 21:
                        actions.append("FTP (21) -> Tester anonymous login, credentials par defaut")
                    elif port == 22:
                        actions.append("SSH (22) -> Brute-force avec credentials trouvees, tester les cles RSA lues")
                    elif port == 3306:
                        actions.append("MySQL (3306) -> Connexion directe avec credentials extraites via SQLi")
                    elif port == 6379:
                        actions.append("Redis (6379) -> Tester acces sans auth, extraire les cles")
                    elif port == 27017:
                        actions.append("MongoDB (27017) -> Tester acces sans auth, lancer NoSQLi scanner")
                    elif port == 9200:
                        actions.append("Elasticsearch (9200) -> GET /_cat/indices, GET /_search pour extraire des donnees")
                    elif port == 5601:
                        actions.append("Kibana (5601) -> Acceder a l'interface, explorer les index et dashboards")

                if actions:
                    self.recommendations.append({
                        "priority": 2,
                        "risk": "HIGH",
                        "title": "Ports critiques ouverts",
                        "actions": actions,
                    })

            elif cat == "directories" and finding.get("sensitive", 0) > 0:
                items = finding.get("items", [])
                actions = [f"Explorer {d['path']} (HTTP {d['status']})" for d in items[:8]]
                self.recommendations.append({
                    "priority": 3,
                    "risk": "MEDIUM",
                    "title": "Chemins sensibles accessibles",
                    "actions": actions,
                })

            elif cat == "subdomains" and finding.get("count", 0) > 5:
                self.recommendations.append({
                    "priority": 4,
                    "risk": "MEDIUM",
                    "title": "Sous-domaines a auditer",
                    "actions": [
                        f"{finding['count']} sous-domaines decouverts",
                        "Lancer le scanner SQLi/XSS sur chaque sous-domaine",
                        "Verifier les certificats SSL de chaque sous-domaine",
                        "Chercher des panels admin ou services internes",
                    ],
                })

            elif cat == "security_config":
                self.recommendations.append({
                    "priority": 5,
                    "risk": "LOW",
                    "title": "Configuration securite faible",
                    "actions": [
                        f"Score securite: {finding.get('score', 0)}%",
                        f"Headers manquants: {', '.join(finding.get('missing_headers', []))}",
                        "Exploiter l'absence de CSP pour les payloads XSS",
                        "Exploiter l'absence de X-Frame-Options pour le clickjacking",
                    ],
                })

            elif cat == "wayback" and finding.get("interesting", 0) > 0:
                items = finding.get("items", [])
                self.recommendations.append({
                    "priority": 4,
                    "risk": "MEDIUM",
                    "title": "URLs historiques a explorer",
                    "actions": [f"Tester: {u[:80]}" for u in items[:8]],
                })

        # Sort by priority
        self.recommendations.sort(key=lambda x: x["priority"])

    def _calculate_risk_score(self):
        """Calculate overall risk score (0-100)."""
        score = 0
        weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}

        for finding in self.attack_surface:
            risk = finding.get("risk", "LOW")
            score += weights.get(risk, 0)

        self.risk_score = min(100, score)

    def _display_results(self):
        """Display the complete analysis results."""
        # Risk score
        if self.risk_score >= 70:
            score_color = "bold red"
            level = "CRITIQUE"
        elif self.risk_score >= 50:
            score_color = "red"
            level = "HAUT"
        elif self.risk_score >= 30:
            score_color = "yellow"
            level = "MOYEN"
        else:
            score_color = "green"
            level = "BAS"

        console.print(Panel(
            f"[{score_color}]Score de risque global: {self.risk_score}/100 ({level})[/{score_color}]",
            title="Evaluation du risque",
            border_style=score_color.replace("bold ", ""),
        ))

        # Attack surface summary
        table = Table(title="Surface d'attaque", border_style="cyan", show_lines=True)
        table.add_column("Categorie", style="bold")
        table.add_column("Quantite", justify="right")
        table.add_column("Risque", width=10)
        table.add_column("Note", max_width=50)

        for finding in self.attack_surface:
            risk = finding["risk"]
            risk_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(risk, "dim")
            table.add_row(
                finding["category"],
                str(finding.get("count", finding.get("score", ""))),
                f"[{risk_style}]{risk}[/{risk_style}]",
                finding.get("note", ""),
            )
        console.print(table)

        # Recommendations
        if self.recommendations:
            console.print(f"\n[bold]{'=' * 60}[/bold]")
            console.print(f"[bold]PLAN D'ATTAQUE RECOMMANDE ({len(self.recommendations)} etapes)[/bold]")
            console.print(f"[bold]{'=' * 60}[/bold]\n")

            for idx, rec in enumerate(self.recommendations, 1):
                risk = rec["risk"]
                risk_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(risk, "dim")

                actions_text = "\n".join(f"  {chr(9654)} {a}" for a in rec["actions"])
                console.print(Panel(
                    f"[{risk_style}][{risk}][/{risk_style}] {rec['title']}\n\n{actions_text}",
                    title=f"Etape {idx} (Priorite {rec['priority']})",
                    border_style=risk_style.replace("bold ", ""),
                ))

    def get_smart_queries(self, discovered_dbs=None, discovered_tables=None):
        """Generate intelligent SQL queries based on all collected intelligence."""
        queries = []

        # If we know the DBMS type from recon/OSINT
        recon_techs = self.data.get("recon", {}).get("technologies", {})
        osint_data = self.data.get("osint", {})

        # Check for specific services that hint at data to look for
        for tech_name in recon_techs:
            if "RADIUS" in tech_name or "FreeRADIUS" in tech_name:
                queries.extend([
                    ("Identifiants RADIUS", "SELECT username, attribute, value FROM radcheck LIMIT 100"),
                    ("NAS (Access Points)", "SELECT nasname, shortname, secret FROM nas"),
                    ("Sessions actives", "SELECT username, framedipaddress, acctstarttime FROM radacct ORDER BY radacctid DESC LIMIT 50"),
                ])
            if "WordPress" in tech_name:
                queries.extend([
                    ("Utilisateurs WordPress", "SELECT user_login, user_pass, user_email FROM wp_users"),
                    ("Options WordPress", "SELECT option_name, option_value FROM wp_options WHERE option_name IN ('siteurl','blogname','admin_email')"),
                ])
            if "Kibana" in tech_name or "Elasticsearch" in tech_name:
                queries.append(("Note", "-- Elasticsearch/Kibana detecte: acceder directement via HTTP"))

        # If we found exposed services with potential data
        for tech_name in recon_techs:
            if "EXPOSED: CouchDB" in tech_name:
                queries.append(("CouchDB", "-- CouchDB expose: GET /_all_dbs pour lister les bases"))

        # Generic high-value queries based on discovered tables
        if discovered_tables:
            for db_key, tables in discovered_tables.items():
                for db_name, tbl_name in tables:
                    tbl_lower = tbl_name.lower()
                    # Password/credential tables
                    if any(kw in tbl_lower for kw in ("user", "account", "member", "login", "auth", "admin")):
                        queries.append((f"Credentials: {tbl_name}", f"SELECT * FROM {db_name}.{tbl_name} LIMIT 100"))
                    # Session/token tables
                    if any(kw in tbl_lower for kw in ("session", "token", "oauth", "jwt")):
                        queries.append((f"Sessions: {tbl_name}", f"SELECT * FROM {db_name}.{tbl_name} ORDER BY 1 DESC LIMIT 50"))
                    # Config tables
                    if any(kw in tbl_lower for kw in ("config", "setting", "option", "param")):
                        queries.append((f"Config: {tbl_name}", f"SELECT * FROM {db_name}.{tbl_name} LIMIT 100"))
                    # Log tables
                    if any(kw in tbl_lower for kw in ("log", "audit", "history", "event")):
                        queries.append((f"Logs: {tbl_name}", f"SELECT * FROM {db_name}.{tbl_name} ORDER BY 1 DESC LIMIT 30"))

        return queries

    def suggest_file_paths(self, technologies=None):
        """Generate intelligent file read suggestions based on detected stack."""
        paths = []

        recon_techs = self.data.get("recon", {}).get("technologies", {})
        all_techs = list(recon_techs.keys())
        if technologies:
            all_techs.extend(technologies)

        tech_str = " ".join(all_techs).lower()

        # Always useful
        paths.append(("Systeme", "/etc/passwd", "Utilisateurs systeme"))
        paths.append(("Systeme", "/etc/shadow", "Hash des mots de passe"))
        paths.append(("Systeme", "/proc/version", "Version kernel"))

        if "nginx" in tech_str:
            paths.append(("Nginx", "/etc/nginx/nginx.conf", "Config Nginx"))
            paths.append(("Nginx", "/etc/nginx/sites-enabled/default", "VirtualHost"))
            paths.append(("Nginx", "/var/log/nginx/error.log", "Logs erreur"))

        if "apache" in tech_str:
            paths.append(("Apache", "/etc/apache2/apache2.conf", "Config Apache"))
            paths.append(("Apache", "/etc/apache2/sites-enabled/000-default.conf", "VirtualHost"))

        if "php" in tech_str:
            paths.append(("PHP", "/etc/php/7.0/apache2/php.ini", "Config PHP"))
            paths.append(("PHP", "/var/www/html/config.php", "Config applicative"))

        if "wordpress" in tech_str:
            paths.append(("WordPress", "/var/www/html/wp-config.php", "Config WordPress (DB creds)"))

        if "laravel" in tech_str:
            paths.append(("Laravel", "/var/www/html/.env", "Variables d'environnement"))

        if "django" in tech_str:
            paths.append(("Django", "/var/www/html/settings.py", "Config Django"))

        if "mysql" in tech_str or "maria" in tech_str:
            paths.append(("MySQL", "/etc/mysql/my.cnf", "Config MySQL"))
            paths.append(("MySQL", "/etc/mysql/debian.cnf", "Credentials Debian"))

        if "postgres" in tech_str:
            paths.append(("PostgreSQL", "/etc/postgresql/main/pg_hba.conf", "Auth PostgreSQL"))

        if "redis" in tech_str:
            paths.append(("Redis", "/etc/redis/redis.conf", "Config Redis"))

        if "mongodb" in tech_str or "mongo" in tech_str:
            paths.append(("MongoDB", "/etc/mongod.conf", "Config MongoDB"))

        if "radius" in tech_str or "freeradius" in tech_str:
            paths.append(("RADIUS", "/etc/freeradius/radiusd.conf", "Config RADIUS"))
            paths.append(("RADIUS", "/etc/freeradius/sql.conf", "Credentials SQL"))
            paths.append(("RADIUS", "/etc/freeradius/clients.conf", "Clients RADIUS"))

        if "docker" in tech_str:
            paths.append(("Docker", "/proc/1/cgroup", "Detection Docker"))
            paths.append(("Docker", "/.dockerenv", "Confirmation Docker"))

        # SSH always
        paths.append(("SSH", "/root/.ssh/id_rsa", "Cle privee SSH root"))
        paths.append(("SSH", "/root/.bash_history", "Historique root"))
        paths.append(("Cron", "/etc/crontab", "Taches planifiees"))

        return paths

    def save_analysis(self):
        """Save analysis results to JSON."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "risk_score": self.risk_score,
            "attack_surface": self.attack_surface,
            "recommendations": self.recommendations,
        }
        path = os.path.join(self.output_dir, "ai_analysis.json")
        os.makedirs(self.output_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        console.print(f"\n  [green]Analyse IA sauvegardee: {path}[/green]")
        return path
