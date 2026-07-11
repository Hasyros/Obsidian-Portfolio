"""
Reconnaissance Module - Enumeration et decouverte automatisee.
Integre: subfinder, crt.sh, Wayback Machine, dirsearch, port scan, tech fingerprint.
Utilise les outils externes si disponibles, sinon fallback Python.
"""

import os
import re
import json
import socket
import shutil
import subprocess
import time
import ssl
import concurrent.futures
from urllib.parse import urlparse, urljoin
from datetime import datetime

import requests
import urllib3
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

urllib3.disable_warnings()
console = Console()

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Common directories/files to bruteforce
COMMON_PATHS = [
    # Admin panels
    "/admin", "/admin/", "/administrator", "/admin.php", "/admin/login",
    "/wp-admin", "/wp-login.php", "/cpanel", "/phpmyadmin", "/pma",
    "/manager", "/panel", "/dashboard", "/control",
    # Config / Sensitive
    "/.env", "/.git/HEAD", "/.git/config", "/.gitignore",
    "/.htaccess", "/.htpasswd", "/web.config", "/crossdomain.xml",
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/composer.json", "/package.json", "/Gemfile", "/requirements.txt",
    # Backup / Debug
    "/backup", "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
    "/debug", "/phpinfo.php", "/info.php", "/test.php", "/test",
    "/server-status", "/server-info",
    # API endpoints
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger.json",
    "/api-docs", "/openapi.json", "/v1", "/v2",
    "/api/users", "/api/admin", "/api/config", "/api/status", "/api/health",
    # Auth
    "/login", "/login.php", "/signin", "/auth", "/authenticate",
    "/register", "/signup", "/forgot", "/reset", "/logout",
    # CMS specific
    "/wp-content/", "/wp-includes/", "/wp-json/",
    "/joomla/", "/drupal/", "/magento/",
    # Services
    "/elasticsearch/", "/_nodes", "/_cat/indices", "/_cluster/health",
    "/kibana/", "/kibana/app/", "/app/kibana",
    "/grafana/", "/prometheus/", "/metrics",
    "/jenkins/", "/gitlab/", "/sonarqube/",
    "/solr/", "/couchdb/", "/_all_dbs", "/_utils",
    # Common files
    "/favicon.ico", "/index.php", "/index.html", "/default.aspx",
    "/config.php", "/configuration.php", "/settings.php",
    "/wp-config.php", "/local.xml", "/database.yml",
    "/error", "/errors", "/error_log", "/access_log",
    "/console", "/shell", "/cmd", "/exec",
    # Uploads
    "/uploads", "/upload", "/files", "/images", "/media",
    "/assets", "/static", "/public", "/tmp",
]

# Common ports to scan
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 1812: "RADIUS",
    2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 9200: "Elasticsearch", 9300: "ES-Transport",
    5601: "Kibana", 27017: "MongoDB", 27018: "MongoDB",
    11211: "Memcached", 5984: "CouchDB",
}

# Technology fingerprints from HTTP headers and body
TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            "PHP": "PHP", "ASP.NET": "ASP.NET", "Express": "Node.js/Express",
            "Servlet": "Java Servlet", "Django": "Python/Django",
            "Flask": "Python/Flask", "Ruby": "Ruby",
        },
        "Server": {
            "Apache": "Apache", "nginx": "Nginx", "IIS": "Microsoft IIS",
            "LiteSpeed": "LiteSpeed", "Caddy": "Caddy",
            "Cloudflare": "Cloudflare", "openresty": "OpenResty",
        },
        "X-Generator": {
            "WordPress": "WordPress", "Drupal": "Drupal",
            "Joomla": "Joomla", "Magento": "Magento",
        },
    },
    "body_patterns": [
        (r'wp-content|wp-includes|wp-json', "WordPress"),
        (r'Joomla!|/components/com_', "Joomla"),
        (r'Drupal\.settings|drupal\.js', "Drupal"),
        (r'shopify\.com|Shopify\.theme', "Shopify"),
        (r'/static/admin/|csrfmiddlewaretoken', "Django"),
        (r'laravel_session|Laravel', "Laravel"),
        (r'__next|_next/static', "Next.js"),
        (r'__nuxt|_nuxt/', "Nuxt.js"),
        (r'react-root|__REACT', "React"),
        (r'ng-version|angular', "Angular"),
        (r'vue-app|__VUE', "Vue.js"),
        (r'MikroTik|RouterOS|mikrotik', "MikroTik RouterOS"),
        (r'FreeRADIUS|freeradius', "FreeRADIUS"),
        (r'phpmyadmin|phpMyAdmin', "phpMyAdmin"),
        (r'grafana-app|Grafana', "Grafana"),
        (r'kibana|Kibana', "Kibana"),
        (r'elasticsearch|Elasticsearch', "Elasticsearch"),
    ],
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
        "connect.sid": "Node.js/Express",
        "csrftoken": "Django",
        "laravel_session": "Laravel",
        "wordpress_logged_in": "WordPress",
        "_rails_session": "Ruby on Rails",
    },
}


class SubdomainFinder:
    """Discover subdomains via crt.sh, subfinder CLI, and DNS brute-force."""

    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()

    def run_all(self):
        """Run all enumeration methods."""
        console.print(f"\n  [bold cyan]Subdomain Enumeration:[/bold cyan] {self.domain}")

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task("crt.sh...", total=None)
            self._crt_sh()
            progress.update(task, description=f"crt.sh: {len(self.subdomains)} trouves")

            task2 = progress.add_task("subfinder CLI...", total=None)
            self._subfinder_cli()
            progress.update(task2, description=f"subfinder: {len(self.subdomains)} total")

            task3 = progress.add_task("DNS brute-force...", total=None)
            self._dns_bruteforce()
            progress.update(task3, description=f"Total: {len(self.subdomains)} sous-domaines")

        return sorted(self.subdomains)

    def _crt_sh(self):
        """Query crt.sh certificate transparency logs."""
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                headers={"User-Agent": USER_AGENT},
                timeout=30,
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and "*" not in sub:
                            self.subdomains.add(sub)
                console.print(f"    [green]crt.sh: {len(self.subdomains)} sous-domaines[/green]")
        except Exception as e:
            console.print(f"    [yellow]crt.sh erreur: {e}[/yellow]")

    def _subfinder_cli(self):
        """Use subfinder CLI if installed."""
        if not shutil.which("subfinder"):
            console.print("    [dim]subfinder non installe (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)[/dim]")
            return
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent"],
                capture_output=True, text=True, timeout=120,
            )
            for line in result.stdout.strip().split("\n"):
                sub = line.strip().lower()
                if sub and sub.endswith(self.domain):
                    self.subdomains.add(sub)
            console.print(f"    [green]subfinder: OK[/green]")
        except Exception as e:
            console.print(f"    [yellow]subfinder erreur: {e}[/yellow]")

    def _dns_bruteforce(self):
        """Basic DNS brute-force with common prefixes."""
        prefixes = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
            "admin", "portal", "vpn", "remote", "secure", "login",
            "api", "dev", "staging", "test", "beta", "app",
            "m", "mobile", "ns1", "ns2", "dns", "mx",
            "db", "database", "sql", "mysql", "mongo",
            "elastic", "kibana", "grafana", "jenkins",
            "gitlab", "git", "svn", "cdn", "static",
            "media", "upload", "files", "backup",
            "intranet", "internal", "private", "public",
            "shop", "store", "blog", "forum", "wiki",
            "support", "help", "docs", "status",
            "radius", "auth", "sso", "ldap", "cas",
        ]
        count_before = len(self.subdomains)

        def resolve(prefix):
            fqdn = f"{prefix}.{self.domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(fqdn)
                return fqdn
            except (socket.gaierror, socket.timeout):
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(resolve, p): p for p in prefixes}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)

        added = len(self.subdomains) - count_before
        console.print(f"    [green]DNS brute: +{added} nouveaux[/green]")


class TechFingerprinter:
    """Identify technologies from HTTP responses."""

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = False
        self.technologies = {}

    def fingerprint(self, url):
        """Fingerprint technologies on the target URL."""
        console.print(f"\n  [bold cyan]Tech Fingerprint:[/bold cyan] {url[:80]}")

        try:
            resp = self.session.get(url, timeout=15, allow_redirects=True)
        except Exception as e:
            console.print(f"  [red]Erreur: {e}[/red]")
            return self.technologies

        # Analyze headers
        for header, sig_map in TECH_SIGNATURES["headers"].items():
            value = resp.headers.get(header, "")
            for sig, tech in sig_map.items():
                if sig.lower() in value.lower():
                    self.technologies[tech] = {
                        "source": f"Header: {header}",
                        "value": value,
                    }

        # Analyze body
        for pattern, tech in TECH_SIGNATURES["body_patterns"]:
            if re.search(pattern, resp.text, re.IGNORECASE):
                self.technologies[tech] = {
                    "source": "HTML body pattern",
                    "value": pattern[:40],
                }

        # Analyze cookies
        for cookie_name, tech in TECH_SIGNATURES["cookies"].items():
            if cookie_name in resp.cookies:
                self.technologies[tech] = {
                    "source": f"Cookie: {cookie_name}",
                    "value": resp.cookies[cookie_name][:30],
                }

        # Security headers analysis
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "X-Frame-Options",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-XSS-Protection": "X-XSS-Protection",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
            "Access-Control-Allow-Origin": "CORS",
        }
        missing_headers = []
        for header, name in security_headers.items():
            if header in resp.headers:
                self.technologies[f"Security: {name}"] = {
                    "source": "Header present",
                    "value": resp.headers[header][:60],
                }
            else:
                missing_headers.append(name)

        if missing_headers:
            self.technologies["MISSING Security Headers"] = {
                "source": "Headers absents",
                "value": ", ".join(missing_headers),
            }

        # Server version
        server = resp.headers.get("Server", "")
        if server:
            self.technologies["Web Server"] = {
                "source": "Server header",
                "value": server,
            }

        # Check for exposed services
        self._check_exposed_services(url)

        return self.technologies

    def _check_exposed_services(self, base_url):
        """Check for exposed admin panels and services."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        checks = [
            ("/kibana/api/status", "Kibana"),
            ("/_cat/health", "Elasticsearch"),
            ("/api/health", "API Health"),
            ("/server-status", "Apache Status"),
            ("/server-info", "Apache Info"),
            ("/phpmyadmin/", "phpMyAdmin"),
            ("/grafana/api/health", "Grafana"),
            ("/.git/HEAD", "Git Repository"),
            ("/wp-json/wp/v2/users", "WordPress API"),
            ("/_all_dbs", "CouchDB"),
        ]

        for path, service in checks:
            try:
                resp = self.session.get(f"{base}{path}", timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    self.technologies[f"EXPOSED: {service}"] = {
                        "source": f"{path}",
                        "value": f"HTTP {resp.status_code} ({len(resp.text)} bytes)",
                    }
                    console.print(f"    [bold red]EXPOSE: {service}[/bold red] ({path})")
            except Exception:
                pass


class DirBuster:
    """Directory and file discovery."""

    def __init__(self, session=None, delay=0.2):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = False
        self.delay = delay
        self.found = []

    def scan(self, base_url, paths=None, extensions=None):
        """Scan for common directories and files."""
        console.print(f"\n  [bold cyan]Directory Discovery:[/bold cyan] {base_url[:80]}")

        if paths is None:
            paths = COMMON_PATHS

        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Also try with extensions
        all_paths = list(paths)
        if extensions:
            for path in paths[:30]:  # Only extend top paths
                for ext in extensions:
                    if not path.endswith(ext) and "." not in path.split("/")[-1]:
                        all_paths.append(f"{path}.{ext}")

        total = len(all_paths)
        found_count = 0

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task(f"Scanning 0/{total}...", total=total)

            for idx, path in enumerate(all_paths):
                try:
                    url = f"{base}{path}"
                    resp = self.session.get(url, timeout=5, allow_redirects=False)

                    if resp.status_code in (200, 301, 302, 403):
                        entry = {
                            "path": path,
                            "status": resp.status_code,
                            "length": len(resp.text),
                            "redirect": resp.headers.get("Location", ""),
                        }
                        self.found.append(entry)
                        found_count += 1

                        status_color = {200: "green", 301: "cyan", 302: "cyan", 403: "yellow"}.get(resp.status_code, "dim")
                        console.print(f"    [{status_color}][{resp.status_code}][/{status_color}] {path} ({len(resp.text)} bytes)")

                    time.sleep(self.delay)
                except Exception:
                    pass

                progress.update(task, advance=1, description=f"Scanning {idx+1}/{total} ({found_count} trouves)")

        console.print(f"\n  [bold]{found_count} chemins trouves sur {total} testes[/bold]")
        return self.found


class PortScanner:
    """TCP port scanning - uses nmap if available, else raw sockets."""

    def __init__(self):
        self.results = []

    def scan(self, host, ports=None):
        """Scan ports on the target host."""
        console.print(f"\n  [bold cyan]Port Scan:[/bold cyan] {host}")

        if ports is None:
            ports = COMMON_PORTS

        # Try nmap first
        if shutil.which("nmap"):
            return self._nmap_scan(host, ports)

        return self._socket_scan(host, ports)

    def _nmap_scan(self, host, ports):
        """Use nmap for port scanning."""
        port_list = ",".join(str(p) for p in ports)
        console.print(f"  [dim]Utilisation de nmap (-sV -sC)[/dim]")

        try:
            result = subprocess.run(
                ["nmap", "-sV", "--open", "-p", port_list, host, "-oN", "-"],
                capture_output=True, text=True, timeout=300,
            )
            output = result.stdout

            for line in output.split("\n"):
                match = re.match(r'^(\d+)/(\w+)\s+(open|filtered)\s+(.*)', line.strip())
                if match:
                    port = int(match.group(1))
                    proto = match.group(2)
                    state = match.group(3)
                    service = match.group(4).strip()
                    entry = {
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "source": "nmap",
                    }
                    self.results.append(entry)
                    console.print(f"    [green]{port}/{proto}[/green] {state} - {service}")

            console.print(f"\n  [bold]{len(self.results)} ports ouverts[/bold]")
            return self.results

        except Exception as e:
            console.print(f"  [yellow]nmap erreur: {e}, fallback socket scan[/yellow]")
            return self._socket_scan(host, ports)

    def _socket_scan(self, host, ports):
        """Fallback: basic TCP connect scan."""
        console.print(f"  [dim]Socket scan (nmap non disponible)[/dim]")

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    service = ports.get(port, "unknown") if isinstance(ports, dict) else "unknown"
                    return {"port": port, "protocol": "tcp", "state": "open", "service": service, "source": "socket"}
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            port_list = ports if isinstance(ports, dict) else {p: "unknown" for p in ports}
            futures = {executor.submit(check_port, p): p for p in port_list}

            with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
                task = progress.add_task(f"Scanning {len(port_list)} ports...", total=len(port_list))

                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.results.append(result)
                        console.print(f"    [green]{result['port']}/tcp[/green] open - {result['service']}")
                    progress.advance(task)

        console.print(f"\n  [bold]{len(self.results)} ports ouverts[/bold]")
        return self.results


class WaybackDiscovery:
    """Discover historical URLs from the Wayback Machine."""

    def __init__(self):
        self.urls = set()

    def discover(self, domain, limit=500):
        """Query Wayback Machine for historical URLs."""
        console.print(f"\n  [bold cyan]Wayback Machine:[/bold cyan] {domain}")

        try:
            resp = requests.get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}",
                headers={"User-Agent": USER_AGENT},
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:  # Skip header row
                    url = row[0]
                    self.urls.add(url)

                # Filter interesting URLs
                interesting = set()
                boring_ext = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}
                for url in self.urls:
                    parsed = urlparse(url)
                    ext = os.path.splitext(parsed.path)[1].lower()
                    if ext not in boring_ext:
                        interesting.add(url)

                console.print(f"  [green]{len(self.urls)} URLs totales, {len(interesting)} interessantes[/green]")
                self.urls = interesting
                return sorted(interesting)[:200]

        except Exception as e:
            console.print(f"  [yellow]Wayback erreur: {e}[/yellow]")

        return []


class NucleiScanner:
    """Run Nuclei vulnerability scanner if available."""

    def __init__(self):
        self.results = []

    def scan(self, url, severity="medium,high,critical"):
        """Run nuclei scan."""
        if not shutil.which("nuclei"):
            console.print("  [dim]nuclei non installe (go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)[/dim]")
            return []

        console.print(f"\n  [bold cyan]Nuclei Scan:[/bold cyan] {url[:80]}")
        console.print(f"  [dim]Severite: {severity}[/dim]")

        try:
            result = subprocess.run(
                ["nuclei", "-u", url, "-severity", severity, "-json", "-silent"],
                capture_output=True, text=True, timeout=600,
            )
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    finding = json.loads(line)
                    self.results.append({
                        "template": finding.get("template-id", ""),
                        "name": finding.get("info", {}).get("name", ""),
                        "severity": finding.get("info", {}).get("severity", ""),
                        "matched_url": finding.get("matched-at", ""),
                        "description": finding.get("info", {}).get("description", "")[:200],
                    })
                    sev = finding.get("info", {}).get("severity", "info")
                    sev_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}.get(sev, "dim")
                    console.print(f"    [{sev_color}][{sev.upper()}][/{sev_color}] {finding.get('info', {}).get('name', '')}")
                except json.JSONDecodeError:
                    pass

            console.print(f"\n  [bold]{len(self.results)} vulnerabilites trouvees[/bold]")
            return self.results

        except Exception as e:
            console.print(f"  [yellow]nuclei erreur: {e}[/yellow]")
            return []


class FullRecon:
    """Orchestrate all reconnaissance tools."""

    def __init__(self, target_url, output_dir="output"):
        self.target_url = target_url
        self.output_dir = output_dir
        self.parsed = urlparse(target_url)
        self.domain = self.parsed.netloc.split(":")[0]
        self.results = {
            "target": target_url,
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "technologies": {},
            "directories": [],
            "ports": [],
            "wayback_urls": [],
            "nuclei": [],
        }

    def run_full(self, skip_ports=False, skip_nuclei=False):
        """Run all recon modules."""
        console.print(f"\n  [bold]Reconnaissance complete sur:[/bold] {self.target_url}")

        # Subdomains
        subfinder = SubdomainFinder(self.domain)
        self.results["subdomains"] = subfinder.run_all()

        # Tech fingerprint
        fingerprinter = TechFingerprinter()
        self.results["technologies"] = fingerprinter.fingerprint(self.target_url)

        # Directory discovery
        dirbuster = DirBuster()
        # Add extensions based on detected tech
        extensions = []
        for tech in self.results["technologies"]:
            if "PHP" in tech:
                extensions.extend(["php", "php5", "phtml"])
            elif "ASP" in tech:
                extensions.extend(["asp", "aspx", "ashx"])
            elif "Java" in tech:
                extensions.extend(["jsp", "jsf", "do"])
            elif "Python" in tech:
                extensions.extend(["py"])
            elif "Node" in tech:
                extensions.extend(["js", "json"])
        self.results["directories"] = dirbuster.scan(self.target_url, extensions=extensions or None)

        # Port scan
        if not skip_ports:
            scanner = PortScanner()
            self.results["ports"] = scanner.scan(self.domain)

        # Wayback Machine
        wayback = WaybackDiscovery()
        self.results["wayback_urls"] = wayback.discover(self.domain)

        # Nuclei
        if not skip_nuclei:
            nuclei = NucleiScanner()
            self.results["nuclei"] = nuclei.scan(self.target_url)

        # Save results
        self._save_results()

        return self.results

    def _save_results(self):
        """Save recon results to JSON."""
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, "recon_results.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n  [green]Resultats sauvegardes: {path}[/green]")
