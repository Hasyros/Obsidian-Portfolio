"""
OSINT Module - Collecte d'informations publiques sur la cible.
DNS, WHOIS, Shodan (si cle API), headers de securite, leak detection.
"""

import os
import re
import json
import socket
import subprocess
import shutil
from urllib.parse import urlparse
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


class DNSEnumerator:
    """DNS record enumeration."""

    def __init__(self, domain):
        self.domain = domain
        self.records = {}

    def enumerate(self):
        """Enumerate all DNS record types."""
        console.print(f"\n  [bold cyan]DNS Enumeration:[/bold cyan] {self.domain}")

        # Use nslookup/dig if available, else basic socket
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]

        if shutil.which("nslookup"):
            for rtype in record_types:
                self._nslookup(rtype)
        else:
            self._socket_resolve()

        return self.records

    def _nslookup(self, record_type):
        """Query DNS using nslookup."""
        try:
            result = subprocess.run(
                ["nslookup", f"-type={record_type}", self.domain],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout
            answers = []

            for line in output.split("\n"):
                line = line.strip()
                # Parse different record formats
                if "mail exchanger" in line.lower():
                    answers.append(line.split("=")[-1].strip() if "=" in line else line)
                elif "nameserver" in line.lower():
                    answers.append(line.split("=")[-1].strip() if "=" in line else line)
                elif "text" in line.lower() and "=" in line:
                    answers.append(line.split("=", 1)[-1].strip().strip('"'))
                elif "address" in line.lower() and self.domain not in line.lower():
                    val = line.split(":")[-1].strip() if ":" in line else line.split()[-1]
                    if val and not val.startswith("#"):
                        answers.append(val)
                elif "primary name server" in line.lower():
                    answers.append(line.split("=")[-1].strip())

            if answers:
                self.records[record_type] = answers
                console.print(f"    [green]{record_type}:[/green] {', '.join(answers[:3])}")

        except Exception:
            pass

    def _socket_resolve(self):
        """Fallback: basic socket DNS resolution."""
        try:
            ips = socket.getaddrinfo(self.domain, None)
            ipv4 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET))
            ipv6 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET6))
            if ipv4:
                self.records["A"] = ipv4
                console.print(f"    [green]A:[/green] {', '.join(ipv4)}")
            if ipv6:
                self.records["AAAA"] = ipv6
                console.print(f"    [green]AAAA:[/green] {', '.join(ipv6)}")
        except Exception as e:
            console.print(f"    [yellow]DNS erreur: {e}[/yellow]")


class WHOISLookup:
    """WHOIS information retrieval."""

    def __init__(self, domain):
        self.domain = domain
        self.info = {}

    def lookup(self):
        """Perform WHOIS lookup."""
        console.print(f"\n  [bold cyan]WHOIS:[/bold cyan] {self.domain}")

        # Try whois CLI
        if shutil.which("whois"):
            return self._whois_cli()

        # Fallback: web API
        return self._whois_api()

    def _whois_cli(self):
        """Use whois CLI."""
        try:
            result = subprocess.run(
                ["whois", self.domain],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout
            fields = {
                "Registrar": r"Registrar:\s*(.+)",
                "Creation Date": r"Creation Date:\s*(.+)",
                "Expiry Date": r"(?:Registry Expiry|Expiration) Date:\s*(.+)",
                "Name Servers": r"Name Server:\s*(.+)",
                "Registrant Org": r"Registrant Organization:\s*(.+)",
                "Registrant Country": r"Registrant Country:\s*(.+)",
                "DNSSEC": r"DNSSEC:\s*(.+)",
            }
            for field, pattern in fields.items():
                matches = re.findall(pattern, output, re.IGNORECASE)
                if matches:
                    self.info[field] = matches[0].strip() if len(matches) == 1 else [m.strip() for m in matches]
                    console.print(f"    [green]{field}:[/green] {matches[0].strip()}")

            return self.info
        except Exception as e:
            console.print(f"    [yellow]whois erreur: {e}[/yellow]")
            return self._whois_api()

    def _whois_api(self):
        """Fallback: use web API for WHOIS."""
        console.print("    [dim]whois CLI non disponible, utilisation API web[/dim]")
        try:
            # Use a free WHOIS API
            resp = requests.get(
                f"https://rdap.org/domain/{self.domain}",
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                self.info["Name"] = data.get("ldhName", "")
                self.info["Status"] = ", ".join(data.get("status", [])[:3])

                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        self.info["Creation Date"] = event.get("eventDate", "")
                    elif event.get("eventAction") == "expiration":
                        self.info["Expiry Date"] = event.get("eventDate", "")

                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        cards = entity.get("vcardArray", [None, []])
                        for card in cards[1] if len(cards) > 1 else []:
                            if card[0] == "fn":
                                self.info["Registrar"] = card[3]

                for key, val in self.info.items():
                    if val:
                        console.print(f"    [green]{key}:[/green] {val}")

            return self.info
        except Exception as e:
            console.print(f"    [yellow]RDAP erreur: {e}[/yellow]")
            return self.info


class SecurityHeadersAnalyzer:
    """Analyze HTTP security headers and configuration."""

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = False
        self.analysis = {"present": {}, "missing": [], "issues": [], "score": 0}

    def analyze(self, url):
        """Analyze security headers of the target."""
        console.print(f"\n  [bold cyan]Security Headers:[/bold cyan] {url[:80]}")

        try:
            resp = self.session.get(url, timeout=15, allow_redirects=True)
        except Exception as e:
            console.print(f"  [red]Erreur: {e}[/red]")
            return self.analysis

        headers = resp.headers
        score = 0
        max_score = 0

        checks = [
            ("Strict-Transport-Security", 15, self._check_hsts),
            ("Content-Security-Policy", 20, self._check_csp),
            ("X-Frame-Options", 10, self._check_xfo),
            ("X-Content-Type-Options", 10, self._check_xcto),
            ("X-XSS-Protection", 5, self._check_xss_protection),
            ("Referrer-Policy", 10, self._check_referrer),
            ("Permissions-Policy", 10, self._check_permissions),
            ("Cache-Control", 5, self._check_cache),
            ("Set-Cookie", 15, lambda v: self._check_cookies(resp)),
        ]

        for header_name, points, check_fn in checks:
            max_score += points
            value = headers.get(header_name, "")

            if value:
                self.analysis["present"][header_name] = value
                issues = check_fn(value)
                if issues:
                    self.analysis["issues"].extend(issues)
                    score += points // 2
                    console.print(f"    [yellow]{header_name}: {value[:50]}[/yellow]")
                    for issue in issues:
                        console.print(f"      [dim]Issue: {issue}[/dim]")
                else:
                    score += points
                    console.print(f"    [green]{header_name}: OK[/green]")
            else:
                if header_name != "Set-Cookie":
                    self.analysis["missing"].append(header_name)
                    console.print(f"    [red]MANQUANT: {header_name}[/red]")

        # Check for info disclosure
        info_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for h in info_headers:
            if h in headers:
                self.analysis["issues"].append(f"Information disclosure: {h}: {headers[h]}")
                console.print(f"    [yellow]Info leak: {h}: {headers[h]}[/yellow]")

        self.analysis["score"] = round(score / max_score * 100) if max_score else 0
        grade = "A" if self.analysis["score"] >= 80 else "B" if self.analysis["score"] >= 60 else "C" if self.analysis["score"] >= 40 else "D" if self.analysis["score"] >= 20 else "F"
        console.print(f"\n    [bold]Score securite: {self.analysis['score']}% (Grade {grade})[/bold]")

        return self.analysis

    def _check_hsts(self, value):
        issues = []
        if "max-age" in value.lower():
            match = re.search(r'max-age=(\d+)', value)
            if match and int(match.group(1)) < 31536000:
                issues.append("HSTS max-age < 1 an")
        if "includesubdomains" not in value.lower():
            issues.append("HSTS: includeSubDomains manquant")
        return issues

    def _check_csp(self, value):
        issues = []
        if "unsafe-inline" in value:
            issues.append("CSP: unsafe-inline autorise")
        if "unsafe-eval" in value:
            issues.append("CSP: unsafe-eval autorise")
        if "*" in value.split():
            issues.append("CSP: wildcard source detectee")
        return issues

    def _check_xfo(self, value):
        if value.upper() not in ("DENY", "SAMEORIGIN"):
            return [f"X-Frame-Options invalide: {value}"]
        return []

    def _check_xcto(self, value):
        if "nosniff" not in value.lower():
            return ["X-Content-Type-Options sans nosniff"]
        return []

    def _check_xss_protection(self, value):
        if "0" in value:
            return ["X-XSS-Protection desactive"]
        return []

    def _check_referrer(self, value):
        if value.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            return [f"Referrer-Policy faible: {value}"]
        return []

    def _check_permissions(self, value):
        return []

    def _check_cache(self, value):
        issues = []
        if "no-store" not in value.lower() and "private" not in value.lower():
            issues.append("Cache-Control: donnees sensibles potentiellement cachees")
        return issues

    def _check_cookies(self, resp):
        issues = []
        for cookie in resp.cookies:
            name = cookie.name
            flags = []
            if not cookie.secure:
                flags.append("Secure manquant")
            if "httponly" not in str(cookie._rest).lower():
                flags.append("HttpOnly manquant")
            if not cookie.has_nonstandard_attr("SameSite") and "samesite" not in str(cookie._rest).lower():
                flags.append("SameSite manquant")
            if flags:
                issues.append(f"Cookie '{name}': {', '.join(flags)}")
        return issues


class ShodanLookup:
    """Shodan API lookup (requires API key)."""

    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
        self.results = {}

    def lookup(self, ip_or_domain):
        """Query Shodan for host information."""
        if not self.api_key:
            console.print("  [dim]Shodan: pas de cle API (set SHODAN_API_KEY ou passez en parametre)[/dim]")
            return {}

        console.print(f"\n  [bold cyan]Shodan:[/bold cyan] {ip_or_domain}")

        try:
            # Resolve domain to IP if needed
            try:
                ip = socket.gethostbyname(ip_or_domain)
            except socket.gaierror:
                ip = ip_or_domain

            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}",
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                self.results = {
                    "ip": data.get("ip_str", ""),
                    "org": data.get("org", ""),
                    "os": data.get("os", ""),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "city": data.get("city", ""),
                    "country": data.get("country_name", ""),
                    "isp": data.get("isp", ""),
                    "last_update": data.get("last_update", ""),
                }

                console.print(f"    [green]IP: {self.results['ip']}[/green]")
                console.print(f"    [green]Org: {self.results['org']}[/green]")
                console.print(f"    [green]Ports: {self.results['ports']}[/green]")
                if self.results["vulns"]:
                    console.print(f"    [bold red]CVEs: {', '.join(self.results['vulns'][:10])}[/bold red]")

            elif resp.status_code == 404:
                console.print(f"    [dim]Pas de donnees Shodan pour {ip}[/dim]")
            else:
                console.print(f"    [yellow]Shodan HTTP {resp.status_code}[/yellow]")

        except Exception as e:
            console.print(f"    [yellow]Shodan erreur: {e}[/yellow]")

        return self.results


class LeakChecker:
    """Check for known data leaks/breaches related to the domain."""

    def __init__(self):
        self.findings = []

    def check(self, domain):
        """Check for exposed data related to the domain."""
        console.print(f"\n  [bold cyan]Leak Detection:[/bold cyan] {domain}")

        # Check common leak indicators
        self._check_github_dorks(domain)
        self._check_paste_sites(domain)

        return self.findings

    def _check_github_dorks(self, domain):
        """Check GitHub for potentially leaked data."""
        dorks = [
            f'"{domain}" password',
            f'"{domain}" secret',
            f'"{domain}" api_key',
            f'"{domain}" token',
        ]
        console.print(f"    [dim]GitHub dorks suggeres (recherche manuelle):[/dim]")
        for dork in dorks:
            console.print(f"      [cyan]site:github.com {dork}[/cyan]")
            self.findings.append({"type": "github_dork", "query": dork})

    def _check_paste_sites(self, domain):
        """Suggest paste site searches."""
        console.print(f"    [dim]Paste sites a verifier:[/dim]")
        console.print(f"      [cyan]site:pastebin.com \"{domain}\"[/cyan]")
        console.print(f"      [cyan]site:ghostbin.com \"{domain}\"[/cyan]")
        self.findings.append({"type": "paste_dork", "query": f'"{domain}"'})


class FullOSINT:
    """Orchestrate all OSINT modules."""

    def __init__(self, target_url, output_dir="output"):
        self.target_url = target_url
        self.output_dir = output_dir
        self.parsed = urlparse(target_url)
        self.domain = self.parsed.netloc.split(":")[0]
        self.results = {
            "target": target_url,
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "dns": {},
            "whois": {},
            "security_headers": {},
            "shodan": {},
            "leaks": [],
        }

    def run_full(self, shodan_key=None):
        """Run all OSINT modules."""
        console.print(f"\n  [bold]OSINT complet sur:[/bold] {self.domain}")

        # DNS
        dns = DNSEnumerator(self.domain)
        self.results["dns"] = dns.enumerate()

        # WHOIS
        whois = WHOISLookup(self.domain)
        self.results["whois"] = whois.lookup()

        # Security headers
        sec = SecurityHeadersAnalyzer()
        self.results["security_headers"] = sec.analyze(self.target_url)

        # Shodan
        if shodan_key or os.environ.get("SHODAN_API_KEY"):
            shodan = ShodanLookup(api_key=shodan_key)
            self.results["shodan"] = shodan.lookup(self.domain)

        # Leak check
        leak = LeakChecker()
        self.results["leaks"] = leak.check(self.domain)

        # Save
        self._save_results()

        return self.results

    def _save_results(self):
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, "osint_results.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n  [green]OSINT sauvegarde: {path}[/green]")
