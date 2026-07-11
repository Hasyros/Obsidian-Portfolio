import os
from urllib.parse import urlparse, urlencode, parse_qs
from rich.console import Console

console = Console()

# Extended from CTF writeups and bug bounty reports
SQLI_PARAM_NAMES = {
    # Classic ID parameters
    "id", "uid", "pid", "catid", "category_id", "product_id", "item_id",
    "user_id", "page_id", "article_id", "news_id", "order_id", "cid",
    "nid", "tid", "fid", "gid", "sid", "aid", "bid", "rid", "eid",
    # Sorting/ordering (cannot use prepared statements!)
    "sort", "order", "orderby", "order_by", "sortby", "sort_by",
    "column", "col", "dir", "direction", "asc", "desc",
    # Search
    "search", "q", "query", "keyword", "s", "term", "filter",
    "find", "lookup", "text",
    # Auth-related (from writeups - UserName pattern)
    "username", "user", "uname", "login", "email", "user_name",
    "UserName", "userName", "usr", "account",
    "password", "passwd", "pass", "pwd",
    # Data retrieval
    "where", "field", "table", "select", "from",
    "year", "month", "date", "from", "to",
    # Pagination
    "limit", "offset", "page", "per_page", "count", "start", "num",
    # File/path (also LFI but sometimes SQLi)
    "file", "path", "url", "redirect", "callback", "ref",
    "type", "action", "cmd", "view", "mode", "lang",
    # REST API common
    "fields", "include", "expand", "embed", "format",
}

# Headers commonly injectable (from writeups/research)
INJECTABLE_HEADERS = [
    ("X-Forwarded-For", "Frequently logged to DB for IP tracking"),
    ("User-Agent", "Stored in analytics/shopping cart DBs"),
    ("Referer", "Stored for analytics/logging"),
    ("X-Originating-IP", "IP tracking"),
    ("X-Remote-IP", "IP tracking"),
    ("X-Remote-Addr", "IP tracking"),
    ("X-Client-IP", "IP tracking"),
    ("Accept-Language", "Sometimes stored for localization"),
]


class InjectionPoint:
    def __init__(self, url, method, param_name, param_value, source, page_url, extra_info=None):
        self.url = url
        self.method = method
        self.param_name = param_name
        self.param_value = param_value
        self.source = source
        self.page_url = page_url
        self.extra_info = extra_info or {}
        self.score = 0
        self.reasons = []
        self._calculate_score()

    def _calculate_score(self):
        name_lower = self.param_name.lower()

        # Direct match with known injectable param names
        if name_lower in {n.lower() for n in SQLI_PARAM_NAMES}:
            self.score += 40
            self.reasons.append(f"Nom de parametre suspect: {self.param_name}")

        # ID-like parameters (most common SQLi vector)
        if name_lower.endswith("_id") or name_lower.endswith("id") or name_lower == "id":
            self.score += 30
            self.reasons.append("Parametre de type ID")

        # Numeric values (classic injection target)
        if self.param_value and self.param_value.isdigit():
            self.score += 25
            self.reasons.append("Valeur numerique (injection classique)")

        # Sort/Order params (CANNOT use prepared statements - from research)
        if name_lower in {"sort", "order", "orderby", "order_by", "sortby", "column", "dir", "direction"}:
            self.score += 45
            self.reasons.append("Parametre ORDER BY (non protegeable par requetes preparees!)")

        # Auth-related fields (from CTF writeups)
        auth_fields = {"username", "user", "uname", "login", "email", "user_name", "username", "usr", "password", "passwd", "pass", "pwd"}
        if name_lower in auth_fields:
            self.score += 35
            self.reasons.append("Champ d'authentification (bypass possible)")

        # Search fields (from bug bounty reports)
        if name_lower in {"search", "q", "query", "keyword", "s", "term", "filter", "find"}:
            self.score += 30
            self.reasons.append("Parametre de recherche (souvent concatene dans LIKE)")

        # Source-based scoring
        source_scores = {
            "form": 15,
            "hidden_input": 25,
            "url_parameter": 15,
            "js_endpoint": 10,
            "redirect_chain": 35,
            "header": 20,
            "cookie": 20,
            "login_form": 40,
            "search_form": 30,
            "json_body": 15,
            "api_endpoint": 20,
        }
        src_score = source_scores.get(self.source, 5)
        self.score += src_score

        source_labels = {
            "form": "Champ de formulaire",
            "hidden_input": "Input cache (souvent non valide cote serveur)",
            "url_parameter": "Parametre URL visible",
            "js_endpoint": "Endpoint decouvert dans le JavaScript",
            "redirect_chain": "Parametre dans une chaine de redirection (interception type Burp)",
            "header": "Header HTTP (injection dans logs/analytics)",
            "cookie": "Valeur de cookie (injection via session)",
            "login_form": "Formulaire de login (auth bypass)",
            "search_form": "Formulaire de recherche",
            "json_body": "Corps JSON (bypass WAF possible)",
            "api_endpoint": "Endpoint API REST",
        }
        self.reasons.append(source_labels.get(self.source, self.source))

        # POST method bonus
        if self.method == "POST":
            self.score += 10
            self.reasons.append("Methode POST")

        # Dynamic extension bonus
        ext = os.path.splitext(urlparse(self.url).path)[1]
        if ext in (".php", ".asp", ".aspx", ".jsp", ".cgi", ".cfm"):
            self.score += 15
            self.reasons.append(f"Extension dynamique ({ext})")

        # Extra: redirect chain params get heavy bonus
        if self.extra_info.get("from_redirect"):
            self.score += 20
            self.reasons.append("Decouvert via interception de redirection")

    @property
    def priority(self):
        if self.score >= 70:
            return "CRITIQUE"
        elif self.score >= 45:
            return "HAUT"
        elif self.score >= 25:
            return "MOYEN"
        return "BAS"


# Parameters that are NEVER injectable - CSRF tokens, framework internals
IGNORED_PARAMS = {
    # CSRF tokens
    "csrftoken", "csrf_token", "csrf", "_csrf", "__csrf", "_token",
    "csrfmiddlewaretoken", "__requestverificationtoken",
    "authenticity_token", "xsrf_token", "_xsrf",
    "antiforgerytoken", "__antiforgerytoken", "anti-csrf-token",
    "x-csrf-token", "x-xsrf-token",
    # Framework internals
    "__viewstate", "__viewstategenerator", "__eventvalidation",
    "__eventtarget", "__eventargument", "__previouspage",
    # Tracking / analytics (not injectable)
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid",
    "_ga", "_gid", "_gat",
    # JS framework internals
    "nonce", "wp_nonce", "_wpnonce", "state",
}

# Domains that should never be scanned (third-party)
IGNORED_DOMAINS = {
    "facebook.com", "www.facebook.com", "graph.facebook.com",
    "google.com", "www.google.com", "apis.google.com", "accounts.google.com",
    "googleapis.com", "googletagmanager.com", "google-analytics.com",
    "twitter.com", "api.twitter.com", "x.com",
    "youtube.com", "www.youtube.com",
    "instagram.com", "www.instagram.com",
    "linkedin.com", "www.linkedin.com",
    "pinterest.com", "tiktok.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "ajax.googleapis.com", "code.jquery.com",
    "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "apple.com", "microsoft.com", "amazon.com",
    "cloudflare.com", "fastly.net", "akamai.net",
    "recaptcha.net", "gstatic.com", "hcaptcha.com",
    "doubleclick.net", "adsense.google.com",
    "stripe.com", "js.stripe.com", "paypal.com",
}


class Analyzer:
    def __init__(self, scan_results, output_dir="output", target_url=None):
        self.scan_results = scan_results
        self.output_dir = output_dir
        self.injection_points = []
        # Extract target domain for filtering
        self.target_domain = None
        if target_url:
            parsed = urlparse(target_url)
            self.target_domain = parsed.netloc.split(":")[0]

    def _is_same_scope(self, url):
        """Check if a URL is in scope (same domain as target)."""
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0].lower()

        # Always reject known third-party domains
        if host in IGNORED_DOMAINS or any(host.endswith(f".{d}") for d in IGNORED_DOMAINS):
            return False

        # If we have a target domain, only accept same domain or subdomains
        if self.target_domain:
            target = self.target_domain.lower()
            return host == target or host.endswith(f".{target}")

        return True

    def _is_ignored_param(self, param_name):
        """Check if a parameter name should be ignored."""
        return param_name.lower() in IGNORED_PARAMS

    def analyze(self):
        for result in self.scan_results:
            if result.error:
                continue
            self._analyze_forms(result)
            self._analyze_url_params(result)
            self._analyze_js_endpoints(result)
            self._analyze_hidden_inputs(result)
            self._analyze_redirect_chain(result)
            self._analyze_headers(result)
            self._analyze_cookies(result)
            self._analyze_json_endpoints(result)

        # Filter out ignored params and out-of-scope URLs
        self.injection_points = [
            ip for ip in self.injection_points
            if not self._is_ignored_param(ip.param_name) and self._is_same_scope(ip.url)
        ]

        self.injection_points.sort(key=lambda x: x.score, reverse=True)

        # Deduplicate by (host, path, method, param_name) to merge redirect variants
        seen = set()
        unique = []
        for ip in self.injection_points:
            parsed = urlparse(ip.url)
            key = (parsed.netloc, parsed.path, ip.method, ip.param_name)
            if key not in seen:
                seen.add(key)
                unique.append(ip)
        self.injection_points = unique

        return self.injection_points

    def _analyze_forms(self, result):
        for form in result.forms:
            # Determine source type
            if form.is_login_form:
                source = "login_form"
            elif form.is_search_form:
                source = "search_form"
            else:
                source = "form"

            for inp in form.inputs:
                if not inp["name"]:
                    continue
                ip = InjectionPoint(
                    url=form.full_action,
                    method=form.method,
                    param_name=inp["name"],
                    param_value=inp["value"],
                    source="hidden_input" if inp["hidden"] else source,
                    page_url=result.url,
                )
                self.injection_points.append(ip)

    def _analyze_url_params(self, result):
        for param_info in result.url_parameters:
            is_redirect = param_info.get("source") == "redirect_chain"
            ip = InjectionPoint(
                url=param_info["url"],
                method="GET",
                param_name=param_info["param"],
                param_value=param_info["value"],
                source="redirect_chain" if is_redirect else "url_parameter",
                page_url=result.url,
                extra_info={"from_redirect": is_redirect},
            )
            self.injection_points.append(ip)

    def _analyze_js_endpoints(self, result):
        for endpoint in result.js_endpoints:
            if endpoint.startswith("__JSON_KEYS__:"):
                continue
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            if params:
                for param_name, values in params.items():
                    ip = InjectionPoint(
                        url=endpoint,
                        method="GET",
                        param_name=param_name,
                        param_value=values[0] if values else "",
                        source="js_endpoint",
                        page_url=result.url,
                    )
                    self.injection_points.append(ip)
            elif "/api/" in endpoint or "/rest/" in endpoint or "/graphql" in endpoint:
                ip = InjectionPoint(
                    url=endpoint,
                    method="GET",
                    param_name="__endpoint__",
                    param_value="",
                    source="api_endpoint",
                    page_url=result.url,
                )
                self.injection_points.append(ip)

    def _analyze_hidden_inputs(self, result):
        for hidden in result.hidden_inputs:
            if not hidden["name"]:
                continue
            already = any(
                ip.param_name == hidden["name"] and ip.source == "hidden_input"
                for ip in self.injection_points
            )
            if not already:
                ip = InjectionPoint(
                    url=result.url,
                    method="POST",
                    param_name=hidden["name"],
                    param_value=hidden["value"],
                    source="hidden_input",
                    page_url=result.url,
                )
                self.injection_points.append(ip)

    def _analyze_redirect_chain(self, result):
        """Extract injection points from redirect chain steps."""
        for step in result.redirect_chain:
            # Parameters in the redirect Location URL
            if step.location_params:
                for pname, pval in step.location_params.items():
                    ip = InjectionPoint(
                        url=step.location,
                        method="GET",
                        param_name=pname,
                        param_value=pval,
                        source="redirect_chain",
                        page_url=result.url,
                        extra_info={"from_redirect": True, "status_code": step.status_code},
                    )
                    self.injection_points.append(ip)

            # Parameters in the original request URL at each step
            parsed = urlparse(step.url)
            params = parse_qs(parsed.query)
            for pname, pvals in params.items():
                already = any(
                    ip.param_name == pname and ip.url == step.url
                    for ip in self.injection_points
                )
                if not already:
                    ip = InjectionPoint(
                        url=step.url,
                        method="GET",
                        param_name=pname,
                        param_value=pvals[0] if pvals else "",
                        source="redirect_chain",
                        page_url=result.url,
                        extra_info={"from_redirect": True},
                    )
                    self.injection_points.append(ip)

    def _analyze_headers(self, result):
        """Add HTTP headers as potential injection points."""
        for header_info in INJECTABLE_HEADERS:
            header_name, reason = header_info
            ip = InjectionPoint(
                url=result.url,
                method="HEADER",
                param_name=header_name,
                param_value="",
                source="header",
                page_url=result.url,
                extra_info={"reason": reason},
            )
            self.injection_points.append(ip)

    def _analyze_cookies(self, result):
        """Add cookie values as injection points."""
        for cookie_info in result.injectable_headers:
            if cookie_info["type"] == "cookie":
                ip = InjectionPoint(
                    url=result.url,
                    method="COOKIE",
                    param_name=cookie_info["name"],
                    param_value=cookie_info["value"],
                    source="cookie",
                    page_url=result.url,
                )
                self.injection_points.append(ip)

    def _analyze_json_endpoints(self, result):
        """Add JSON body keys as injection points."""
        for ep in result.json_endpoints:
            if ep.get("type") == "json_body" and ep.get("keys"):
                for key in ep["keys"]:
                    ip = InjectionPoint(
                        url=ep.get("url", result.url),
                        method="POST",
                        param_name=key,
                        param_value="",
                        source="json_body",
                        page_url=result.url,
                    )
                    self.injection_points.append(ip)

    def generate_request_files(self):
        os.makedirs(self.output_dir, exist_ok=True)
        request_files = []

        # Group by (host+path, method) to deduplicate redirect chain variants
        # e.g. login.php?lg=fr and login.php?lg=en with same params -> one target
        grouped = {}
        header_points = []
        cookie_points = []

        for ip in self.injection_points:
            if ip.source == "header":
                header_points.append(ip)
            elif ip.source == "cookie":
                cookie_points.append(ip)
            else:
                parsed = urlparse(ip.url)
                # Group by (host, path, method) instead of full URL
                dedup_key = (parsed.netloc, parsed.path, ip.method)
                if dedup_key not in grouped:
                    grouped[dedup_key] = {"url": ip.url, "params": {}}
                # Keep param with highest score, merge all params
                existing = grouped[dedup_key]["params"]
                if ip.param_name not in existing or ip.score > existing[ip.param_name].score:
                    existing[ip.param_name] = ip

        idx = 0

        # Standard GET/POST request files (already deduplicated by host+path+method)
        for (netloc, path_part, method), group_data in grouped.items():
            url = group_data["url"]
            params_dict = group_data["params"]  # {param_name: InjectionPoint}
            params = list(params_dict.values())

            if not params:
                continue

            parsed = urlparse(url)
            host = parsed.netloc or netloc
            path = path_part or "/"

            if method == "GET":
                query_params = {}
                for p in params:
                    if p.param_name != "__endpoint__":
                        query_params[p.param_name] = p.param_value or "FUZZ"
                query_string = urlencode(query_params)
                request_line = f"GET {path}?{query_string} HTTP/1.1"
                body = ""
            else:
                request_line = f"POST {path} HTTP/1.1"
                body_params = {}
                for p in params:
                    if p.param_name != "__endpoint__":
                        body_params[p.param_name] = p.param_value or "FUZZ"
                body = urlencode(body_params)

            request_content = f"{request_line}\n"
            request_content += f"Host: {host}\n"
            request_content += f"User-Agent: {USER_AGENT}\n"
            request_content += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n"
            request_content += "Accept-Language: fr-FR,fr;q=0.9,en;q=0.8\n"
            request_content += "Connection: keep-alive\n"

            if method == "POST":
                request_content += "Content-Type: application/x-www-form-urlencoded\n"
                request_content += f"Content-Length: {len(body)}\n"

            request_content += "\n"
            if body:
                request_content += body

            filename = os.path.join(self.output_dir, f"request_{idx:03d}_{method.lower()}.txt")
            with open(filename, "w") as f:
                f.write(request_content)

            max_score = max(p.score for p in params)
            param_names = [p.param_name for p in params if p.param_name != "__endpoint__"]
            request_files.append({
                "file": filename,
                "url": url,
                "method": method,
                "params": param_names,
                "max_score": max_score,
                "source": params[0].source,
            })
            idx += 1

        # Header injection request file
        if header_points:
            url = header_points[0].url
            parsed = urlparse(url)
            host = parsed.netloc
            path = parsed.path or "/"

            request_content = f"GET {path} HTTP/1.1\n"
            request_content += f"Host: {host}\n"
            # Mark injectable headers with *
            for hp in header_points:
                request_content += f"{hp.param_name}: test*\n"
            request_content += "Accept: text/html,application/xhtml+xml\n"
            request_content += "Connection: keep-alive\n"
            request_content += "\n"

            filename = os.path.join(self.output_dir, f"request_{idx:03d}_headers.txt")
            with open(filename, "w") as f:
                f.write(request_content)

            request_files.append({
                "file": filename,
                "url": url,
                "method": "HEADER",
                "params": [hp.param_name for hp in header_points],
                "max_score": max(hp.score for hp in header_points),
                "source": "header",
            })
            idx += 1

        # Cookie injection request file
        if cookie_points:
            url = cookie_points[0].url
            parsed = urlparse(url)
            host = parsed.netloc
            path = parsed.path or "/"

            cookie_str = "; ".join(f"{cp.param_name}={cp.param_value or 'FUZZ'}*" for cp in cookie_points)

            request_content = f"GET {path} HTTP/1.1\n"
            request_content += f"Host: {host}\n"
            request_content += f"User-Agent: {USER_AGENT}\n"
            request_content += f"Cookie: {cookie_str}\n"
            request_content += "Accept: text/html,application/xhtml+xml\n"
            request_content += "Connection: keep-alive\n"
            request_content += "\n"

            filename = os.path.join(self.output_dir, f"request_{idx:03d}_cookies.txt")
            with open(filename, "w") as f:
                f.write(request_content)

            request_files.append({
                "file": filename,
                "url": url,
                "method": "COOKIE",
                "params": [cp.param_name for cp in cookie_points],
                "max_score": max(cp.score for cp in cookie_points),
                "source": "cookie",
            })
            idx += 1

        request_files.sort(key=lambda x: x["max_score"], reverse=True)
        return request_files


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
