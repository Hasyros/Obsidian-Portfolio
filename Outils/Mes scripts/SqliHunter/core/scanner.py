import re
import ssl
import json
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from rich.console import Console


class WeakSSLAdapter(HTTPAdapter):
    """Allow connections to servers with weak DH keys, old TLS, or bad certs."""
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.options &= ~ssl.OP_NO_SSLv3
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)

console = Console()

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

JS_ENDPOINT_PATTERNS = [
    r"""fetch\s*\(\s*['"](.*?)['"]""",
    r"""\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"](.*?)['"]""",
    r"""\.get\s*\(\s*['"](.*?)['"]""",
    r"""\.post\s*\(\s*['"](.*?)['"]""",
    r"""\.put\s*\(\s*['"](.*?)['"]""",
    r"""\.delete\s*\(\s*['"](.*?)['"]""",
    r"""axios\s*[\.(]\s*['"](.*?)['"]""",
    r"""XMLHttpRequest[^;]*\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"](.*?)['"]""",
    r"""(?:src|href|action|url|endpoint|api_url|baseURL|apiUrl)\s*[:=]\s*['"](\/[^'"]*?)['"]""",
    r"""['"](\/api\/[^'"]*?)['"]""",
    r"""['"](\/v[0-9]+\/[^'"]*?)['"]""",
    r"""['"](\/?[a-zA-Z0-9_-]+\.php(?:\?[^'"]*)?)['"]\s*""",
    r"""['"](\/graphql[^'"]*?)['"]""",
    r"""['"](\/rest\/[^'"]*?)['"]""",
    r"""['"](\/ws\/[^'"]*?)['"]""",
    r"""\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"](.*?)['"]""",
    r"""(?:window|document)\.location\s*=\s*['"](.*?)['"]""",
    r"""location\.href\s*=\s*['"](.*?)['"]""",
]


class FormData:
    def __init__(self, action, method, inputs, page_url, enctype=None):
        self.action = action
        self.method = method.upper()
        self.inputs = inputs
        self.page_url = page_url
        self.enctype = enctype or "application/x-www-form-urlencoded"
        self.full_action = urljoin(page_url, action) if action else page_url
        self.is_login_form = self._detect_login()
        self.is_search_form = self._detect_search()

    def _detect_login(self):
        login_indicators = {"username", "user", "login", "email", "password", "passwd", "pass", "pwd", "uname", "user_name", "UserName"}
        field_names = {inp.get("name", "").lower() for inp in self.inputs}
        field_types = {inp.get("type", "").lower() for inp in self.inputs}
        return bool(field_names & login_indicators) or "password" in field_types

    def _detect_search(self):
        search_indicators = {"search", "q", "query", "keyword", "s", "term", "filter"}
        field_names = {inp.get("name", "").lower() for inp in self.inputs}
        return bool(field_names & search_indicators)

    def to_dict(self):
        return {
            "action": self.action,
            "full_action": self.full_action,
            "method": self.method,
            "enctype": self.enctype,
            "inputs": self.inputs,
            "page_url": self.page_url,
            "is_login_form": self.is_login_form,
            "is_search_form": self.is_search_form,
        }


class RedirectStep:
    """Captures one step in a redirect chain."""
    def __init__(self, url, status_code, headers, cookies, location=None):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.cookies = cookies
        self.location = location
        self.location_params = {}
        if location:
            parsed = urlparse(location)
            self.location_params = {
                k: v[0] if v else ""
                for k, v in parse_qs(parsed.query).items()
            }


class PageScanResult:
    def __init__(self, url):
        self.url = url
        self.status_code = None
        self.headers = {}
        self.cookies = {}
        self.forms = []
        self.links = []
        self.js_files = []
        self.js_endpoints = []
        self.url_parameters = []
        self.comments = []
        self.technologies = []
        self.hidden_inputs = []
        self.redirect_chain = []
        self.api_endpoints = []
        self.injectable_headers = []
        self.json_endpoints = []
        self.error = None


class WebScanner:
    def __init__(self, verify_ssl=False, timeout=15, custom_headers=None, cookies=None):
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        # Weak SSL adapter (legacy ciphers + no cert check) ONLY when verification is
        # disabled via --no-ssl-verify. With verification ON, keep requests' default
        # (real certificate validation) so verify_ssl is not silently neutralized.
        if not verify_ssl:
            self.session.mount("https://", WeakSSLAdapter())
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        if custom_headers:
            self.session.headers.update(custom_headers)
        if cookies:
            self.session.cookies.update(cookies)
        self.timeout = timeout

    def fetch(self, url, method="GET", data=None, allow_redirects=True):
        try:
            if method == "POST":
                resp = self.session.post(
                    url, data=data, verify=self.verify_ssl,
                    timeout=self.timeout, allow_redirects=allow_redirects,
                )
            else:
                resp = self.session.get(
                    url, verify=self.verify_ssl,
                    timeout=self.timeout, allow_redirects=allow_redirects,
                )
            return resp
        except requests.RequestException as e:
            console.print(f"  [red]Erreur requete {url}: {e}[/red]")
            return None

    def fetch_with_redirect_chain(self, url, method="GET", data=None):
        """Follow redirects manually, capturing every step."""
        chain = []
        current_url = url
        visited = set()
        final_resp = None

        for _ in range(15):  # max 15 redirects
            if current_url in visited:
                break
            visited.add(current_url)

            resp = self.fetch(current_url, method=method, data=data, allow_redirects=False)
            if not resp:
                break

            location = resp.headers.get("Location", "")
            step = RedirectStep(
                url=current_url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                cookies={c.name: c.value for c in resp.cookies if c.name and c.name.lower() not in ('httponly', 'secure', 'samesite')},
                location=urljoin(current_url, location) if location else None,
            )
            chain.append(step)

            if resp.status_code in (301, 302, 303, 307, 308) and location:
                resolved = urljoin(current_url, location)
                console.print(f"    [dim]Redirect {resp.status_code} -> {resolved}[/dim]")
                current_url = resolved
                # After redirect, switch to GET (except 307/308)
                if resp.status_code in (301, 302, 303):
                    method = "GET"
                    data = None
            else:
                final_resp = resp
                break

        if not final_resp and chain:
            # Fetch the last URL with redirects enabled as fallback
            final_resp = self.fetch(current_url)

        return chain, final_resp

    def scan_page(self, url):
        result = PageScanResult(url)

        # Fetch with redirect interception
        chain, resp = self.fetch_with_redirect_chain(url)
        result.redirect_chain = chain

        if not resp:
            result.error = "Impossible de joindre la page"
            return result

        result.status_code = resp.status_code
        result.headers = dict(resp.headers)
        result.cookies = dict(resp.cookies)

        # Collect all cookies from the entire chain
        for step in chain:
            result.cookies.update(step.cookies)

        result.technologies = self._detect_technologies(resp)
        result.injectable_headers = self._identify_injectable_headers(resp)

        soup = BeautifulSoup(resp.text, "lxml")

        result.forms = self._extract_forms(soup, url)
        result.links = self._extract_links(soup, url)
        result.js_files = self._extract_js_files(soup, url)
        result.comments = self._extract_comments(soup)
        result.hidden_inputs = self._extract_hidden_inputs(soup)

        # Extract params from page links AND redirect chain
        all_links = list(result.links)
        for step in chain:
            if step.location:
                all_links.append(step.location)
            all_links.append(step.url)
        result.url_parameters = self._extract_url_parameters(all_links)

        # JS analysis
        for js_url in result.js_files:
            endpoints = self._analyze_js(js_url, url)
            result.js_endpoints.extend(endpoints)

        inline_scripts = soup.find_all("script", src=False)
        for script in inline_scripts:
            if script.string:
                endpoints = self._analyze_js_content(script.string, url)
                result.js_endpoints.extend(endpoints)

        result.js_endpoints = list(set(result.js_endpoints))

        # Detect JSON/API endpoints
        result.json_endpoints = self._detect_json_endpoints(result)

        return result

    def scan_form_submission(self, form, test_values=None):
        """Submit a form and capture the full redirect chain."""
        if test_values is None:
            test_values = {}

        post_data = {}
        for inp in form.inputs:
            name = inp.get("name", "")
            if not name:
                continue
            if name in test_values:
                post_data[name] = test_values[name]
            elif inp.get("value"):
                post_data[name] = inp["value"]
            else:
                post_data[name] = "test"

        chain, resp = self.fetch_with_redirect_chain(
            form.full_action,
            method=form.method,
            data=post_data if form.method == "POST" else None,
        )

        return chain, resp, post_data

    def _extract_forms(self, soup, page_url):
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET")
            enctype = form.get("enctype", "")

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "tag": inp.name,
                    "type": inp.get("type", "text"),
                    "name": inp.get("name", ""),
                    "value": inp.get("value", ""),
                    "id": inp.get("id", ""),
                    "placeholder": inp.get("placeholder", ""),
                    "required": inp.has_attr("required"),
                    "hidden": inp.get("type") == "hidden",
                }
                if inp.name == "select":
                    input_data["options"] = [
                        opt.get("value", opt.text.strip())
                        for opt in inp.find_all("option")
                    ]
                inputs.append(input_data)

            if inputs:
                forms.append(FormData(action, method, inputs, page_url, enctype))
        return forms

    def _extract_links(self, soup, page_url):
        links = set()
        base_domain = urlparse(page_url).netloc

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            full_url = urljoin(page_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc == base_domain:
                links.add(full_url)

        for tag in soup.find_all(["form"], action=True):
            action = tag["action"].strip()
            if action and not action.startswith(("#", "javascript:")):
                links.add(urljoin(page_url, action))

        # Extract links from meta refresh
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
            content = meta.get("content", "")
            match = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.I)
            if match:
                links.add(urljoin(page_url, match.group(1)))

        # Extract from iframe src
        for iframe in soup.find_all("iframe", src=True):
            src = iframe["src"].strip()
            if not src.startswith(("javascript:", "about:")):
                full_url = urljoin(page_url, src)
                parsed = urlparse(full_url)
                if parsed.netloc == base_domain:
                    links.add(full_url)

        return list(links)

    def _extract_js_files(self, soup, page_url):
        js_urls = []
        for script in soup.find_all("script", src=True):
            src = script["src"]
            full_url = urljoin(page_url, src)
            js_urls.append(full_url)
        return js_urls

    def _analyze_js(self, js_url, page_url):
        resp = self.fetch(js_url)
        if not resp or not resp.text:
            return []
        return self._analyze_js_content(resp.text, page_url)

    def _analyze_js_content(self, js_content, page_url):
        endpoints = []
        for pattern in JS_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match and len(match) > 1 and not match.startswith("data:"):
                    full_url = urljoin(page_url, match)
                    endpoints.append(full_url)

        # Detect JSON POST bodies in JS
        json_patterns = [
            r"""JSON\.stringify\s*\(\s*(\{[^}]+\})""",
            r"""(?:body|data)\s*:\s*(\{[^}]+\})""",
        ]
        for pattern in json_patterns:
            for match in re.findall(pattern, js_content):
                try:
                    # Try to extract key names from the JSON-like structure
                    keys = re.findall(r"""['"](\w+)['"]\s*:""", match)
                    if keys:
                        endpoints.append(f"__JSON_KEYS__:{','.join(keys)}")
                except Exception:
                    pass

        return endpoints

    def _extract_comments(self, soup):
        comments = []
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = comment.strip()
            if len(text) > 3:
                comments.append(text)
        return comments

    def _extract_hidden_inputs(self, soup):
        hidden = []
        for inp in soup.find_all("input", type="hidden"):
            hidden.append({
                "name": inp.get("name", ""),
                "value": inp.get("value", ""),
                "form_action": inp.find_parent("form").get("action", "") if inp.find_parent("form") else "",
            })
        return hidden

    def _extract_url_parameters(self, links):
        params_found = []
        seen = set()
        for link in links:
            parsed = urlparse(link)
            params = parse_qs(parsed.query)
            for param_name in params:
                key = (link.split("?")[0], param_name)
                if key not in seen:
                    seen.add(key)
                    params_found.append({
                        "url": link,
                        "param": param_name,
                        "value": params[param_name][0] if params[param_name] else "",
                    })
        return params_found

    def _detect_technologies(self, resp):
        techs = []
        server = resp.headers.get("Server", "")
        if server:
            techs.append(f"Server: {server}")

        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            techs.append(f"X-Powered-By: {powered_by}")

        cookie_names = list(resp.cookies.keys())
        tech_cookies = {
            "PHPSESSID": "PHP",
            "JSESSIONID": "Java/JSP",
            "ASP.NET_SessionId": "ASP.NET",
            "laravel_session": "Laravel",
            "ci_session": "CodeIgniter",
            "csrftoken": "Django",
            "connect.sid": "Node.js/Express",
            "_rails_session": "Ruby on Rails",
            "XSRF-TOKEN": "Laravel/Angular",
            "wp-settings": "WordPress",
        }
        for cname in cookie_names:
            for pattern, tech in tech_cookies.items():
                if pattern.lower() in cname.lower():
                    techs.append(f"Cookie: {cname} -> {tech}")

        content_type = resp.headers.get("Content-Type", "")
        if content_type:
            techs.append(f"Content-Type: {content_type}")

        asp_headers = ["X-AspNet-Version", "X-AspNetMvc-Version"]
        for h in asp_headers:
            val = resp.headers.get(h, "")
            if val:
                techs.append(f"{h}: {val}")

        return techs

    def _identify_injectable_headers(self, resp):
        """Identify which headers the server likely processes (logging, analytics, etc.)."""
        injectable = []
        # These headers are commonly logged/processed server-side
        test_headers = [
            "X-Forwarded-For",
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Client-IP",
            "User-Agent",
            "Referer",
            "Accept-Language",
        ]

        # Check if cookies exist (= server tracks sessions = possible cookie injection)
        if resp.cookies:
            for cname in resp.cookies.keys():
                injectable.append({
                    "type": "cookie",
                    "name": cname,
                    "value": resp.cookies[cname],
                })

        for header in test_headers:
            injectable.append({
                "type": "header",
                "name": header,
                "value": resp.request.headers.get(header, "") if resp.request else "",
            })

        return injectable

    def _detect_json_endpoints(self, result):
        """Identify endpoints that accept JSON or return JSON."""
        json_eps = []
        content_type = result.headers.get("Content-Type", "")
        if "json" in content_type.lower():
            json_eps.append({"url": result.url, "type": "json_response"})

        for ep in result.js_endpoints:
            if ep.startswith("__JSON_KEYS__:"):
                keys = ep.replace("__JSON_KEYS__:", "").split(",")
                json_eps.append({"url": result.url, "keys": keys, "type": "json_body"})

        for ep in result.js_endpoints:
            if "/api/" in ep or "/graphql" in ep or "/rest/" in ep:
                json_eps.append({"url": ep, "type": "api_endpoint"})

        return json_eps

    def check_robots_txt(self, base_url):
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        resp = self.fetch(robots_url)
        if resp and resp.status_code == 200:
            paths = []
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        full_url = urljoin(base_url, path)
                        paths.append(full_url)
            return paths
        return []

    def check_sitemap(self, base_url):
        parsed = urlparse(base_url)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        resp = self.fetch(sitemap_url)
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            urls = [loc.text.strip() for loc in soup.find_all("loc") if loc.text]
            return urls[:100]
        return []


class Crawler:
    def __init__(self, scanner, max_depth=3, max_pages=50):
        self.scanner = scanner
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.results = []

    def crawl(self, start_url):
        base_domain = urlparse(start_url).netloc
        queue = [(start_url, 0)]

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.pop(0)

            clean_url = url.split("#")[0]
            if clean_url in self.visited:
                continue
            self.visited.add(clean_url)

            console.print(f"  [dim]Scan [{len(self.visited)}/{self.max_pages}][/dim] {clean_url}")
            result = self.scanner.scan_page(clean_url)
            self.results.append(result)

            # Also submit forms to discover redirect chains
            for form in result.forms:
                if form.is_login_form or form.is_search_form:
                    console.print(f"    [yellow]Soumission formulaire {'login' if form.is_login_form else 'search'}: {form.full_action}[/yellow]")
                    chain, resp, post_data = self.scanner.scan_form_submission(form)
                    # Add redirect chain params to result
                    for step in chain:
                        if step.location:
                            for pname, pval in step.location_params.items():
                                result.url_parameters.append({
                                    "url": step.location,
                                    "param": pname,
                                    "value": pval,
                                    "source": "redirect_chain",
                                })

            if depth < self.max_depth:
                for link in result.links:
                    link_clean = link.split("#")[0]
                    if link_clean not in self.visited:
                        link_domain = urlparse(link_clean).netloc
                        if link_domain == base_domain:
                            queue.append((link_clean, depth + 1))

        return self.results
