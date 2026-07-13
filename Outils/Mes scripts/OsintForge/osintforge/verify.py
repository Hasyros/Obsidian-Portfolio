"""Deep-verify — visit candidate PROFILE pages, follow redirects, score them.

Only applied to PROFILE findings that are not already ``pre_verified``. This is
the piece that must never run on breaches/accounts/dorks (the old tool's bug).
"""

from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from .config import ProxyConfig
from .http import make_session, rate_limiter
from .models import Finding, Discarded, Confidence, categorize, is_high_trust

console = Console()

_thread_local = threading.local()


def _session_for(proxy: Optional[ProxyConfig]):
    key = proxy.url if (proxy and proxy.enabled) else ""
    cache = getattr(_thread_local, "sessions", None)
    if cache is None:
        cache = {}
        _thread_local.sessions = cache
    if key not in cache:
        cache[key] = make_session(proxy=proxy)
    return cache[key]


SOFT_404 = re.compile(
    r"page\s*not\s*found|^404\b|not\s*found|user\s*not\s*found|doesn.t\s*exist|"
    r"account\s*(has\s*been\s*)?(suspended|deleted|removed|banned)|"
    r"this\s*(page|account|profile)\s*is\s*not\s*available|content\s*(is\s*)?unavailable|"
    r"no\s*such\s*user|invalid\s*(user|profile|account)|profil\s*introuvable|"
    r"utilisateur\s*introuvable|no\s*results?\s*found|member\s*not\s*found",
    re.I)
BOT_RE = re.compile(r"checking\s*(if|your)|cf[-_]?challenge|just\s*a\s*moment|captcha|access\s*denied", re.I)
LOGIN_RE = re.compile(
    r"sign\s*in\s*to\s*(continue|view|access|see|your)|log\s*in\s*to\s*(continue|view|see|your)|"
    r"you\s*must\s*be\s*logged\s*in|login\s*required|please\s*(log|sign)\s*in|connectez.vous", re.I)
SIGNUP_RE = re.compile(
    r"claim\s*this\s*(username|name|handle)|this\s*(username|name|handle)\s*is\s*available|"
    r"create\s*(your|an?)\s*account|username\s*is\s*not\s*taken|cr[ée]er?\s*(votre|un)\s*compte", re.I)
AVATAR_RE = re.compile(
    r'(?:og:image|profile.image|avatar)["\s]*(?:content|src|href)\s*=\s*["\']?(https?://[^"\'\s>]+)', re.I)
BIO_RE = re.compile(r'(?:og:description|user.bio)["\s]*content\s*=\s*["\']([^"\']{10,300})', re.I)


def verify_one(query: str, finding: Finding, timeout: int = 12,
               proxy: Optional[ProxyConfig] = None) -> tuple[bool, object]:
    site, url = finding.title, finding.url
    ht = finding.high_trust or is_high_trust(site, url)
    orig_domain = urlparse(url).netloc.lower().replace("www.", "")
    session = _session_for(proxy)
    try:
        rate_limiter.wait(orig_domain)
        t0 = time.time()
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        ms = int((time.time() - t0) * 1000)
        code = resp.status_code
        final = resp.url
        body = resp.text[:50_000]
        bl = body.lower()
        redir = len(resp.history)
        tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.DOTALL)
        title = tm.group(1).strip()[:120] if tm else ""
        ql = query.lower()
        q_in = ql in bl
        sz = len(body)
        final_domain = urlparse(final).netloc.lower().replace("www.", "")
        final_path = urlparse(final).path.strip("/").lower()

        # eliminations
        if code in (404, 410) or code == 403 or code >= 500:
            return False, Discarded(site, url, finding.source, f"HTTP {code}")
        if redir > 0 and final_path in ("", "index.html", "index.php", "home", "en", "fr"):
            return False, Discarded(site, url, finding.source, "Redirige -> accueil")
        if (final_domain != orig_domain and not final_domain.endswith(orig_domain)
                and not orig_domain.endswith(final_domain)):
            return False, Discarded(site, url, finding.source, f"Redirige -> {final_domain}")
        for kw in ("login", "signin", "sign-in", "auth", "sso"):
            if kw in final_path:
                return False, Discarded(site, url, finding.source, "Redirige -> login")
        for kw in ("signup", "register", "join", "create-account"):
            if kw in final_path:
                return False, Discarded(site, url, finding.source, "Redirige -> inscription")
        if sz < 500 and not body.strip().startswith("{"):
            return False, Discarded(site, url, finding.source, f"Page vide ({sz}B)")
        if BOT_RE.search(bl[:5000]) and not ht:
            return False, Discarded(site, url, finding.source, "Anti-bot/Cloudflare")
        zone = bl[:4000]
        if SOFT_404.search(zone) and (not q_in or len(SOFT_404.findall(zone)) >= 2):
            return False, Discarded(site, url, finding.source, "Soft 404")
        if LOGIN_RE.search(bl[:5000]) and not q_in:
            return False, Discarded(site, url, finding.source, "Mur de login")
        if SIGNUP_RE.search(bl[:5000]) and not q_in:
            return False, Discarded(site, url, finding.source, "Page d'inscription/claim")

        # scoring
        score = 0
        score += 2 if code == 200 else 0
        score += 3 if q_in else 0
        score += 2 if ql in title.lower() else 0
        score += 1 if redir == 0 else 0
        score += 1 if sz > 5000 else 0
        score += 4 if ht else 0
        if score >= 7:
            conf = Confidence.HIGH
        elif score >= 4:
            conf = Confidence.HIGH if ht else Confidence.MEDIUM
        elif score >= 2:
            conf = Confidence.MEDIUM
        else:
            conf = Confidence.LOW

        am = AVATAR_RE.search(body[:15000])
        bm = BIO_RE.search(body[:15000])
        finding.http_status = code
        finding.final_url = final
        finding.redirect_count = redir
        finding.query_in_body = q_in
        finding.page_title = title
        finding.page_size = sz
        finding.response_time_ms = ms
        finding.confidence = conf
        finding.high_trust = ht
        finding.avatar_url = am.group(1) if am else ""
        finding.bio = (bm.group(1).strip() if bm else "")
        if not finding.tags:
            finding.tags = categorize(site)
        return True, finding
    except Exception as e:
        return False, Discarded(site, url, finding.source, f"Reseau: {type(e).__name__}")


def verify_profiles(query: str, candidates: list[Finding], workers: int = 30,
                    timeout: int = 12, proxy: Optional[ProxyConfig] = None
                    ) -> tuple[list[Finding], list[Discarded]]:
    if not candidates:
        return [], []
    valid: list[Finding] = []
    discarded: list[Discarded] = []
    ok_n = ko_n = 0
    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("| [green]{task.fields[ok]}[/green] [red]{task.fields[ko]}[/red]"),
        TimeElapsedColumn(), console=console,
    ) as prog:
        task = prog.add_task(f"Deep verify {len(candidates)} profils...",
                             total=len(candidates), ok=0, ko=0)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(verify_one, query, c, timeout, proxy): c for c in candidates}
            for f in as_completed(futs):
                passed, res = f.result()
                if passed:
                    ok_n += 1
                    valid.append(res)
                else:
                    ko_n += 1
                    discarded.append(res)
                prog.update(task, advance=1, ok=ok_n, ko=ko_n)
    return valid, discarded
