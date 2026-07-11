"""Deep Verify — visits each URL, follows redirects, analyzes content."""

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn,
)

from .config import ProxyConfig
from .models import (
    SiteResult, DiscardedResult, Confidence, Status,
    categorize, is_high_trust,
)
from .session import make_session, random_ua, rate_limiter

console = Console()

# Reuse one Session per (thread, proxy) — avoids rebuilding a Session + adapters
# for every URL, and lets the proxy actually take effect during Deep Verify.
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


# Social/profile links found in a page body — used by correlation to link accounts.
_SOCIAL_LINK_RE = re.compile(
    r'https?://(?:www\.)?(?:twitter|x|instagram|github|linkedin|youtube|tiktok|'
    r'facebook|reddit|medium|twitch|t\.me|linktr\.ee|bsky\.app|mastodon)'
    r'[.\w]*/[\w@./-]+',
    re.I,
)

SOFT_404 = re.compile(
    r"page\s*not\s*found|^404\b|not\s*found|user\s*not\s*found|"
    r"doesn.t\s*exist|account\s*(has\s*been\s*)?(suspended|deleted|removed|banned)|"
    r"this\s*(page|account|profile)\s*is\s*not\s*available|"
    r"content\s*(is\s*)?unavailable|nothing\s*here|"
    r"sorry.{0,20}(couldn.t|can.t)\s*find|"
    r"no\s*longer\s*(here|available)|has\s*been\s*removed|"
    r"oops|hmm+.*this\s*page|could\s*not\s*be\s*found|"
    r"is\s*not\s*(a\s*)?valid\s*username|"
    r"we\s*(couldn.t|can.t)\s*find|"
    r"no\s*such\s*user|invalid\s*(user|profile|account)|"
    r"profil\s*introuvable|utilisateur\s*introuvable|page\s*introuvable|"
    r"this\s*user\s*(doesn.t|does\s*not)\s*exist|"
    r"the\s*page\s*you.re\s*looking\s*for|"
    r"this\s*account\s*is\s*private|user\s*is\s*private|"
    r"profile\s*(does\s*not|doesn.t)\s*exist|"
    r"no\s*results?\s*found|no\s*user\s*(with\s*that|by\s*that|named)|"
    r"member\s*not\s*found|player\s*not\s*found|"
    r"that\s*page\s*doesn.t\s*exist|we\s*couldn.t\s*find\s*that\s*page",
    re.I,
)

BOT_RE = re.compile(
    r"checking\s*(if|your)|cf[-_]?challenge|cloudflare|just\s*a\s*moment|"
    r"captcha|access\s*denied|rate\s*limit",
    re.I,
)

LOGIN_RE = re.compile(
    r"sign\s*in\s*to\s*(continue|view|access|see|your)|"
    r"log\s*in\s*to\s*(continue|view|see|access|your)|"
    r"you\s*must\s*be\s*logged\s*in|login\s*required|"
    r"please\s*(log|sign)\s*in|authentication\s*required|"
    r"you\s*need\s*to\s*(log|sign)\s*in|"
    r"connectez.vous|connexion\s*requise|identifiez.vous|"
    r"enter\s*your\s*(password|credentials)|"
    r"this\s*(page|content)\s*is\s*private|"
    r"log\s*in\s*or\s*(sign|register)|sign\s*in\s*or\s*(register|create)",
    re.I,
)

SIGNUP_RE = re.compile(
    r"sign\s*up\s*(now|today|free)|claim\s*this\s*(username|name|handle)|"
    r"this\s*(username|name|handle)\s*is\s*available|create\s*(your|an?)\s*account|"
    r"join\s*(us|now|today|for\s*free)|get\s*started|"
    r"reserve\s*(this|your)\s*(name|username|handle)|"
    r"register\s*(now|today|for\s*free|to\s)|"
    r"want\s*this\s*username|take\s*this\s*username|"
    r"this\s*name\s*is\s*available|username\s*is\s*not\s*taken|"
    r"cr[ée]er?\s*(votre|un)\s*compte|inscri(vez|re|ption)",
    re.I,
)

AVATAR_RE = re.compile(
    r'(?:og:image|profile.image|avatar|user.photo|profile.photo)["\s]*'
    r'(?:content|src|href)\s*=\s*["\']?(https?://[^"\'\s>]+)',
    re.I,
)

BIO_RE = re.compile(
    r'(?:og:description|profile.description|user.bio)["\s]*'
    r'content\s*=\s*["\']([^"\']{10,300})',
    re.I,
)


def _extract_avatar(body: str) -> str:
    m = AVATAR_RE.search(body[:15_000])
    return m.group(1) if m else ""


def _extract_bio(body: str) -> str:
    m = BIO_RE.search(body[:15_000])
    return m.group(1).strip() if m else ""


def verify_one(username: str, site: str, url: str, timeout: int = 12,
               proxy: Optional[ProxyConfig] = None):
    """Visit URL, analyze. Returns (passed: bool, result)."""
    ht = is_high_trust(site, url)
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

        # Title
        tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.DOTALL)
        title = tm.group(1).strip()[:120] if tm else ""

        uname_l = username.lower()
        uname_in = uname_l in bl
        sz = len(body)

        final_domain = urlparse(final).netloc.lower().replace("www.", "")
        final_path = urlparse(final).path.strip("/").lower()

        # === ELIMINATIONS ===

        if code in (404, 410):
            return False, DiscardedResult(site, url, "", f"HTTP {code}")

        if code >= 500 or code == 403:
            return False, DiscardedResult(site, url, "", f"HTTP {code}")

        if redir > 0 and final_path in ("", "index.html", "index.php", "home", "en", "fr"):
            return False, DiscardedResult(site, url, "", "Redirige -> accueil")

        if (final_domain != orig_domain
                and not final_domain.endswith(orig_domain)
                and not orig_domain.endswith(final_domain)):
            return False, DiscardedResult(site, url, "", f"Redirige -> {final_domain}")

        for kw in ("login", "signin", "sign-in", "auth", "sso"):
            if kw in final_path:
                return False, DiscardedResult(site, url, "", "Redirige -> login")
        for kw in ("signup", "sign-up", "register", "join", "create-account"):
            if kw in final_path:
                return False, DiscardedResult(site, url, "", "Redirige -> inscription")
        for kw in ("404", "not-found", "notfound", "error"):
            if kw in final_path:
                return False, DiscardedResult(site, url, "", "Redirige -> 404")

        if sz < 500 and not body.strip().startswith("{"):
            return False, DiscardedResult(site, url, "", f"Page vide ({sz}B)")

        if BOT_RE.search(bl[:5000]) and not ht:
            return False, DiscardedResult(site, url, "", "Anti-bot/Cloudflare")

        zone = bl[:4000]
        if SOFT_404.search(zone):
            hits = len(SOFT_404.findall(zone))
            if not uname_in or hits >= 2:
                return False, DiscardedResult(site, url, "", "Soft 404 (erreur deguisee)")

        tl = title.lower()
        if title and re.search(
            r"^(404|error|not found|page not|oops|sorry|sign (in|up)|log in|access denied|forbidden)",
            tl,
        ):
            if not uname_in:
                return False, DiscardedResult(site, url, "", f"Titre erreur: '{title[:40]}'")

        if LOGIN_RE.search(bl[:5000]) and not uname_in:
            return False, DiscardedResult(site, url, "", "Mur de login")

        if SIGNUP_RE.search(bl[:5000]) and not uname_in:
            return False, DiscardedResult(site, url, "", "Page d'inscription/claim")

        # Login form detection: password field present + username NOT in body
        if not uname_in and re.search(r'<input[^>]*type\s*=\s*["\']password["\']', bl[:10_000]):
            if LOGIN_RE.search(bl[:5000]) or re.search(r'<form[^>]*action\s*=\s*["\'][^"\']*(?:login|signin|auth)', bl[:10_000], re.I):
                return False, DiscardedResult(site, url, "", "Formulaire de login")

        # Redirect chain passed through login/auth URL
        if redir > 0:
            for hist_resp in resp.history:
                hp = urlparse(hist_resp.url).path.lower()
                for kw in ("login", "signin", "sign-in", "auth", "oauth", "sso", "cas/login"):
                    if kw in hp:
                        return False, DiscardedResult(site, url, "", f"Redirect via {kw}")

        # === PASSED -> SCORING ===
        score = 0
        if code == 200:
            score += 2
        if uname_in:
            score += 3
        if uname_l in tl:
            score += 2
        if redir == 0:
            score += 1
        if sz > 5000:
            score += 1
        if ht:
            score += 4

        if score >= 7:
            conf = Confidence.HIGH
        elif score >= 4:
            conf = Confidence.HIGH if ht else Confidence.MEDIUM
        elif score >= 2:
            conf = Confidence.MEDIUM
        else:
            conf = Confidence.LOW

        avatar_url = _extract_avatar(body)
        bio = _extract_bio(body)
        links = sorted({
            m.group(0).rstrip("/").lower()
            for m in _SOCIAL_LINK_RE.finditer(body)
        })

        return True, SiteResult(
            site_name=site, url=url, http_status=code, final_url=final,
            redirect_count=redir, username_in_body=uname_in,
            page_title=title, page_size=sz, confidence=conf,
            response_time_ms=ms, tags=categorize(site), high_trust=ht,
            avatar_url=avatar_url or None, bio=bio or None, links=links,
        )

    except Exception as e:
        return False, DiscardedResult(site, url, "", f"Reseau: {type(e).__name__}")


def verify_all(
    username: str,
    raw: list[dict],
    workers: int = 30,
    timeout: int = 12,
    proxy: Optional[ProxyConfig] = None,
) -> tuple[list[SiteResult], list[DiscardedResult]]:
    """Deep verify in parallel. Returns (valid[], discarded[])."""
    if not raw:
        return [], []

    valid = []
    discarded = []
    ok_n = 0
    ko_n = 0

    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("| [green]{task.fields[ok]}[/green] [red]{task.fields[ko]}[/red]"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task(f"Deep verify {len(raw)} URLs...", total=len(raw), ok=0, ko=0)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {
                pool.submit(verify_one, username, r["site"], r["url"], timeout, proxy): r
                for r in raw
            }
            for f in as_completed(futs):
                ri = futs[f]
                passed, res = f.result()
                if passed:
                    ok_n += 1
                    res.source = ri.get("source", "")
                    valid.append(res)
                else:
                    ko_n += 1
                    res.source = ri.get("source", "")
                    discarded.append(res)
                prog.update(task, advance=1, ok=ok_n, ko=ko_n)

    # Multi-source boost
    url_src: dict[str, set[str]] = {}
    for r in raw:
        url_src.setdefault(r["url"].rstrip("/").lower(), set()).add(r.get("source", "?"))
    for r in valid:
        srcs = url_src.get(r.url.rstrip("/").lower(), set())
        if len(srcs) >= 2:
            if r.confidence == Confidence.MEDIUM:
                r.confidence = Confidence.HIGH
            r.note = f"Multi-source ({', '.join(sorted(srcs))})"
            r.source = " + ".join(sorted(srcs))

    order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    valid.sort(key=lambda r: (order[r.confidence], not r.high_trust, r.site_name))
    return valid, discarded
