"""GoogleDork — scrapes Bing for targeted dorks + emits clickable Google queries."""

from __future__ import annotations

import random
import re
import time
from urllib.parse import quote_plus

from .base import Engine, url_to_site_name
from ..http import make_session, random_ua
from ..models import Finding, FindingKind, Confidence, InputType

_EXCLUDE = re.compile(
    r"(google\.[a-z]+/(search|intl|maps|play|accounts|support|policies|translate)|"
    r"bing\.com/(search|news|images|maps)|duckduckgo\.com|"
    r"facebook\.com/sharer|twitter\.com/intent|linkedin\.com/shareArticle|"
    r"doubleclick|googleadservices|googletagmanager)", re.I)

_BING_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.7",
    "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none",
}


def _scrape_bing(query: str, session) -> list[str]:
    urls, seen = [], set()
    session.headers.update(_BING_HEADERS)
    session.headers["User-Agent"] = random_ua()
    try:
        r = session.get(f"https://www.bing.com/search?q={quote_plus(query)}&count=20", timeout=12)
        if r.status_code != 200:
            return urls
        for m in re.finditer(r'<li class="b_algo".*?<a[^>]+href="(https?://[^"]+)"', r.text, re.DOTALL | re.I):
            u = m.group(1).split('"')[0].strip()
            if u not in seen and not _EXCLUDE.search(u):
                seen.add(u)
                urls.append(u)
    except Exception:
        pass
    return urls[:12]


class GoogleDorkEngine(Engine):
    name = "GoogleDork"
    desc = "Recherche ciblee (scrape Bing + liens Google)"
    modes = ["name", "username"]

    def is_available(self) -> bool:
        return True

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        cfg = kwargs.get("config")
        session = make_session(proxy=getattr(cfg, "proxy", None))
        findings: list[Finding] = []
        seen: set[str] = set()

        if input_type == InputType.NAME:
            dorks = [f'"{query}" site:linkedin.com', f'"{query}" site:facebook.com',
                     f'"{query}" site:instagram.com', f'"{query}" site:twitter.com',
                     f'"{query}" site:youtube.com', f'"{query}" site:github.com',
                     f'"{query}" (CV OR resume) filetype:pdf',
                     f'"{query}" site:pagesjaunes.fr OR site:copainsdavant.linternaute.com']
        else:
            dorks = [f'"{query}" site:linkedin.com', f'"{query}" site:github.com',
                     f'"{query}" site:reddit.com', f'"{query}" site:twitter.com',
                     f'"{query}" site:instagram.com', f'"{query}" site:tiktok.com']

        for dork in dorks[:6]:
            for u in _scrape_bing(dork, session):
                if u not in seen:
                    seen.add(u)
                    findings.append(Finding(
                        source=self.name, title=url_to_site_name(u, query), url=u,
                        kind=FindingKind.LINK, confidence=Confidence.MEDIUM,
                        note=f"Trouve via: {dork[:40]}"))
            time.sleep(random.uniform(0.4, 1.0))

        # Always add clickable Google queries (useful even when Bing returns little).
        for dork in dorks:
            gurl = f"https://www.google.com/search?q={quote_plus(dork)}"
            target = dork.split("site:")[-1].split()[0] if "site:" in dork else dork[:24]
            findings.append(Finding(
                source=self.name, title=f"Google: {target}", url=gurl,
                kind=FindingKind.DORK, confidence=Confidence.LOW, note=dork))
        return findings
