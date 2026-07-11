"""Google/Bing Dorking — targeted search via dorks."""

import re
import time
import random
from urllib.parse import quote_plus

from .base import Engine, url_to_site_name
from ..models import InputType
from ..session import make_session, random_ua

# Domains to exclude (search engine UI, ads, share buttons)
_EXCLUDE = re.compile(
    r"(google\.[a-z]+/(search|intl|maps|play|accounts|support|policies|translate)|"
    r"bing\.com/(search|news|images|maps)|"
    r"duckduckgo\.com|yahoo\.com/(search|news)|"
    r"facebook\.com/sharer|twitter\.com/intent|linkedin\.com/shareArticle|"
    r"microsofttranslator|microsoft\.com/en-us/legal|"
    r"doubleclick|googleadservices|googletagmanager)",
    re.I,
)

_BING_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
}


def _scrape_bing(query: str, session) -> list[str]:
    """Scrape Bing web results for a query. Returns list of URLs."""
    urls = []
    seen: set[str] = set()
    session.headers.update(_BING_HEADERS)
    session.headers["User-Agent"] = random_ua()

    try:
        url = f"https://www.bing.com/search?q={quote_plus(query)}&count=20&setlang=fr"
        r = session.get(url, timeout=12)
        if r.status_code != 200:
            return urls

        # Bing result links: <a href="..."> inside <li class="b_algo">
        for m in re.finditer(
            r'<li class="b_algo".*?<a[^>]+href="(https?://[^"]+)"',
            r.text, re.DOTALL | re.I,
        ):
            u = m.group(1).split('"')[0].strip()
            if u not in seen and not _EXCLUDE.search(u):
                seen.add(u)
                urls.append(u)

        # Also catch simple href links in results
        for m in re.finditer(r'<a[^>]+href="(https?://(?!www\.bing\.com)[^"]+)"', r.text):
            u = m.group(1).split('"')[0].strip()
            if u not in seen and not _EXCLUDE.search(u) and len(u) > 20:
                seen.add(u)
                urls.append(u)

    except Exception:
        pass
    return urls[:15]


class GoogleDorkEngine(Engine):
    name = "GoogleDork"
    desc = "Recherche ciblee via dorks (Bing + Google)"
    modes = ["name", "username"]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        results = []
        seen: set[str] = set()
        cfg = kwargs.get("config")
        session = make_session(proxy=getattr(cfg, "proxy", None))

        if input_type == InputType.NAME:
            dorks = [
                f'"{query}" site:linkedin.com',
                f'"{query}" site:facebook.com',
                f'"{query}" site:twitter.com',
                f'"{query}" site:instagram.com',
                f'"{query}" site:youtube.com',
                f'"{query}" site:tiktok.com',
                f'"{query}" site:medium.com',
                f'"{query}" site:github.com',
                f'"{query}" site:reddit.com',
                f'"{query}" site:viadeo.com OR site:xing.com',
                f'"{query}" (CV OR resume OR curriculum vitae) filetype:pdf',
                f'"{query}" (profil OR profile OR contact)',
                f'"{query}" site:pagesjaunes.fr OR site:annuaire.com',
                f'"{query}" site:copainsdavant.linternaute.com',
            ]
        else:
            dorks = [
                f'"{query}" site:linkedin.com',
                f'"{query}" site:facebook.com',
                f'"{query}" site:twitter.com',
                f'"{query}" site:instagram.com',
                f'"{query}" site:github.com',
                f'"{query}" site:reddit.com',
                f'"{query}" site:tiktok.com',
            ]

        # === 1. Bing scraping (permissif, pas de CAPTCHA agressif) ===
        for dork in dorks[:8]:  # max 8 requetes Bing pour ne pas se faire bloquer
            bing_urls = _scrape_bing(dork, session)
            for u in bing_urls:
                if u not in seen:
                    seen.add(u)
                    results.append({
                        "site": f"[Dork] {url_to_site_name(u, query)}",
                        "url": u,
                    })
            if bing_urls:
                time.sleep(random.uniform(0.5, 1.2))

        # === 2. Clickable Google dork URLs (toujours générés — utiles au clic) ===
        # Pour name: generer TOUS les dorks cliquables
        # Pour username: seulement si Bing n'a rien trouve
        generate_all = (input_type == InputType.NAME)
        if len(results) < 3 or generate_all:
            limit = len(dorks) if generate_all else 6
            for dork in dorks[:limit]:
                gurl = f"https://www.google.com/search?q={quote_plus(dork)}"
                if gurl not in seen:
                    seen.add(gurl)
                    target = dork.split("site:")[-1].split()[0] if "site:" in dork else dork[:30]
                    results.append({
                        "site": f"[Dork] {target} (cliquer)",
                        "url": gurl,
                    })

        return results[:50]
