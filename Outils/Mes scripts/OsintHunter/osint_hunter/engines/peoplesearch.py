"""PeopleSearch — annuaires de personnes et liens OSINT directs."""

import re
from urllib.parse import quote_plus, quote

from .base import Engine, url_to_site_name
from ..models import InputType
from ..session import make_session, random_ua


class PeopleSearchEngine(Engine):
    name = "PeopleSearch"
    desc = "Annuaires personnes (Webmii, PeekYou, Yasni, Pipl...)"
    modes = ["name"]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        results = []
        seen: set[str] = set()
        cfg = kwargs.get("config")
        session = make_session(proxy=getattr(cfg, "proxy", None))
        q = query.strip()
        qenc = quote_plus(q)

        # Junk filter
        _JUNK = re.compile(
            r"(sharer\.php|intent/tweet|apps\.apple\.com|play\.google|"
            r"doubleclick|googleadservices|javascript:|mailto:)",
            re.I,
        )

        # ── 1. Sites qui permettent le scraping ──────────────────────────────

        # Webmii — agrège les profils sociaux par nom
        try:
            session.headers["User-Agent"] = random_ua()
            wm_url = f"https://webmii.com/people?n={qenc}"
            r = session.get(wm_url, timeout=12)
            if r.status_code == 200:
                first = q.split()[0].lower()
                # Liens vers des profils externes trouvés par Webmii
                for m in re.finditer(r'href="(https?://(?!webmii\.com)[^"]{15,})"', r.text):
                    u = m.group(1).rstrip("/")
                    if u not in seen and not _JUNK.search(u) and first in u.lower():
                        seen.add(u)
                        results.append({
                            "site": f"[Webmii] {url_to_site_name(u, q)}",
                            "url": u,
                        })
                # Page de résultats Webmii elle-même
                if first in r.text.lower() and wm_url not in seen:
                    seen.add(wm_url)
                    results.append({"site": "Webmii", "url": wm_url})
        except Exception:
            pass

        # Yasni — annuaire FR/DE avec agrégation de profils
        try:
            session.headers["User-Agent"] = random_ua()
            parts = q.split()
            if len(parts) >= 2:
                yn_q = "+".join(parts)
                yn_url = f"https://yasni.fr/{yn_q}/"
                r = session.get(yn_url, timeout=12, allow_redirects=True)
                if r.status_code == 200 and parts[0].lower() in r.text.lower():
                    final = r.url
                    if final not in seen:
                        seen.add(final)
                        results.append({"site": "Yasni", "url": final})
                    # Profils externes trouvés par Yasni
                    for m in re.finditer(r'href="(https?://(?!yasni\.)[^"]{15,})"', r.text):
                        u = m.group(1).rstrip("/")
                        if (u not in seen and not _JUNK.search(u)
                                and parts[0].lower() in u.lower()):
                            seen.add(u)
                            results.append({
                                "site": f"[Yasni] {url_to_site_name(u, q)}",
                                "url": u,
                            })
        except Exception:
            pass

        # ── 2. Liens cliquables vers annuaires de personnes ──────────────────
        # Ces liens s'ouvrent directement dans le navigateur (menu O ou clic)

        directories = [
            ("Webmii (cliquer)",        f"https://webmii.com/people?n={qenc}"),
            ("Yasni (cliquer)",         f"https://yasni.fr/{quote_plus(q).replace('+', '+')}"),
            ("PeekYou (cliquer)",       f"https://www.peekayou.com/search/?q={qenc}"),
            ("Pipl (cliquer)",          f"https://pipl.com/search/?q={qenc}&l=&sloc=&in=5"),
            ("Spokeo (cliquer)",        f"https://www.spokeo.com/search?q={qenc}"),
            ("192.com (cliquer)",       f"https://www.192.com/people/{qenc}/"),
            ("TruePeopleSearch",        f"https://www.truepeoplesearch.com/results?name={qenc}"),
            ("Google People",           f"https://www.google.com/search?q={quote_plus(chr(34)+q+chr(34))}"),
        ]

        for name_dir, url_dir in directories:
            if url_dir not in seen:
                seen.add(url_dir)
                results.append({
                    "site": f"[PeopleDir] {name_dir}",
                    "url": url_dir,
                })

        return results[:40]
