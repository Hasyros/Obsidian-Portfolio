"""EmailFinder — découverte d'emails associés à un nom."""

import re
from urllib.parse import quote_plus, quote

from .base import Engine, url_to_site_name
from ..models import InputType
from ..session import make_session, random_ua

# Regex pour extraire les emails dans du texte HTML
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.[a-zA-Z]{2,6}",
    re.I,
)

# Domaines à ignorer dans les emails extraits (faux positifs)
_IGNORE_EMAIL_DOMAINS = {
    "example.com", "test.com", "domain.com", "email.com",
    "sentry.io", "w3.org", "schema.org", "cloudflare.com",
    "jquery.com", "facebook.com", "twitter.com", "google.com",
    "instagram.com", "tiktok.com", "apple.com", "microsoft.com",
    "amazon.com", "cdnjs.com", "bootstrapcdn.com",
}

# Fournisseurs email courants en France et international
_EMAIL_PROVIDERS_FR = [
    "gmail.com", "hotmail.com", "hotmail.fr", "yahoo.fr", "yahoo.com",
    "outlook.com", "outlook.fr", "orange.fr", "free.fr", "sfr.fr",
    "laposte.net", "wanadoo.fr", "bbox.fr", "numericable.fr",
    "live.fr", "live.com", "icloud.com", "protonmail.com",
]


def _extract_emails_from_html(html: str, query: str) -> list[str]:
    """Extrait les emails depuis du HTML, filtre les faux positifs."""
    parts = [p.lower() for p in query.split() if len(p) > 2]
    found = []
    seen = set()

    for m in _EMAIL_RE.finditer(html):
        email = m.group(0).lower().strip(".,;:\"'")
        domain = email.split("@")[-1]
        if domain in _IGNORE_EMAIL_DOMAINS:
            continue
        if email in seen:
            continue
        seen.add(email)

        # Score: l'email contient des mots du nom → plus fiable
        score = sum(1 for p in parts if p in email)
        found.append((score, email))

    # Trier par score décroissant
    found.sort(key=lambda x: -x[0])
    return [e for _, e in found[:10]]


class EmailFinderEngine(Engine):
    name = "EmailFinder"
    desc = "Emails par nom: dorks, phonebook, GitHub, extraction"
    modes = ["name"]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        results = []
        seen_urls: set[str] = set()
        emails_found: set[str] = set()
        cfg = kwargs.get("config")
        session = make_session(proxy=getattr(cfg, "proxy", None))
        q = query.strip()
        qenc = quote_plus(q)

        def add_email(email: str, source: str):
            if email not in emails_found:
                emails_found.add(email)
                results.append({
                    "site": f"[Email] {email}",
                    "url": f"https://leakcheck.io/result/{quote(email)}/0",
                    "note": f"Trouvé via {source}",
                })

        def add_link(site: str, url: str):
            if url not in seen_urls:
                seen_urls.add(url)
                results.append({"site": site, "url": url})

        # ── 1. Google dorks email (cliquables) ───────────────────────────────
        providers_dork = " OR ".join(f'"@{p}"' for p in _EMAIL_PROVIDERS_FR[:6])
        email_dorks = [
            (f'[EmailDork] Providers FR',
             f'"{q}" ({providers_dork})'),
            (f'[EmailDork] Générique',
             f'"{q}" email OR contact OR "@" -site:linkedin.com'),
            (f'[EmailDork] PDF/Doc contact',
             f'"{q}" (filetype:pdf OR filetype:doc OR filetype:docx) email OR contact'),
            (f'[EmailDork] LinkedIn email',
             f'"{q}" site:linkedin.com email OR contact'),
            (f'[EmailDork] Site pro/CV',
             f'"{q}" (CV OR resume OR "curriculum vitae" OR portfolio) email'),
            (f'[EmailDork] Forum/blog',
             f'"{q}" "@gmail.com" OR "@hotmail" OR "@yahoo"'),
            (f'[EmailDork] Académique',
             f'"{q}" site:researchgate.net OR site:academia.edu email'),
            (f'[EmailDork] Presse/media',
             f'"{q}" contact OR "joindre" OR "écrire à" email'),
        ]
        for site_name, dork in email_dorks:
            add_link(site_name, f"https://www.google.com/search?q={quote_plus(dork)}")

        # ── 2. Phonebook.cz — base email/domain publique ─────────────────────
        try:
            session.headers["User-Agent"] = random_ua()
            # Essai avec le nom complet
            pb_url = f"https://phonebook.cz/?term={qenc}&type=2&target=1"
            add_link("[EmailHunt] Phonebook.cz", pb_url)

            r = session.get(pb_url, timeout=12)
            if r.status_code == 200:
                emails = _extract_emails_from_html(r.text, q)
                for e in emails:
                    add_email(e, "Phonebook.cz")
        except Exception:
            pass

        # ── 3. Skymem — moteur de recherche d'emails ─────────────────────────
        try:
            sky_url = f"https://www.skymem.info/srp?q={qenc}"
            add_link("[EmailHunt] Skymem", sky_url)

            session.headers["User-Agent"] = random_ua()
            r = session.get(sky_url, timeout=12)
            if r.status_code == 200:
                emails = _extract_emails_from_html(r.text, q)
                for e in emails:
                    add_email(e, "Skymem")
        except Exception:
            pass

        # ── 4. GitHub — recherche commits par nom d'auteur ──────────────────
        try:
            session.headers["User-Agent"] = random_ua()
            session.headers["Accept"] = "application/vnd.github.v3+json"
            # GitHub commit search par auteur
            gh_url = f"https://api.github.com/search/commits?q=author-name:{quote(q)}&per_page=5"
            r = session.get(gh_url, timeout=12)
            if r.status_code == 200:
                import json
                data = r.json()
                for item in data.get("items", []):
                    commit = item.get("commit", {})
                    author = commit.get("author", {})
                    email = author.get("email", "")
                    if email and "@" in email:
                        domain = email.split("@")[-1]
                        if domain not in _IGNORE_EMAIL_DOMAINS and "noreply" not in email:
                            add_email(email, "GitHub commits")
        except Exception:
            pass

        # ── 5. Hunter.io (sans clé) — domaine + prénom/nom ──────────────────
        # Si on a des infos sur l'entreprise on peut essayer
        try:
            # Lien cliquable Hunter.io
            add_link("[EmailHunt] Hunter.io",
                     f"https://hunter.io/email-finder?first_name={quote_plus(q.split()[0])}"
                     f"&last_name={quote_plus(' '.join(q.split()[1:]))}")
        except Exception:
            pass

        # ── 6. VoilaNorbert / FindThatEmail ─────────────────────────────────
        try:
            parts = q.split()
            if len(parts) >= 2:
                add_link("[EmailHunt] VoilaNorbert",
                         f"https://www.voilanorbert.com/?name={qenc}")
                add_link("[EmailHunt] FindThatEmail",
                         f"https://findthat.email/search?name={qenc}")
                add_link("[EmailHunt] Snov.io",
                         f"https://app.snov.io/email-finder?firstName={quote_plus(parts[0])}"
                         f"&lastName={quote_plus(' '.join(parts[1:]))}")
        except Exception:
            pass

        # ── 7. Breach databases (avec le nom comme indice) ──────────────────
        try:
            add_link("[EmailHunt] BreachDirectory",
                     f"https://breachdirectory.org/?q={qenc}")
            add_link("[EmailHunt] Dehashed",
                     f"https://dehashed.com/search?query={qenc}")
        except Exception:
            pass

        return results[:60]
