"""DNS/Whois — check if username has an associated domain."""

import requests

from .base import Engine
from ..models import InputType


class DnsWhoisEngine(Engine):
    name = "DNS/Whois"
    desc = "Domaine associe au username"
    modes = ["username"]

    TLDS = [".com", ".net", ".org", ".io", ".dev", ".me", ".fr", ".co"]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        results = []

        for tld in self.TLDS:
            domain = f"{query}{tld}"
            try:
                r = requests.get(
                    f"https://{domain}",
                    timeout=5,
                    allow_redirects=True,
                    headers={"User-Agent": "OSINT-Hunter/5.0"},
                )
                if r.status_code < 400:
                    results.append({
                        "site": f"[Domain] {domain}",
                        "url": f"https://{domain}",
                    })
            except Exception:
                continue

        # Whois via free API
        if results:
            domain = results[0]["url"].replace("https://", "").replace("http://", "").rstrip("/")
            try:
                r = requests.get(
                    f"https://rdap.org/domain/{domain}",
                    timeout=8,
                    headers={"Accept": "application/rdap+json"},
                )
                if r.status_code == 200:
                    data = r.json()
                    registrar = ""
                    for entity in data.get("entities", []):
                        handle = entity.get("handle", "")
                        if handle:
                            registrar = handle
                            break
                    events = data.get("events", [])
                    created = next(
                        (e["eventDate"][:10] for e in events if e.get("eventAction") == "registration"),
                        "",
                    )
                    if created or registrar:
                        results.append({
                            "site": f"[Whois] {domain} (cree: {created}, registrar: {registrar})",
                            "url": f"https://who.is/whois/{domain}",
                        })
            except Exception:
                pass

        return results
