"""Have I Been Pwned — breach check (API key for breaches, free for passwords)."""

import hashlib
import os

import requests

from .base import Engine
from ..models import InputType


class HIBPEngine(Engine):
    name = "HIBP"
    desc = "Have I Been Pwned — fuites"
    modes = ["email"]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        cfg = kwargs.get("config")
        results = []

        # Breach check (requires API key)
        key = ""
        if cfg:
            key = cfg.api_keys.hibp
        if not key:
            key = os.environ.get("HIBP_API_KEY", "")

        if key:
            try:
                r = requests.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(query)}",
                    headers={"hibp-api-key": key, "user-agent": "OSINT-Hunter/5.0"},
                    timeout=10,
                )
                if r.status_code == 200:
                    for b in r.json():
                        name = b.get("Name", "Unknown")
                        date = b.get("BreachDate", "")
                        count = b.get("PwnCount", 0)
                        results.append({
                            "site": f"[Breach] {name} ({date}, {count:,} comptes)",
                            "url": f"https://haveibeenpwned.com/account/{requests.utils.quote(query)}",
                        })
            except Exception:
                pass

        # Paste check (requires API key too)
        if key:
            try:
                r = requests.get(
                    f"https://haveibeenpwned.com/api/v3/pasteaccount/{requests.utils.quote(query)}",
                    headers={"hibp-api-key": key, "user-agent": "OSINT-Hunter/5.0"},
                    timeout=10,
                )
                if r.status_code == 200:
                    pastes = r.json()
                    if pastes:
                        results.append({
                            "site": f"[HIBP] {len(pastes)} paste(s) trouves",
                            "url": "https://haveibeenpwned.com",
                        })
            except Exception:
                pass

        if not results:
            results.append({
                "site": "[HIBP] Verifier manuellement (cle API recommandee)",
                "url": f"https://haveibeenpwned.com/?search={requests.utils.quote(query)}",
            })

        return results
