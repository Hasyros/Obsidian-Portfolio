"""Hunter.io — find emails from name + company."""

import os

import requests
from urllib.parse import quote_plus

from .base import Engine
from ..models import InputType


class HunterIOEngine(Engine):
    name = "Hunter.io"
    desc = "Trouver emails via nom + entreprise"
    modes = ["name", "email"]

    def is_available(self) -> bool:
        return bool(self._get_key())

    def _get_key(self, cfg=None) -> str:
        if cfg:
            return cfg.api_keys.hunter_io
        return os.environ.get("OSINT_HUNTER_IO_KEY", "")

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        cfg = kwargs.get("config")
        key = self._get_key(cfg)
        if not key:
            return []

        results = []

        if input_type == InputType.EMAIL:
            # Email verifier
            try:
                r = requests.get(
                    "https://api.hunter.io/v2/email-verifier",
                    params={"email": query, "api_key": key},
                    timeout=10,
                )
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    status = data.get("status", "unknown")
                    score = data.get("score", 0)
                    results.append({
                        "site": f"[Hunter.io] Email {status} (score: {score})",
                        "url": f"https://hunter.io/verify/{quote_plus(query)}",
                    })
                    # Associated domain/company
                    domain = query.split("@")[-1] if "@" in query else ""
                    if domain:
                        r2 = requests.get(
                            "https://api.hunter.io/v2/domain-search",
                            params={"domain": domain, "api_key": key, "limit": 5},
                            timeout=10,
                        )
                        if r2.status_code == 200:
                            d2 = r2.json().get("data", {})
                            org = d2.get("organization", "")
                            if org:
                                results.append({
                                    "site": f"[Hunter.io] Organisation: {org}",
                                    "url": f"https://hunter.io/companies/{domain}",
                                })
            except Exception:
                pass

        elif input_type == InputType.NAME:
            # Email finder by name
            parts = query.strip().split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                try:
                    r = requests.get(
                        "https://api.hunter.io/v2/email-finder",
                        params={
                            "first_name": first,
                            "last_name": last,
                            "api_key": key,
                        },
                        timeout=10,
                    )
                    if r.status_code == 200:
                        data = r.json().get("data", {})
                        email = data.get("email", "")
                        if email:
                            results.append({
                                "site": f"[Hunter.io] Email: {email}",
                                "url": f"mailto:{email}",
                            })
                except Exception:
                    pass

        return results
