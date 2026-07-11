"""Dehashed — comprehensive breach search (requires API key)."""

import os

import requests

from .base import Engine
from ..models import InputType


class DehashedEngine(Engine):
    name = "Dehashed"
    desc = "Breach search avance (cle API requise)"
    modes = ["email", "username"]

    def is_available(self) -> bool:
        creds = self._get_creds()
        return bool(creds[0] and creds[1])

    def _get_creds(self, cfg=None) -> tuple[str, str]:
        if cfg:
            email = cfg.api_keys.dehashed_email
            key = cfg.api_keys.dehashed_key
            if email and key:
                return email, key
        email = os.environ.get("OSINT_DEHASHED_EMAIL", "")
        key = os.environ.get("OSINT_DEHASHED_KEY", "")
        return (email, key) if email and key else ("", "")

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        cfg = kwargs.get("config")
        email, key = self._get_creds(cfg)
        if not email or not key:
            return []

        results = []
        field = "email" if input_type == InputType.EMAIL else "username"

        try:
            r = requests.get(
                "https://api.dehashed.com/search",
                params={"query": f'{field}:"{query}"', "size": 20},
                auth=(email, key),
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                entries = data.get("entries", []) or []
                seen: set[str] = set()
                for entry in entries[:15]:
                    db_name = entry.get("database_name", "unknown")
                    found_email = entry.get("email", "")
                    found_user = entry.get("username", "")
                    found_name = entry.get("name", "")
                    has_pass = "oui" if entry.get("hashed_password") or entry.get("password") else "non"

                    key_str = f"{db_name}:{found_email}:{found_user}"
                    if key_str in seen:
                        continue
                    seen.add(key_str)

                    parts = [f"DB: {db_name}"]
                    if found_email:
                        parts.append(f"email: {found_email}")
                    if found_user:
                        parts.append(f"user: {found_user}")
                    if found_name:
                        parts.append(f"nom: {found_name}")
                    parts.append(f"pass: {has_pass}")

                    results.append({
                        "site": f"[Dehashed] {' | '.join(parts)[:90]}",
                        "url": "https://dehashed.com",
                    })

                total = data.get("total", 0)
                if total > 15:
                    results.append({
                        "site": f"[Dehashed] {total} resultats au total",
                        "url": "https://dehashed.com",
                    })
        except Exception:
            pass

        return results
