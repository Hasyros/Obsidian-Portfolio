"""Epieos — Google ID recovery, account linking via Google/Skype."""

import os

import requests

from .base import Engine
from ..models import InputType


class EpieosEngine(Engine):
    name = "Epieos"
    desc = "Google ID, liens entre comptes Google/Skype"
    modes = ["email"]

    def is_available(self) -> bool:
        return True  # Public endpoint + optional API key

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        cfg = kwargs.get("config")
        api_key = ""
        if cfg:
            api_key = cfg.api_keys.epieos
        if not api_key:
            api_key = os.environ.get("OSINT_EPIEOS_KEY", "")

        results = []

        # Google account check (public)
        try:
            r = requests.get(
                f"https://epieos.com/api/v1/google?email={requests.utils.quote(query)}",
                headers={"User-Agent": "OSINT-Hunter/5.0"},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("exists"):
                    name = data.get("name", "")
                    gid = data.get("google_id", "")
                    photo = data.get("photo", "")
                    parts = ["Google account existe"]
                    if name:
                        parts.append(f"Nom: {name}")
                    if gid:
                        parts.append(f"ID: {gid}")
                    results.append({
                        "site": f"[Epieos] {' | '.join(parts)}",
                        "url": f"https://epieos.com/?q={requests.utils.quote(query)}",
                    })
                    if photo:
                        results.append({
                            "site": "[Epieos] Photo Google",
                            "url": photo,
                        })

                    # Google Maps reviews
                    if gid:
                        maps_url = f"https://www.google.com/maps/contrib/{gid}"
                        results.append({
                            "site": "[Epieos] Google Maps",
                            "url": maps_url,
                        })
        except Exception:
            pass

        # Holehe-like with API key
        if api_key:
            try:
                r = requests.get(
                    f"https://api.epieos.com/v1/holehe?email={requests.utils.quote(query)}",
                    headers={"Authorization": f"Bearer {api_key}"},
                    timeout=15,
                )
                if r.status_code == 200:
                    data = r.json()
                    for service in data.get("services", []):
                        if service.get("exists"):
                            results.append({
                                "site": f"[Epieos] {service.get('name', '?')}",
                                "url": f"https://{service.get('domain', '')}",
                            })
            except Exception:
                pass

        return results
