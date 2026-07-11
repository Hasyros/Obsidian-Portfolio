"""BreachDirectory — breach/password exposure check."""

import requests
from urllib.parse import quote_plus

from .base import Engine
from ..models import InputType


class BreachDirEngine(Engine):
    name = "BreachDir"
    desc = "BreachDirectory — fuites/passwords exposes"
    modes = ["email", "username"]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        results = []
        try:
            r = requests.get(
                f"https://breachdirectory.org/api/search?query={quote_plus(query)}",
                timeout=10,
                headers={"User-Agent": "OSINT-Hunter/5.0"},
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("found") or data.get("result"):
                    entries = data.get("result", [])
                    seen_sources: set[str] = set()
                    for entry in entries[:10]:
                        src = entry.get("sources", "unknown")
                        if src not in seen_sources:
                            seen_sources.add(src)
                            results.append({
                                "site": f"[Breach] {src}",
                                "url": "https://breachdirectory.org",
                            })
                    if not results:
                        results.append({
                            "site": "[Breach] Trouve dans BreachDirectory",
                            "url": "https://breachdirectory.org",
                        })
        except Exception:
            pass
        return results
