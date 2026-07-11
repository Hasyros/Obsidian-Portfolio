"""LeakCheck — breach database search."""

import requests
from urllib.parse import quote_plus

from .base import Engine
from ..models import InputType


class LeakCheckEngine(Engine):
    name = "LeakCheck"
    desc = "Recherche dans les bases de fuites"
    modes = ["email", "username"]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        results = []
        try:
            r = requests.get(
                f"https://leakcheck.io/api/public?check={quote_plus(query)}",
                timeout=10,
                headers={"User-Agent": "OSINT-Hunter/5.0"},
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("found"):
                    for i, src in enumerate(data.get("sources", [])):
                        name = src.get("name", "Unknown breach")
                        date = src.get("date", "")
                        # Unique URL per breach to avoid dedup eating them
                        results.append({
                            "site": f"[Leak] {name} ({date})",
                            "url": f"https://leakcheck.io/result/{quote_plus(query)}/{i}",
                        })
                    if not results:
                        results.append({
                            "site": f"[Leak] Trouve dans {data.get('found', 0)} fuite(s)",
                            "url": f"https://leakcheck.io/result/{quote_plus(query)}",
                        })
        except Exception:
            pass
        return results
