"""Wayback Machine — find archived/deleted profiles."""

import requests
from urllib.parse import quote_plus

from .base import Engine, console
from ..models import InputType


class WaybackEngine(Engine):
    name = "Wayback"
    desc = "Archive.org — profils supprimes/archives"
    modes = ["username", "email"]

    CDX_API = "https://web.archive.org/cdx/search/cdx"

    PROFILE_URLS = [
        "twitter.com/{q}", "x.com/{q}", "instagram.com/{q}",
        "facebook.com/{q}", "github.com/{q}", "reddit.com/user/{q}",
        "linkedin.com/in/{q}", "tiktok.com/@{q}", "youtube.com/@{q}",
        "medium.com/@{q}", "t.me/{q}", "keybase.io/{q}",
    ]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        results = []
        seen: set[str] = set()

        urls_to_check = [u.replace("{q}", query) for u in self.PROFILE_URLS]

        for target in urls_to_check:
            try:
                r = requests.get(
                    self.CDX_API,
                    params={
                        "url": target,
                        "output": "json",
                        "limit": "3",
                        "fl": "timestamp,original,statuscode",
                        "filter": "statuscode:200",
                    },
                    timeout=10,
                    headers={"User-Agent": "OSINT-Hunter/5.0"},
                )
                if r.status_code != 200:
                    continue
                data = r.json()
                if len(data) <= 1:  # first row is headers
                    continue
                for row in data[1:]:
                    ts, original, status = row[0], row[1], row[2]
                    archive_url = f"https://web.archive.org/web/{ts}/{original}"
                    if archive_url not in seen:
                        seen.add(archive_url)
                        domain = original.split("/")[0] if "/" in original else original
                        results.append({
                            "site": f"[Archive] {domain} ({ts[:4]})",
                            "url": archive_url,
                        })
            except Exception:
                continue

        return results
