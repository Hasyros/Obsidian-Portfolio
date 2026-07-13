"""Wayback Machine — archived / deleted profile pages via the CDX API."""

from __future__ import annotations

import requests

from .base import Engine
from ..models import Finding, FindingKind, Confidence, InputType

_CDX = "https://web.archive.org/cdx/search/cdx"
_PROFILE_TPLS = [
    "twitter.com/{q}", "x.com/{q}", "instagram.com/{q}", "facebook.com/{q}",
    "github.com/{q}", "reddit.com/user/{q}", "tiktok.com/@{q}", "youtube.com/@{q}",
    "medium.com/@{q}", "t.me/{q}", "keybase.io/{q}",
]


class WaybackEngine(Engine):
    name = "Wayback"
    desc = "Archive.org — profils supprimes/archives"
    modes = ["username", "email"]

    def is_available(self) -> bool:
        return True

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        targets = [t.replace("{q}", query) for t in _PROFILE_TPLS]
        if input_type == InputType.EMAIL:
            targets = [query]  # search the email string itself
        for target in targets:
            try:
                r = requests.get(_CDX, params={
                    "url": target, "output": "json", "limit": "3",
                    "fl": "timestamp,original,statuscode", "filter": "statuscode:200",
                }, timeout=10, headers={"User-Agent": "OsintForge/1.0"})
                if r.status_code != 200:
                    continue
                rows = r.json()
                for row in rows[1:]:  # first row = header
                    ts, original = row[0], row[1]
                    url = f"https://web.archive.org/web/{ts}/{original}"
                    if url in seen:
                        continue
                    seen.add(url)
                    domain = original.split("/")[0]
                    findings.append(Finding(
                        source=self.name, title=f"{domain} ({ts[:4]})", url=url,
                        kind=FindingKind.ARCHIVE, confidence=Confidence.MEDIUM,
                        note="Copie archivee"))
            except Exception:
                continue
        return findings
