"""Epieos — Google account existence + Google ID / Maps links (public endpoint)."""

from __future__ import annotations

import requests

from .base import Engine
from ..models import Finding, FindingKind, Confidence, InputType


class EpieosEngine(Engine):
    name = "Epieos"
    desc = "Google ID, liens comptes Google"
    modes = ["email"]

    def is_available(self) -> bool:
        return True

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        q = requests.utils.quote(query)
        try:
            r = requests.get(f"https://epieos.com/api/v1/google?email={q}",
                             headers={"User-Agent": "OsintForge/1.0"}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get("exists"):
                    name = data.get("name", "")
                    gid = data.get("google_id", "")
                    findings.append(Finding(
                        source=self.name, title=f"Compte Google {('- ' + name) if name else 'existe'}",
                        url=f"https://epieos.com/?q={q}", kind=FindingKind.ACCOUNT,
                        confidence=Confidence.HIGH, note=f"gaia ID: {gid}" if gid else "",
                        tags=["google"], data={"gaia_id": gid, "name": name}))
                    if data.get("photo"):
                        findings.append(Finding(
                            source=self.name, title="Photo Google", url=data["photo"],
                            kind=FindingKind.INFO, confidence=Confidence.MEDIUM, tags=["google"]))
                    if gid:
                        findings.append(Finding(
                            source=self.name, title="Google Maps (contributions)",
                            url=f"https://www.google.com/maps/contrib/{gid}",
                            kind=FindingKind.LINK, confidence=Confidence.MEDIUM,
                            tags=["google", "geo"]))
        except Exception:
            pass
        return findings
