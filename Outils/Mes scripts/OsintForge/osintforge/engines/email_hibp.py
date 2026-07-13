"""Have I Been Pwned — breach + paste check (breach API needs a key)."""

from __future__ import annotations

import os

import requests

from .base import Engine, ASSISTED
from ..models import Finding, FindingKind, Confidence, InputType


class HIBPEngine(Engine):
    name = "HIBP"
    desc = "Have I Been Pwned — fuites"
    modes = ["email"]

    def is_available(self) -> bool:
        return True  # always usable (falls back to a manual-check link)

    def status(self) -> str:
        from .base import LIVE
        return LIVE

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        cfg = kwargs.get("config")
        key = (getattr(cfg.api_keys, "hibp", "") if cfg else "") or os.environ.get("HIBP_API_KEY", "")
        findings: list[Finding] = []
        q = requests.utils.quote(query)

        if key:
            try:
                r = requests.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{q}?truncateResponse=false",
                    headers={"hibp-api-key": key, "user-agent": "OsintForge/1.0"}, timeout=12)
                if r.status_code == 200:
                    for b in r.json():
                        name = b.get("Name", "?")
                        date = b.get("BreachDate", "")
                        count = b.get("PwnCount", 0)
                        classes = ", ".join(b.get("DataClasses", [])[:4])
                        findings.append(Finding(
                            source=self.name,
                            title=f"{name} ({date})",
                            url=f"https://haveibeenpwned.com/account/{q}",
                            kind=FindingKind.BREACH, confidence=Confidence.HIGH,
                            note=f"{count:,} comptes — {classes}".replace(",", " "),
                            tags=["breach"], data={"breach": name, "date": date, "count": count},
                        ))
                elif r.status_code == 404:
                    findings.append(Finding(
                        source=self.name, title="Aucune fuite connue (HIBP)",
                        url=f"https://haveibeenpwned.com/", kind=FindingKind.INFO,
                        confidence=Confidence.MEDIUM, note="0 breach pour cet email"))
            except Exception:
                pass

        if not findings:
            findings.append(Finding(
                source=self.name, title="Verifier manuellement (cle API recommandee)",
                url=f"https://haveibeenpwned.com/", kind=FindingKind.LINK,
                confidence=Confidence.LOW,
                note="Sans cle HIBP: ouvrir le site et coller l'email"))
        return findings
