"""GHunt — Google account OSINT from an email (gaia ID, name, photo, maps, reviews).

GHunt v2 is a CLI that needs a one-time ``ghunt login`` (stores Google cookies).
If GHunt is installed and authenticated we shell out and parse its JSON; if it is
installed but not logged in we surface a clear setup note instead of failing.
"""

from __future__ import annotations

import json
import sys

from .base import Engine, NEEDS_SETUP, ASSISTED, run_cmd, has_binary, has_module, tmpdir
from ..models import Finding, FindingKind, Confidence, InputType


class GHuntEngine(Engine):
    name = "GHunt"
    desc = "Compte Google via email (gaia ID, nom, photo, Maps)"
    modes = ["email"]

    def _cmd_prefix(self) -> list[str] | None:
        if has_binary("ghunt"):
            return ["ghunt"]
        if has_module("ghunt"):
            return [sys.executable, "-m", "ghunt"]
        return None

    def is_available(self) -> bool:
        return self._cmd_prefix() is not None

    def status(self) -> str:
        return NEEDS_SETUP if self.is_available() else ASSISTED

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        prefix = self._cmd_prefix()
        if not prefix:
            # Not installed at all -> assisted guidance.
            return [Finding(
                source=self.name, title="GHunt non installe",
                url="https://github.com/mxrch/GHunt", kind=FindingKind.LINK,
                confidence=Confidence.LOW,
                note="pip install ghunt puis 'ghunt login' (cookies Google)")]

        out_file = tmpdir("ghunt") / "email.json"
        out, err, rc = run_cmd(prefix + ["email", query, "--json", str(out_file)], timeout=90)
        blob = (out + err).lower()
        if "not logged" in blob or "no creds" in blob or "authenticat" in blob or "login" in blob and rc != 0:
            return [Finding(
                source=self.name, title="GHunt non authentifie",
                url="https://github.com/mxrch/GHunt", kind=FindingKind.LINK,
                confidence=Confidence.LOW, note="Lancer 'ghunt login' une fois")]

        data = {}
        try:
            data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

        findings = self._parse(query, data)
        if not findings and rc == 0:
            findings.append(Finding(
                source=self.name, title="Aucun compte Google trouve",
                url="", kind=FindingKind.INFO, confidence=Confidence.LOW))
        return findings

    def _parse(self, query: str, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        # GHunt JSON layout changes across versions; dig defensively.
        prof = data.get("PROFILE_CONTAINER", {}).get("profile", {}) if isinstance(data, dict) else {}
        gaia = prof.get("personId") or data.get("gaiaID") or ""
        name = ""
        names = prof.get("names") or {}
        if isinstance(names, dict):
            for v in names.values():
                if isinstance(v, dict) and v.get("fullname"):
                    name = v["fullname"]
                    break
        photo = ""
        photos = prof.get("profilePhotos") or {}
        if isinstance(photos, dict):
            for v in photos.values():
                if isinstance(v, dict) and v.get("url"):
                    photo = v["url"]
                    break

        if gaia or name:
            findings.append(Finding(
                source=self.name, title=f"Compte Google: {name or 'existe'}",
                url=f"https://www.google.com/maps/contrib/{gaia}" if gaia else "",
                kind=FindingKind.ACCOUNT, confidence=Confidence.HIGH,
                note=f"gaia ID: {gaia}" if gaia else "", tags=["google"],
                data={"gaia_id": gaia, "name": name}))
        if photo:
            findings.append(Finding(
                source=self.name, title="Photo de profil Google", url=photo,
                kind=FindingKind.INFO, confidence=Confidence.MEDIUM, tags=["google"]))
        if gaia:
            findings.append(Finding(
                source=self.name, title="Avis Google Maps",
                url=f"https://www.google.com/maps/contrib/{gaia}/reviews",
                kind=FindingKind.LINK, confidence=Confidence.MEDIUM, tags=["google", "geo"]))
        return findings
