"""Holehe — checks 120+ sites via password-reset to see where an email is used.

These are ACCOUNT findings ("email registered on X"), never profile pages, so
they are not deep-verified.
"""

from __future__ import annotations

import re
import sys

from .base import Engine, run_cmd, has_binary, has_module
from ..models import Finding, FindingKind, Confidence, InputType, categorize, is_high_trust


class HoleheEngine(Engine):
    name = "Holehe"
    desc = "120+ sites via password-reset (email enregistre)"
    modes = ["email"]

    def is_available(self) -> bool:
        return has_binary("holehe") or has_module("holehe")

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        if has_binary("holehe"):
            cmd = ["holehe", query, "--no-color", "--only-used"]
        else:
            cmd = [sys.executable, "-m", "holehe", query, "--no-color", "--only-used"]
        out, err, rc = run_cmd(cmd)
        blob = out + "\n" + err

        findings: list[Finding] = []
        seen: set[str] = set()
        # Only real domains after [+]. This deliberately skips the legend line
        # "[+] Email used, [-] Email not used, [x] Rate limit" that broke the old
        # tool (it produced a bogus host 'email' -> DNS failure).
        for m in re.finditer(r"\[\+\]\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", blob, re.I):
            domain = m.group(1).rstrip(":").lower()
            if domain in seen:
                continue
            seen.add(domain)
            findings.append(Finding(
                source=self.name, title=domain, url=f"https://{domain}",
                kind=FindingKind.ACCOUNT, confidence=Confidence.MEDIUM,
                note="Email enregistre (password-reset)",
                tags=categorize(domain), high_trust=is_high_trust(domain, f"https://{domain}"),
            ))
        return findings
