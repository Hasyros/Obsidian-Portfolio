"""Domain recon — DNS resolution + certificate-transparency & whois links."""

from __future__ import annotations

import socket

import requests

from .base import Engine
from ..models import Finding, FindingKind, Confidence, InputType


class DomainDnsEngine(Engine):
    name = "DNS/Whois"
    desc = "Resolution DNS, sous-domaines (crt.sh), whois"
    modes = ["domain"]

    def is_available(self) -> bool:
        return True

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        domain = query.lower().strip()

        try:
            ip = socket.gethostbyname(domain)
            findings.append(Finding(
                source=self.name, title=f"A record: {ip}",
                url=f"https://ipinfo.io/{ip}", kind=FindingKind.INFO,
                confidence=Confidence.HIGH, note=f"{domain} -> {ip}"))
        except Exception:
            findings.append(Finding(
                source=self.name, title="Resolution DNS echouee", url="",
                kind=FindingKind.INFO, confidence=Confidence.LOW))

        # Subdomains via crt.sh (certificate transparency)
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
            if r.status_code == 200:
                subs = sorted({row.get("name_value", "").lower()
                               for row in r.json()
                               if domain in row.get("name_value", "")})
                subs = [s for s in subs if s and "*" not in s][:25]
                for s in subs:
                    findings.append(Finding(
                        source="crt.sh", title=s, url=f"https://{s}",
                        kind=FindingKind.INFO, confidence=Confidence.MEDIUM,
                        note="Sous-domaine (transparence certificats)"))
        except Exception:
            pass

        findings.append(Finding(
            source=self.name, title="Whois complet",
            url=f"https://who.is/whois/{domain}", kind=FindingKind.LINK,
            confidence=Confidence.LOW))
        return findings
