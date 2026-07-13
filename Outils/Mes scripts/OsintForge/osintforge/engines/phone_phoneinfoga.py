"""PhoneInfoga — phone-number OSINT (carrier/country/line-type) + numverify API."""

from __future__ import annotations

import os
import re
from urllib.parse import quote_plus

import requests

from .base import Engine, LIVE, NEEDS_SETUP, ASSISTED, find_binary, run_cmd
from ..models import Finding, FindingKind, Confidence, InputType


def _normalize(phone: str) -> str:
    p = re.sub(r"[\s\-().]+", "", phone.strip())
    return p if p.startswith("+") else "+" + p


_DORK_HEADER = re.compile(r"^(Reputation|Individuals|General):\s*$")
_SCANNER_HEADER = re.compile(r"^Results for (.+)$")
_URL_LINE = re.compile(r"^\s*URL:\s*(\S+)")
_KV_LINE = re.compile(r"^([A-Za-z][A-Za-z ]*):\s*(.+)$")
# Keys that are redundant/noisy and not worth surfacing as their own finding.
_SKIP_KEYS = {"found", "raw local"}


def _parse_scan_output(source: str, blob: str) -> list[Finding]:
    """Parse `phoneinfoga scan` text output (v2.11.x) into findings.

    Output has two shapes: dork-category blocks ("Reputation:" / "Individuals:" /
    "General:" each followed by "\tURL: ..." lines) and scanner-result blocks
    ("Results for <scanner>" followed by "Key: value" lines, or just "Found: false"
    when the scanner has nothing). We parse generically by key/value rather than
    hardcoding field names, since those differ per scanner and changed across
    PhoneInfoga versions.
    """
    findings: list[Finding] = []
    dork_category: str | None = None
    scanner_name: str | None = None
    scanner_kv: dict[str, str] = {}

    def flush_scanner():
        if not scanner_name:
            return
        if scanner_kv.get("found", "true").lower() == "false":
            return
        parts = [f"{k.strip()}: {v.strip()}" for k, v in scanner_kv.items()
                 if k.strip().lower() not in _SKIP_KEYS and v.strip()]
        if parts:
            findings.append(Finding(
                source=source, title=f"[{scanner_name}] " + " | ".join(parts),
                url="", kind=FindingKind.INFO, confidence=Confidence.MEDIUM,
                tags=["phone"]))

    dork_count = 0
    for line in blob.splitlines():
        m = _DORK_HEADER.match(line)
        if m:
            flush_scanner()
            scanner_name = None
            dork_category = m.group(1)
            continue
        m = _SCANNER_HEADER.match(line)
        if m:
            flush_scanner()
            dork_category = None
            scanner_name = m.group(1).strip()
            scanner_kv = {}
            continue
        if dork_category:
            m = _URL_LINE.match(line)
            if m and dork_count < 20:
                dork_count += 1
                findings.append(Finding(
                    source=source, title=f"PhoneInfoga: {dork_category}", url=m.group(1),
                    kind=FindingKind.DORK, confidence=Confidence.LOW,
                    note=f"Categorie: {dork_category}"))
            continue
        if scanner_name:
            m = _KV_LINE.match(line)
            if m:
                scanner_kv[m.group(1)] = m.group(2)
    flush_scanner()
    return findings


class PhoneInfogaEngine(Engine):
    name = "PhoneInfoga"
    desc = "OSINT numero (operateur, pays, dorks)"
    modes = ["phone"]

    def is_available(self) -> bool:
        # Always usable: numverify (if key) + generated dorks even without the binary.
        return True

    def status(self) -> str:
        return LIVE if find_binary("phoneinfoga") else NEEDS_SETUP

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        phone = _normalize(query)
        findings: list[Finding] = []

        binary = find_binary("phoneinfoga")
        if binary:
            out, err, rc = run_cmd([binary, "scan", "-n", phone], timeout=90)
            findings.extend(_parse_scan_output(self.name, out + "\n" + err))

        # numverify (optional key)
        cfg = kwargs.get("config")
        key = (getattr(cfg.api_keys, "numverify", "") if cfg else "") or os.environ.get("OSINT_NUMVERIFY_KEY", "")
        if key:
            try:
                r = requests.get("http://apilayer.net/api/validate",
                                 params={"access_key": key, "number": phone}, timeout=10)
                d = r.json() if r.status_code == 200 else {}
                if d.get("valid"):
                    info = " | ".join(x for x in [
                        f"Pays: {d.get('country_name')}" if d.get("country_name") else "",
                        f"Operateur: {d.get('carrier')}" if d.get("carrier") else "",
                        f"Type: {d.get('line_type')}" if d.get("line_type") else "",
                    ] if x)
                    findings.append(Finding(
                        source="numverify", title=info or "Numero valide", url="",
                        kind=FindingKind.INFO, confidence=Confidence.HIGH))
            except Exception:
                pass

        # Clickable search dorks (always).
        for tpl, label in [('"{p}"', "Recherche exacte"),
                           ('"{p}" site:facebook.com', "Facebook"),
                           ('"{p}" site:linkedin.com', "LinkedIn"),
                           ('intext:"{p}"', "Mentions")]:
            dork = tpl.replace("{p}", phone)
            findings.append(Finding(
                source=self.name, title=f"Dork {label}",
                url=f"https://www.google.com/search?q={quote_plus(dork)}",
                kind=FindingKind.DORK, confidence=Confidence.LOW, note=dork))
        return findings
