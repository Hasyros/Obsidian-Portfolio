"""WhatsMyName — 600+ sites with self-verifying checks (e_string / e_code).

Because WMN validates each hit against the site's own success signature, its
results are marked ``pre_verified`` PROFILE findings and skip our deep-verify.
The wmn-data.json list is cached on disk for a day to avoid re-downloading.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

from .base import Engine, console, tmpdir
from ..http import random_ua
from ..models import Finding, FindingKind, Confidence, InputType, categorize, is_high_trust

_WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
_CACHE = Path(tmpdir("wmn").parent) / "osintforge_wmn.json"
_CACHE_TTL = 86_400


class WhatsMyNameEngine(Engine):
    name = "WhatsMyName"
    desc = "600+ sites, verifies (vrais liens)"
    modes = ["username"]

    def is_available(self) -> bool:
        return True

    def _load_sites(self) -> list[dict]:
        if _CACHE.is_file() and time.time() - _CACHE.stat().st_mtime < _CACHE_TTL:
            try:
                return json.loads(_CACHE.read_text(encoding="utf-8")).get("sites", [])
            except Exception:
                pass
        console.print("    [dim]Telechargement base WMN...[/dim]")
        data = requests.get(_WMN_URL, timeout=20).json()
        try:
            _CACHE.write_text(json.dumps(data), encoding="utf-8")
        except Exception:
            pass
        return data.get("sites", [])

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        workers = kwargs.get("workers", 40)
        timeout = kwargs.get("timeout", 8)
        try:
            sites = self._load_sites()
        except Exception as e:
            console.print(f"    [red]WMN indisponible: {e}[/red]")
            return []
        console.print(f"    [dim]{len(sites)} sites charges[/dim]")
        headers = {"User-Agent": random_ua()}

        def check(si: dict):
            uri = si.get("uri_check", "")
            if not uri or "{account}" not in uri:
                return None
            url = uri.replace("{account}", query)
            e_str = si.get("e_string", "")
            e_code = si.get("e_code", 200)
            m_str = si.get("m_string", "")
            try:
                r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                if r.status_code != e_code:
                    return None
                body = r.text[:40_000]
                if e_str and e_str not in body:
                    return None
                if m_str and m_str in body:
                    return None
            except Exception:
                return None
            name = si.get("name", "?")
            pretty = si.get("uri_pretty", url).replace("{account}", query)
            return Finding(
                source="WhatsMyName", title=name, url=pretty,
                kind=FindingKind.PROFILE, pre_verified=True,
                confidence=Confidence.HIGH, http_status=r.status_code,
                tags=categorize(name), high_trust=is_high_trust(name, pretty),
                query_in_body=True,
            )

        findings: list[Finding] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(check, s) for s in sites]
            for f in as_completed(futs):
                r = f.result()
                if r:
                    findings.append(r)
        return findings
