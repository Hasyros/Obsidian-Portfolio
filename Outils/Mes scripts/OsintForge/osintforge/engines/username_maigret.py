"""Maigret — 3000+ sites (candidate profiles, deep-verified afterwards)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .base import Engine, LIVE, NEEDS_SETUP, run_cmd, tmpdir, console, url_to_site_name
from ..models import Finding, FindingKind, Confidence, InputType, categorize, is_high_trust


class MaigretEngine(Engine):
    name = "Maigret"
    desc = "3000+ sites (candidats, verifies ensuite)"
    modes = ["username"]

    def is_available(self) -> bool:
        try:
            r = subprocess.run([sys.executable, "-m", "maigret", "--version"],
                               capture_output=True, text=True, timeout=10)
            combined = (r.stdout or "") + (r.stderr or "")
            if "No module named" in combined or "ModuleNotFoundError" in combined:
                return False
            if "appengine" in combined.lower() or "ImportError" in combined:
                return False
            return r.returncode == 0
        except Exception:
            return False

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        od = tmpdir(f"maigret_{query}")
        out, err, rc = run_cmd([
            sys.executable, "-m", "maigret", query,
            "-J", "simple", "--folderoutput", str(od), "--no-color", "--timeout", "10",
        ])
        if "appengine" in err.lower() or "ImportError" in err:
            console.print("    [yellow]Maigret casse (urllib3/requests_toolbelt) — "
                          "pip install -U requests-toolbelt urllib3[/yellow]")
            return []

        findings: list[Finding] = []
        seen: set[str] = set()
        for folder in (od, Path("results")):
            if not folder.exists():
                continue
            for jf in sorted(folder.glob("*.json"),
                             key=lambda p: p.stat().st_mtime if p.exists() else 0,
                             reverse=True):
                try:
                    data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    continue
                inner = data.get(query, data) if isinstance(data, dict) else {}
                for site, v in inner.items():
                    url = ""
                    if isinstance(v, str) and v.startswith("http"):
                        url = v
                    elif isinstance(v, dict):
                        url = v.get("url_user") or v.get("url", "")
                    if url and url not in seen:
                        seen.add(url)
                        findings.append(Finding(
                            source=self.name, title=site, url=url,
                            kind=FindingKind.PROFILE, tags=categorize(site),
                            high_trust=is_high_trust(site, url),
                        ))
                if findings:
                    return findings
        return findings
