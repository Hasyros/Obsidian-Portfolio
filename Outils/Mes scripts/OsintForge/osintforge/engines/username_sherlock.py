"""Sherlock — 400+ sites, fast (candidate profiles, deep-verified afterwards)."""

from __future__ import annotations

import re
import sys

from .base import Engine, run_cmd, has_binary, has_module, tmpdir, url_to_site_name
from ..models import Finding, FindingKind, InputType, categorize, is_high_trust


class SherlockEngine(Engine):
    name = "Sherlock"
    desc = "400+ sites, rapide"
    modes = ["username"]

    def is_available(self) -> bool:
        return has_binary("sherlock") or has_module("sherlock") or has_module("sherlock_project")

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        # Sherlock writes a "<username>.txt" report to the CURRENT directory by
        # default (even with --print-found). For a single username the way to
        # redirect it is --output <file> (--folderoutput is only for multi-user
        # runs); this keeps the working directory / repo clean. We parse stdout
        # regardless.
        out_file = str(tmpdir(f"sherlock_{query}") / "found.txt")
        common = ["--print-found", "--timeout", "10", "--no-color", "--output", out_file]
        if has_binary("sherlock"):
            cmd = ["sherlock", query, *common]
        else:
            cmd = [sys.executable, "-m", "sherlock_project", query, *common]
        out, err, rc = run_cmd(cmd)
        if "No module named" in (out + err):
            cmd[1:2] = ["-m", "sherlock"]
            out, err, rc = run_cmd([sys.executable] + cmd[1:])

        findings: list[Finding] = []
        seen: set[str] = set()
        # Sherlock prints:  [+] SiteName: https://...
        for m in re.finditer(r"\[\+\]\s*([^:]+):\s*(https?://\S+)", out + "\n" + err):
            site = m.group(1).strip()
            url = m.group(2).rstrip(".,;)")
            if url in seen:
                continue
            seen.add(url)
            findings.append(Finding(
                source=self.name, title=site, url=url, kind=FindingKind.PROFILE,
                tags=categorize(site), high_trust=is_high_trust(site, url),
            ))
        return findings
