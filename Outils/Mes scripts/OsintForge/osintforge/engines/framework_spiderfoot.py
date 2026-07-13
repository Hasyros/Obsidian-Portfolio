"""SpiderFoot — automation framework. Runs a bounded passive CLI scan if present.

SpiderFoot is heavyweight; driving a full scan can take many minutes. To stay
responsive we run a small, fast passive module set with a hard timeout and parse
the CSV. If SpiderFoot isn't installed we emit a launch guide instead.
"""

from __future__ import annotations

import re
import sys

from .base import Engine, LIVE, ASSISTED, NEEDS_SETUP, has_binary, has_module, find_script, run_cmd
from ..models import Finding, FindingKind, Confidence, InputType

# sf.py's "-o csv" output is NOT real quoted CSV — each line is Source,Type,Data
# naively delimiter-joined, so a Data field containing commas (e.g. raw whois text)
# breaks a csv.reader. We instead match lines by their known Source prefix
# (a module name or "SpiderFoot UI") and split on the first two commas only, which
# keeps any commas inside Data intact. On Windows the header line can also appear
# AFTER the data rows (parent/child process stdout buffering), so we don't rely on
# row position at all — just skip the literal header text if seen.
_ROW_RE = re.compile(r"^(SpiderFoot UI|sfp_[A-Za-z0-9_]+),([^,]+),(.*)$")

# Map our input types to SpiderFoot target types.
_SF_TYPE = {
    InputType.EMAIL: "EMAILADDR",
    InputType.DOMAIN: "INTERNET_NAME",
    InputType.PHONE: "PHONE_NUMBER",
    InputType.NAME: "HUMAN_NAME",
    InputType.USERNAME: "USERNAME",
}
# A few fast, purely-passive modules (no bruteforce, no long crawls).
_FAST_MODULES = "sfp_dnsresolve,sfp_whois,sfp_email,sfp_socialprofiles,sfp_accounts"


class SpiderFootEngine(Engine):
    name = "SpiderFoot"
    desc = "Framework OSINT (scan passif borne si installe)"
    modes = ["email", "domain", "name", "username"]

    def _prefix(self):
        if has_binary("spiderfoot"):
            return ["spiderfoot"]
        if has_binary("sf.py"):
            return ["sf.py"]
        if has_module("spiderfoot"):
            return [sys.executable, "-m", "spiderfoot"]
        local = find_script("spiderfoot", "sf.py")
        if local:
            return local
        return None

    def is_available(self) -> bool:
        return self._prefix() is not None

    def status(self) -> str:
        return LIVE if self.is_available() else ASSISTED

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        prefix = self._prefix()
        if not prefix:
            return [Finding(
                source=self.name, title="SpiderFoot non installe",
                url="https://github.com/smicallef/spiderfoot", kind=FindingKind.LINK,
                confidence=Confidence.LOW,
                note="pip install spiderfoot — puis 'sf.py -l 127.0.0.1:5001' (web) "
                     f"ou CLI: sf.py -s {query} -m {_FAST_MODULES} -o csv -q")]

        # A locally-cloned sf.py resolves its module/config paths relative to its
        # own directory, so it must be run with that directory as cwd.
        import os
        cwd = os.path.dirname(prefix[-1]) if prefix[-1].endswith("sf.py") else None
        out, err, rc = run_cmd(
            prefix + ["-s", query, "-m", _FAST_MODULES, "-o", "csv", "-q"], timeout=180, cwd=cwd or None)

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for line in out.splitlines():
            m = _ROW_RE.match(line)
            if not m:
                continue
            module, sf_type, data = m.group(1), m.group(2).strip(), m.group(3).strip()
            if module == "SpiderFoot UI" or not data:
                continue  # synthetic "target declared" event, not a discovery
            # Some event types store "<scanned target>,<actual value>" as their raw
            # data — strip the redundant target prefix for a cleaner display.
            if data.startswith(f"{query},"):
                data = data[len(query) + 1:]
            key = (sf_type, data[:200])
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                source=self.name, title=f"{sf_type}: {data[:80].splitlines()[0]}",
                url=data if data.startswith("http") else "",
                kind=FindingKind.INFO, confidence=Confidence.MEDIUM,
                note=f"Module: {module}", tags=["spiderfoot"]))
        if not findings:
            findings.append(Finding(
                source=self.name, title="SpiderFoot: aucun resultat (ou scan borne)",
                url="https://github.com/smicallef/spiderfoot", kind=FindingKind.LINK,
                confidence=Confidence.LOW,
                note=f"Scan complet: sf.py -s {query} (interface web plus riche)"))
        return findings[:40]
