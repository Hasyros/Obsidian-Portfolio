"""Recon-ng — modular recon framework.

Fully driving Recon-ng interactively is version-sensitive, so we wire up exactly
one free, no-key module end-to-end — recon/domains-hosts/hackertarget, for
DOMAIN scans — and fall back to launch-assist commands for the other modes.
Those need either an API key (hibp_breach, fullcontact) or turned out, in
testing, to be redundant/slow/imprecise: recon/profiles-profiles/profiler uses
the same uri_check/e_string/m_string technique as our own WhatsMyName engine
across ~600 sites, took 90+ seconds, and returned 108 hits for a well-known real
username with signals (e.g. an NSFW-site match) that look like false positives —
not worth auto-running when WhatsMyName already covers this more carefully.

Windows note: this vendored copy of recon-ng has two path-separator bugs that
break it on Windows:
  1. `_load_module`'s category regex assumes '/'-joined dirpaths, but os.walk()
     yields backslash paths on Windows. Patched directly in
     tools/recon-ng/recon/core/base.py (one line, documented there).
  2. The marketplace installer's `_write_local_file` splits the target path on
     os.sep (backslash) to compute the directory to create, but the module path
     itself contains forward slashes — so on Windows it never creates the
     nested module directory and install always fails with FileNotFoundError.
     We work around this (not patched upstream) by fetching module files
     ourselves from the same official repo recon-ng's marketplace uses, via
     `_ensure_module`, with correct Windows path joining.
"""

from __future__ import annotations

import re
import urllib.request
from pathlib import Path

from .base import Engine, LIVE, ASSISTED, find_script, has_binary, run_cmd
from ..models import Finding, FindingKind, Confidence, InputType

_MODULE_REPO = "https://raw.githubusercontent.com/lanmaster53/recon-ng-modules/master/modules/"
_HACKERTARGET_MODULE = "recon/domains-hosts/hackertarget"
_WORKSPACE = "osintforge"

# Modes where we only hand back a ready-to-run recon-cli command (needs an API
# key, or — for profiler — is slow/redundant per the note above).
_LINK_MODULES = {
    InputType.NAME: [("Profils (profiler, lent)", "recon/profiles-profiles/profiler"),
                     ("Comptes (fullcontact, cle requise)", "recon/contacts-profiles/fullcontact")],
    InputType.USERNAME: [("Profils (profiler, ~600 sites, lent)", "recon/profiles-profiles/profiler")],
    InputType.EMAIL: [("Fuites (hibp, cle requise)", "recon/contacts-credentials/hibp_breach")],
}

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_KV_LINE = re.compile(r"^\[\*\]\s+([A-Za-z_]+):\s*(.*)$")
_SEP_LINE = re.compile(r"^\[\*\]\s+-+\s*$")


def _parse_host_results(source: str, blob: str) -> list[Finding]:
    """Parse hackertarget's record-block output. recon-ng colorizes its CLI
    output with ANSI codes even when piped (not just when attached to a tty),
    so those must be stripped before the "[*] Key: Value" lines will match."""
    findings: list[Finding] = []
    current: dict[str, str] = {}

    def flush():
        if not current:
            return
        host = current.get("Host")
        ip = current.get("Ip_Address")
        if not host and not ip:
            return
        parts = [f"{k}: {v}" for k, v in current.items() if v and v != "None"]
        findings.append(Finding(
            source=source, title=host or ip, url=f"https://{host}" if host else "",
            kind=FindingKind.INFO, confidence=Confidence.MEDIUM,
            note=" | ".join(parts), tags=["domain"]))

    for raw_line in blob.splitlines():
        line = _ANSI_RE.sub("", raw_line)
        if _SEP_LINE.match(line):
            flush()
            current = {}
            continue
        m = _KV_LINE.match(line)
        if m:
            current[m.group(1)] = m.group(2).strip()
    flush()
    return findings


class ReconNgEngine(Engine):
    name = "Recon-ng"
    desc = "Framework recon (hackertarget live sur domaine, liens sinon)"
    modes = ["domain", "name", "username", "email"]

    def _cli(self) -> list[str] | None:
        if has_binary("recon-cli"):
            return ["recon-cli"]
        return find_script("recon-ng", "recon-cli")

    def is_available(self) -> bool:
        return self._cli() is not None

    def status(self) -> str:
        return LIVE if self.is_available() else ASSISTED

    def _ensure_module(self, path: str) -> bool:
        """Make sure a module .py file is present under ~/.recon-ng/modules/,
        downloading it from the official recon-ng-modules repo if missing."""
        parts = path.split("/")
        dest = Path.home() / ".recon-ng" / "modules" / Path(*parts[:-1]) / f"{parts[-1]}.py"
        if dest.is_file():
            return True
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(_MODULE_REPO + path + ".py", dest)
            return dest.is_file()
        except Exception:
            return False

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        cli = self._cli()
        if not cli:
            return [Finding(
                source=self.name, title="Recon-ng non installe",
                url="https://github.com/lanmaster53/recon-ng", kind=FindingKind.LINK,
                confidence=Confidence.LOW, note="git clone + pip install -r REQUIREMENTS")]

        cwd = str(Path(cli[-1]).parent) if cli[-1].endswith("recon-cli") and len(cli) > 1 else None

        if input_type == InputType.DOMAIN:
            findings: list[Finding] = []
            if self._ensure_module(_HACKERTARGET_MODULE):
                out, err, rc = run_cmd(
                    cli + ["-w", _WORKSPACE, "-m", _HACKERTARGET_MODULE,
                          "-o", f"SOURCE={query}", "-x"], timeout=90, cwd=cwd)
                findings.extend(_parse_host_results(self.name, out + "\n" + err))
            else:
                findings.append(Finding(
                    source=self.name, title="Module hackertarget indisponible",
                    url="https://hackertarget.com/", kind=FindingKind.LINK,
                    confidence=Confidence.LOW,
                    note="Telechargement du module echoue (reseau ?)"))
            return findings

        findings = []
        for label, module in _LINK_MODULES.get(input_type, []):
            cmd = f'recon-cli -w {_WORKSPACE} -m {module} -o SOURCE="{query}" -x'
            findings.append(Finding(
                source=self.name, title=f"Module: {label}",
                url="https://github.com/lanmaster53/recon-ng",
                kind=FindingKind.LINK, confidence=Confidence.LOW, note=cmd))
        return findings
