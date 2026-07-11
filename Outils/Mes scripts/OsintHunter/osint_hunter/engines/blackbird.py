"""Blackbird — 600+ sites, username+email."""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from .base import Engine, run_cmd, has_module, url_to_site_name, debug_log
from ..models import InputType

# Local blackbird directory (sibling of osint_hunter in the project)
_LOCAL_BLACKBIRD = Path(__file__).parent.parent.parent / "blackbird" / "blackbird.py"
_BLACKBIRD_DIR = _LOCAL_BLACKBIRD.parent


def _blackbird_available() -> bool:
    if _LOCAL_BLACKBIRD.exists():
        # Local Blackbird needs 'chardet' (install it once; we do NOT pip-install
        # at scan time). If missing, the engine is simply marked unavailable.
        return has_module("chardet")
    return has_module("blackbird")


# Wrapper that bypasses Blackbird's Rich banner + argparse,
# sets up config manually, runs the scan, outputs JSON to stdout.
_WRAPPER = '''\
import sys, os, io, json, logging
from datetime import datetime

bb_dir = {bb_dir!r}
os.chdir(bb_dir)
sys.path.insert(0, os.path.join(bb_dir, "src"))

# Silence logs
logging.basicConfig(level=logging.WARNING)

# Import config module (blackbird/src/config.py)
import config

# Set up all config attributes manually (same as initiate() but no argparse)
from rich.console import Console
config.console = Console(file=io.StringIO(), force_terminal=False, no_color=True)

config.username = {username!r}
config.email = {email!r}
config.username_file = None
config.email_file = None
config.permute = False
config.permuteall = False
config.csv = False
config.pdf = False
config.json = False
config.filter = None
config.no_nsfw = False
config.dump = False
config.proxy = None
config.verbose = False
config.ai = False
config.setup_ai = False
config.timeout = 30
config.max_concurrent_requests = 30
config.no_update = True
config.about = False
config.instagram_session_id = None
config.api_url = None
config.dateRaw = datetime.now().strftime("%m_%d_%Y")
config.datePretty = datetime.now().strftime("%B %d, %Y")
config.usernameFoundAccounts = None
config.emailFoundAccounts = None
config.currentUser = None
config.currentEmail = None

from modules.utils.userAgent import getRandomUserAgent
config.userAgent = getRandomUserAgent(config)

# Skip update check (--no-update)

if config.username:
    from modules.core.username import verifyUsername
    for user in config.username:
        config.currentUser = user
        verifyUsername(user, config)
        accounts = config.usernameFoundAccounts or []
        json.dump(accounts, sys.stdout, ensure_ascii=False)
        sys.stdout.flush()

elif config.email:
    from modules.core.email import verifyEmail
    for email in config.email:
        config.currentEmail = email
        verifyEmail(email, config)
        accounts = config.emailFoundAccounts or []
        json.dump(accounts, sys.stdout, ensure_ascii=False)
        sys.stdout.flush()
'''


class BlackbirdEngine(Engine):
    name = "Blackbird"
    desc = "600+ sites, username+email"
    modes = ["username", "email"]

    def is_available(self) -> bool:
        return _blackbird_available()

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        if _LOCAL_BLACKBIRD.exists():
            return self._scan_local(query, input_type)
        # Fallback: installed module
        flag = "--email" if input_type == InputType.EMAIL else "--username"
        cmd = [sys.executable, "-m", "blackbird", flag, query, "--no-color"]
        out, err, rc = run_cmd(cmd)
        return self._parse_text(out + "\n" + err, query)

    def _scan_local(self, query: str, input_type: InputType) -> list[dict]:
        """Run local Blackbird via wrapper that bypasses Rich console crash."""
        bb_dir = str(_BLACKBIRD_DIR).replace("\\", "/")

        if input_type == InputType.EMAIL:
            username, email = None, [query]
        else:
            username, email = [query], None

        script = _WRAPPER.format(bb_dir=bb_dir, username=username, email=email)

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8",
        )
        tmp.write(script)
        tmp.close()

        try:
            r = subprocess.run(
                [sys.executable, tmp.name],
                capture_output=True, text=True, timeout=300,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
            # Try JSON output first
            stdout = (r.stdout or "").strip()
            if stdout:
                try:
                    accounts = json.loads(stdout)
                    return self._parse_json(accounts, query)
                except json.JSONDecodeError:
                    pass
            # Fallback: parse text from stderr
            combined = (r.stdout or "") + "\n" + (r.stderr or "")
            return self._parse_text(combined, query)
        except Exception as e:
            debug_log("blackbird", e)
            return []
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def _parse_json(self, accounts: list, query: str) -> list[dict]:
        """Parse Blackbird JSON result format."""
        results = []
        seen: set[str] = set()
        for acc in accounts:
            url = acc.get("url", "")
            name = acc.get("name", "") or acc.get("site", "")
            if url and url.startswith("http") and url not in seen:
                seen.add(url)
                results.append({
                    "site": name or url_to_site_name(url, query),
                    "url": url,
                })
        return results

    def _parse_text(self, text: str, query: str) -> list[dict]:
        """Parse Blackbird stdout/stderr text for results."""
        results = []
        seen: set[str] = set()

        for m in re.finditer(r"\[\+\]\s*(?:(\S+?):\s*)?(https?://\S+)", text):
            site_name = m.group(1) or ""
            u = m.group(2).rstrip(",;:)\"'")
            if u not in seen:
                seen.add(u)
                results.append({
                    "site": site_name.strip() if site_name else url_to_site_name(u, query),
                    "url": u,
                })

        if not results:
            for m in re.finditer(r"(https?://\S+)", text):
                u = m.group(1).rstrip(",;:)\"'")
                context = text[max(0, m.start() - 30):m.start()]
                if u not in seen and "[-]" not in context:
                    seen.add(u)
                    results.append({
                        "site": url_to_site_name(u, query),
                        "url": u,
                    })
        return results
