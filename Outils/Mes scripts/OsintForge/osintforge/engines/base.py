"""Engine base class + shared helpers (subprocess, module/binary probing, URLs)."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from ..models import Finding, InputType

console = Console()

_DEBUG = os.environ.get("OSINT_DEBUG", "").lower() in ("1", "true", "yes")


def debug_log(where: str, exc: Exception) -> None:
    if _DEBUG:
        console.print(f"    [dim red]debug[{where}]: {type(exc).__name__}: {exc}[/dim red]")


# Availability states shown in the engine table.
LIVE = "live"          # runs automatically, no setup
NEEDS_SETUP = "setup"  # needs a binary / login / API key that is missing
ASSISTED = "assisted"  # can't run headless — produces links/queries to open


class Engine(ABC):
    name: str = ""
    desc: str = ""
    modes: list[str] = []          # InputType values this engine handles
    availability: str = LIVE       # default; override in is_available via status()

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        ...

    def status(self) -> str:
        """Human-facing availability tag used by the TUI."""
        try:
            return LIVE if self.is_available() else NEEDS_SETUP
        except Exception:
            return NEEDS_SETUP


def run_cmd(cmd: list[str], timeout: int = 300, echo: bool = True,
           cwd: str | None = None) -> tuple[str, str, int]:
    if echo:
        console.print(f"    [dim]{' '.join(str(c) for c in cmd)}[/dim]")
    # Force UTF-8 in the child process. Otherwise Python tools with progress bars
    # (e.g. Maigret via alive_progress/colorama) crash with UnicodeEncodeError
    # when writing non-ASCII to a legacy cp1252 Windows console, producing no
    # output at all (looked like "0 findings").
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace", cwd=cwd, env=env)
        return p.stdout or "", p.stderr or "", p.returncode
    except FileNotFoundError:
        return "", "FileNotFoundError", 127
    except subprocess.TimeoutExpired:
        return "", "Timeout", 124


def has_module(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


def has_binary(name: str) -> bool:
    return shutil.which(name) is not None


# Local tools directory: OsintForge/tools/ (sibling of the osintforge package).
# Populated by cloning frameworks that aren't on PyPI (recon-ng, spiderfoot) and
# by dropping prebuilt binaries (phoneinfoga) — see tools/README.md.
TOOLS_DIR = Path(__file__).resolve().parent.parent.parent / "tools"


def find_binary(name: str) -> str | None:
    """PATH first, then OsintForge/tools/bin/<name>[.exe]."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in (TOOLS_DIR / "bin" / name, TOOLS_DIR / "bin" / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return None


def find_script(subdir: str, script: str) -> list[str] | None:
    """A cloned Python-script tool (no PyPI package): OsintForge/tools/<subdir>/<script>.
    Returns an invocable [sys.executable, path] prefix, or None if not present.
    """
    import sys
    path = TOOLS_DIR / subdir / script
    return [sys.executable, str(path)] if path.is_file() else None


def tmpdir(prefix: str) -> Path:
    import tempfile
    d = Path(tempfile.gettempdir()) / f"forge_{prefix}_{int(time.time())}"
    d.mkdir(parents=True, exist_ok=True)
    return d


_DOMAIN_NAMES: dict[str, str] = {
    "t.me": "Telegram", "last.fm": "Last.fm", "chess.com": "Chess.com",
    "dev.to": "DevTo", "itch.io": "Itch.io", "x.com": "Twitter/X",
    "vk.com": "VK", "ok.ru": "Odnoklassniki", "500px.com": "500px",
    "bsky.app": "Bluesky", "news.ycombinator.com": "HackerNews",
    "open.spotify.com": "Spotify", "steamcommunity.com": "Steam",
    "hub.docker.com": "DockerHub", "web.archive.org": "Archive.org",
}


def url_to_site_name(url: str, query: str = "") -> str:
    """Human-readable site name from a URL."""
    netloc = urlparse(url).netloc.lower().replace("www.", "")
    if netloc in _DOMAIN_NAMES:
        return _DOMAIN_NAMES[netloc]
    for domain, name in _DOMAIN_NAMES.items():
        if netloc == domain or netloc.endswith("." + domain):
            return name
    parts = netloc.split(".")
    ql = query.lower() if query else ""
    if len(parts) >= 2 and parts[0] == ql:
        return parts[1].capitalize()
    if len(parts) >= 3:
        return parts[-2].capitalize()
    if len(parts) >= 2:
        return parts[0].capitalize()
    return netloc.capitalize() or url
