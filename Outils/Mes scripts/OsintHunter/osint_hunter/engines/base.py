"""Engine base class and helpers."""

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

from ..models import InputType

console = Console()

# Set OSINT_DEBUG=1 to surface otherwise-swallowed exceptions.
_DEBUG = os.environ.get("OSINT_DEBUG", "").lower() in ("1", "true", "yes")


def debug_log(where: str, exc: Exception) -> None:
    """Report a swallowed exception when OSINT_DEBUG is set (silent otherwise)."""
    if _DEBUG:
        console.print(f"    [dim red]debug[{where}]: {type(exc).__name__}: {exc}[/dim red]")


class Engine(ABC):
    name: str = ""
    desc: str = ""
    modes: list = []

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]: ...


def run_cmd(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    console.print(f"    [dim]{' '.join(cmd)}[/dim]")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout or "", p.stderr or "", p.returncode
    except FileNotFoundError:
        return "", "FileNotFoundError", 1
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1


def has_module(mod: str) -> bool:
    """True if a Python module/package is importable (fast, no subprocess)."""
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        # find_spec raises if a parent package is missing -> treat as absent.
        return False


def has_binary(name: str) -> bool:
    return shutil.which(name) is not None


def parse_urls(text: str, username: str = "") -> list[dict]:
    results = []
    seen: set[str] = set()
    for m in re.finditer(r"\[\+\]\s*(.+?)[\s:\-\u2013\u2014]+\s*(https?://\S+)", text, re.I):
        u = m.group(2).rstrip(",;:)\"'")
        if u not in seen:
            seen.add(u)
            results.append({"site": m.group(1).strip(), "url": u})
    if not results and username:
        for m in re.finditer(r"(https?://\S+)", text):
            u = m.group(1).rstrip(",;:)\"'")
            if username.lower() in u.lower() and u not in seen:
                seen.add(u)
                try:
                    site = url_to_site_name(u, username)
                except Exception:
                    site = u.split("/")[2] if "/" in u else u
                results.append({"site": site, "url": u})
    return results


def tmpdir(prefix: str) -> Path:
    """Create a temp directory, cross-platform."""
    import tempfile
    d = Path(tempfile.gettempdir()) / f"oh_{prefix}_{int(time.time())}"
    d.mkdir(parents=True, exist_ok=True)
    return d


# Known domain -> friendly name mapping
_DOMAIN_NAMES: dict[str, str] = {
    "t.me": "Telegram", "last.fm": "Last.fm", "chess.com": "Chess.com",
    "dev.to": "DevTo", "itch.io": "Itch.io", "x.com": "Twitter/X",
    "vk.com": "VK", "ok.ru": "Odnoklassniki", "500px.com": "500px",
    "bio.site": "Bio.site", "solo.to": "Solo.to", "bsky.app": "Bluesky",
    "news.ycombinator.com": "HackerNews", "account.venmo.com": "Venmo",
    "api.mojang.com": "Minecraft", "data.typeracer.com": "TypeRacer",
    "open.spotify.com": "Spotify", "steamcommunity.com": "Steam",
    "hub.docker.com": "DockerHub", "beta.cent.co": "Cent",
    "web.archive.org": "Archive.org", "web.zepeto.me": "Zepeto",
    "connect.garmin.com": "Garmin", "profiles.wordpress.org": "WordPress",
    "wordpress.org": "WordPress", "discussions.apple.com": "Apple Discussions",
    "forum.ionicframework.com": "Ionic Forum", "forum.igromania.ru": "Igromania",
    "addons.wago.io": "Wago.io",
}


def url_to_site_name(url: str, username: str = "") -> str:
    """Extract a clean, human-readable site name from a URL."""
    parsed = urlparse(url)
    netloc = parsed.netloc.lower().replace("www.", "")

    # Check known domain mapping first
    if netloc in _DOMAIN_NAMES:
        return _DOMAIN_NAMES[netloc]
    # Check with subdomain
    for domain, name in _DOMAIN_NAMES.items():
        if netloc == domain or netloc.endswith("." + domain):
            return name

    # If subdomain equals the username, use the root domain instead
    parts = netloc.split(".")
    uname_l = username.lower() if username else ""
    if len(parts) >= 2 and parts[0] == uname_l:
        # e.g. "trost.tumblr.com" -> "Tumblr"
        return parts[1].capitalize()

    # For subdomains like "api.example.com" or "account.example.com"
    # use the main domain, not the subdomain
    if len(parts) >= 3:
        return parts[-2].capitalize()

    # Standard: use the domain without TLD
    if len(parts) >= 2:
        return parts[0].capitalize()

    return netloc.capitalize()
