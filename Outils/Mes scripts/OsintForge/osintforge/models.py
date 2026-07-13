"""Core data models for OsintForge.

The central design idea (and the fix for the old OsintHunter) is the typed
`Finding`. Every engine returns `Finding` objects tagged with a `FindingKind`,
and the pipeline treats each kind appropriately:

    PROFILE  -> a real profile page. Only these go through deep page-verify.
    ACCOUNT  -> "this email/phone is registered on X" (Holehe, socialscan email,
                GHunt). NOT a profile page, so it is never page-verified.
    BREACH   -> data-breach / leak hit.
    ARCHIVE  -> Wayback / archived copy of a page.
    DORK     -> a ready-to-click search query (GHDB, Google dork).
    LINK     -> an assisted external link/query (TinEye, Overpass, Jimpl...).
    INFO     -> a raw data point (a name, a Google ID, a carrier, GPS coords...).
    ERROR    -> an engine failure surfaced to the user.

This removes the old bug where breach entries and API endpoints were forced
through username-profile heuristics.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class InputType(Enum):
    USERNAME = "username"
    EMAIL = "email"
    NAME = "name"
    PHONE = "phone"
    DOMAIN = "domain"
    IMAGE = "image"


class FindingKind(Enum):
    PROFILE = "profile"
    ACCOUNT = "account"
    BREACH = "breach"
    ARCHIVE = "archive"
    DORK = "dork"
    LINK = "link"
    INFO = "info"
    ERROR = "error"


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


# Which kinds represent an actual account/presence worth "opening" or reviewing,
# vs. pure informational helpers.
ACCOUNTish = {FindingKind.PROFILE, FindingKind.ACCOUNT}


@dataclass
class Finding:
    """One result produced by an engine."""

    source: str                     # engine name, e.g. "Maigret"
    title: str                      # display label, e.g. "GitHub" or "Adobe (2019 breach)"
    kind: FindingKind = FindingKind.PROFILE
    url: str = ""
    confidence: Confidence = Confidence.LOW
    status: Status = Status.PENDING
    note: str = ""
    tags: list = field(default_factory=list)

    # Whether the engine already confirmed this hit itself (WhatsMyName,
    # DirectProbe, socialscan...). Pre-verified PROFILE findings skip deep verify.
    pre_verified: bool = False
    high_trust: bool = False        # page exists only if the account exists

    # Filled in by deep-verify (PROFILE kind only)
    http_status: Optional[int] = None
    final_url: str = ""
    redirect_count: int = 0
    query_in_body: Optional[bool] = None
    page_title: str = ""
    page_size: int = 0
    response_time_ms: Optional[int] = None
    avatar_url: str = ""
    bio: str = ""
    links: list = field(default_factory=list)

    # Free-form extra data (carrier, google_id, gps, breach date...)
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["confidence"] = self.confidence.value
        d["status"] = self.status.value
        return d


@dataclass
class Discarded:
    """A candidate profile eliminated by deep-verify."""

    title: str
    url: str
    source: str
    reason: str


@dataclass
class ScanRecord:
    """A saved scan row (history)."""

    scan_id: Optional[int] = None
    query: str = ""
    input_type: str = ""
    timestamp: str = ""
    total_found: int = 0
    total_discarded: int = 0
    engines_used: str = ""


# ---------------------------------------------------------------------------
# Categorisation + high-trust knowledge (shared by engines, verify, export)
# ---------------------------------------------------------------------------

CATEGORIES: dict[str, list[str]] = {
    "social": ["facebook", "twitter", "instagram", "tiktok", "snapchat",
               "linkedin", "mastodon", "threads", "x.com", "bsky", "vk", "reddit"],
    "dev": ["github", "gitlab", "bitbucket", "stackoverflow", "kaggle", "npm",
            "pypi", "dockerhub", "replit", "codepen", "hackerrank", "leetcode",
            "codewars", "dev.to", "hashnode", "huggingface"],
    "media": ["youtube", "twitch", "soundcloud", "spotify", "vimeo", "dailymotion",
              "mixcloud", "last.fm", "deezer"],
    "gaming": ["steam", "chess.com", "lichess", "roblox", "minecraft", "epicgames",
               "twitch", "xbox", "playstation", "riot"],
    "forum": ["forum", "discourse", "reddit", "quora", "disqus", "hackernews"],
    "photo": ["flickr", "500px", "deviantart", "behance", "artstation", "dribbble",
              "vsco", "pexels", "figma", "unsplash"],
    "commerce": ["ebay", "etsy", "vinted", "grailed", "fiverr", "patreon", "amazon"],
    "messaging": ["telegram", "t.me", "keybase", "skype", "discord", "signal"],
    "breach": ["breach", "leak", "pwned", "dehashed", "snusbase", "hibp"],
    "google": ["google", "gmail", "gaia", "epieos", "ghunt"],
    "geo": ["overpass", "osm", "openstreetmap", "maps", "gps"],
}

HT_SITES = {
    "instagram", "tiktok", "twitter", "x.com", "snapchat", "threads", "facebook",
    "linkedin", "mastodon.social", "bluesky", "bsky", "vk", "github", "gitlab",
    "bitbucket", "stackoverflow", "kaggle", "hackerrank", "leetcode", "codepen",
    "replit", "hackerone", "tryhackme", "hackthebox", "codewars", "codeforces",
    "dev.to", "hashnode", "npm", "pypi", "dockerhub", "huggingface", "youtube",
    "twitch", "soundcloud", "spotify", "vimeo", "mixcloud", "dailymotion",
    "last.fm", "steam", "steamcommunity", "chess.com", "lichess", "flickr",
    "deviantart", "dribbble", "behance", "artstation", "500px", "vsco", "figma",
    "reddit", "quora", "producthunt", "myanimelist", "letterboxd", "telegram",
    "t.me", "keybase", "discord", "ebay", "etsy", "vinted", "fiverr", "patreon",
    "linktree", "duolingo", "trello", "goodreads", "gravatar", "medium",
    "pinterest",
}


def categorize(name: str) -> list[str]:
    nl = (name or "").lower()
    return [c for c, kws in CATEGORIES.items() if any(k in nl for k in kws)] or ["other"]


def is_high_trust(name: str, url: str = "") -> bool:
    from urllib.parse import urlparse

    nl = (name or "").lower().strip()
    if nl in HT_SITES:
        return True
    if url:
        d = urlparse(url).netloc.lower().replace("www.", "")
        if d in HT_SITES:
            return True
        return any(p in HT_SITES for p in d.split("."))
    return False
