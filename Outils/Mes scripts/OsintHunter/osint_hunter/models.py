"""Data models for OSINT Hunter."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class InputType(Enum):
    USERNAME = "username"
    EMAIL = "email"
    NAME = "name"
    PHONE = "phone"


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


@dataclass
class SiteResult:
    site_name: str
    url: str
    source: str = ""
    http_status: Optional[int] = None
    final_url: str = ""
    redirect_count: int = 0
    username_in_body: Optional[bool] = None
    page_title: Optional[str] = None
    page_size: int = 0
    confidence: Confidence = Confidence.LOW
    status: Status = Status.PENDING
    note: str = ""
    response_time_ms: Optional[int] = None
    tags: list = field(default_factory=list)
    high_trust: bool = False
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    links: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["confidence"] = self.confidence.value
        d["status"] = self.status.value
        return d


@dataclass
class DiscardedResult:
    site_name: str
    url: str
    source: str
    reason: str


@dataclass
class ScanRecord:
    """Represents a saved scan in the database."""
    scan_id: Optional[int] = None
    query: str = ""
    input_type: str = ""
    timestamp: str = ""
    total_found: int = 0
    total_discarded: int = 0
    engines_used: str = ""


CATEGORIES = {
    "social": [
        "facebook", "twitter", "instagram", "tiktok", "snapchat",
        "linkedin", "mastodon", "threads", "x.com", "bsky", "vk",
    ],
    "dev": [
        "github", "gitlab", "bitbucket", "stackoverflow", "codepen",
        "replit", "npm", "pypi", "dockerhub", "kaggle", "huggingface",
        "hackerone", "tryhackme", "hackthebox", "codewars", "codeforces",
        "leetcode", "hackerrank", "dev.to", "hashnode",
    ],
    "media": [
        "youtube", "twitch", "vimeo", "dailymotion", "soundcloud",
        "spotify", "bandcamp", "mixcloud",
    ],
    "forum": [
        "reddit", "quora", "producthunt", "myanimelist", "letterboxd",
        "hackernews",
    ],
    "gaming": ["steam", "xbox", "playstation", "chess.com", "lichess", "roblox"],
    "commerce": ["ebay", "etsy", "vinted", "grailed", "redbubble", "fiverr", "amazon"],
    "blog": ["medium", "wordpress", "blogger", "substack", "tumblr", "ghost"],
    "messaging": ["telegram", "discord", "signal", "keybase", "slack"],
    "photo": [
        "flickr", "500px", "unsplash", "pinterest", "deviantart",
        "behance", "artstation", "dribbble", "vsco", "pexels", "figma",
    ],
    "breach": ["breach", "leak", "pwned", "dehashed", "snusbase"],
}

HT_SITES = {
    "instagram", "tiktok", "twitter", "x.com", "snapchat", "threads",
    "facebook", "linkedin", "mastodon.social", "bluesky", "bsky", "vk",
    "github", "gitlab", "bitbucket", "stackoverflow", "kaggle", "hackerrank",
    "leetcode", "codepen", "replit", "hackerone", "tryhackme", "hackthebox",
    "exercism", "codewars", "codeforces", "dev.to", "hashnode", "npm", "pypi",
    "dockerhub", "huggingface", "youtube", "twitch", "soundcloud", "spotify",
    "vimeo", "mixcloud", "dailymotion", "last.fm", "steam", "steamcommunity",
    "chess.com", "lichess", "flickr", "deviantart", "dribbble", "behance",
    "artstation", "500px", "vsco", "figma", "reddit", "quora", "hackernews",
    "producthunt", "myanimelist", "letterboxd", "telegram", "t.me", "keybase",
    "discord", "ebay", "etsy", "vinted", "grailed", "redbubble", "fiverr",
    "patreon", "linktree", "duolingo", "trello", "goodreads", "gravatar",
    "disqus", "opensea", "genius", "pexels", "medium", "pinterest",
}


def categorize(name: str) -> list[str]:
    nl = name.lower()
    return [c for c, kws in CATEGORIES.items() if any(k in nl for k in kws)] or ["other"]


def is_high_trust(name: str, url: str = "") -> bool:
    from urllib.parse import urlparse
    nl = name.lower().strip()
    if nl in HT_SITES:
        return True
    if url:
        d = urlparse(url).netloc.lower().replace("www.", "")
        return d in HT_SITES or any(p in HT_SITES for p in d.split("."))
    return False
