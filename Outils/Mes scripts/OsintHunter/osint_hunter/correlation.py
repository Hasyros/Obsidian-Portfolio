"""Cross-platform correlation — avatars, bios, links."""

import io
import re
from collections import defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Optional
from urllib.parse import urlparse

from .models import SiteResult
from .session import make_session

# Optional: perceptual hashing for avatar comparison
try:
    from PIL import Image
    import imagehash
    HAS_IMAGEHASH = True
except ImportError:
    HAS_IMAGEHASH = False


@dataclass
class CorrelationResult:
    """Represents a link between two accounts."""
    source: str        # site A
    target: str        # site B
    link_type: str     # "avatar", "bio", "link", "email"
    confidence: float  # 0..1
    detail: str = ""


@dataclass
class CorrelationReport:
    results: list[SiteResult]
    links: list[CorrelationResult] = field(default_factory=list)
    avatar_clusters: list[list[str]] = field(default_factory=list)
    shared_links: dict[str, list[str]] = field(default_factory=dict)
    emails_found: list[str] = field(default_factory=list)


LINK_RE = re.compile(
    r'(?:href|src|content)\s*=\s*["\']?(https?://(?!(?:fonts|cdn|static|assets|www\.w3)'
    r')[^\s"\'<>]{10,200})',
    re.I,
)

SOCIAL_LINK_RE = re.compile(
    r'https?://(?:www\.)?(twitter|x|instagram|github|linkedin|youtube|tiktok|'
    r'facebook|reddit|medium|twitch|t\.me|linktr\.ee|bsky\.app|mastodon)'
    r'[.\w]*[./][\w@./-]+',
    re.I,
)

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _fetch_avatar_hash(url: str, session, timeout: int = 8) -> Optional[str]:
    """Download image and compute perceptual hash."""
    if not HAS_IMAGEHASH or not url:
        return None
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code != 200 or len(r.content) < 500:
            return None
        img = Image.open(io.BytesIO(r.content)).convert("RGB").resize((64, 64))
        return str(imagehash.phash(img))
    except Exception:
        return None


def _bio_similarity(bio_a: str, bio_b: str) -> float:
    if not bio_a or not bio_b:
        return 0.0
    return SequenceMatcher(None, bio_a.lower(), bio_b.lower()).ratio()


def _extract_page_links(result: SiteResult, body: str = "") -> set[str]:
    """Extract social/profile links from page content or bio."""
    links: set[str] = set()
    text = (result.bio or "") + " " + body
    for m in SOCIAL_LINK_RE.finditer(text):
        link = m.group(0).rstrip(",;:)\"'")
        normalized = link.rstrip("/").lower()
        if result.url.rstrip("/").lower() != normalized:
            links.add(normalized)
    return links


def _extract_emails_from_results(results: list[SiteResult]) -> list[str]:
    emails: set[str] = set()
    for r in results:
        if r.bio:
            for m in EMAIL_RE.finditer(r.bio):
                email = m.group(0)
                if "noreply" not in email and "example" not in email:
                    emails.add(email.lower())
        if r.site_name.startswith("[") and "email" in r.site_name.lower():
            for m in EMAIL_RE.finditer(r.site_name + " " + r.url):
                email = m.group(0)
                if "noreply" not in email:
                    emails.add(email.lower())
    return sorted(emails)


def correlate(
    results: list[SiteResult],
    check_avatars: bool = True,
    check_bios: bool = True,
    check_links: bool = True,
    similarity_threshold: float = 0.75,
    proxy=None,
) -> CorrelationReport:
    """Analyze cross-platform correlations between found accounts."""
    report = CorrelationReport(results=results)

    # Filter to real profile results only, and deduplicate by URL
    # (avoids self-correlation for same site found by different engines)
    profiles = []
    seen_urls: set[str] = set()
    for r in results:
        if r.site_name.startswith("["):
            continue
        norm = r.url.rstrip("/").lower()
        if norm not in seen_urls:
            seen_urls.add(norm)
            profiles.append(r)

    # Build unique key for each profile (site_name can duplicate across engines)
    def _uid(r: SiteResult) -> str:
        return f"{r.site_name}||{r.url.rstrip('/').lower()}"

    # 1. Avatar clustering
    if check_avatars and HAS_IMAGEHASH:
        avatar_hashes: dict[str, str] = {}  # uid -> hash
        uid_to_name: dict[str, str] = {}
        session = make_session(proxy=proxy)
        for r in profiles:
            if r.avatar_url:
                uid = _uid(r)
                h = _fetch_avatar_hash(r.avatar_url, session)
                if h:
                    avatar_hashes[uid] = h
                    uid_to_name[uid] = r.site_name

        # Group by similar hashes (hamming distance <= 10)
        if avatar_hashes:
            uids = list(avatar_hashes.keys())
            clusters: list[set[str]] = []
            used: set[str] = set()
            for i, u1 in enumerate(uids):
                if u1 in used:
                    continue
                cluster = {u1}
                h1 = imagehash.hex_to_hash(avatar_hashes[u1])
                for u2 in uids[i + 1:]:
                    if u2 in used:
                        continue
                    # Skip if same base domain (not a real cross-platform link)
                    if uid_to_name[u1].lower() == uid_to_name[u2].lower():
                        continue
                    h2 = imagehash.hex_to_hash(avatar_hashes[u2])
                    if h1 - h2 <= 10:  # hamming distance
                        cluster.add(u2)
                        report.links.append(CorrelationResult(
                            source=uid_to_name[u1], target=uid_to_name[u2],
                            link_type="avatar",
                            confidence=1.0 - (h1 - h2) / 64.0,
                            detail=f"Hamming distance: {h1 - h2}",
                        ))
                if len(cluster) > 1:
                    used.update(cluster)
                    clusters.append(cluster)
            report.avatar_clusters = [
                sorted({uid_to_name[u] for u in c}) for c in clusters
            ]

    # 2. Bio similarity
    if check_bios:
        bios = [(r.site_name, r.bio, _uid(r)) for r in profiles if r.bio]
        for i, (s1, b1, uid1) in enumerate(bios):
            for s2, b2, uid2 in bios[i + 1:]:
                # Skip self (same site name = probably the same platform)
                if s1.lower() == s2.lower():
                    continue
                sim = _bio_similarity(b1, b2)
                if sim >= similarity_threshold:
                    report.links.append(CorrelationResult(
                        source=s1, target=s2, link_type="bio",
                        confidence=sim,
                        detail=f"Similarite: {sim:.0%}",
                    ))

    # 3. Shared links
    if check_links:
        site_links: dict[str, set[str]] = {}
        for r in profiles:
            # Links extracted from the page body during Deep Verify (r.links)
            # + any links found in the bio.
            self_url = r.url.rstrip("/").lower()
            page_links = {l for l in r.links if l != self_url}
            links = page_links | _extract_page_links(r)
            if links:
                site_links[r.site_name] = links

        # Find links that appear on multiple profiles
        link_to_sites: dict[str, list[str]] = defaultdict(list)
        for site, links in site_links.items():
            for link in links:
                link_to_sites[link].append(site)

        for link, sites in link_to_sites.items():
            if len(sites) >= 2:
                report.shared_links[link] = sites
                for i, s1 in enumerate(sites):
                    for s2 in sites[i + 1:]:
                        report.links.append(CorrelationResult(
                            source=s1, target=s2, link_type="link",
                            confidence=0.8,
                            detail=f"Lien partage: {link[:60]}",
                        ))

    # 4. Emails
    report.emails_found = _extract_emails_from_results(results)

    return report
