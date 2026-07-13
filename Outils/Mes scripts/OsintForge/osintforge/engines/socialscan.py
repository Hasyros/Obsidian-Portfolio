"""socialscan — queries registration servers (works for username AND email).

- username mode -> the handle is taken -> PROFILE (pre_verified) with a real URL.
- email mode    -> the email is registered -> ACCOUNT (no fake profile URL).
"""

from __future__ import annotations

from .base import Engine, has_module
from ..models import Finding, FindingKind, Confidence, InputType, categorize, is_high_trust

_PROFILE_URL = {
    "Instagram": "https://instagram.com/{q}",
    "Twitter": "https://x.com/{q}",
    "GitHub": "https://github.com/{q}",
    "Tumblr": "https://{q}.tumblr.com",
    "GitLab": "https://gitlab.com/{q}",
    "Reddit": "https://reddit.com/user/{q}",
    "Pinterest": "https://pinterest.com/{q}",
    "Spotify": "https://open.spotify.com/user/{q}",
}
_HOME = {
    "Instagram": "https://instagram.com", "Twitter": "https://x.com",
    "GitHub": "https://github.com", "Tumblr": "https://tumblr.com",
    "GitLab": "https://gitlab.com", "Reddit": "https://reddit.com",
    "Pinterest": "https://pinterest.com", "Spotify": "https://spotify.com",
    "Snapchat": "https://snapchat.com", "Yahoo": "https://yahoo.com",
    "Lastfm": "https://last.fm",
}


class SocialscanEngine(Engine):
    name = "socialscan"
    desc = "Serveurs d'inscription (username + email)"
    modes = ["username", "email"]

    def is_available(self) -> bool:
        return has_module("socialscan")

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        try:
            from socialscan.util import Platforms, sync_execute_queries
        except Exception:
            return []
        try:
            raw = sync_execute_queries([query], list(Platforms))
        except Exception:
            return []

        findings: list[Finding] = []
        for r in raw:
            if not (getattr(r, "success", False) and not r.available and r.valid):
                continue
            pn = str(r.platform).split(".")[-1]
            if input_type == InputType.EMAIL:
                findings.append(Finding(
                    source=self.name, title=f"{pn} (email enregistre)",
                    url=_HOME.get(pn, f"https://{pn.lower()}.com"),
                    kind=FindingKind.ACCOUNT, confidence=Confidence.MEDIUM,
                    note="Email deja utilise sur cette plateforme",
                    tags=categorize(pn), high_trust=is_high_trust(pn),
                ))
            else:
                url = _PROFILE_URL.get(pn, f"https://{pn.lower()}.com/{query}").replace("{q}", query)
                findings.append(Finding(
                    source=self.name, title=pn, url=url,
                    kind=FindingKind.PROFILE, pre_verified=True,
                    confidence=Confidence.HIGH, note="Handle pris",
                    tags=categorize(pn), high_trust=is_high_trust(pn, url),
                ))
        return findings
