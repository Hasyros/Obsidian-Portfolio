"""DirectProbe — built-in prober for a curated set of high-signal sites.

No external tool needed. Each site has an explicit check: expected status code
plus an optional "not-found" marker string. Hits are self-verified, so they are
emitted as pre_verified PROFILE findings.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .base import Engine
from ..http import random_ua
from ..models import Finding, FindingKind, Confidence, InputType, categorize, is_high_trust

# High-PRECISION set only: sites that return a real non-200 (or a reliable marker
# string) for a missing user. Sites that soft-return 200 for ANY handle are left
# out on purpose — WhatsMyName covers breadth with curated per-site signatures, so
# DirectProbe stays a low-false-positive complement.
# name, CHECK url ({u}), success code, ("not found" markers -> any = miss), DISPLAY url
_SITES: list[tuple[str, str, int, tuple[str, ...], str]] = [
    ("GitHub", "https://api.github.com/users/{u}", 200, (), "https://github.com/{u}"),
    ("GitLab", "https://gitlab.com/{u}", 200, (), "https://gitlab.com/{u}"),
    ("Reddit", "https://www.reddit.com/user/{u}/about.json", 200, ('"is_suspended": true',), "https://www.reddit.com/user/{u}"),
    ("Chess.com", "https://www.chess.com/member/{u}", 200, ("we couldn't find",), "https://www.chess.com/member/{u}"),
    ("Steam", "https://steamcommunity.com/id/{u}", 200, ("The specified profile could not be found",), "https://steamcommunity.com/id/{u}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}", 200, ("No such user.",), "https://news.ycombinator.com/user?id={u}"),
    ("Keybase", "https://keybase.io/{u}", 200, (), "https://keybase.io/{u}"),
    ("Gravatar", "https://gravatar.com/{u}.json", 200, (), "https://gravatar.com/{u}"),
    ("Replit", "https://replit.com/@{u}", 200, ("404", "not found"), "https://replit.com/@{u}"),
    ("Vimeo", "https://vimeo.com/{u}", 200, ("Page not found",), "https://vimeo.com/{u}"),
    ("Wattpad", "https://www.wattpad.com/user/{u}", 200, (), "https://www.wattpad.com/user/{u}"),
    ("Docker Hub", "https://hub.docker.com/v2/users/{u}/", 200, (), "https://hub.docker.com/u/{u}"),
]


class DirectProbeEngine(Engine):
    name = "DirectProbe"
    desc = "Sondes integrees (sites a fort signal)"
    modes = ["username"]

    def is_available(self) -> bool:
        return True

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        timeout = kwargs.get("timeout", 8)
        headers = {"User-Agent": random_ua()}

        def check(entry):
            name, check_tpl, code, misses, display_tpl = entry
            url = check_tpl.replace("{u}", query)
            try:
                r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                if r.status_code != code:
                    return None
                body = r.text[:40_000]
                if any(mk.lower() in body.lower() for mk in misses):
                    return None
            except Exception:
                return None
            display = display_tpl.replace("{u}", query)
            return Finding(
                source="DirectProbe", title=name, url=display,
                kind=FindingKind.PROFILE, pre_verified=True,
                confidence=Confidence.HIGH, http_status=r.status_code,
                tags=categorize(name), high_trust=is_high_trust(name, display),
                query_in_body=None,
            )

        findings: list[Finding] = []
        with ThreadPoolExecutor(max_workers=kwargs.get("workers", 20)) as pool:
            futs = [pool.submit(check, e) for e in _SITES]
            for f in as_completed(futs):
                r = f.result()
                if r:
                    findings.append(r)
        return findings
