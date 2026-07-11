"""GitHub API — repos, emails from commits, activity."""

import os

import requests

from .base import Engine
from ..models import InputType


class GitHubApiEngine(Engine):
    name = "GitHubAPI"
    desc = "Repos, emails dans commits, activite"
    modes = ["username"]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        cfg = kwargs.get("config")
        token = ""
        if cfg:
            token = cfg.api_keys.github
        if not token:
            token = os.environ.get("OSINT_GITHUB_TOKEN", "")

        headers = {"User-Agent": "OSINT-Hunter/5.0", "Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        results = []

        # User profile
        try:
            r = requests.get(f"https://api.github.com/users/{query}", headers=headers, timeout=10)
            if r.status_code == 200:
                u = r.json()
                results.append({
                    "site": "GitHub",
                    "url": u.get("html_url", f"https://github.com/{query}"),
                })
                if u.get("blog"):
                    results.append({"site": "[GitHub] Blog/Site", "url": u["blog"]})
                if u.get("twitter_username"):
                    results.append({
                        "site": "[GitHub] Twitter",
                        "url": f"https://x.com/{u['twitter_username']}",
                    })
                if u.get("email"):
                    results.append({
                        "site": f"[GitHub] Email: {u['email']}",
                        "url": f"mailto:{u['email']}",
                    })
                bio = u.get("bio", "")
                company = u.get("company", "")
                location = u.get("location", "")
                info_parts = []
                if bio:
                    info_parts.append(f"Bio: {bio}")
                if company:
                    info_parts.append(f"Company: {company}")
                if location:
                    info_parts.append(f"Location: {location}")
                if info_parts:
                    results.append({
                        "site": f"[GitHub] {' | '.join(info_parts)[:80]}",
                        "url": f"https://github.com/{query}",
                    })
        except Exception:
            pass

        # Emails from recent commit events
        try:
            r = requests.get(
                f"https://api.github.com/users/{query}/events/public",
                headers=headers, timeout=10, params={"per_page": 30},
            )
            if r.status_code == 200:
                emails_found: set[str] = set()
                for event in r.json():
                    if event.get("type") == "PushEvent":
                        for commit in event.get("payload", {}).get("commits", []):
                            email = commit.get("author", {}).get("email", "")
                            if email and "noreply" not in email and email not in emails_found:
                                emails_found.add(email)
                for email in list(emails_found)[:5]:
                    results.append({
                        "site": f"[GitHub] Commit email: {email}",
                        "url": f"mailto:{email}",
                    })
        except Exception:
            pass

        return results
