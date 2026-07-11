"""socialscan — 100% accuracy, queries registration servers."""

import re

from .base import Engine, run_cmd, has_binary
from ..models import InputType


class SocialscanEngine(Engine):
    name = "socialscan"
    desc = "100% accuracy, interroge serveurs inscription"
    modes = ["username", "email"]

    def is_available(self) -> bool:
        try:
            from socialscan.util import Platforms
            return True
        except Exception:
            return has_binary("socialscan")

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        try:
            from socialscan.util import Platforms, sync_execute_queries
            raw = sync_execute_queries([query], list(Platforms))
            results = []
            url_map = {
                "Instagram": f"https://instagram.com/{query}",
                "Twitter": f"https://x.com/{query}",
                "GitHub": f"https://github.com/{query}",
                "Tumblr": f"https://{query}.tumblr.com",
                "LastFM": f"https://last.fm/user/{query}",
                "Snapchat": f"https://snapchat.com/add/{query}",
                "GitLab": f"https://gitlab.com/{query}",
                "Reddit": f"https://reddit.com/user/{query}",
                "Yahoo": f"https://yahoo.com",
                "Pinterest": f"https://pinterest.com/{query}",
                "Spotify": f"https://open.spotify.com/user/{query}",
            }
            for r in raw:
                if r.success and not r.available and r.valid:
                    pn = str(r.platform).split(".")[-1]
                    url = url_map.get(pn, f"https://{pn.lower()}.com/{query}")
                    results.append({"site": pn, "url": url})
            return results
        except ImportError:
            out, err, rc = run_cmd(["socialscan", query, "--verbose"])
            results = []
            for line in (out + "\n" + err).splitlines():
                if "taken" in line.lower() or "not available" in line.lower():
                    m = re.match(r"\s*(\w+)", line)
                    if m:
                        results.append({
                            "site": m.group(1),
                            "url": f"https://{m.group(1).lower()}.com/{query}",
                        })
            return results
