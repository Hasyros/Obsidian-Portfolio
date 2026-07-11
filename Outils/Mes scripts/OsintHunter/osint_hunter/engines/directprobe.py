"""DirectProbe — built-in 90+ site checker."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from .base import Engine
from ..models import InputType
from ..session import random_ua


class DirectProbeEngine(Engine):
    name = "DirectProbe"
    desc = "90+ sites integres"
    modes = ["username"]

    SITES = {
        "Twitter/X": ("https://x.com/{u}", ["doesn't exist", "This account"]),
        "Instagram": ("https://www.instagram.com/{u}/", ["Sorry, this page"]),
        "TikTok": ("https://www.tiktok.com/@{u}", ["Couldn't find"]),
        "GitHub": ("https://github.com/{u}", ["Not Found"]),
        "GitLab": ("https://gitlab.com/{u}", ["Sign in", "404"]),
        "YouTube": ("https://www.youtube.com/@{u}", ["isn't available"]),
        "Twitch": ("https://www.twitch.tv/{u}", ["is unavailable"]),
        "Reddit": ("https://www.reddit.com/user/{u}", ["nobody on Reddit", "page not found"]),
        "Steam": ("https://steamcommunity.com/id/{u}", ["could not be found"]),
        "Pinterest": ("https://www.pinterest.com/{u}/", ["Sorry"]),
        "Medium": ("https://medium.com/@{u}", ["PAGE NOT FOUND"]),
        "Spotify": ("https://open.spotify.com/user/{u}", ["not found"]),
        "SoundCloud": ("https://soundcloud.com/{u}", ["can't find"]),
        "DeviantArt": ("https://www.deviantart.com/{u}", ["not known"]),
        "Dribbble": ("https://dribbble.com/{u}", ["not found"]),
        "Behance": ("https://www.behance.net/{u}", ["Oops"]),
        "Flickr": ("https://www.flickr.com/people/{u}/", ["could not find"]),
        "Vimeo": ("https://vimeo.com/{u}", ["couldn't find"]),
        "Telegram": ("https://t.me/{u}", ["If you have"]),
        "Keybase": ("https://keybase.io/{u}", ["Not found"]),
        "StackOverflow": ("https://stackoverflow.com/users/{u}", ["not found"]),
        "npm": ("https://www.npmjs.com/~{u}", ["404"]),
        "PyPI": ("https://pypi.org/user/{u}/", ["Not Found"]),
        "Kaggle": ("https://www.kaggle.com/{u}", ["404"]),
        "HackerRank": ("https://www.hackerrank.com/{u}", ["went wrong"]),
        "LeetCode": ("https://leetcode.com/{u}/", ["doesn't exist"]),
        "HackerOne": ("https://hackerone.com/{u}", ["not found"]),
        "Huggingface": ("https://huggingface.co/{u}", ["doesn't exist"]),
        "eBay": ("https://www.ebay.com/usr/{u}", ["User ID"]),
        "Etsy": ("https://www.etsy.com/shop/{u}", ["unavailable"]),
        "Patreon": ("https://www.patreon.com/{u}", ["become a patron"]),
        "Linktree": ("https://linktr.ee/{u}", ["went wrong"]),
        "Fiverr": ("https://www.fiverr.com/{u}", ["no longer"]),
        "Quora": ("https://www.quora.com/profile/{u}", ["Not Found"]),
        "Tryhackme": ("https://tryhackme.com/p/{u}", ["not found"]),
        "Chess.com": ("https://www.chess.com/member/{u}", ["not a valid"]),
        "Lichess": ("https://lichess.org/@/{u}", ["not found"]),
        "Last.fm": ("https://www.last.fm/user/{u}", ["not found"]),
        "Snapchat": ("https://www.snapchat.com/add/{u}", ["not found"]),
        "DockerHub": ("https://hub.docker.com/u/{u}", ["HttpError"]),
        "Codewars": ("https://www.codewars.com/users/{u}", ["not found"]),
        "Figma": ("https://www.figma.com/@{u}", ["doesn't exist"]),
        "VK": ("https://vk.com/{u}", ["This community"]),
        "Letterboxd": ("https://letterboxd.com/{u}/", ["Error"]),
        "OpenSea": ("https://opensea.io/{u}", ["page is lost"]),
        "Rumble": ("https://rumble.com/{u}", ["404"]),
        "Disqus": ("https://disqus.com/by/{u}/", ["404"]),
        "VSCO": ("https://vsco.co/{u}/gallery", ["not found"]),
        "Gravatar": ("https://en.gravatar.com/{u}.json", []),
        "Tumblr": ("https://{u}.tumblr.com", ["nothing here"]),
        "WordPress": ("https://{u}.wordpress.com", ["doesn't exist"]),
        "Substack": ("https://{u}.substack.com", ["Ready for more"]),
        "Bluesky": ("https://bsky.app/profile/{u}.bsky.social", ["not found"]),
        "Mastodon": ("https://mastodon.social/@{u}", ["not found"]),
        "Threads": ("https://www.threads.net/@{u}", ["not found"]),
        "Roblox": ("https://www.roblox.com/user.aspx?username={u}", ["not found"]),
        "Exercism": ("https://exercism.org/profiles/{u}", ["not found"]),
        "Hashnode": ("https://hashnode.com/@{u}", ["not found"]),
        "DevTo": ("https://dev.to/{u}", ["not found"]),
        "BandCamp": ("https://{u}.bandcamp.com", ["not found"]),
        "ArtStation": ("https://www.artstation.com/{u}", ["not found"]),
        "500px": ("https://500px.com/p/{u}", ["not found"]),
        "Unsplash": ("https://unsplash.com/@{u}", ["not found"]),
        "Pexels": ("https://www.pexels.com/@{u}", ["not found"]),
        "Genius": ("https://genius.com/{u}", ["not found"]),
        "Goodreads": ("https://www.goodreads.com/{u}", ["not found"]),
        "MyAnimeList": ("https://myanimelist.net/profile/{u}", ["not found"]),
        "Codeforces": ("https://codeforces.com/profile/{u}", ["not found"]),
        "Replit": ("https://replit.com/@{u}", ["not found"]),
        "CodePen": ("https://codepen.io/{u}", ["not found"]),
        "ProductHunt": ("https://www.producthunt.com/@{u}", ["not found"]),
        "Duolingo": ("https://www.duolingo.com/profile/{u}", ["not found"]),
        "Trello": ("https://trello.com/{u}", ["not found"]),
    }

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        workers = kwargs.get("workers", 50)
        timeout = kwargs.get("timeout", 8)
        headers = {"User-Agent": random_ua()}
        results = []

        def check(name, template, anti_strings):
            url = template.replace("{u}", query)
            try:
                r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                if r.status_code == 404:
                    return None
                if r.status_code in (301, 302) and urlparse(r.url).path.strip("/") == "":
                    return None
                body = r.text[:20_000]
                for indicator in anti_strings:
                    if indicator.lower() in body.lower():
                        return None
                if r.status_code == 200:
                    return {"site": name, "url": url}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {
                pool.submit(check, n, t, a): n
                for n, (t, a) in self.SITES.items()
            }
            for f in as_completed(futs):
                r = f.result()
                if r:
                    results.append(r)
        return results
