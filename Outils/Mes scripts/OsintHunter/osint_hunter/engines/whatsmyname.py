"""WhatsMyName — 600+ sites with real profile links."""

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .base import Engine, console
from ..models import InputType
from ..session import random_ua


class WhatsMyNameEngine(Engine):
    name = "WhatsMyName"
    desc = "600+ sites, vrais liens profils"
    modes = ["username"]
    WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        workers = kwargs.get("workers", 40)
        timeout = kwargs.get("timeout", 8)

        try:
            console.print("    [dim]Telechargement base WMN...[/dim]")
            sites = requests.get(self.WMN_URL, timeout=15).json().get("sites", [])
        except Exception as e:
            console.print(f"    [red]{e}[/red]")
            return []

        console.print(f"    [dim]{len(sites)} sites charges[/dim]")
        results = []
        headers = {"User-Agent": random_ua()}

        def check(si):
            uri = si.get("uri_check", "")
            if not uri or "{account}" not in uri:
                return None
            url = uri.replace("{account}", query)
            es = si.get("e_string", "")
            ec = si.get("e_code", 200)
            ms_str = si.get("m_string", "")
            try:
                r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                if r.status_code != ec:
                    return None
                body = r.text[:30_000]
                if es and es not in body:
                    return None
                if ms_str and ms_str in body:
                    return None
                profile_url = si.get("uri_pretty", url).replace("{account}", query)
                return {"site": si.get("name", "?"), "url": profile_url}
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(check, s): s for s in sites}
            for f in as_completed(futs):
                r = f.result()
                if r:
                    results.append(r)
        return results
