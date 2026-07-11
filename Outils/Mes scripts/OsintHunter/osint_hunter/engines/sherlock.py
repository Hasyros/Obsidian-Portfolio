"""Sherlock — 400+ sites, fast."""

import re
import sys
from urllib.parse import urlparse

from .base import Engine, run_cmd, parse_urls, has_module, has_binary, tmpdir, url_to_site_name
from ..models import InputType


class SherlockEngine(Engine):
    name = "Sherlock"
    desc = "400+ sites, rapide"
    modes = ["username"]

    def is_available(self) -> bool:
        if has_binary("sherlock"):
            return True
        return has_module("sherlock_project") or has_module("sherlock")

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        cmd = ["sherlock"] if has_binary("sherlock") else [sys.executable, "-m", "sherlock_project"]
        of = tmpdir("sherlock") / f"{query}.txt"
        out, err, rc = run_cmd(cmd + [query, "--output", str(of), "--print-found", "--no-color"])

        results = []
        seen: set[str] = set()

        # Sherlock stdout: "site_name: url" format
        for m in re.finditer(r"^\[\+\]\s*(.+?):\s*(https?://\S+)", out + "\n" + err, re.M):
            site_name = m.group(1).strip()
            url = m.group(2).rstrip(",;:)\"'")
            if url not in seen:
                seen.add(url)
                results.append({"site": site_name, "url": url})

        # Fallback: file output (URL-only, one per line)
        if of.exists():
            for line in open(of):
                line = line.strip()
                if line.startswith("http") and line not in seen:
                    seen.add(line)
                    results.append({
                        "site": url_to_site_name(line, query),
                        "url": line,
                    })

        # Final fallback: generic URL parser
        for r in parse_urls(out + "\n" + err, query):
            if r["url"] not in seen:
                seen.add(r["url"])
                results.append(r)
        return results
