"""theHarvester — emails/names via Google, Bing."""

import re
import sys
from urllib.parse import urlparse

from .base import Engine, run_cmd, has_module, has_binary
from ..models import InputType


class TheHarvesterEngine(Engine):
    name = "theHarvester"
    desc = "Emails/noms via Google,Bing"
    modes = ["name", "email"]

    def is_available(self) -> bool:
        return has_binary("theHarvester") or has_module("theHarvester")

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        cmd_base = (
            ["theHarvester"] if has_binary("theHarvester")
            else [sys.executable, "-m", "theHarvester"]
        )
        out, err, rc = run_cmd(cmd_base + ["-d", query, "-b", "google,bing", "-l", "200"])

        results = []
        combined = out + "\n" + err
        for m in re.finditer(r"[\w.+-]+@[\w-]+\.[\w.-]+", combined):
            results.append({
                "site": "[Email] " + m.group(),
                "url": f"mailto:{m.group()}",
            })
        for m in re.finditer(r"(https?://\S+)", combined):
            u = m.group(1).rstrip(",;:)\"'")
            results.append({
                "site": urlparse(u).netloc.split(".")[0].capitalize(),
                "url": u,
            })
        return results
