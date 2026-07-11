"""NExfil — 350+ sites, low FP."""

import sys

from .base import Engine, run_cmd, parse_urls, has_module, has_binary
from ..models import InputType


class NexfilEngine(Engine):
    name = "NExfil"
    desc = "350+ sites, peu de FP"
    modes = ["username"]

    def is_available(self) -> bool:
        return has_binary("nexfil") or has_module("nexfil")

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        cmd = ["nexfil"] if has_binary("nexfil") else [sys.executable, "-m", "nexfil"]
        out, err, rc = run_cmd(cmd + ["-u", query])
        return parse_urls(out + "\n" + err, query)
