"""Holehe — 120+ sites via password reset."""

import re
import sys

from .base import Engine, run_cmd, has_binary, has_module
from ..models import InputType


class HoleheEngine(Engine):
    name = "Holehe"
    desc = "120+ sites via password reset"
    modes = ["email"]

    def is_available(self) -> bool:
        return has_binary("holehe") or has_module("holehe")

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        if has_binary("holehe"):
            cmd = ["holehe", query, "--no-color"]
        else:
            cmd = [sys.executable, "-m", "holehe", query, "--no-color"]
        out, err, rc = run_cmd(cmd)
        results = []
        for m in re.finditer(r"\[\+\]\s*(\S+)", out + "\n" + err):
            s = m.group(1).rstrip(":")
            results.append({"site": s, "url": f"https://{s}"})
        return results
