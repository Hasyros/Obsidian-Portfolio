"""Maigret — 3000+ sites."""

import json
import subprocess
import sys
from pathlib import Path

from .base import Engine, run_cmd, parse_urls, tmpdir, console
from ..models import InputType


class MaigretEngine(Engine):
    name = "Maigret"
    desc = "3000+ sites (si fonctionnel)"
    modes = ["username"]

    def is_available(self) -> bool:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "maigret", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            combined = (r.stdout or "") + (r.stderr or "")
            if "No module named" in combined or "ModuleNotFoundError" in combined:
                return False
            if "appengine" in combined.lower() or "ImportError" in combined:
                return False
            return r.returncode == 0
        except Exception:
            return False

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        od = tmpdir(f"maigret_{query}")
        out, err, rc = run_cmd([
            sys.executable, "-m", "maigret", query,
            "-J", "simple", "--folderoutput", str(od), "--no-color",
        ])
        if "appengine" in err.lower() or "ImportError" in err:
            console.print("    [bold red]Maigret casse (conflit urllib3/requests_toolbelt)[/bold red]")
            console.print("    [yellow]Fix: pip install --upgrade requests-toolbelt urllib3 cloudscraper[/yellow]")
            return []

        results = []
        for folder in [od, Path("results")]:
            if not folder.exists():
                continue
            for jf in sorted(
                folder.glob("*.json"),
                key=lambda p: p.stat().st_mtime if p.exists() else 0,
                reverse=True,
            ):
                try:
                    with open(jf) as fh:
                        data = json.load(fh)
                    if isinstance(data, dict):
                        inner = data.get(query, data)
                        for k, v in inner.items():
                            if isinstance(v, str) and v.startswith("http"):
                                results.append({"site": k, "url": v})
                            elif isinstance(v, dict):
                                u = v.get("url_user") or v.get("url", "")
                                if u:
                                    results.append({"site": k, "url": u})
                    if results:
                        return results
                except Exception:
                    continue
        return parse_urls(out + "\n" + err, query)
