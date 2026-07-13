"""Reverse image search — TinEye + Google Lens + Yandex.

For a public image URL we build ready-to-open reverse-search links (and query the
TinEye API if a key is configured). For a local file we explain the upload step,
since these engines need a URL or an uploaded file.
"""

from __future__ import annotations

import os

import requests

from .base import Engine, ASSISTED
from ..models import Finding, FindingKind, Confidence, InputType


class ReverseImageEngine(Engine):
    name = "TinEye/Lens"
    desc = "Recherche d'image inversee (TinEye, Lens, Yandex)"
    modes = ["image"]

    def is_available(self) -> bool:
        return True

    def status(self) -> str:
        return ASSISTED

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        is_url = query.startswith("http")

        if is_url:
            from urllib.parse import quote
            u = quote(query, safe="")
            findings += [
                Finding(source="TinEye", title="TinEye (recherche inversee)",
                        url=f"https://www.tineye.com/search?url={u}",
                        kind=FindingKind.LINK, confidence=Confidence.MEDIUM),
                Finding(source="Google Lens", title="Google Lens",
                        url=f"https://lens.google.com/uploadbyurl?url={u}",
                        kind=FindingKind.LINK, confidence=Confidence.MEDIUM),
                Finding(source="Yandex", title="Yandex Images",
                        url=f"https://yandex.com/images/search?rpt=imageview&url={u}",
                        kind=FindingKind.LINK, confidence=Confidence.MEDIUM),
            ]
            # TinEye API (optional key)
            cfg = kwargs.get("config")
            key = (getattr(cfg.api_keys, "tineye", "") if cfg else "") or os.environ.get("OSINT_TINEYE_KEY", "")
            if key:
                try:
                    r = requests.post("https://api.tineye.com/rest/search/",
                                      data={"image_url": query}, auth=(key, ""), timeout=20)
                    if r.status_code == 200:
                        n = r.json().get("results", {}).get("total_results", 0)
                        findings.append(Finding(
                            source="TinEye API", title=f"{n} correspondances TinEye",
                            url=f"https://www.tineye.com/search?url={u}",
                            kind=FindingKind.INFO, confidence=Confidence.HIGH))
                except Exception:
                    pass
        else:
            findings += [
                Finding(source="TinEye", title="TinEye — uploader la photo",
                        url="https://www.tineye.com/", kind=FindingKind.LINK,
                        confidence=Confidence.LOW,
                        note="TinEye/Lens ont besoin d'une URL publique ou d'un upload"),
                Finding(source="Google Lens", title="Google Lens — uploader la photo",
                        url="https://lens.google.com/", kind=FindingKind.LINK,
                        confidence=Confidence.LOW),
                Finding(source="Yandex", title="Yandex Images — uploader la photo",
                        url="https://yandex.com/images/", kind=FindingKind.LINK,
                        confidence=Confidence.LOW),
            ]
        return findings
