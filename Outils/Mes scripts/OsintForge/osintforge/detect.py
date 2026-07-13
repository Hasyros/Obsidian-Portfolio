"""Auto-detection of the input type from a raw query string."""

from __future__ import annotations

import re
from pathlib import Path

from .models import InputType

_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")
_PHONE_RE = re.compile(r"^\+?\d[\d\s\-().]{6,18}\d$")
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$", re.I)
_IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".bmp", ".heic"}
# File extensions that must NOT be mistaken for a domain TLD.
_FILE_EXT = _IMAGE_EXT | {".pdf", ".doc", ".docx", ".txt", ".csv", ".xlsx",
                          ".zip", ".exe", ".mp4", ".mp3", ".json", ".html"}


def detect_input(query: str) -> InputType:
    q = query.strip()

    # Image: any path/URL ending in an image extension (existence not required —
    # the image engines handle a missing file with a Jimpl upload link).
    if Path(q).suffix.lower() in _IMAGE_EXT:
        return InputType.IMAGE

    if _EMAIL_RE.match(q):
        return InputType.EMAIL

    digits = re.sub(r"[\s\-().+]", "", q)
    if _PHONE_RE.match(q) and 7 <= len(digits) <= 15:
        return InputType.PHONE

    # Domain: contains a dot, no space/@, valid label chars, TLD >= 2, and not a
    # known file extension (so "notes.txt" or "photo.png" is never a domain).
    if (" " not in q and "@" not in q and "/" not in q and _DOMAIN_RE.match(q)
            and Path(q).suffix.lower() not in _FILE_EXT):
        tld = q.rsplit(".", 1)[-1]
        if tld.isalpha() and len(tld) >= 2:
            return InputType.DOMAIN

    if " " in q and len(q.split()) >= 2:
        return InputType.NAME

    return InputType.USERNAME


def input_icon(it: InputType) -> str:
    return {
        InputType.USERNAME: "\U0001f464",   # bust
        InputType.EMAIL: "\U0001f4e7",       # envelope
        InputType.NAME: "\U0001f524",        # abc
        InputType.PHONE: "\U0001f4de",       # phone
        InputType.DOMAIN: "\U0001f310",      # globe
        InputType.IMAGE: "\U0001f5bc",       # framed picture
    }[it]
