"""Username variant generation (leet, case, separators, common suffixes)."""

from __future__ import annotations

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


def generate_variants(username: str) -> list[str]:
    u = username.strip()
    out: list[str] = []

    def add(v: str):
        if v and v not in out and v != u:
            out.append(v)

    add(u.lower())
    add(u.upper())
    add(u.capitalize())
    add(u.translate(_LEET))
    add("_" + u)
    add(u + "_")
    add(u.replace(" ", "_"))
    add(u.replace(" ", "."))
    add(u.replace(" ", ""))
    for suffix in ("1", "01", "official", "real", "_", "x"):
        add(u + suffix)
    if u and u[0].isalpha():
        add(u[0] + u[1:].translate(_LEET))
    return out[:20]
