"""Username variant generator — leet speak, case, separators, suffixes."""

import itertools
from dataclasses import dataclass


@dataclass
class VariantSet:
    original: str
    variants: list[str]
    labels: dict[str, str]   # variant -> description

    def all_queries(self) -> list[str]:
        return [self.original] + self.variants


# Leet speak mappings (forward and reverse)
_LEET_MAP = {
    "a": ["4", "@"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"],
    "l": ["1"],
    "b": ["8"],
    "g": ["9"],
}

_REVERSE_LEET = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i",
}

_COMMON_SUFFIXES = ["_", "1", "2", "12", "123", "69", "420", "007", "x", "xx"]
_COMMON_PREFIXES = ["x", "the", "real", "its", "im", "not", "mr", "ms", "dr", "0x"]
_SEPARATORS = ["_", ".", "-"]


def generate_variants(username: str, max_variants: int = 30) -> VariantSet:
    """Generate plausible username variants for multi-persona detection."""
    original = username.strip()
    variants: dict[str, str] = {}  # variant -> label

    def _add(v: str, label: str):
        v = v.strip()
        if v and v.lower() != original.lower() and v not in variants:
            variants[v] = label

    # === 1. Case variations ===
    _add(original.lower(), "minuscules")
    _add(original.upper(), "majuscules")
    _add(original.capitalize(), "capitalize")
    _add(original.swapcase(), "swapcase")

    # === 2. Leet speak (forward) ===
    lower = original.lower()
    for char, replacements in _LEET_MAP.items():
        if char in lower:
            for repl in replacements:
                leet_v = lower.replace(char, repl, 1)  # Replace first occurrence
                _add(leet_v, f"leet ({char}->{repl})")
                # Also try with original casing
                cased = original
                idx = cased.lower().find(char)
                if idx >= 0:
                    cased = cased[:idx] + repl + cased[idx + 1:]
                    _add(cased, f"leet ({char}->{repl})")

    # === 3. Reverse leet (if username contains digits) ===
    deleet = original
    for digit, letter in _REVERSE_LEET.items():
        if digit in deleet:
            deleet = deleet.replace(digit, letter)
    _add(deleet, "reverse leet")
    _add(deleet.capitalize(), "reverse leet + capitalize")

    # === 4. Common suffixes ===
    for suffix in _COMMON_SUFFIXES:
        _add(f"{original}{suffix}", f"suffixe '{suffix}'")
        _add(f"{original.lower()}{suffix}", f"suffixe '{suffix}' (lower)")

    # === 5. Common prefixes ===
    for prefix in _COMMON_PREFIXES:
        _add(f"{prefix}{original}", f"prefixe '{prefix}'")
        _add(f"{prefix}{original.lower()}", f"prefixe '{prefix}' (lower)")

    # === 6. Separator insertion (if username looks like compound word) ===
    # Try splitting at case boundaries: "JohnDoe" -> "John_Doe"
    import re
    parts = re.findall(r"[A-Z][a-z]+|[a-z]+|[A-Z]+|\d+", original)
    if len(parts) >= 2:
        for sep in _SEPARATORS:
            _add(sep.join(parts).lower(), f"split '{sep}'")
            _add(sep.join(parts), f"split '{sep}' (cased)")

    # === 7. Double letters / typos ===
    if len(original) >= 4:
        # Remove double letters
        deduped = re.sub(r"(.)\1", r"\1", original)
        _add(deduped, "sans doublon")
        # Add double last letter
        _add(original + original[-1], "lettre double")

    # === 8. Truncation ===
    if len(original) >= 5:
        _add(original[:4], "tronque 4")
        _add(original[:6], "tronque 6")

    # Limit results
    limited = dict(list(variants.items())[:max_variants])

    return VariantSet(
        original=original,
        variants=list(limited.keys()),
        labels=limited,
    )


def display_variants_menu(vs: VariantSet) -> list[str]:
    """Let the user pick which variants to scan. Returns selected queries."""
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt
    from rich import box

    console = Console()

    t = Table(
        title=f"[bold]Variantes de '{vs.original}'[/bold]",
        box=box.ROUNDED, border_style="magenta", padding=(0, 1),
    )
    t.add_column("#", width=4, justify="right", style="dim")
    t.add_column("Variante", style="bold cyan", width=25)
    t.add_column("Type", style="dim")

    t.add_row("0", vs.original, "[green]original[/green]")
    for i, v in enumerate(vs.variants, 1):
        t.add_row(str(i), v, vs.labels[v])

    console.print()
    console.print(t)
    console.print()
    console.print("  [bold]a[/bold]=toutes  [bold]0[/bold]=original seul  [bold]1,3,5[/bold]=selection  [bold]q[/bold]=annuler")

    choice = Prompt.ask("  Variantes a scanner", default="0")

    if choice.lower() == "q":
        return []
    if choice.lower() == "a":
        return vs.all_queries()
    if choice == "0":
        return [vs.original]

    selected = [vs.original]  # Always include original
    for s in choice.split(","):
        s = s.strip()
        if s.isdigit():
            idx = int(s)
            if 1 <= idx <= len(vs.variants):
                selected.append(vs.variants[idx - 1])
    return selected
