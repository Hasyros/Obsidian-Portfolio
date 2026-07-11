"""Scanner — orchestrates engine execution, verify, correlation, export, DB."""

import re
from urllib.parse import urlparse

from rich.console import Console
from rich.rule import Rule

from .cache import Cache
from .config import Config
from .correlation import correlate, CorrelationReport
from .database import Database
from .detection import detect_input, input_icon
from .engines import get_all_engines
from .engines.base import Engine
from .export import export_all
from .models import (
    InputType, SiteResult, DiscardedResult, Confidence, Status,
)
from .verify import verify_all

console = Console()


# URLs that are NOT actual profile pages — filter them out
_JUNK_URL_PATTERNS = re.compile(
    r"/api/v\d|/api/json|/search\?|/filter\?|/users\?|"
    r"^https?://discord\.com/?$|^https?://www\.discord\.com/?$",
    re.I,
)


def _normalize_url(url: str) -> str:
    """Normalize URL for dedup: strip www, trailing slash, force https."""
    url = url.strip().rstrip("/")
    url = re.sub(r"^http://", "https://", url)
    url = re.sub(r"://www\.", "://", url)
    return url.lower()


def _is_junk_url(url: str) -> bool:
    """Return True if the URL is a search/api/homepage, not a profile."""
    return bool(_JUNK_URL_PATTERNS.search(url))


def detect_engines(engines: list[Engine]) -> list[tuple[Engine, bool]]:
    res = []
    for e in engines:
        try:
            ok = e.is_available()
        except Exception:
            ok = False
        res.append((e, ok))
    return res


def engines_for_mode(input_type: InputType, engine_status: list[tuple[Engine, bool]]) -> list[Engine]:
    return [e for e, ok in engine_status if ok and input_type.value in e.modes]


def run_scan(
    query: str,
    input_type: InputType,
    engines: list[Engine],
    config: Config,
    cache: Cache,
) -> list[dict]:
    """Run all selected engines on the query. Returns raw results."""
    all_results = []
    seen: set[str] = set()

    for e in engines:
        console.print(f"\n  [bold cyan]> {e.name}[/bold cyan]")

        # Check cache
        cached = cache.get(e.name, query)
        if cached is not None:
            console.print(f"    [dim]Cache hit ({len(cached)} resultats)[/dim]")
            for r in cached:
                n = _normalize_url(r["url"])
                if n not in seen:
                    seen.add(n)
                    r["source"] = e.name
                    all_results.append(r)
            continue

        try:
            raw = e.scan(query, input_type, config=config)
            new = 0
            for r in raw:
                # Skip junk URLs (API endpoints, search pages, bare homepages)
                if not r["site"].startswith("[") and _is_junk_url(r["url"]):
                    continue
                n = _normalize_url(r["url"])
                if n not in seen:
                    seen.add(n)
                    r["source"] = e.name
                    all_results.append(r)
                    new += 1
            console.print(f"    [green]{len(raw)} trouves, {new} nouveaux[/green]")
            cache.set(e.name, query, raw)
        except Exception as ex:
            console.print(f"    [red]{ex}[/red]")

    return all_results


def do_scan(
    query: str,
    input_type: InputType,
    engines: list[Engine],
    config: Config,
    cache: Cache,
    db: Database,
    skip_verify: bool = False,
    skip_correlation: bool = False,
) -> tuple[list[SiteResult], list[DiscardedResult], CorrelationReport | None, int]:
    """Full scan pipeline: collect -> verify -> correlate -> save to DB.

    Returns (valid, discarded, correlation, scan_id).
    """
    console.print(Rule(f"[bold green] Scan '{query}' — {input_type.value} — {len(engines)} moteur(s) [/bold green]"))

    # 1. Collect
    raw = run_scan(query, input_type, engines, config, cache)
    if not raw:
        console.print("  [yellow]Aucun resultat.[/yellow]")
        return [], [], None, 0

    console.print(f"\n  [bold green]{len(raw)} URLs collectees[/bold green]")

    # Separate real URLs from meta results ([Breach], [Dork], [Email], etc.)
    real = [r for r in raw if r["url"].startswith("http") and not r["site"].startswith("[")]
    meta = [r for r in raw if r["site"].startswith("[")]

    # 2. Deep Verify
    valid: list[SiteResult] = []
    discarded: list[DiscardedResult] = []

    if real and not skip_verify:
        console.print(Rule("[bold cyan] DEEP VERIFY [/bold cyan]"))
        console.print(f"  [dim]{len(real)} URLs a verifier[/dim]\n")
        uname = query.split()[0] if " " in query else query
        valid, discarded = verify_all(
            uname, real,
            workers=config.deep_verify.workers,
            timeout=config.deep_verify.timeout,
            proxy=config.proxy,
        )
    elif real:
        # Skip verify — convert raw to SiteResult directly
        from .models import categorize, is_high_trust
        for r in real:
            ht = is_high_trust(r["site"], r["url"])
            valid.append(SiteResult(
                site_name=r["site"], url=r["url"], source=r.get("source", ""),
                confidence=Confidence.MEDIUM if ht else Confidence.LOW,
                tags=categorize(r["site"]), high_trust=ht,
            ))

    # Add meta results — Dorks get HIGH, others MEDIUM
    from .models import categorize
    for r in meta:
        conf = Confidence.HIGH if r["site"].startswith("[Dork]") else Confidence.MEDIUM
        valid.append(SiteResult(
            site_name=r["site"], url=r["url"], source=r.get("source", ""),
            confidence=conf, tags=categorize(r["site"]), note="Info",
        ))

    # 3. Correlation
    correlation = None
    if valid and not skip_correlation:
        console.print(Rule("[bold magenta] CORRELATION [/bold magenta]"))
        correlation = correlate(
            valid,
            check_avatars=config.correlation.avatar_comparison,
            check_bios=config.correlation.bio_similarity,
            check_links=config.correlation.link_extraction,
            similarity_threshold=config.correlation.similarity_threshold,
            proxy=config.proxy,
        )
        if correlation.links:
            console.print(f"  [magenta]{len(correlation.links)} liens trouves entre comptes[/magenta]")
        if correlation.emails_found:
            console.print(f"  [magenta]{len(correlation.emails_found)} emails detectes[/magenta]")
        if correlation.avatar_clusters:
            console.print(f"  [magenta]{len(correlation.avatar_clusters)} cluster(s) d'avatar similaires[/magenta]")

    # 4. Save to DB
    engine_names = [e.name for e in engines]
    scan_id = db.save_scan(query, input_type.value, valid, discarded, engine_names)
    console.print(f"\n  [dim]Scan #{scan_id} sauvegarde en base[/dim]")

    return valid, discarded, correlation, scan_id
