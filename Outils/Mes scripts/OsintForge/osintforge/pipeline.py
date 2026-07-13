"""Scan orchestration: run engines -> verify candidate profiles -> merge -> store."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.rule import Rule

from .config import Config
from .engines.base import Engine
from .models import (
    Finding, Discarded, FindingKind, Confidence, InputType, is_high_trust,
)
from .store import Store
from .verify import verify_profiles

console = Console()


def engines_for(input_type: InputType, engine_status: list[tuple[Engine, bool]]) -> list[Engine]:
    return [e for e, ok in engine_status if ok and input_type.value in e.modes]


def detect_engines(engines: list[Engine]) -> list[tuple[Engine, bool]]:
    out = []
    for e in engines:
        try:
            ok = e.is_available()
        except Exception:
            ok = False
        out.append((e, ok))
    return out


def _norm_url(url: str) -> str:
    return url.strip().rstrip("/").lower().replace("http://", "https://").replace("://www.", "://")


def collect(query: str, input_type: InputType, engines: list[Engine], config: Config
            ) -> list[Finding]:
    """Run every engine (each in its own thread) and gather raw findings."""
    findings: list[Finding] = []

    def run_engine(e: Engine) -> list[Finding]:
        try:
            return e.run(query, input_type, config=config,
                         workers=config.verify.workers, timeout=config.verify.timeout)
        except Exception as ex:
            return [Finding(source=e.name, title=f"Erreur: {type(ex).__name__}",
                            kind=FindingKind.ERROR, confidence=Confidence.LOW, note=str(ex)[:200])]

    with ThreadPoolExecutor(max_workers=min(len(engines), 8) or 1) as pool:
        futs = {pool.submit(run_engine, e): e for e in engines}
        for f in as_completed(futs):
            e = futs[f]
            res = f.result()
            n = len(res)
            console.print(f"  [bold cyan]{e.name}[/bold cyan] [dim]->[/dim] "
                          f"[green]{n}[/green] finding(s)")
            findings.extend(res)
    return findings


def run_scan(query: str, input_type: InputType, engines: list[Engine], config: Config,
             store: Store | None = None
             ) -> tuple[list[Finding], list[Discarded], int]:
    """Full pipeline. Returns (findings, discarded, scan_id)."""
    console.print(Rule(f"[bold green] Scan '{query}' — {input_type.value} — "
                       f"{len(engines)} moteur(s) [/bold green]"))

    raw = collect(query, input_type, engines, config)
    if not raw:
        console.print("  [yellow]Aucun resultat.[/yellow]")
        return [], [], 0
    console.print(f"\n  [bold green]{len(raw)} findings collectes[/bold green]")

    # Split: candidate profiles needing verification vs everything else.
    candidates = [f for f in raw
                  if f.kind == FindingKind.PROFILE and not f.pre_verified and f.url.startswith("http")]
    passthrough = [f for f in raw if f not in candidates]

    valid: list[Finding] = []
    discarded: list[Discarded] = []

    if candidates and config.verify.enabled:
        console.print(Rule("[bold cyan] DEEP VERIFY [/bold cyan]"))
        console.print(f"  [dim]{len(candidates)} profils candidats a verifier[/dim]\n")
        v, discarded = verify_profiles(query, candidates,
                                       workers=config.verify.workers,
                                       timeout=config.verify.timeout, proxy=config.proxy)
        valid.extend(v)
    else:
        valid.extend(candidates)

    valid.extend(passthrough)

    # Dedupe by (kind, normalized-url) keeping the highest confidence.
    valid = _dedupe(valid)

    # Multi-source boost for account-ish findings confirmed by >=2 engines.
    _multi_source_boost(valid)

    _sort(valid)

    scan_id = 0
    if store is not None:
        scan_id = store.save_scan(query, input_type.value, valid, discarded,
                                  [e.name for e in engines])
        console.print(f"\n  [dim]Scan #{scan_id} sauvegarde[/dim]")
    return valid, discarded, scan_id


_CONF_ORDER = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
_KIND_ORDER = {
    FindingKind.PROFILE: 0, FindingKind.ACCOUNT: 1, FindingKind.BREACH: 2,
    FindingKind.ARCHIVE: 3, FindingKind.INFO: 4, FindingKind.LINK: 5,
    FindingKind.DORK: 6, FindingKind.ERROR: 7,
}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    best: dict[tuple, Finding] = {}
    order = []
    for f in findings:
        key = (f.kind, _norm_url(f.url) if f.url else f.title.lower())
        if key not in best:
            best[key] = f
            order.append(key)
        else:
            cur = best[key]
            # keep higher confidence; merge sources
            if _CONF_ORDER[f.confidence] < _CONF_ORDER[cur.confidence]:
                if cur.source not in f.source:
                    f.source = f"{f.source} + {cur.source}"
                best[key] = f
            elif cur.source and f.source not in cur.source:
                cur.source = f"{cur.source} + {f.source}"
    return [best[k] for k in order]


def _multi_source_boost(findings: list[Finding]) -> None:
    for f in findings:
        if f.kind in (FindingKind.PROFILE, FindingKind.ACCOUNT) and " + " in f.source:
            if f.confidence == Confidence.MEDIUM:
                f.confidence = Confidence.HIGH
            f.note = (f.note + " | " if f.note else "") + "Multi-source"


def _sort(findings: list[Finding]) -> None:
    findings.sort(key=lambda f: (_KIND_ORDER.get(f.kind, 9),
                                 _CONF_ORDER[f.confidence],
                                 not f.high_trust,
                                 f.title.lower()))
