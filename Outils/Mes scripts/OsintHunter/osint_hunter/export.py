"""Export — JSON, CSV, and interactive HTML report."""

import csv
import json
import time
from pathlib import Path
from typing import Optional

from jinja2 import Template

from .models import SiteResult, DiscardedResult, Confidence
from .correlation import CorrelationReport

_TEMPLATE_PATH = Path(__file__).parent / "templates" / "report.html"


def _sanitize_name(q: str) -> str:
    return q.replace(" ", "_").replace("@", "_at_").replace("/", "_")


def export_json(
    results: list[SiteResult],
    query: str,
    out_dir: str = ".",
    discarded: Optional[list[DiscardedResult]] = None,
    correlation: Optional[CorrelationReport] = None,
) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    name = _sanitize_name(query)
    fp = out / f"osint_{name}_{ts}.json"

    data = {
        "query": query,
        "timestamp": ts,
        "version": "5.0.0",
        "total": len(results),
        "results": [r.to_dict() for r in results],
    }
    if discarded:
        data["discarded"] = [
            {"site_name": d.site_name, "url": d.url, "source": d.source, "reason": d.reason}
            for d in discarded
        ]
    if correlation:
        data["correlation"] = {
            "links": [
                {
                    "source": l.source, "target": l.target,
                    "type": l.link_type, "confidence": l.confidence,
                    "detail": l.detail,
                }
                for l in correlation.links
            ],
            "avatar_clusters": correlation.avatar_clusters,
            "shared_links": correlation.shared_links,
            "emails_found": correlation.emails_found,
        }

    fp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return fp


def export_csv(results: list[SiteResult], query: str, out_dir: str = ".") -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    name = _sanitize_name(query)
    fp = out / f"osint_{name}_{ts}.csv"

    with open(fp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "site", "url", "source", "http_status", "confidence",
            "status", "high_trust", "note", "tags", "avatar_url", "bio",
        ])
        for r in results:
            w.writerow([
                r.site_name, r.url, r.source, r.http_status,
                r.confidence.value, r.status.value, r.high_trust,
                r.note, "|".join(r.tags), r.avatar_url or "", r.bio or "",
            ])
    return fp


def export_html(
    results: list[SiteResult],
    query: str,
    out_dir: str = ".",
    discarded: Optional[list[DiscardedResult]] = None,
    correlation: Optional[CorrelationReport] = None,
) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    name = _sanitize_name(query)
    fp = out / f"osint_{name}_{ts}.html"

    template_text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    tmpl = Template(template_text)

    hi = sum(1 for r in results if r.confidence == Confidence.HIGH)
    md = sum(1 for r in results if r.confidence == Confidence.MEDIUM)
    lo = sum(1 for r in results if r.confidence == Confidence.LOW)
    ht = sum(1 for r in results if r.high_trust)

    # Category counts
    cat_counts: dict[str, int] = {}
    for r in results:
        for tag in r.tags:
            cat_counts[tag] = cat_counts.get(tag, 0) + 1

    html = tmpl.render(
        query=query,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        results=results,
        discarded=discarded or [],
        total=len(results),
        high=hi, medium=md, low=lo, high_trust=ht,
        cat_counts=cat_counts,
        correlation=correlation,
        cat_counts_json=json.dumps(cat_counts),
    )

    fp.write_text(html, encoding="utf-8")
    return fp


def export_all(
    results: list[SiteResult],
    query: str,
    out_dir: str = "./reports",
    discarded: Optional[list[DiscardedResult]] = None,
    correlation: Optional[CorrelationReport] = None,
) -> dict[str, Path]:
    """Export in all formats. Returns dict of format -> filepath."""
    paths = {}
    paths["json"] = export_json(results, query, out_dir, discarded, correlation)
    paths["csv"] = export_csv(results, query, out_dir)
    paths["html"] = export_html(results, query, out_dir, discarded, correlation)
    return paths
