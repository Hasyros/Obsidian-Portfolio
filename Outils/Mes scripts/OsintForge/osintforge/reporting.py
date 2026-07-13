"""Export findings to JSON, CSV, a self-contained HTML report, and Maltego CSV."""

from __future__ import annotations

import csv
import html
import json
import time
from pathlib import Path
from typing import Optional

from .models import Finding, Discarded, FindingKind, Confidence


def _sanitize(q: str) -> str:
    return q.replace(" ", "_").replace("@", "_at_").replace("/", "_").replace("\\", "_").replace(":", "")


def _stamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def export_json(findings: list[Finding], query: str, out_dir: str,
                discarded: Optional[list[Discarded]] = None) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    fp = out / f"osint_{_sanitize(query)}_{_stamp()}.json"
    data = {
        "query": query, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tool": "OsintForge", "total": len(findings),
        "findings": [f.to_dict() for f in findings],
        "discarded": [{"title": d.title, "url": d.url, "source": d.source, "reason": d.reason}
                      for d in (discarded or [])],
    }
    fp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return fp


def export_csv(findings: list[Finding], query: str, out_dir: str) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    fp = out / f"osint_{_sanitize(query)}_{_stamp()}.csv"
    with open(fp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["kind", "title", "url", "source", "confidence", "status",
                    "high_trust", "http_status", "note", "tags"])
        for r in findings:
            w.writerow([r.kind.value, r.title, r.url, r.source, r.confidence.value,
                        r.status.value, r.high_trust, r.http_status or "", r.note,
                        "|".join(r.tags)])
    return fp


def export_maltego(findings: list[Finding], query: str, out_dir: str) -> Path:
    """Maltego-importable CSV (entity value + type + weight)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    fp = out / f"maltego_{_sanitize(query)}_{_stamp()}.csv"
    type_map = {
        FindingKind.PROFILE: "maltego.Website", FindingKind.ACCOUNT: "maltego.Website",
        FindingKind.BREACH: "maltego.Phrase", FindingKind.ARCHIVE: "maltego.URL",
        FindingKind.INFO: "maltego.Phrase", FindingKind.LINK: "maltego.URL",
        FindingKind.DORK: "maltego.URL",
    }
    with open(fp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Entity", "EntityType", "Link", "Source", "Confidence"])
        for r in findings:
            if r.kind == FindingKind.ERROR:
                continue
            w.writerow([r.title, type_map.get(r.kind, "maltego.Phrase"),
                        r.url, r.source, r.confidence.value])
    return fp


_CONF_COLORS = {"high": "#16a34a", "medium": "#d97706", "low": "#6b7280"}


def export_html(findings: list[Finding], query: str, out_dir: str,
                discarded: Optional[list[Discarded]] = None) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    fp = out / f"osint_{_sanitize(query)}_{_stamp()}.html"

    hi = sum(1 for r in findings if r.confidence == Confidence.HIGH)
    md = sum(1 for r in findings if r.confidence == Confidence.MEDIUM)
    lo = sum(1 for r in findings if r.confidence == Confidence.LOW)
    ht = sum(1 for r in findings if r.high_trust)

    rows = []
    for r in findings:
        url_cell = (f'<a href="{html.escape(r.url)}" target="_blank" rel="noopener">'
                    f'{html.escape(r.url[:70])}</a>') if r.url else ""
        color = _CONF_COLORS.get(r.confidence.value, "#6b7280")
        rows.append(
            f'<tr data-kind="{r.kind.value}" data-conf="{r.confidence.value}">'
            f'<td><span class="pill" style="background:{color}">{r.confidence.value.upper()}</span></td>'
            f'<td>{"⭐" if r.high_trust else ""}</td>'
            f'<td class="kind">{r.kind.value}</td>'
            f'<td class="title">{html.escape(r.title)}</td>'
            f'<td class="url">{url_cell}</td>'
            f'<td>{html.escape(r.source)}</td>'
            f'<td class="note">{html.escape(r.note)}</td></tr>')

    disc_rows = "".join(
        f'<tr><td>{html.escape(d.title)}</td><td>{html.escape(d.reason)}</td>'
        f'<td>{html.escape(d.source)}</td></tr>' for d in (discarded or []))

    doc = _HTML.format(
        query=html.escape(query), ts=time.strftime("%Y-%m-%d %H:%M:%S"),
        total=len(findings), hi=hi, md=md, lo=lo, ht=ht,
        rows="".join(rows),
        disc_section=(f'<h2>Élimimés ({len(discarded)})</h2>'
                      f'<table class="disc"><thead><tr><th>Site</th><th>Raison</th>'
                      f'<th>Source</th></tr></thead><tbody>{disc_rows}</tbody></table>'
                      if discarded else ""))
    fp.write_text(doc, encoding="utf-8")
    return fp


def export_all(findings: list[Finding], query: str, out_dir: str = "./reports",
               discarded: Optional[list[Discarded]] = None) -> dict[str, Path]:
    return {
        "json": export_json(findings, query, out_dir, discarded),
        "csv": export_csv(findings, query, out_dir),
        "html": export_html(findings, query, out_dir, discarded),
        "maltego": export_maltego(findings, query, out_dir),
    }


_HTML = """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OsintForge — {query}</title><style>
:root{{--bg:#0f1115;--card:#181b22;--fg:#e6e8ee;--mut:#9aa3b2;--bd:#272c38;--acc:#3b82f6}}
@media (prefers-color-scheme:light){{:root{{--bg:#f6f7f9;--card:#fff;--fg:#1a1d24;--mut:#5b6472;--bd:#e2e5ea}}}}
*{{box-sizing:border-box}}body{{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--fg);padding:24px}}
h1{{font-size:20px;margin:0 0 4px}}.sub{{color:var(--mut);margin-bottom:16px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 18px;min-width:90px}}
.card .n{{font-size:22px;font-weight:700}}.card .l{{color:var(--mut);font-size:12px}}
.controls{{margin-bottom:12px}}input,select{{background:var(--card);color:var(--fg);
border:1px solid var(--bd);border-radius:8px;padding:7px 10px;margin-right:8px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd);
border-radius:10px;overflow:hidden}}th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--bd);
vertical-align:top}}th{{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}}
td.url a{{color:var(--acc);text-decoration:none;word-break:break-all}}
.kind{{color:var(--mut);font-size:12px}}.title{{font-weight:600}}.note{{color:var(--mut);font-size:12px}}
.pill{{color:#fff;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}}
.disc td{{color:var(--mut)}}h2{{margin-top:28px;font-size:16px}}
.wrap{{overflow-x:auto}}</style></head><body>
<h1>🔎 OsintForge — {query}</h1><div class="sub">{ts} · {total} findings</div>
<div class="cards">
<div class="card"><div class="n" style="color:#16a34a">{hi}</div><div class="l">HIGH</div></div>
<div class="card"><div class="n" style="color:#d97706">{md}</div><div class="l">MEDIUM</div></div>
<div class="card"><div class="n" style="color:#6b7280">{lo}</div><div class="l">LOW</div></div>
<div class="card"><div class="n">{ht}</div><div class="l">High-trust ⭐</div></div>
<div class="card"><div class="n">{total}</div><div class="l">Total</div></div></div>
<div class="controls"><input id="q" placeholder="Filtrer..." onkeyup="flt()">
<select id="k" onchange="flt()"><option value="">Tous types</option>
<option>profile</option><option>account</option><option>breach</option>
<option>archive</option><option>info</option><option>link</option><option>dork</option></select>
<select id="c" onchange="flt()"><option value="">Toutes confiances</option>
<option>high</option><option>medium</option><option>low</option></select></div>
<div class="wrap"><table id="t"><thead><tr><th>Conf</th><th>HT</th><th>Type</th>
<th>Site</th><th>URL</th><th>Source</th><th>Note</th></tr></thead><tbody>{rows}</tbody></table></div>
{disc_section}
<script>
function flt(){{var q=document.getElementById('q').value.toLowerCase(),
k=document.getElementById('k').value,c=document.getElementById('c').value;
document.querySelectorAll('#t tbody tr').forEach(function(r){{
var t=r.textContent.toLowerCase(),mk=!k||r.dataset.kind===k,mc=!c||r.dataset.conf===c;
r.style.display=(t.indexOf(q)>=0&&mk&&mc)?'':'none';}});}}
</script></body></html>"""
