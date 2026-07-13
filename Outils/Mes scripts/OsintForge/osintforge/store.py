"""SQLite persistence — scan history, findings, comparisons, stats."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .models import (
    Finding, Discarded, FindingKind, Confidence, Status, ScanRecord,
)


class Store:
    def __init__(self, db_path: str = "./osintforge.db"):
        self._path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query TEXT NOT NULL, input_type TEXT NOT NULL, timestamp TEXT NOT NULL,
                total_found INTEGER DEFAULT 0, total_discarded INTEGER DEFAULT 0,
                engines_used TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
                source TEXT, title TEXT, kind TEXT, url TEXT, confidence TEXT,
                status TEXT, note TEXT, tags TEXT, high_trust INTEGER,
                http_status INTEGER, page_title TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS discarded (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
                title TEXT, url TEXT, source TEXT, reason TEXT);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scans_query ON scans(query);
        """)
        self._conn.commit()

    def save_scan(self, query: str, input_type: str, findings: list[Finding],
                  discarded: list[Discarded], engines_used: list[str]) -> int:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        cur = self._conn.execute(
            "INSERT INTO scans (query, input_type, timestamp, total_found, "
            "total_discarded, engines_used) VALUES (?,?,?,?,?,?)",
            (query, input_type, ts, len(findings), len(discarded), ",".join(engines_used)))
        scan_id = cur.lastrowid
        for f in findings:
            self._conn.execute(
                "INSERT INTO findings (scan_id, source, title, kind, url, confidence, "
                "status, note, tags, high_trust, http_status, page_title, data) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, f.source, f.title, f.kind.value, f.url, f.confidence.value,
                 f.status.value, f.note, json.dumps(f.tags), 1 if f.high_trust else 0,
                 f.http_status, f.page_title, json.dumps(f.data)))
        for d in discarded:
            self._conn.execute(
                "INSERT INTO discarded (scan_id, title, url, source, reason) VALUES (?,?,?,?,?)",
                (scan_id, d.title, d.url, d.source, d.reason))
        self._conn.commit()
        return scan_id

    def list_scans(self, limit: int = 20) -> list[ScanRecord]:
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [ScanRecord(scan_id=r["id"], query=r["query"], input_type=r["input_type"],
                           timestamp=r["timestamp"], total_found=r["total_found"],
                           total_discarded=r["total_discarded"], engines_used=r["engines_used"])
                for r in rows]

    def get_findings(self, scan_id: int) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY confidence, title", (scan_id,)).fetchall()
        out = []
        for r in rows:
            out.append(Finding(
                source=r["source"], title=r["title"], kind=FindingKind(r["kind"]),
                url=r["url"], confidence=Confidence(r["confidence"]),
                status=Status(r["status"]), note=r["note"] or "",
                tags=json.loads(r["tags"]) if r["tags"] else [],
                high_trust=bool(r["high_trust"]), http_status=r["http_status"],
                page_title=r["page_title"] or "",
                data=json.loads(r["data"]) if r["data"] else {}))
        return out

    def get_discarded(self, scan_id: int) -> list[Discarded]:
        rows = self._conn.execute(
            "SELECT * FROM discarded WHERE scan_id=?", (scan_id,)).fetchall()
        return [Discarded(title=r["title"], url=r["url"], source=r["source"], reason=r["reason"])
                for r in rows]

    def compare(self, old_id: int, new_id: int) -> dict:
        old = {(f.url or f.title).rstrip("/").lower(): f for f in self.get_findings(old_id)}
        new = {(f.url or f.title).rstrip("/").lower(): f for f in self.get_findings(new_id)}
        ok, nk = set(old), set(new)
        added = [new[k] for k in nk - ok]
        removed = [old[k] for k in ok - nk]
        changed = [{"title": new[k].title, "old": old[k].confidence.value,
                    "new": new[k].confidence.value}
                   for k in ok & nk if old[k].confidence != new[k].confidence]
        return {"added": added, "removed": removed, "changed": changed,
                "old_total": len(old), "new_total": len(new)}

    def stats(self) -> dict:
        c = self._conn.execute
        return {
            "total_scans": c("SELECT COUNT(*) FROM scans").fetchone()[0],
            "total_findings": c("SELECT COUNT(*) FROM findings").fetchone()[0],
            "unique_sites": c("SELECT COUNT(DISTINCT title) FROM findings").fetchone()[0],
            "unique_queries": c("SELECT COUNT(DISTINCT query) FROM scans").fetchone()[0],
        }

    def close(self):
        self._conn.close()
