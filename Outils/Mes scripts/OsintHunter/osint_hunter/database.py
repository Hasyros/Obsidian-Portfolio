"""SQLite persistence layer — scan history, results, comparisons."""

import json
import sqlite3
import time
from pathlib import Path

from .models import SiteResult, DiscardedResult, Confidence, Status, ScanRecord


class Database:
    def __init__(self, db_path: str = "./osint_hunter.db"):
        self._path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._init_tables()

    def _init_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query TEXT NOT NULL,
                input_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                total_found INTEGER DEFAULT 0,
                total_discarded INTEGER DEFAULT 0,
                engines_used TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                site_name TEXT NOT NULL,
                url TEXT NOT NULL,
                source TEXT DEFAULT '',
                http_status INTEGER,
                final_url TEXT DEFAULT '',
                redirect_count INTEGER DEFAULT 0,
                username_in_body INTEGER,
                page_title TEXT DEFAULT '',
                page_size INTEGER DEFAULT 0,
                confidence TEXT DEFAULT 'low',
                status TEXT DEFAULT 'pending',
                note TEXT DEFAULT '',
                response_time_ms INTEGER,
                tags TEXT DEFAULT '[]',
                high_trust INTEGER DEFAULT 0,
                avatar_url TEXT DEFAULT '',
                bio TEXT DEFAULT '',
                links TEXT DEFAULT '[]',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS discarded (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                site_name TEXT NOT NULL,
                url TEXT NOT NULL,
                source TEXT DEFAULT '',
                reason TEXT DEFAULT '',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE INDEX IF NOT EXISTS idx_scans_query ON scans(query);
            CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_results_site ON results(site_name);
        """)
        self._conn.commit()

    def save_scan(
        self,
        query: str,
        input_type: str,
        results: list[SiteResult],
        discarded: list[DiscardedResult],
        engines_used: list[str],
    ) -> int:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        cur = self._conn.execute(
            "INSERT INTO scans (query, input_type, timestamp, total_found, total_discarded, engines_used) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (query, input_type, ts, len(results), len(discarded), ",".join(engines_used)),
        )
        scan_id = cur.lastrowid

        for r in results:
            self._conn.execute(
                "INSERT INTO results "
                "(scan_id, site_name, url, source, http_status, final_url, redirect_count, "
                "username_in_body, page_title, page_size, confidence, status, note, "
                "response_time_ms, tags, high_trust, avatar_url, bio, links) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id, r.site_name, r.url, r.source, r.http_status,
                    r.final_url, r.redirect_count,
                    1 if r.username_in_body else (0 if r.username_in_body is not None else None),
                    r.page_title, r.page_size, r.confidence.value, r.status.value,
                    r.note, r.response_time_ms, json.dumps(r.tags),
                    1 if r.high_trust else 0, r.avatar_url or "", r.bio or "",
                    json.dumps(r.links),
                ),
            )

        for d in discarded:
            self._conn.execute(
                "INSERT INTO discarded (scan_id, site_name, url, source, reason) VALUES (?, ?, ?, ?, ?)",
                (scan_id, d.site_name, d.url, d.source, d.reason),
            )

        self._conn.commit()
        return scan_id

    def list_scans(self, limit: int = 50) -> list[ScanRecord]:
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            ScanRecord(
                scan_id=r["id"], query=r["query"], input_type=r["input_type"],
                timestamp=r["timestamp"], total_found=r["total_found"],
                total_discarded=r["total_discarded"], engines_used=r["engines_used"],
            )
            for r in rows
        ]

    def get_scan_results(self, scan_id: int) -> list[SiteResult]:
        rows = self._conn.execute(
            "SELECT * FROM results WHERE scan_id = ? ORDER BY confidence ASC, site_name ASC",
            (scan_id,),
        ).fetchall()
        results = []
        for r in rows:
            uib = r["username_in_body"]
            results.append(SiteResult(
                site_name=r["site_name"], url=r["url"], source=r["source"],
                http_status=r["http_status"], final_url=r["final_url"],
                redirect_count=r["redirect_count"],
                username_in_body=bool(uib) if uib is not None else None,
                page_title=r["page_title"], page_size=r["page_size"],
                confidence=Confidence(r["confidence"]),
                status=Status(r["status"]),
                note=r["note"], response_time_ms=r["response_time_ms"],
                tags=json.loads(r["tags"]) if r["tags"] else [],
                high_trust=bool(r["high_trust"]),
                avatar_url=r["avatar_url"] or None,
                bio=r["bio"] or None,
                links=json.loads(r["links"]) if ("links" in r.keys() and r["links"]) else [],
            ))
        return results

    def get_scan_discarded(self, scan_id: int) -> list[DiscardedResult]:
        rows = self._conn.execute(
            "SELECT * FROM discarded WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [
            DiscardedResult(
                site_name=r["site_name"], url=r["url"],
                source=r["source"], reason=r["reason"],
            )
            for r in rows
        ]

    def compare_scans(self, scan_id_old: int, scan_id_new: int) -> dict:
        """Compare two scans: new accounts, removed accounts, changed confidence."""
        old = {r.url.rstrip("/").lower(): r for r in self.get_scan_results(scan_id_old)}
        new = {r.url.rstrip("/").lower(): r for r in self.get_scan_results(scan_id_new)}

        old_urls = set(old.keys())
        new_urls = set(new.keys())

        added = [new[u] for u in new_urls - old_urls]
        removed = [old[u] for u in old_urls - new_urls]

        changed = []
        for u in old_urls & new_urls:
            if old[u].confidence != new[u].confidence:
                changed.append({
                    "site": new[u].site_name,
                    "url": new[u].url,
                    "old_confidence": old[u].confidence.value,
                    "new_confidence": new[u].confidence.value,
                })

        return {
            "added": added,
            "removed": removed,
            "changed": changed,
            "old_total": len(old),
            "new_total": len(new),
        }

    def search_results(self, query: str = "", site: str = "") -> list[SiteResult]:
        """Search across all stored results."""
        sql = "SELECT * FROM results WHERE 1=1"
        params = []
        if query:
            sql += " AND scan_id IN (SELECT id FROM scans WHERE query LIKE ?)"
            params.append(f"%{query}%")
        if site:
            sql += " AND site_name LIKE ?"
            params.append(f"%{site}%")
        sql += " ORDER BY scan_id DESC LIMIT 100"

        rows = self._conn.execute(sql, params).fetchall()
        return [
            SiteResult(
                site_name=r["site_name"], url=r["url"], source=r["source"],
                http_status=r["http_status"], confidence=Confidence(r["confidence"]),
                status=Status(r["status"]), note=r["note"],
                high_trust=bool(r["high_trust"]),
            )
            for r in rows
        ]

    def stats(self) -> dict:
        total_scans = self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        total_results = self._conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        unique_sites = self._conn.execute("SELECT COUNT(DISTINCT site_name) FROM results").fetchone()[0]
        unique_queries = self._conn.execute("SELECT COUNT(DISTINCT query) FROM scans").fetchone()[0]
        return {
            "total_scans": total_scans,
            "total_results": total_results,
            "unique_sites": unique_sites,
            "unique_queries": unique_queries,
        }

    def close(self):
        self._conn.close()
