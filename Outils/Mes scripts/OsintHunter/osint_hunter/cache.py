"""File-based cache with TTL for scan results and HTTP responses."""

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Optional


class Cache:
    def __init__(self, cache_dir: str = ".cache/osint_hunter", ttl: int = 3600):
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl

    @staticmethod
    def _sanitize(name: str) -> str:
        """Remove chars that break file paths (/, \\, :, etc.)."""
        return re.sub(r'[/\\:*?"<>|]', "_", name)

    def _key(self, namespace: str, value: str) -> str:
        safe_ns = self._sanitize(namespace)
        h = hashlib.sha256(f"{namespace}:{value}".encode()).hexdigest()[:16]
        return f"{safe_ns}_{h}"

    def _path(self, key: str) -> Path:
        return self._dir / f"{key}.json"

    def get(self, namespace: str, value: str) -> Optional[list[dict]]:
        if self._ttl <= 0:
            return None
        p = self._path(self._key(namespace, value))
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if time.time() - data.get("ts", 0) > self._ttl:
                p.unlink(missing_ok=True)
                return None
            return data.get("results")
        except Exception:
            return None

    def set(self, namespace: str, value: str, results: list[dict]) -> None:
        if self._ttl <= 0:
            return
        p = self._path(self._key(namespace, value))
        p.write_text(
            json.dumps({"ts": time.time(), "query": value, "results": results},
                       ensure_ascii=False),
            encoding="utf-8",
        )

    def clear(self) -> int:
        count = 0
        for f in self._dir.glob("*.json"):
            f.unlink(missing_ok=True)
            count += 1
        return count

    def prune_expired(self) -> int:
        count = 0
        now = time.time()
        for f in self._dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if now - data.get("ts", 0) > self._ttl:
                    f.unlink(missing_ok=True)
                    count += 1
            except Exception:
                f.unlink(missing_ok=True)
                count += 1
        return count
