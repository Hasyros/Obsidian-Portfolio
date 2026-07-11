"""FastAPI REST API for OSINT Hunter."""

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .cache import Cache
from .config import Config, load_config
from .database import Database
from .detection import detect_input
from .engines import get_all_engines
from .models import InputType
from .scanner import detect_engines, engines_for_mode, do_scan


class ScanRequest(BaseModel):
    query: str
    input_type: Optional[str] = None
    engines: Optional[list[str]] = None
    skip_verify: bool = False
    skip_correlation: bool = False


class ScanResponse(BaseModel):
    scan_id: int
    query: str
    input_type: str
    total_found: int
    total_discarded: int
    results: list[dict]
    discarded: list[dict]
    correlation: Optional[dict] = None


def create_app(cfg: Optional[Config] = None) -> FastAPI:
    if cfg is None:
        cfg = load_config()

    db = Database(cfg.db_path)
    cache = Cache(ttl=cfg.cache_ttl)
    all_engines = get_all_engines()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        db.close()

    app = FastAPI(
        title="OSINT Hunter API",
        version="5.0.0",
        description="Multi-engine OSINT scanner with deep verify & cross-platform correlation",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.api_server.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Optional API key — only enforced if api_server.api_key is set in config.
    # Protects the endpoints that trigger work or mutate state.
    def require_api_key(x_api_key: str = Header(default="")):
        if cfg.api_server.api_key and x_api_key != cfg.api_server.api_key:
            raise HTTPException(401, "Cle API invalide ou manquante (header X-API-Key)")

    @app.get("/")
    def root():
        return {"name": "OSINT Hunter API", "version": "5.0.0"}

    @app.get("/engines")
    def list_engines():
        es = detect_engines(all_engines)
        return [
            {
                "name": e.name,
                "description": e.desc,
                "modes": e.modes,
                "available": ok,
            }
            for e, ok in es
        ]

    @app.post("/scan", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
    def scan(req: ScanRequest):
        if not req.query.strip():
            raise HTTPException(400, "Query vide")

        if req.input_type:
            try:
                it = InputType(req.input_type)
            except ValueError:
                raise HTTPException(400, f"Type invalide: {req.input_type}")
        else:
            it = detect_input(req.query)

        es = detect_engines(all_engines)
        if req.engines:
            names = {n.lower() for n in req.engines}
            engs = [e for e, ok in es if ok and e.name.lower() in names]
        else:
            engs = engines_for_mode(it, es)

        if not engs:
            raise HTTPException(400, "Aucun moteur disponible pour ce type")

        valid, discarded, correlation, scan_id = do_scan(
            req.query, it, engs, cfg, cache, db,
            skip_verify=req.skip_verify,
            skip_correlation=req.skip_correlation,
        )

        corr_data = None
        if correlation:
            corr_data = {
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

        return ScanResponse(
            scan_id=scan_id,
            query=req.query,
            input_type=it.value,
            total_found=len(valid),
            total_discarded=len(discarded),
            results=[r.to_dict() for r in valid],
            discarded=[
                {"site_name": d.site_name, "url": d.url, "source": d.source, "reason": d.reason}
                for d in discarded
            ],
            correlation=corr_data,
        )

    @app.get("/history")
    def history(limit: int = Query(20, ge=1, le=200)):
        scans = db.list_scans(limit)
        return [
            {
                "scan_id": s.scan_id, "query": s.query,
                "input_type": s.input_type, "timestamp": s.timestamp,
                "total_found": s.total_found, "total_discarded": s.total_discarded,
                "engines_used": s.engines_used,
            }
            for s in scans
        ]

    @app.get("/scan/{scan_id}")
    def get_scan(scan_id: int):
        results = db.get_scan_results(scan_id)
        if not results:
            raise HTTPException(404, "Scan introuvable")
        discarded = db.get_scan_discarded(scan_id)
        return {
            "scan_id": scan_id,
            "total_found": len(results),
            "total_discarded": len(discarded),
            "results": [r.to_dict() for r in results],
            "discarded": [
                {"site_name": d.site_name, "url": d.url, "source": d.source, "reason": d.reason}
                for d in discarded
            ],
        }

    @app.get("/scan/{scan_id_old}/compare/{scan_id_new}")
    def compare(scan_id_old: int, scan_id_new: int):
        diff = db.compare_scans(scan_id_old, scan_id_new)
        return {
            "old_total": diff["old_total"],
            "new_total": diff["new_total"],
            "added": [r.to_dict() for r in diff["added"]],
            "removed": [r.to_dict() for r in diff["removed"]],
            "changed": diff["changed"],
        }

    @app.get("/stats")
    def stats():
        return db.stats()

    @app.delete("/cache", dependencies=[Depends(require_api_key)])
    def clear_cache():
        count = cache.clear()
        return {"cleared": count}

    return app
