"""Configuration loader — YAML + env var overrides."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class ProxyConfig:
    enabled: bool = False
    url: str = ""
    rotate: bool = False


@dataclass
class ApiKeys:
    hibp: str = ""
    shodan: str = ""
    hunter_io: str = ""
    dehashed_email: str = ""
    dehashed_key: str = ""
    virustotal: str = ""
    numverify: str = ""
    epieos: str = ""
    github: str = ""


@dataclass
class DeepVerifyConfig:
    enabled: bool = True
    workers: int = 30
    timeout: int = 12
    strict_mode: bool = False


@dataclass
class ApiServerConfig:
    host: str = "127.0.0.1"
    port: int = 8400
    cors_origins: list = field(default_factory=lambda: ["http://localhost:3000"])
    api_key: str = ""   # si defini, exige le header X-API-Key sur /scan et DELETE /cache


@dataclass
class CorrelationConfig:
    avatar_comparison: bool = True
    bio_similarity: bool = True
    link_extraction: bool = True
    similarity_threshold: float = 0.75


@dataclass
class Config:
    version: str = "5.0.0"
    language: str = "fr"
    output_dir: str = "./reports"
    max_workers: int = 40
    default_timeout: int = 12
    cache_ttl: int = 3600
    db_path: str = "./osint_hunter.db"
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    api_keys: ApiKeys = field(default_factory=ApiKeys)
    deep_verify: DeepVerifyConfig = field(default_factory=DeepVerifyConfig)
    api_server: ApiServerConfig = field(default_factory=ApiServerConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)


_ENV_MAP = {
    "OSINT_HIBP_API_KEY": "hibp",
    "OSINT_SHODAN_API_KEY": "shodan",
    "OSINT_HUNTER_IO_KEY": "hunter_io",
    "OSINT_DEHASHED_EMAIL": "dehashed_email",
    "OSINT_DEHASHED_KEY": "dehashed_key",
    "OSINT_VT_API_KEY": "virustotal",
    "OSINT_NUMVERIFY_KEY": "numverify",
    "OSINT_EPIEOS_KEY": "epieos",
    "OSINT_GITHUB_TOKEN": "github",
}


def _apply_env(keys: ApiKeys) -> None:
    for env_var, attr in _ENV_MAP.items():
        val = os.environ.get(env_var, "")
        if val:
            setattr(keys, attr, val)


def load_config(path: Optional[str] = None) -> Config:
    """Load config from YAML file, with env var overrides for API keys."""
    cfg = Config()

    candidates = [
        path,
        os.environ.get("OSINT_CONFIG"),
        "config.yaml",
        str(Path.home() / ".osint_hunter" / "config.yaml"),
    ]
    for p in candidates:
        if p and Path(p).is_file():
            with open(p, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            _merge(cfg, data)
            break

    _apply_env(cfg.api_keys)
    # API key can also come from the environment
    env_api_key = os.environ.get("OSINT_API_KEY", "")
    if env_api_key:
        cfg.api_server.api_key = env_api_key
    return cfg


def _merge(cfg: Config, data: dict) -> None:
    g = data.get("general", {})
    if g:
        for k in ("version", "language", "output_dir", "max_workers",
                   "default_timeout", "cache_ttl"):
            if k in g:
                setattr(cfg, k, g[k])

    p = data.get("proxy", {})
    if p:
        cfg.proxy = ProxyConfig(
            enabled=p.get("enabled", False),
            url=p.get("url", ""),
            rotate=p.get("rotate", False),
        )

    keys = data.get("api_keys", {})
    if keys:
        for k, v in keys.items():
            if v and hasattr(cfg.api_keys, k):
                setattr(cfg.api_keys, k, v)

    dv = data.get("deep_verify", {})
    if dv:
        cfg.deep_verify = DeepVerifyConfig(**{
            k: dv[k] for k in ("enabled", "workers", "timeout", "strict_mode") if k in dv
        })

    api = data.get("api_server", {})
    if api:
        cfg.api_server = ApiServerConfig(
            host=api.get("host", "127.0.0.1"),
            port=api.get("port", 8400),
            cors_origins=api.get("cors_origins", ["http://localhost:3000"]),
            api_key=api.get("api_key", ""),
        )

    db = data.get("database", {})
    if db and "path" in db:
        cfg.db_path = db["path"]

    cor = data.get("correlation", {})
    if cor:
        cfg.correlation = CorrelationConfig(**{
            k: cor[k] for k in ("avatar_comparison", "bio_similarity",
                                 "link_extraction", "similarity_threshold") if k in cor
        })
