"""Configuration: dataclass defaults, optional YAML file, env-var overrides.

Nothing here is required to run — every field has a sane default and every
API key is optional (engines that need one degrade gracefully).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ProxyConfig:
    enabled: bool = False
    url: str = ""


@dataclass
class ApiKeys:
    hibp: str = ""
    numverify: str = ""
    tineye: str = ""
    github: str = ""
    hunter_io: str = ""


@dataclass
class VerifyConfig:
    enabled: bool = True
    workers: int = 30
    timeout: int = 12


@dataclass
class Config:
    version: str = "1.0.0"
    output_dir: str = "./reports"
    db_path: str = "./osintforge.db"
    cache_ttl: int = 3600
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    api_keys: ApiKeys = field(default_factory=ApiKeys)
    verify: VerifyConfig = field(default_factory=VerifyConfig)


_ENV_MAP = {
    "OSINT_HIBP_API_KEY": "hibp",
    "HIBP_API_KEY": "hibp",
    "OSINT_NUMVERIFY_KEY": "numverify",
    "OSINT_TINEYE_KEY": "tineye",
    "OSINT_GITHUB_TOKEN": "github",
    "OSINT_HUNTER_IO_KEY": "hunter_io",
}


def _apply_env(keys: ApiKeys) -> None:
    for env_var, attr in _ENV_MAP.items():
        val = os.environ.get(env_var, "")
        if val:
            setattr(keys, attr, val)


def load_config(path: Optional[str] = None) -> Config:
    cfg = Config()
    candidates = [
        path,
        os.environ.get("OSINTFORGE_CONFIG"),
        "config.yaml",
        str(Path.home() / ".osintforge" / "config.yaml"),
    ]
    for p in candidates:
        if p and Path(p).is_file():
            try:
                import yaml
                with open(p, encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                _merge(cfg, data)
            except Exception:
                pass
            break
    _apply_env(cfg.api_keys)
    return cfg


def _merge(cfg: Config, data: dict) -> None:
    g = data.get("general", {})
    for k in ("version", "output_dir", "db_path", "cache_ttl"):
        if k in g:
            setattr(cfg, k, g[k])

    p = data.get("proxy", {})
    if p:
        cfg.proxy = ProxyConfig(enabled=p.get("enabled", False), url=p.get("url", ""))

    keys = data.get("api_keys", {})
    for k, v in keys.items():
        if v and hasattr(cfg.api_keys, k):
            setattr(cfg.api_keys, k, v)

    v = data.get("verify", {})
    if v:
        cfg.verify = VerifyConfig(**{
            k: v[k] for k in ("enabled", "workers", "timeout") if k in v
        })
