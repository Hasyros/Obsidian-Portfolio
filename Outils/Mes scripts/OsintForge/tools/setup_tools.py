#!/usr/bin/env python3
"""Installe les outils externes d'OsintForge (non disponibles sur PyPI).

Idempotent : relançable sans risque, il saute ce qui est déjà présent.

    python tools/setup_tools.py            # tout installer
    python tools/setup_tools.py --only phoneinfoga,spiderfoot
    python tools/setup_tools.py --list     # afficher l'état

Ce qu'il fait :
  - PhoneInfoga : télécharge le binaire précompilé (release GitHub) et vérifie
    son SHA256 contre le fichier de checksums officiel.
  - SpiderFoot  : git clone + installe les dépendances en évitant les pins
    obsolètes (lxml<5 / cryptography<4) qui cassent d'autres paquets.
  - Recon-ng    : git clone + dépendances + applique le correctif Windows
    (séparateur de chemin) nécessaire au chargement des modules.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
BIN = TOOLS / "bin"


def log(msg: str) -> None:
    print(f"[setup] {msg}")


def run(cmd: list[str], cwd: Path | None = None) -> int:
    log("$ " + " ".join(cmd))
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None).returncode


# --------------------------------------------------------------------------- #
# PhoneInfoga — prebuilt binary from GitHub releases
# --------------------------------------------------------------------------- #
def _phoneinfoga_asset() -> str:
    system = platform.system()          # Windows / Linux / Darwin
    machine = platform.machine().lower()
    arch = "x86_64" if machine in ("amd64", "x86_64") else \
           "arm64" if machine in ("arm64", "aarch64") else "i386"
    return f"phoneinfoga_{system}_{arch}.tar.gz"


def install_phoneinfoga(force: bool = False) -> None:
    exe = BIN / ("phoneinfoga.exe" if os.name == "nt" else "phoneinfoga")
    if exe.is_file() and not force:
        log("PhoneInfoga déjà présent, saut.")
        return
    BIN.mkdir(parents=True, exist_ok=True)
    log("Récupération de la dernière release PhoneInfoga...")
    with urllib.request.urlopen(
            "https://api.github.com/repos/sundowndev/phoneinfoga/releases/latest") as r:
        rel = json.load(r)
    asset_name = _phoneinfoga_asset()
    assets = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
    if asset_name not in assets:
        log(f"ERREUR: asset {asset_name} introuvable pour cette plateforme.")
        return
    tgz = BIN / asset_name
    log(f"Téléchargement {asset_name} ({rel['tag_name']})...")
    urllib.request.urlretrieve(assets[asset_name], tgz)

    # Vérification SHA256
    sums = BIN / "phoneinfoga_checksums.txt"
    urllib.request.urlretrieve(assets["phoneinfoga_checksums.txt"], sums)
    expected = ""
    for line in sums.read_text().splitlines():
        if asset_name in line:
            expected = line.split()[0]
            break
    actual = hashlib.sha256(tgz.read_bytes()).hexdigest()
    if expected and actual != expected:
        log(f"ERREUR: checksum invalide ! attendu {expected}, obtenu {actual}")
        tgz.unlink(missing_ok=True)
        sums.unlink(missing_ok=True)
        return
    log(f"SHA256 vérifié: {actual[:16]}...")

    with tarfile.open(tgz) as t:
        t.extractall(BIN)
    tgz.unlink(missing_ok=True)
    sums.unlink(missing_ok=True)
    log(f"PhoneInfoga installé -> {exe}")


# --------------------------------------------------------------------------- #
# SpiderFoot — git clone + deps (avoiding the obsolete pins)
# --------------------------------------------------------------------------- #
def install_spiderfoot(force: bool = False) -> None:
    dest = TOOLS / "spiderfoot"
    if (dest / "sf.py").is_file() and not force:
        log("SpiderFoot déjà cloné, saut du clone.")
    else:
        if force and dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        if run(["git", "clone", "--depth", "1",
                "https://github.com/smicallef/spiderfoot.git", str(dest)]) != 0:
            log("ERREUR: git clone SpiderFoot a échoué.")
            return

    req = dest / "requirements.txt"
    if req.is_file():
        # Ces pins de SpiderFoot n'ont pas de wheel récent (lxml<5) ou
        # rétrogradent des paquets partagés et cassent d'autres outils
        # (cryptography<4, pyOpenSSL<22, PyPDF2<2 -> cassent maigret/pyhanko).
        # On les exclut, puis on installe des versions modernes juste après.
        skip = ("lxml", "cryptography", "pyopenssl", "pypdf2")
        filtered = TOOLS / "_sf_requirements.txt"
        filtered.write_text(
            "\n".join(l for l in req.read_text().splitlines()
                      if not l.strip().lower().startswith(skip)),
            encoding="utf-8")
        run([sys.executable, "-m", "pip", "install", "--user", "-r", str(filtered)])
        filtered.unlink(missing_ok=True)
        run([sys.executable, "-m", "pip", "install", "--user",
             "cryptography", "pyOpenSSL", "PyPDF2>=3.0.1,<4.0.0"])
    log("SpiderFoot prêt.")


# --------------------------------------------------------------------------- #
# Recon-ng — git clone + deps + Windows path-separator patch
# --------------------------------------------------------------------------- #
_PATCH_ANCHOR = "    def _load_module(self, dirpath, filename):\n"
_PATCH_LINE = "        dirpath = dirpath.replace(os.sep, '/')  # OsintForge: Windows path fix\n"


def _patch_recon_ng(dest: Path) -> None:
    base = dest / "recon" / "core" / "base.py"
    if not base.is_file():
        log("AVERTISSEMENT: recon/core/base.py introuvable, patch non appliqué.")
        return
    text = base.read_text(encoding="utf-8")
    if "OsintForge: Windows path fix" in text:
        log("Correctif Recon-ng déjà appliqué.")
        return
    if _PATCH_ANCHOR not in text:
        log("AVERTISSEMENT: ancre du patch Recon-ng introuvable (version différente ?).")
        return
    base.write_text(text.replace(_PATCH_ANCHOR, _PATCH_ANCHOR + _PATCH_LINE),
                    encoding="utf-8")
    log("Correctif Windows Recon-ng appliqué (_load_module).")


def install_recon_ng(force: bool = False) -> None:
    dest = TOOLS / "recon-ng"
    if (dest / "recon-cli").is_file() and not force:
        log("Recon-ng déjà cloné, saut du clone.")
    else:
        if force and dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        if run(["git", "clone", "--depth", "1",
                "https://github.com/lanmaster53/recon-ng.git", str(dest)]) != 0:
            log("ERREUR: git clone Recon-ng a échoué.")
            return
        req = dest / "REQUIREMENTS"
        if req.is_file():
            run([sys.executable, "-m", "pip", "install", "--user", "-r", str(req)])
    _patch_recon_ng(dest)
    log("Recon-ng prêt.")


# --------------------------------------------------------------------------- #
def show_status() -> None:
    exe = BIN / ("phoneinfoga.exe" if os.name == "nt" else "phoneinfoga")
    checks = [
        ("PhoneInfoga", exe.is_file()),
        ("SpiderFoot", (TOOLS / "spiderfoot" / "sf.py").is_file()),
        ("Recon-ng", (TOOLS / "recon-ng" / "recon-cli").is_file()),
    ]
    for name, ok in checks:
        print(f"  {'[OK]  ' if ok else '[   ] '} {name}")


INSTALLERS = {
    "phoneinfoga": install_phoneinfoga,
    "spiderfoot": install_spiderfoot,
    "recon-ng": install_recon_ng,
}


def main() -> int:
    ap = argparse.ArgumentParser(description="Installe les outils externes d'OsintForge.")
    ap.add_argument("--only", help="liste séparée par des virgules (phoneinfoga,spiderfoot,recon-ng)")
    ap.add_argument("--force", action="store_true", help="réinstalle même si présent")
    ap.add_argument("--list", action="store_true", help="affiche seulement l'état")
    args = ap.parse_args()

    if args.list:
        show_status()
        return 0

    targets = args.only.split(",") if args.only else list(INSTALLERS)
    for name in targets:
        name = name.strip()
        fn = INSTALLERS.get(name)
        if not fn:
            log(f"Outil inconnu: {name} (choix: {', '.join(INSTALLERS)})")
            continue
        print(f"\n=== {name} ===")
        try:
            fn(force=args.force)
        except Exception as e:
            log(f"ERREUR sur {name}: {type(e).__name__}: {e}")

    print()
    show_status()
    return 0


if __name__ == "__main__":
    sys.exit(main())
