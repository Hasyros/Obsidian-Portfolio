---
titre: "OsintHunter"
tags: [Outils, "Mes scripts", OSINT, python, orchestrateur]
source: "projet perso — code dans ce dossier (osint_hunter/)"
---

# OsintHunter

**Orchestrateur OSINT multi-moteurs** que j'ai développé (Python). À partir d'un
**username / email / nom / téléphone**, il interroge ~22 moteurs en parallèle,
**vérifie chaque résultat** (deep-verify), **corrèle** les comptes entre
plateformes, met en cache, historise en base et expose une **API**. Interfaces :
TUI interactive, CLI, et serveur FastAPI.

> ⚠️ OSINT sur des personnes = données réelles. Usage **légal et éthique**
> uniquement, dans le respect de la vie privée (cf. `README` du vault).
> **Ne jamais committer** la base/cache/logs (voir `.gitignore` du projet).

## Architecture (mon code : `osint_hunter/`)
- **engines/** — 22 moteurs : Maigret, Sherlock, Blackbird, NExfil, socialscan,
  Holehe, HIBP, LeakCheck, BreachDirectory, WhatsMyName, DirectProbe,
  theHarvester, GoogleDork, PeopleSearch, EmailFinder, Wayback, GitHub API,
  DNS/Whois, Hunter.io, Dehashed, Epieos, PhoneInfoga.
- **scanner.py** — orchestration (collecte → dédup → verify → corrélation → BDD).
- **verify.py** — *Deep Verify* : visite chaque URL, suit les redirections,
  détecte soft-404 / murs de login / pages d'inscription, **score** la confiance
  (HIGH/MEDIUM/LOW), boost multi-source.
- **correlation.py** — liens inter-comptes : **avatars** (perceptual hash),
  **bios** (similarité), **liens partagés**, emails.
- **cache.py** (TTL), **database.py** (SQLite : historique, comparaison de scans),
  **api.py** (FastAPI), **tui.py**, **cli.py**, **config.py**, système de **plugins**.

## Installation
```bash
cd OsintHunter
python -m venv env && source env/bin/activate      # (env/ ignoré par git)
pip install -r requirements.txt
# Moteurs externes optionnels (installés à part, marqués "OK" s'ils sont là) :
pipx install maigret holehe socialscan            # ex.
# Blackbird / NExfil : cloner à côté du projet si on veut ces moteurs.
# Clés API (facultatives) : config.yaml OU variables d'env OSINT_*
export OSINT_HIBP_API_KEY=...  OSINT_GITHUB_TOKEN=...
```

## Utilisation
```bash
# TUI interactive (mode par défaut)
python -m osint_hunter

# CLI non interactive
python -m osint_hunter scan "username"                 # détection auto du type
python -m osint_hunter scan "cible@mail.com" -t email
python -m osint_hunter scan "Jean Dupont" -t name -f html  # export HTML
python -m osint_hunter scan user -e maigret,sherlock       # moteurs choisis
python -m osint_hunter scan user --no-verify --no-cache
python -m osint_hunter engines        # lister les moteurs et leur dispo
python -m osint_hunter history        # historique des scans
python -m osint_hunter compare 3 7    # diff entre 2 scans (nouveaux/supprimés)
python -m osint_hunter stats

# Serveur API (FastAPI)
python -m osint_hunter api            # http://127.0.0.1:8400/docs
```
**Proxy / OPSEC** : `--proxy socks5://127.0.0.1:9050` (Tor) — le proxy est
appliqué au deep-verify, aux moteurs de scraping et au téléchargement d'avatars.
**API** : définir `api_server.api_key` (ou `OSINT_API_KEY`) pour exiger `X-API-Key`.

## Notes de conception
Deep-verify + corrélation réduisent fortement les faux positifs des outils bruts.
Les moteurs bruts que j'orchestre ont leurs propres fiches :
[[sherlock]] · [[Maigret]] · [[holehe]] · [[phoneinfoga]] · [[WhatsMyName]] ·
[[theHarvester]] · [[Wayback Machine]] · [[Google Hacking Database (GHDB)]].
Voisin maison : [[Blind SQLi — Scripts d'automatisation]], [[UUID — Attaque temporelle (v1)]].
