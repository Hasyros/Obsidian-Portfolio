---
titre: "SqliHunter (SQLi Auto-Auditor)"
tags: [Outils, "Mes scripts", SQLI, XSS, scanner, python]
source: "projet perso — code dans ce dossier (main.py, core/)"
---

# SqliHunter — SQLi Auto-Auditor

**Auditeur web automatisé** que j'ai développé (Python) : recon → crawl →
identification des **points d'injection** → probing rapide (SQLi/auth bypass) →
orchestration **sqlmap** avec bypass WAF → rapport. Couvre aussi XSS et NoSQLi.

> ⚠️ Le programme **exige une confirmation d'autorisation** au lancement. À
> n'utiliser que sur des cibles **explicitement autorisées** (cf. `README` du vault).
> **Ne jamais committer** `output/` (résultats/loot sur cibles) — voir `.gitignore`.

## Ce qu'il fait (mon code : `core/`)
- **scanner.py** — crawl multi-pages, **interception des chaînes de redirection**
  (capture des paramètres à la Burp), extraction formulaires / liens / endpoints JS.
- **analyzer.py** — **scoring** des points d'injection (nom de param, ORDER BY,
  champs d'auth, source, extension dynamique…), scoping strict, génération de
  fichiers de requêtes pour sqlmap.
- **prober.py** — détection rapide **avant** sqlmap : boolean-based, time-based
  (par SGBD), error-based, et **auth bypass** sur les formulaires de login.
- **sqlmap_runner.py** — lance sqlmap (`-r`/`-u`), **retry avec tamper scripts**
  (bypass WAF), watchdog de timeout, parsing des vulnérabilités.
- **recon.py / osint.py** — sous-domaines (crt.sh, subfinder, brute DNS),
  fingerprint techno, dirbuster, ports (nmap/socket), nuclei, WHOIS/DNS, wayback.
- **xss.py / nosqli.py** — détection XSS (contexte) et NoSQL injection.
- **loot.py / ai_agent.py / reporter.py** — collecte de données, corrélation
  heuristique, rapports **JSON + HTML**.

## Installation
```bash
cd SqliHunter
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Requis pour la phase d'exploitation :
sudo apt install sqlmap
# Optionnels (phase recon) : nmap, whois, dnsutils, subfinder, nuclei
```

## Utilisation
```bash
# audit simple (le programme demande la confirmation d'autorisation)
python main.py https://cible.tld

# options utiles
python main.py https://cible.tld --recon --osint      # recon + OSINT avant scan
python main.py https://cible.tld --full               # recon + osint + scan + IA
python main.py https://cible.tld --no-sqlmap          # scan + probe seulement
python main.py https://cible.tld --no-crawl           # page unique
python main.py https://cible.tld --level 3 --risk 2   # niveaux sqlmap
python main.py https://cible.tld --cookie "PHPSESSID=abc" --header "Authorization: Bearer x"
python main.py https://cible.tld --no-ssl-verify      # cibles à cert self-signed/legacy
python main.py https://cible.tld --top 10 --probe-top 20
```
Sorties dans `output/` : `report.json`, `report.html`, fichiers `request_*.txt`
(réutilisables : `sqlmap -r output/request_XXX.txt --batch`).

## Failles & outils liés
Théorie/techniques : [[SQLI - Index]] · [[XSS - Index]].
Outils orchestrés : sqlmap/nmap ([[CLI — ffuf, sqlmap, nmap, curl]]),
[[Nuclei]], [[ProjectDiscovery (subfinder, httpx, naabu)|subfinder]].
Voisins maison : [[Blind SQLi — Scripts d'automatisation]] (probing SQLi manuel),
[[XSS Finder]], [[OsintForge]] (le pendant OSINT).
