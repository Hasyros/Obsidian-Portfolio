---
titre: "OsintForge"
tags: [Outils, "Mes scripts", OSINT, python, orchestrateur]
source: "projet perso — repo GitHub : https://github.com/Hasyros/OsintForge (code aussi dans ce dossier : osintforge/)"
repo: "https://github.com/Hasyros/OsintForge"
---

# OsintForge

**Orchestrateur OSINT multi-moteurs** que j'ai développé (Python), réécriture
propre de l'ancien OsintHunter (remplacé). À partir d'un **username / email / nom / téléphone /
domaine / image**, il détecte le type, interroge les moteurs adaptés en
parallèle, **vérifie les profils candidats** (deep-verify), déduplique et
exporte. **Repo :** https://github.com/Hasyros/OsintForge (licence MIT).

> ⚠️ OSINT sur des personnes = données réelles. Usage **légal et éthique**
> uniquement (self-OSINT, tests autorisés). **Ne jamais committer** base/cache/
> `config.yaml` (voir `.gitignore`).

## L'idée clé : le *finding typé*
Chaque résultat porte un `kind` — `profile` / `account` / `breach` / `archive` /
`dork` / `link` / `info` — et **seuls les `profile` candidats** passent la
vérification de page. Les fuites, emails enregistrés (Holehe), dorks, etc. ne
sont **jamais** forcés dans les heuristiques de profil. C'est ce qui corrige le
défaut d'OsintHunter (résultats mal étiquetés, faux positifs, crash sur email).

## Architecture (`osintforge/`)
- **engines/** — 19 moteurs (un fichier chacun) : Maigret, Sherlock, WhatsMyName,
  DirectProbe (intégré, haute précision), socialscan, Holehe, HIBP, GHunt, Epieos,
  GoogleDork, GHDB (dorks offline), PhoneInfoga, Wayback, DNS/Whois+crt.sh,
  SpiderFoot, Recon-ng, Jimpl/EXIF (GPS local), TinEye/Lens, Overpass Turbo.
- **pipeline.py** — orchestration : collecte → verify (profils) → dédup →
  boost multi-source → BDD.
- **verify.py** — *Deep Verify* : visite l'URL, suit les redirections, détecte
  soft-404 / murs de login / pages d'inscription, **score** la confiance
  (signal central = pseudo présent dans la page).
- **store.py** (SQLite : historique, comparaison), **reporting.py**
  (JSON/CSV/HTML/Maltego), **tui.py**, **detect.py**, **models.py**.

## Anti-faux-positifs (couches)
1. Routage par type (ne pas mal-tester).
2. Moteurs auto-vérifiés (WhatsMyName `e_string`/`e_code`, DirectProbe liste haute
   précision, socialscan « pris »).
3. Deep-verify : élimine 404/redirections/soft-404/murs de login…
4. Scoring → HIGH/MED/LOW + boost si ≥2 sources d'accord.
5. Notion *high-trust* (page qui n'existe que si le compte existe).

## Installation
```bash
git clone https://github.com/Hasyros/OsintForge.git
cd OsintForge
python -m pip install -r requirements.txt          # rich + requests suffisent
python -m pip install maigret sherlock-project holehe socialscan pillow  # optionnel
python tools/setup_tools.py                         # PhoneInfoga / SpiderFoot / Recon-ng
# Clés API facultatives : config.yaml OU variables d'env (HIBP_API_KEY, …)
```

## Utilisation
```bash
python -m osintforge                       # TUI interactive
python -m osintforge busterpiment          # scan direct (type auto-détecté)
python -m osintforge cible@mail.com        # email
python -m osintforge "Jean Dupont"         # nom
python -m osintforge +33612345678          # téléphone
python -m osintforge exemple.com           # domaine
python -m osintforge ./photo.jpg           # image → EXIF/GPS
python -m osintforge user --json out.json  # export
python -m osintforge exemple.com --no-verify
```

## Notes de conception
Deep-verify + findings typés réduisent fortement les faux positifs des outils
bruts. Moteurs orchestrés (fiches dédiées) :
[[sherlock]] · [[Maigret]] · [[holehe]] · [[phoneinfoga]] · [[WhatsMyName]] ·
[[Wayback Machine]] · [[Google Hacking Database (GHDB)]] · [[SpiderFoot]] ·
[[recon-ng]] · [[GHunt]] · [[Maltego]] · [[TinEye]] · [[Overpass Turbo]].
Voisins maison : [[SqliHunter]], [[Blind SQLi — Scripts d'automatisation]].
