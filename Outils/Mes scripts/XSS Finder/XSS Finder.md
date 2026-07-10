---
titre: "XSS Finder"
tags: [Outils, XSS, payloads, fuzzing]
---

# XSS Finder

Outil personnel de **recherche et de sélection de payloads XSS**. Une page HTML
autonome (`xss-finder.html`, titre *XSS Payload Finder*) qui agrège des milliers
de payloads dans un tableau filtrable par **recherche libre** (payload,
description, tags) et par contexte. Référencé depuis [[XSS - Index]]
et [[XSS - Index]].

> ⚠️ Payloads offensifs — usage strictement limité aux cibles autorisées. Cf. `README`.

## Contenu

- **`xss-finder.html`** — l'outil : interface de recherche + tableau `PAYLOADS`
  (chaque entrée a `id`, `payload`, `desc`, `tags`). Certains payloads sortent
  d'un `<title>`, réécrivent le DOM (faux formulaire de login), etc.
- **`check.py`** — script de contrôle qualité : détecte les *template literals*
  (backticks) contenant un `${...}` non échappé qui casserait le tableau JS.
- **`_sources/`** — ~42 collections de payloads brutes agrégées
  (PayloadBox `pbox_*`, SecLists `seclists_*`, PortSwigger, brutelogic, polyglots,
  bypass CSP/Cloudflare/ModSecurity, frameworks Angular/React/Vue/Svelte/jQuery…).
  `build_bulk.py` / `inject_bulk.py` construisent `bulk.json` puis injectent les
  payloads dans le tableau de l'outil.
- **`Payloads.txt`**, **`Lien XSS.txt`** — payloads et liens de référence en vrac.

## Utilisation

Ouvrir `xss-finder.html` dans un navigateur, filtrer par mot-clé ou par contexte
(ex. `csp`, `no-parens`, `angular`, `blind`), copier le payload adapté.

Pour régénérer la base à partir des sources :
```bash
python _sources/build_bulk.py     # agrège les _sources/ -> bulk.json
python _sources/inject_bulk.py    # injecte bulk.json dans xss-finder.html
python check.py                   # vérifie l'intégrité du tableau PAYLOADS
```
