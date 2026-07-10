---
titre: "GHunt"
tags: [Outils, OSINT, google, email]
source: https://github.com/mxrch/GHunt
---

# GHunt

**Framework OSINT offensif Google** (mxrch). À partir d'un **email Gmail** / d'un
**Gaia ID**, récupère : nom du compte, photo, avis Google Maps, calendriers/docs
publics, Gaia ID… Un des meilleurs outils pour pivoter sur un compte Google.

> ⚠️ Recherche d'infos publiques ; respecter la vie privée. Cf. `README`.

## Installation
```bash
pipx install ghunt
```

## Authentification (une fois)
```bash
ghunt login          # via l'extension "GHunt Companion" ou cookies base64
```

## Utilisation
```bash
ghunt email cible@gmail.com        # infos sur l'email (nom, photo, Gaia ID)
ghunt gaia 1234567890               # infos via Gaia ID
ghunt drive <file_id>               # infos sur un fichier/dossier Drive public
```

## Réflexe
Nécessite une **session Google** valide (comptes jetables recommandés). Le nom/
photo obtenus → reverse image ([[TinEye]]) et énumération de pseudos ([[Maigret]]).
