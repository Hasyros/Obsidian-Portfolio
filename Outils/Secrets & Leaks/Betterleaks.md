---
titre: "Betterleaks"
tags: [Outils, secrets, DevSecOps, git, scanner]
source: https://github.com/betterleaks/betterleaks
---

# Betterleaks

**Scanner de secrets** (créé par l'auteur de Gitleaks, en **Go**, MIT). Détecte
et **valide** clés API, tokens et identifiants exposés dans des dépôts git,
répertoires, archives et apps web. Pensé comme **remplaçant drop-in de Gitleaks**
(config et flags rétro-compatibles), avec moins de faux positifs.

> ⚠️ Scanner des dépôts/actifs qu'on est autorisé à analyser. Cf. `README`.

## Points forts
- Tokenisation **BPE** au lieu de l'entropie → **98,6 % de rappel** (CredData) vs ~70 %.
- **Validation de liveness** : requêtes HTTP asynchrones (via `Expr`) pour tester
  si un secret trouvé est encore actif.
- Détecte GitHub, GitLab, AWS, Slack… (des dizaines de types).

## Téléchargement / installation
```bash
# binaire Go
go install github.com/betterleaks/betterleaks@latest
# ou release / Docker (voir le repo) ; drop-in : mêmes fichiers .gitleaks.toml
```

## Utilisation
```bash
betterleaks detect  -s .                 # scanner l'historique git du repo courant
betterleaks dir     -s /chemin/projet    # scanner un dossier (hors git)
betterleaks detect  -s . --report-format json --report-path out.json
# CI/CD : GitHub Action dispo (dortort/betterleaks-action)
```

## Réflexe
Un secret trouvé + **validé actif** = priorité haute. Croiser avec la
[[Wayback Machine]] et la [[Google Hacking Database (GHDB)]] (secrets indexés/archivés).
