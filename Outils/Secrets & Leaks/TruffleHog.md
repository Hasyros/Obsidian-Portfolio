---
titre: "TruffleHog"
tags: [Outils, secrets, git, DevSecOps]
source: https://github.com/trufflesecurity/trufflehog
---

# TruffleHog

**Scanner de secrets** (Truffle Security). Cherche clés API, tokens et
identifiants dans du code/git/cloud, et **vérifie** s'ils sont **actifs**
(700+ détecteurs avec validation). C'est la référence historique que mon
[[Betterleaks]] cherche à surpasser.

> ⚠️ Scanner des cibles autorisées uniquement. Cf. `README`.

## Installation
```bash
# binaire (Go) / Docker / brew
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

## Utilisation
```bash
trufflehog git https://github.com/org/repo         # scanner un repo distant
trufflehog git file://. --since-commit HEAD~50      # historique local
trufflehog filesystem /chemin/projet                # dossier
trufflehog github --org=orgname                      # toute une org
trufflehog --only-verified git file://.             # ne garder que les secrets actifs
```

## Réflexe
`--only-verified` réduit drastiquement le bruit (secrets réellement valides). Un
`.git` exposé sur le web se récupère avec [[git-dumper]] puis se scanne. Comparer
les résultats avec [[Betterleaks]] et [[Gitleaks]].
