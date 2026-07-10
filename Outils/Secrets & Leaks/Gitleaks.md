---
titre: "Gitleaks"
tags: [Outils, secrets, git, DevSecOps]
source: https://github.com/gitleaks/gitleaks
---

# Gitleaks

**Scanner de secrets git** (Go), très répandu en **CI/CD**. Détecte les
identifiants dans l'historique via des règles regex + entropie. C'est l'outil dont
[[Betterleaks]] est le successeur *drop-in* (config `.gitleaks.toml` compatible).

> ⚠️ Scanner des cibles autorisées uniquement. Cf. `README`.

## Installation
```bash
sudo apt install gitleaks
# ou binaire (releases GitHub) / Docker / brew install gitleaks
```

## Utilisation
```bash
gitleaks detect --source .                     # scanner l'historique git du repo
gitleaks detect --source . -v                  # verbeux (montre les findings)
gitleaks detect --source . -r rapport.json -f json
gitleaks dir ./projet                          # dossier hors git
gitleaks protect --staged                      # pré-commit (bloquer avant push)
```

## Réflexe
Idéal en **hook pré-commit** pour ne pas pousser de secret. Beaucoup de faux
positifs sur l'entropie → affiner `.gitleaks.toml`, ou tester
[[Betterleaks]]/[[TruffleHog]] (moins de bruit, validation).
