---
titre: "git-dumper"
tags: [Outils, secrets, git, web]
source: https://github.com/arthaud/git-dumper
---

# git-dumper

**Reconstruit un dépôt git exposé sur le web.** Quand un serveur laisse accessible
`https://cible/.git/`, git-dumper télécharge et **reconstitue le repo complet** —
souvent une mine d'or : code source, identifiants, historique, fichiers supprimés.

> ⚠️ Sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
pipx install git-dumper
# ou : git clone https://github.com/arthaud/git-dumper && pip install -r requirements.txt
```

## Utilisation
```bash
git-dumper https://cible.tld/.git/ ./sortie
cd sortie
git log --oneline           # historique
git show <commit>           # voir un changement (secret introduit puis "retiré" ?)
```

## Réflexe
Détecter d'abord l'exposition : `curl -s https://cible/.git/HEAD` renvoie
`ref: refs/heads/...` = vulnérable (à fuzzer avec [[feroxbuster & gobuster]]).
Après dump, scanner l'historique avec [[TruffleHog]]/[[Gitleaks]] : un secret
« supprimé » reste dans les anciens commits.
