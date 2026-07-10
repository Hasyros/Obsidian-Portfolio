---
titre: "sherlock"
tags: [Outils, OSINT, recon]
---

# sherlock

Outil d'**OSINT** : recherche un **nom d'utilisateur** sur des centaines de
réseaux sociaux et plateformes, et renvoie les profils existants. Utile pour la
reconnaissance / les challenges OSINT.

> ⚠️ Recherche d'informations publiques ; respecter la vie privée et le cadre légal. Cf. `README`.

## Installation / usage
```bash
python3 sherlock.py <pseudo>              # depuis le repo cloné
# ou : pipx install sherlock-project
sherlock busterpiment                     # cherche le pseudo partout
sherlock user1 user2 --timeout 5          # plusieurs cibles
sherlock <pseudo> --csv                   # export CSV
```

## Réflexe
Croiser les résultats (même pseudo ≠ même personne). Enchaîner avec une recherche
manuelle sur les profils trouvés.

> Sources présentes dans le dossier CTF (`sherlock-master.zip`), non versionnées dans le vault.
