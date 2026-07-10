---
titre: "Maigret"
tags: [Outils, OSINT, username, dossier]
source: https://github.com/soxoj/maigret
---

# Maigret

**Constitution d'un dossier à partir d'un seul username.** Successeur spirituel de
sherlock, en plus profond : vérifie les comptes sur **3000+ sites** et **extrait
les infos** des pages trouvées (bio, autres pseudos, liens). Aucune clé API requise.

> ⚠️ Recherche d'infos publiques ; respecter la vie privée. Cf. `README`.

## Installation
```bash
pipx install maigret
# ou : git clone https://github.com/soxoj/maigret && pip install .
```

## Utilisation
```bash
maigret busterpiment                         # recherche simple
maigret busterpiment --html --pdf            # rapport HTML/PDF
maigret busterpiment -a                       # all sites (exhaustif, plus lent)
maigret busterpiment --top-sites 500          # limiter aux N sites les + courants
maigret --username user1 --username user2      # plusieurs cibles
```

## Réflexe
Maigret > [[sherlock]] quand on veut **extraire** de l'info, pas juste lister des
comptes. Croiser avec [[WhatsMyName]] (autre base). Un email associé → [[holehe]].
