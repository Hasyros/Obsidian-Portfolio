---
titre: "theHarvester"
tags: [Outils, recon, OSINT, emails]
source: https://github.com/laramies/theHarvester
---

# theHarvester

**Collecte d'empreinte externe** (recon passif) : emails, noms, sous-domaines,
hosts et IP d'une organisation, agrégés depuis des moteurs de recherche et sources
OSINT. Idéal en **phase de reconnaissance initiale**.

> ⚠️ Recon sur périmètre autorisé uniquement. Cf. `README`.

## Installation
```bash
sudo apt install theharvester      # Kali
# ou : pipx install theHarvester
```

## Utilisation
```bash
theHarvester -d cible.tld -b all                     # toutes les sources
theHarvester -d cible.tld -b bing,duckduckgo,crtsh    # sources précises
theHarvester -d cible.tld -b all -f rapport           # export HTML/JSON
theHarvester -d cible.tld -b crtsh -l 500              # limiter les résultats
```

## Réflexe
Les **emails** récoltés → format de nommage (`prenom.nom@`) → listes d'usernames
pour [[Kerbrute]]/spraying. Les **sous-domaines** → [[ProjectDiscovery (subfinder, httpx, naabu)|httpx]].
Vérifier si un email est réutilisé ailleurs : [[holehe]].
