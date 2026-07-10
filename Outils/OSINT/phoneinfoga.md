---
titre: "PhoneInfoga"
tags: [Outils, OSINT, telephone]
source: https://github.com/sundowndev/phoneinfoga
---

# PhoneInfoga

**OSINT sur numéro de téléphone.** À partir d'un numéro international, déduit le
**pays, la zone, l'opérateur et le type de ligne** (fixe/mobile/VoIP), puis cherche
des **empreintes** sur les moteurs de recherche (annonces, réseaux sociaux, fuites).

> ⚠️ Recherche d'infos publiques ; respecter la vie privée. Cf. `README`.

## Installation
```bash
# script d'install (binaire Go)
bash <(curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install)
sudo mv ./phoneinfoga /usr/local/bin/
# ou : brew install phoneinfoga  |  image Docker
```

## Utilisation
```bash
phoneinfoga scan -n "+33 6 12 34 56 78"      # scan CLI
phoneinfoga serve -p 8080                     # interface web -> http://localhost:8080
```

## Réflexe
Le type **VoIP** et l'opérateur orientent l'enquête. Enchaîner les *footprints*
(dorks générés) avec la [[Google Hacking Database (GHDB)]] et les recherches de
pseudo/email ([[Maigret]], [[holehe]]).
