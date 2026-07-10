---
titre: "Amass"
tags: [Outils, recon, subdomains, OWASP]
source: https://github.com/owasp-amass/amass
---

# Amass (OWASP)

**Énumération de sous-domaines en profondeur** et cartographie de surface d'attaque
externe. Plus exhaustif (mais plus lent) que [[ProjectDiscovery (subfinder, httpx, naabu)|subfinder]] :
combine sources passives, DNS, certificats, et peut faire du **brute-force**.

> ⚠️ Recon sur périmètre autorisé uniquement. Cf. `README`.

## Installation
```bash
sudo apt install amass
# ou : go install github.com/owasp-amass/amass/v4/...@master
```

## Utilisation
```bash
amass enum -passive -d cible.tld                     # rapide, discret (OSINT only)
amass enum -active  -d cible.tld -brute               # + résolution + brute-force
amass enum -d cible.tld -o subs.txt                   # sortie fichier
amass intel -d cible.tld                              # infos org (ASN, plages)
amass db -names -d cible.tld                          # relire les résultats stockés
```

## Réflexe
`-passive` pour rester discret ; `-active -brute` quand on veut la **couverture
maximale**. Renseigner les clés API (`~/.config/amass/config.ini`) pour plus de
sources. Enchaîner la sortie vers `httpx | nuclei`.
