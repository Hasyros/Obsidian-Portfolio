---
titre: "WPProbe"
tags: [Outils, Web, wordpress, enumeration, CVE]
source: https://github.com/Chocapikk/wpprobe
---

# WPProbe

**Énumération rapide et furtive de plugins/thèmes WordPress** (Chocapikk, Go).
Au lieu de brute-forcer, interroge la **REST API** (`?rest_route=/`) et recoupe
les routes exposées avec une base de signatures (**5000+ plugins**), puis **mappe
les plugins détectés sur des CVE connues** (avec version). Complète ma fiche
[[WordPress xmlrpc - Index]].

> ⚠️ Scan sur cible autorisée uniquement. Cf. `README`.

## Téléchargement / installation
```bash
go install github.com/Chocapikk/wpprobe@latest
# Kali : sudo apt install wpprobe
wpprobe update-db      # récupère la base de signatures (màj CI toutes les 2 h, pas de clé API)
```

## Utilisation
```bash
wpprobe scan -u https://cible.tld                 # mode furtif (REST API)
wpprobe scan -u https://cible.tld --mode bruteforce   # brute-force des chemins
wpprobe scan -u https://cible.tld --mode hybrid        # les deux
wpprobe scan -u https://cible.tld -o resultats.json    # sortie JSON (ou CSV)
```
Modes : **stealthy** (REST), **bruteforce** (chemins directs), **hybrid**.

## Limites & réflexe
Les plugins qui **n'exposent pas** de route REST, ou désactivés/cachés, peuvent
échapper au mode furtif → repasser en **hybrid**. Les CVE trouvées orientent
ensuite la recherche d'exploit ([[searchsploit]]).
