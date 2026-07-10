---
titre: "hcxtools (+ hcxdumptool)"
tags: [Outils, WiFi, PMKID, hashcat]
source: https://github.com/ZerBea/hcxtools
---

# hcxtools & hcxdumptool

Chaîne moderne pour capturer et **convertir** les données WPA vers le format de
[[Hashcat]]. **hcxdumptool** capture (dont **PMKID**, sans client connecté),
**hcxtools** convertit les captures en `.hc22000`.

> ⚠️ Réseau propre / mandaté uniquement. Cf. `README`.

## Installation
```bash
sudo apt install hcxtools hcxdumptool
```

## Utilisation
```bash
# 1) capture (PMKID + handshakes) sur l'interface moniteur
sudo hcxdumptool -i wlan0mon -o capture.pcapng

# 2) conversion vers le format Hashcat 22000
hcxpcapngtool -o hash.hc22000 capture.pcapng

# 3) crack GPU
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

## Réflexe
La **PMKID** (clé dérivée envoyée par l'AP) permet d'attaquer **sans** attendre
qu'un client se connecte. `-m 22000` remplace les anciens modes 2500/16800.
Capture « manuelle » alternative : [[aircrack-ng]] ; automatisation : [[Wifite]].
