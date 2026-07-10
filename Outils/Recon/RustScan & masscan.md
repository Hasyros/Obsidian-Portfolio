---
titre: "RustScan & masscan"
tags: [Outils, recon, port-scan, vitesse]
source: https://github.com/RustScan/RustScan
---

# RustScan & masscan

**Scan de ports ultra-rapide**, en amont de nmap. Idée : trouver **très vite** les
ports ouverts, puis laisser nmap faire l'énumération fine (`-sV -sC`) **seulement**
sur ces ports.

> ⚠️ Scan sur périmètre autorisé uniquement. Cf. `README`.

## RustScan — rapide + relais vers nmap
```bash
sudo apt install rustscan        # ou binaire/Docker (releases)
rustscan -a 10.10.10.10                      # tous les ports, très vite
rustscan -a 10.10.10.10 -- -sV -sC -oN nmap.txt   # -- passe la main à nmap
rustscan -a 10.10.10.10 -r 1-65535 --ulimit 5000  # plage + perf
```

## masscan — scan de très grandes plages
```bash
sudo apt install masscan
sudo masscan 10.10.0.0/16 -p1-65535 --rate 10000 -oL out.txt
sudo masscan 10.10.10.10 -p1-65535 --rate 1000
```

## Réflexe
Enchaînement classique : **RustScan/masscan (découverte) → nmap `-sV -sC` (détail)**.
Prudence avec `--rate` (un débit trop élevé sature le réseau/fausse les résultats).
Détail nmap : [[Nmap - Network Enumeration]].
