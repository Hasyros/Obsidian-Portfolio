---
titre: "ProjectDiscovery (subfinder, httpx, naabu, dnsx)"
tags: [Outils, recon, subdomains, pipeline]
source: https://github.com/projectdiscovery
---

# ProjectDiscovery — subfinder · httpx · naabu · dnsx

Suite d'outils Go modulaires qui s'enchaînent en **pipeline** de reconnaissance
web moderne. Se termine souvent par [[Nuclei]].

> ⚠️ Recon sur périmètre autorisé uniquement. Cf. `README`.

## Installation
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# Kali : sudo apt install subfinder httpx-toolkit naabu dnsx
```

## Rôle de chaque outil
- **subfinder** — énumération **passive** de sous-domaines (sources OSINT/API).
- **dnsx** — résolution DNS de masse, filtre les sous-domaines vivants.
- **naabu** — scan de ports rapide (SYN), en amont de nmap.
- **httpx** — sonde HTTP : quels hosts répondent, code, titre, techno, longueur.

## Pipeline type
```bash
subfinder -d cible.tld -silent \
  | dnsx -silent \
  | httpx -silent -title -tech-detect -status-code \
  | tee live.txt
# puis scan de vulns
cat live.txt | nuclei -severity critical,high
# ports d'un host
naabu -host cible.tld -top-ports 1000 -silent | nmap -sV -iL -   # (via -)
```

## Réflexe
subfinder (passif) d'abord, puis httpx pour ne garder que le **vivant**, puis
naabu/nmap + Nuclei. Renseigner les clés API subfinder (`~/.config/subfinder/`)
pour plus de sources. Alternative sous-domaines : [[Amass]].
