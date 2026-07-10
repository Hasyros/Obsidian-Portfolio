---
titre: "feroxbuster & gobuster"
tags: [Outils, Web, brute-force, content-discovery]
source: https://github.com/epi052/feroxbuster
---

# feroxbuster & gobuster

**Découverte de contenu web par brute-force** (répertoires, fichiers, vhosts,
sous-domaines). Complètent [[CLI — ffuf, sqlmap, nmap, curl|ffuf]] ; chacun a ses
adeptes.

> ⚠️ Sur cible autorisée uniquement. Cf. `README`.

## feroxbuster — récursif par défaut
```bash
sudo apt install feroxbuster
feroxbuster -u https://cible.tld -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
feroxbuster -u https://cible.tld -x php,txt,bak -d 2      # extensions + profondeur
feroxbuster -u https://cible.tld -s 200,301,302           # filtrer par code
```

## gobuster — rapide, multi-modes
```bash
sudo apt install gobuster
gobuster dir -u https://cible.tld -w common.txt -x php,html      # répertoires/fichiers
gobuster dns -d cible.tld -w subdomains-top1million-110000.txt    # sous-domaines
gobuster vhost -u https://cible.tld -w subdomains.txt --append-domain  # vhosts
```

## Réflexe
- **feroxbuster** : la **récursivité** auto est son gros atout.
- **gobuster** : pratique pour DNS/vhost.
- **ffuf** : le plus polyvalent (position `FUZZ`, filtrage fin) — cf. [[CLI — ffuf, sqlmap, nmap, curl]].
Wordlists : [[SecLists]] (`Discovery/Web-Content/`).
