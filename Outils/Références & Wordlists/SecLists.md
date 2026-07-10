---
titre: "SecLists"
tags: [Outils, wordlists, fuzzing, référence]
source: https://github.com/danielmiessler/SecLists
---

# SecLists

**LA collection de wordlists** du pentester : noms d'utilisateurs, mots de passe,
répertoires/fichiers web, sous-domaines, payloads (XSS, SQLi, LFI…), patterns de
fuzzing. Le socle de tous les outils de brute-force/fuzzing du vault.

## Installation
```bash
sudo apt install seclists          # Kali -> /usr/share/seclists
# ou : git clone https://github.com/danielmiessler/SecLists
```

## Les listes que j'utilise le plus
```text
# Répertoires / fichiers web (avec [[CLI — ffuf, sqlmap, nmap, curl|ffuf]])
Discovery/Web-Content/directory-list-2.3-medium.txt
Discovery/Web-Content/raft-medium-directories.txt
Discovery/Web-Content/common.txt

# Sous-domaines (avec ffuf/amass)
Discovery/DNS/subdomains-top1million-110000.txt

# Mots de passe (avec [[John the Ripper]]/[[Hashcat]])
Passwords/Leaked-Databases/rockyou.txt
Passwords/Common-Credentials/10-million-password-list-top-1000.txt

# Utilisateurs (spraying AD -> [[Kerbrute]])
Usernames/xato-net-10-million-usernames.txt
```

## Réflexe
`rockyou.txt` est en `.gz` sur Kali : `gunzip /usr/share/wordlists/rockyou.txt.gz`.
Commencer petit (common) puis élargir (medium/big). Payloads d'attaque plutôt
dans [[PayloadsAllTheThings]].
