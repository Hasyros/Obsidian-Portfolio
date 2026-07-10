---
titre: "wpscan"
tags: [Outils, Web, wordpress, scanner, CVE]
source: https://github.com/wpscanteam/wpscan
---

# WPScan

**Scanner de sécurité WordPress** (Ruby). Énumère version du core, thèmes,
plugins, utilisateurs, et **mappe les vulnérabilités** connues via sa base
(clé API gratuite). Complète [[WPProbe]] (WPProbe = énum plugins rapide via REST ;
WPScan = scan complet + base de vulns + brute-force).

> ⚠️ Sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
sudo apt install wpscan          # Kali
# ou : gem install wpscan
# clé API gratuite : https://wpscan.com/api  (--api-token)
```

## Utilisation
```bash
wpscan --url https://cible.tld --api-token <TOKEN>            # scan de base + vulns
wpscan --url https://cible.tld -e vp,vt,u                      # plugins/thèmes vuln + users
wpscan --url https://cible.tld -e ap --plugins-detection aggressive  # tous les plugins
# brute-force d'un user trouvé (via xmlrpc)
wpscan --url https://cible.tld -U admin -P /usr/share/wordlists/rockyou.txt
```

## Réflexe
`-e u` pour énumérer les logins → puis brute-force ciblé. La détection `aggressive`
est bruyante mais complète. Contexte xmlrpc : [[WordPress xmlrpc - Index]] ; recherche
d'exploit sur une CVE trouvée : [[searchsploit]].
