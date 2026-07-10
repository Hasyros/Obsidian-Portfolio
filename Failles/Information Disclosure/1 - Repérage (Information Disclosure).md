---
titre: "Information Disclosure — 1 - Repérage"
tags: [Failles, information-disclosure, fuzzing, reconnaissance]
---

# Information Disclosure — 1. Repérage

> ⬅ [[Information Disclosure - Index]]

## Fuzzer les paramètres cachés — le piège de la taille constante
```bash
# 1) SANS filtre : toutes les réponses ont la même taille (l'API renvoie le même
#    texte pour tout paramètre inconnu → pas de 404, l'info est noyée)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u 'http://TARGET:3003/?FUZZ=test_value'

# 2) FILTRER cette taille -> l'anomalie ressort
ffuf -w .../burp-parameter-names.txt \
     -u 'http://TARGET:3003/?FUZZ=test_value' -fs 19
# → id [Status: 200, Size: 38]   ← le bon paramètre
```
```bash
curl 'http://TARGET:3003/?id=1'
# [{"id":"1","username":"admin","position":"1"}]
```
> 🔑 Réflexe : mesurer la taille de la réponse « par défaut » puis `-fs` dessus.
> Idem pour un endpoint (404 custom) : filtrer sa taille.

## Fuzzer les endpoints / fichiers oubliés
```bash
feroxbuster -u http://CIBLE/ -x php,bak,old,txt,zip,git
ffuf -w seclists/Discovery/Web-Content/raft-medium-files.txt -u http://CIBLE/FUZZ
# cibles juteuses
/.git/HEAD  /.env  /backup.zip  /config.php.bak  /swagger.json  /actuator/env
/robots.txt  /sitemap.xml  /.well-known/  /server-status
```
`.git/` exposé → [[git-dumper]] ; puis scanner l'historique avec [[TruffleHog]].

## Lire ce que le serveur laisse fuiter
```bash
curl -sI http://CIBLE            # en-têtes Server, X-Powered-By, versions
# commentaires HTML/JS (dev notes, endpoints, creds)
curl -s http://CIBLE | grep -Ei '<!--|api|token|key|todo'
# messages d'erreur verbeux (stack traces, chemins absolus, requêtes SQL)
```

## Recon passive
[[Wayback Machine]] (anciens endpoints/secrets archivés) ·
[[Google Hacking Database (GHDB)]] (`site:cible filetype:env`).
> Exploitation (IDOR, énumération, escalade SQLi) : [[2 - Exploitation & techniques (Information Disclosure)]].
