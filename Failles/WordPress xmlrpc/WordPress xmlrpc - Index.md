---
titre: "WordPress — xmlrpc.php"
tags: [Failles, wordpress, xmlrpc, index]
---

# WordPress — `xmlrpc.php`

> ⚠️ Cibles autorisées uniquement (cf. `README`). Write-ups appliqués : dossier `CTF/`.

`xmlrpc.php` est une **fonctionnalité légitime** de WordPress (XML-RPC pour trafic
inter-blogs, apps mobiles). **Ce n'est pas une vulnérabilité en soi**, mais selon
les **méthodes exposées**, elle devient un levier puissant : brute-force sans rate
limit, amplification, **SSRF** (`pingback.ping`).

> 🔑 Réflexe : sur **toute** cible WordPress, tester `/xmlrpc.php` +
> `system.listMethods` dès la reco.

## Fiches
- [[1 - Repérage (WordPress xmlrpc)]] — détecter, lister les méthodes exposées
- [[2 - Exploitation & techniques (WordPress xmlrpc)]] — brute-force `multicall`, `pingback.ping` (SSRF/DDoS)

Voisins : [[SSRF - Index]] (`pingback.ping` = SSRF), [[wpscan]]/[[WPProbe]] (audit WP).

## Remédiation
- Désactiver `xmlrpc.php` si inutilisé (plugin ou règle serveur).
- Désactiver spécifiquement `pingback.ping` et `system.multicall`.
- Rate limiting / MFA sur l'authentification.
