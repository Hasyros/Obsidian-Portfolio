---
titre: "WordPress xmlrpc — 1 - Repérage"
tags: [Failles, wordpress, xmlrpc, reconnaissance]
---

# WordPress xmlrpc — 1. Repérage

> ⬅ [[WordPress xmlrpc - Index]]

## Détecter WordPress puis xmlrpc
```bash
# WordPress présent ?
curl -s http://blog.cible.com/ | grep -i 'wp-content\|wp-includes\|generator'
curl -s http://blog.cible.com/wp-login.php -o /dev/null -w '%{http_code}\n'
# xmlrpc présent ? (répond à une requête vide par une erreur XML)
curl -s http://blog.cible.com/xmlrpc.php
# → "XML-RPC server accepts POST requests only." = présent
```
Énumération WP plus large : [[wpscan]] / [[WPProbe]].

## Lister les méthodes exposées (l'étape clé)
```bash
curl -s -X POST http://blog.cible.com/xmlrpc.php \
  -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'
```
Méthodes à repérer dans la réponse :
| Méthode | Intérêt offensif |
|---|---|
| `wp.getUsersBlogs` | **brute-force** d'authentification (user+password) |
| `wp.getUsers`, `wp.getProfile` | énumération/infos une fois authentifié |
| `system.multicall` | **amplification** : des centaines d'essais en 1 requête |
| `pingback.ping` | **SSRF** / IP disclosure / DDoS |

## Énumérer les utilisateurs (auteurs)
```bash
# via l'API REST (souvent ouverte)
curl -s 'http://blog.cible.com/wp-json/wp/v2/users' | jq '.[].slug'
# via ?author=N (redirige vers /author/<login>/)
curl -sI 'http://blog.cible.com/?author=1' | grep -i location
```
Les logins obtenus alimentent le brute-force → [[2 - Exploitation & techniques (WordPress xmlrpc)]].
