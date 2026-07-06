---
titre: "Attacking GraphQL — Index (MOC)"
aliases:
  - "Attacking GraphQL — Index (MOC)"
plateforme: "Hack The Box Academy"
module: "Attacking GraphQL"
date: 2026-07-06
tags: [HTB, GraphQL, API, Pentest, MOC, Index, Notes]
---

# 🗺️ Attacking GraphQL — Index (MOC)

> Module HTB Academy 271 — 9 sections. GraphQL est un langage de requêtes pour API (alternative à REST) où **le client choisit les données**. Ce basculement de pouvoir vers le client est la source de toute la surface d'attaque.

## 📋 Table des vulnérabilités

| Vulnérabilité | Query / Vecteur | Impact | Note |
|---|---|---|---|
| Information Disclosure (introspection) | `__schema`, `__type` | Dump du schéma complet | [[03 - Introspection et Information Disclosure]] |
| IDOR | `user(username:"admin")`, sous-requête `posts{author{password}}` | Lecture de données d'autres users | [[04 - IDOR]] |
| SQL Injection | argument String injectable (`'`) → UNION | Dump de tables cachées hors GraphQL | [[05 - Injection Attacks]] |
| XSS | argument reflété dans messages d'erreur | Exécution JS (limité) | [[05 - Injection Attacks]] |
| DoS (nested queries) | boucle `User↔Post` imbriquée ×10 | Crash serveur (exponentiel) | [[06 - DoS et Batching]] |
| Batching / Alias Overloading | `[{query1},{query2},...]` ou alias ×1000 | Bypass rate limit → brute-force | [[06 - DoS et Batching]] |
| Mass Assignment (mutations) | `registerUser(input:{role:"admin"})` | Escalade de privilèges | [[07 - Mutations et Escalade de Privileges]] |

## 🧭 Cheminement d'attaque (résumé)

```
1. Trouver /graphql           → graphw00f -d -f, ffuf POST __typename
2. Fingerprint moteur          → graphw00f -f → Threat Matrix
3. Introspection (dump schéma) → __schema { types }, queryType, mutationType
4. Visualiser                  → GraphQL Voyager, InQL
5. Identifier les cibles       → types suspects, champs sensibles, arguments
6. Exploiter                   → IDOR, SQLi, mutations, over-fetching
```

→ Détail complet : [[01 - Méthodologie - Cheminement GraphQL]]

## 📂 Notes du module

**Concepts :**
- [[02 - Fondamentaux GraphQL]]
- [[03 - Introspection et Information Disclosure]]
- [[04 - IDOR]]
- [[05 - Injection Attacks]]
- [[06 - DoS et Batching]]
- [[07 - Mutations et Escalade de Privileges]]

**Arsenal & Référence :**
- [[08 - Outils GraphQL]]
- [[09 - Cheatsheet GraphQL]]
- [[10 - Skills Assessment Write-up]]

## 🔗 Liens avec d'autres modules

- [[API & Web Server - Index]] — SOAP/REST/WSDL, module complémentaire
- Module "Web Attacks" (IDOR en profondeur)
- Module "SQL Injection Fundamentals" (SQLi UNION avancée)
- Module "Broken Authentication" (brute-force, rate limit bypass)
