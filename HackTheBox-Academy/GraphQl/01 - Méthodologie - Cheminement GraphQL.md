---
titre: "Méthodologie — Cheminement GraphQL en cas pratique"
aliases:
  - "Méthodologie — Cheminement GraphQL en cas pratique"
plateforme: "Hack The Box Academy"
module: "Attacking GraphQL"
date: 2026-07-06
tags: [HTB, GraphQL, Méthodologie, Recon, Checklist, Notes]
---

# 🧭 Méthodologie — Cheminement GraphQL en cas pratique

Lié : [[Attacking GraphQL - Index]] · [[08 - Outils GraphQL]] · [[09 - Cheatsheet GraphQL]]

> Ce document décrit le **cheminement de pensée complet** à suivre quand on identifie un service GraphQL sur une cible. Chaque phase renvoie vers la note détaillée correspondante.

---

## Phase 0 — Découvrir l'endpoint

**Objectif** : localiser le endpoint GraphQL (souvent `/graphql`, `/api/graphql`, `/gql`…).

**Automatique (rapide) :**
```bash
python3 /opt/graphw00f/main.py -d -f -t http://<TARGET>
```
graphw00f teste une liste de chemins courants et confirme en parlant GraphQL.

**Manuel (si graphw00f échoue ou pour trouver des endpoints cachés) :**
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/graphql.txt \
     -u http://<TARGET>/FUZZ \
     -X POST -H "Content-Type: application/json" \
     -d '{"query":"{__typename}"}' \
     -mr "__typename|data|errors"
```
Le POST avec `{__typename}` est la sonde universelle : si le serveur répond `{"data":{"__typename":"Query"}}`, c'est du GraphQL.

**Chemins courants à connaître :**
`/graphql`, `/graphql/`, `/api/graphql`, `/api/gql`, `/graphiql`, `/graphql/console`, `/v1/graphql`, `/v2/graphql`, `/query`, `/graphql.php`

**Vérifier si GraphiQL est exposé :** ouvrir `/graphql` dans un navigateur. Si tu vois un IDE interactif → GraphiQL activé = confort d'exploration + léger défaut de config (surface de debug exposée).

→ Détail : [[03 - Introspection et Information Disclosure]]

---

## Phase 1 — Identifier le moteur & profil de failles

**Objectif** : savoir quelle implémentation tourne (Apollo, Graphene, Hasura…) pour connaître les **défauts par défaut**.

```bash
python3 /opt/graphw00f/main.py -f -t http://<TARGET>/graphql
```

Le lien "Attack Surface Matrix" fourni pointe vers la **GraphQL Threat Matrix** :
- https://github.com/nicholasaleks/graphql-threat-matrix

**Ce qu'on regarde en priorité :**

| Fonctionnalité | Si activée | Impact |
|---|---|---|
| Introspection | Phase 2 possible | Dump complet du schéma |
| Field Suggestions | Plan B si introspection off | Fuite de noms de champs |
| Query Depth Limit | Si absent → DoS | Requêtes imbriquées exponentielles |
| Batching | Si activé → brute-force | Bypass rate limit |

**Audit automatique (complément) :**
```bash
python3 /opt/graphql-cop/graphql-cop.py -t http://<TARGET>/graphql
```
→ Liste toutes les faiblesses de config d'un coup (DoS, CSRF, introspection, batching…).

→ Détail : [[08 - Outils GraphQL]]

---

## Phase 2 — Cartographier le schéma (introspection)

**Objectif** : obtenir la **carte complète** — types, queries, mutations, champs, arguments.

**Ordre recommandé (du rapide au complet) :**

### 2.1 — Lister tous les types (les "objets" de l'API)
```graphql
{ __schema { types { name } } }
```
→ Trier : ignorer le bruit (`String`, `Int`, `Boolean`, `__*`) → repérer les **types métier** (`UserObject`, `PostObject`…) et surtout **l'intrus** (`SecretObject`, `FlagObject`, `ApiKeyObject`… tout ce qui "n'a rien à faire là").

### 2.2 — Lister les queries (les "portes de lecture") + arguments
```graphql
{ __schema { queryType { fields { name args { name type { name kind } } } } } }
```
→ Chaque query = un point d'entrée. Les arguments = points d'injection potentiels (SQLi) et leviers d'IDOR.

### 2.3 — Lister les mutations (les "portes d'écriture") + inputs
```graphql
{ __schema { mutationType { fields { name args { name type { name kind ofType { name } } } } } } }
```
→ Repérer les mutations type `register`, `create`, `update`. Les input types = candidats à mass assignment.

### 2.4 — Détailler les champs de chaque type intéressant
```graphql
{ __type(name: "UserObject") { fields { name type { name kind } } } }
```
Pour les **input types** des mutations (attention, `inputFields` et non `fields`) :
```graphql
{ __type(name: "RegisterUserInput") { inputFields { name type { name kind } } } }
```
→ Chercher : `password`, `role`, `isAdmin`, `flag`, `secret`, `token`, `key`, `msg`…

### 2.5 — Dump total + visualisation
Lancer la grosse `query IntrospectionQuery { ... }` (voir [[09 - Cheatsheet GraphQL]]) → coller le JSON dans **GraphQL Voyager** → obtenir le diagramme complet avec relations.

→ Détail : [[03 - Introspection et Information Disclosure]]

---

## Phase 3 — Identifier les vecteurs d'attaque

**Grille de décision** (parcourir chaque élément trouvé en Phase 2) :

| Ce que tu vois | Question à te poser | Attaque | Note |
|---|---|---|---|
| Un type/champ sensible non affiché dans le front (`password`, `secret`, `key`, `msg`) | Est-ce que je peux le demander ? | **Over-fetching** : ajouter le champ à la query | [[03 - Introspection et Information Disclosure]] |
| Une query avec un argument identifiant (`user(username:)`, `post(id:)`) | Et si je mets l'identifiant d'un autre ? | **IDOR direct** | [[04 - IDOR]] |
| Une relation vers un objet sensible (`posts { author { password } }`) | Puis-je atteindre le champ par un chemin détourné ? | **IDOR par sous-requête** | [[04 - IDOR]] |
| Un argument de type String | Est-ce qu'une `'` change le comportement ? | **SQLi** → test `'` → UNION | [[05 - Injection Attacks]] |
| Un argument reflété dans une erreur | Le HTML est-il encodé ? | **XSS** via message d'erreur | [[05 - Injection Attacks]] |
| Une boucle dans le schéma (A → B → A) | Le serveur limite-t-il la profondeur ? | **DoS par imbrication** | [[06 - DoS et Batching]] |
| Un login/auth en GraphQL + rate limit | Le batching est-il activé ? | **Batching brute-force** | [[06 - DoS et Batching]] |
| Une mutation `register/update` avec champ `role` ou `isAdmin` | Puis-je choisir mon propre rôle ? | **Mass assignment → escalade** | [[07 - Mutations et Escalade de Privileges]] |
| Des Global IDs en Base64 (`VXNlck9iamVjdDox` = `UserObject:1`) | Puis-je forger l'ID d'un autre ? | **IDOR par Global ID** | [[04 - IDOR]] |

---

## Phase 4 — Exploiter

Dérouler l'attaque identifiée. Points clés transversaux :

- **SQLi** : le nombre de colonnes du UNION = nombre de champs du type retourné (l'introspection te le donne gratuitement). `GROUP_CONCAT` obligatoire (GraphQL renvoie souvent un seul objet). La SQLi peut sortir du bac à sable GraphQL (tables non exposées = tables `flag`).
- **IDOR** : tester TOUS les chemins vers une donnée (query directe + sous-requêtes via relations).
- **Mutations** : hasher les mots de passe si nécessaire (`echo -n 'password' | md5sum`, attention au `-n`).
- **Relay Global IDs** : `echo -n "TypeObject:2" | base64` pour forger des IDs.

→ Détail par attaque : notes [[04 - IDOR]] à [[07 - Mutations et Escalade de Privileges]]

---

## Phase 5 — Post-exploitation & documentation

- Capturer les preuves (screenshots, requêtes/réponses).
- Vérifier si le flag/secret donne accès à d'autres fonctionnalités (une API key admin → `allCustomers(apiKey:"...")` par ex.).
- Documenter dans le vault Obsidian pour réutilisation.

---

## Arbre de décision rapide

```
Tu vois /graphql ?
├── OUI → graphw00f -f (moteur ?) → introspection activée ?
│   ├── OUI → dump schéma → types/queries/mutations/champs
│   │   ├── champ sensible ? → over-fetching / IDOR
│   │   ├── argument String ? → test SQLi (')
│   │   ├── mutation avec role ? → mass assignment
│   │   └── boucle dans le schéma ? → DoS
│   └── NON → field suggestions ? → deviner les noms
│       └── NON → ffuf / brute noms de queries
└── NON → ffuf POST __typename sur tous les chemins
```

---

## Réflexes transversaux (ponts avec d'autres modules)

- **SQLi GraphQL** = même technique que SQLi REST/SOAP : UNION, `GROUP_CONCAT`, `information_schema`. Seul l'enrobage change (JSON + arguments GraphQL).
- **Batching** = cousin de `system.multicall` (xmlrpc) et bypass `X-Forwarded-For` : trois façons de multiplier les opérations par requête HTTP.
- **Mass assignment** = même pattern que "champ `role` modifiable" sur REST/SOAP.
- **Over-fetching** = spécifique à GraphQL (le client choisit les champs → il peut demander ce que le front ne montre jamais).
- **Introspection** = équivalent du WSDL en SOAP, mais demandable directement à l'API.
