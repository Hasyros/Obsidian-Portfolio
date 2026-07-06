---
titre: "Fondamentaux GraphQL (SOAP vs REST vs GraphQL)"
aliases:
  - "Fondamentaux GraphQL (SOAP vs REST vs GraphQL)"
plateforme: "Hack The Box Academy"
module: "Attacking GraphQL"
date: 2026-07-06
tags: [HTB, GraphQL, API, REST, SOAP, Fondamentaux, Notes]
---

# 📘 Fondamentaux GraphQL

Lié : [[Attacking GraphQL - Index]] · [[03 - Introspection et Information Disclosure]]

---

## Qu'est-ce que GraphQL

GraphQL est un **langage de requêtes pour API**, alternative à REST, créé par Facebook (2015). Le client formule une requête décrivant **exactement** les données voulues, et le serveur ne renvoie que ça — ni plus, ni moins.

**Deux caractéristiques fondamentales :**
1. **Un endpoint unique** : tout passe par `/graphql` (contrairement à REST qui a `/users`, `/posts`, `/users/2`…).
2. **Le client choisit les champs** : le serveur définit des **types** (structures), le client pioche les **fields** qui l'intéressent. → C'est ce basculement de pouvoir qui crée la surface d'attaque.

## Comparaison SOAP / REST / GraphQL

| | SOAP | REST | **GraphQL** |
|---|---|---|---|
| Endpoints | 1 (`/wsdl`) | multiples (`/users`, `/posts`…) | **1** (`/graphql`) |
| Format | XML obligatoire | JSON (souvent) | JSON |
| Découverte schéma | fichier WSDL | fuzzing d'endpoints | **introspection** |
| Qui choisit les données | serveur | serveur | **client** |
| Injection via | champs du body XML | params GET/POST | **arguments de query** |
| Écriture | opérations SOAP | POST/PUT/DELETE | **mutations** |

## Anatomie d'une requête

```graphql
{                          ← accolades = query de lecture
  users {                  ← nom de la query (une "porte" du schéma)
    id                     ← champ demandé
    username               ← champ demandé
    role                   ← champ demandé
  }
}
```

**Principe du miroir** : la réponse épouse exactement la structure de la requête.

```json
{
  "data": {
    "users": [
      { "id": 1, "username": "admin", "role": "admin" },
      { "id": 2, "username": "test",  "role": "user" }
    ]
  }
}
```

## Arguments (filtrage)

```graphql
{ user(username: "admin") { id username role } }
```

`(username: "admin")` filtre le résultat. L'argument est une **valeur contrôlée par le client** → point d'injection potentiel (comme un paramètre GET en REST).

## Sous-requêtage (relations)

Un champ peut être un **objet lié** à un autre type :

```graphql
{
  posts {
    title
    author {         ← author est un UserObject, pas un scalaire
      username
      password       ← on traverse la relation pour atteindre un champ sensible
    }
  }
}
```

Les relations = des **chemins d'accès** vers des données sensibles (IDOR par sous-requête).

## Types d'opérations

| Opération | Rôle | Syntaxe |
|---|---|---|
| **query** | Lire des données | `{ users { ... } }` ou `query { ... }` |
| **mutation** | Créer/modifier/supprimer | `mutation { registerUser(input: {...}) { ... } }` |
| **subscription** | Écouter en temps réel (WebSocket) | `subscription { newPost { title } }` |

## Vocabulaire clé

- **Type** : structure de données (ex. `UserObject` avec ses champs `id`, `username`, `password`…). Équivalent d'une classe en POO.
- **Field** : champ d'un type (une propriété). Peut être **scalaire** (`String`, `Int`, `Boolean`) ou un **objet** (relation).
- **Resolver** : fonction backend qui exécute la logique d'une query/mutation (va chercher en base, vérifie les droits…). C'est dans le resolver que se trouvent les vulnérabilités (SQLi, absence d'auth…).
- **Schema** : l'ensemble des types, queries et mutations définis. L'introspection permet de le lire.
- **Relay / Connection / Edge / Node** : convention de pagination (Graphene/Relay). Un champ de type Connection contient `edges → node → objet réel`.
- **Global ID** : identifiant encodé en Base64 au format `TypeObject:n` (convention Relay). Décodable et forgeable : `echo -n "UserObject:2" | base64`.
