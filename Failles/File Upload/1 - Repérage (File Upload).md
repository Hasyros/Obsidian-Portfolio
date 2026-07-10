---
titre: "File Upload — 1 - Repérage"
tags: [Failles, file-upload, reconnaissance]
---

# File Upload — 1. Repérage

> ⬅ [[File Upload - Index]]

## Cartographier les 4 protections (leur absence = vulnérable)
Sur toute fonctionnalité d'upload, tester **chacune** :
| Contrôle | Comment le tester |
|---|---|
| **Extension** (black/whitelist) | uploader `.php`, puis `.phtml/.php5/.phar`, double `.jpg.php`, casse `.pHp` |
| **Content-Type** (header MIME) | garder le contenu PHP mais forcer `Content-Type: image/jpeg` (Burp) |
| **Contenu / magic bytes** | préfixer le PHP par `GIF89a;` ou vrais octets d'image |
| **Emplacement** connu ? | l'app révèle-t-elle l'URL ? sinon fuzzer `/uploads/`,`/files/`,`/media/` |

## Trouver l'emplacement du fichier
```bash
# l'app le révèle parfois dans la réponse : {"path":"/uploads/backdoor.php"}
# sinon, fuzzer les dossiers d'upload
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u 'http://CIBLE/FUZZ'
feroxbuster -u http://CIBLE/uploads/ -x php
# noms : original conservé ? renommé en hash ? horodaté (timestamp) ?
```

## Détecter la validation côté client uniquement
Si le filtrage d'extension se fait en JavaScript → **le contourner trivialement** :
uploader un fichier autorisé, puis **modifier la requête dans Burp/Caido** (renommer
en `.php`) avant l'envoi. Le serveur ne re-vérifie pas → bypass.

## Repérer le moteur (choisir la bonne extension)
```
serveur PHP   → .php .phtml .php5 .phar .pht
Java/Tomcat   → .jsp .jspx .war
ASP.NET/IIS   → .aspx .asp .config
Node          → rarement exécuté ; viser LFI/chemin, pas l'exécution directe
```
> Exploitation & payloads : [[2 - Exploitation & techniques (File Upload)]] ·
> [[3 - Payloads & bypass (File Upload)]].
