---
titre: "exiftool"
tags: [Outils, forensics, métadonnées, stégano]
---

# exiftool

Lecture/écriture des **métadonnées** de fichiers (images, PDF, vidéos…). Employé
dans le CTF [[MidNight - Index|MidnightFlag]] pour inspecter des artefacts. Très
utile en **forensics / stéganographie** : un flag est souvent caché dans un champ
EXIF (`Comment`, `Artist`, GPS, etc.).

> ⚠️ Usage sur fichiers autorisés uniquement. Cf. `README`.

## Usage typique
```bash
exiftool image.jpg                 # dump de toutes les métadonnées
exiftool -Comment image.jpg        # un champ précis
exiftool -a -u -g1 fichier         # tout, y compris champs inconnus, groupés
exiftool -Comment="test" out.jpg   # écrire un champ (forger/injecter)
```

## Astuces CTF
- Chercher un flag : `exiftool fichier | grep -i flag`
- Coordonnées GPS d'une photo (OSINT géoloc).
- Combiner avec `binwalk`/`strings` si les métadonnées ne suffisent pas.

> Binaire Windows présent dans les sources du CTF (`exiftool.exe`), non versionné dans le vault.
