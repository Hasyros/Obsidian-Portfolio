---
titre: "binwalk"
tags: [Outils, forensics, firmware, carving, stegano]
source: https://github.com/ReFirmLabs/binwalk
---

# binwalk

**Analyse et extraction de fichiers imbriqués.** Repère des signatures (magic
bytes) à l'intérieur d'un fichier/firmware et **extrait** les données cachées :
archives, images, systèmes de fichiers… Réflexe en **forensics** et **stégane**
(un fichier caché dans un autre).

> ⚠️ Sur fichiers autorisés uniquement. Cf. `README`.

## Installation
```bash
sudo apt install binwalk
# extraction avancée : sudo apt install binwalk-extractor  (ou 'sasquatch' pour squashfs)
```

## Utilisation
```bash
binwalk fichier.bin              # lister les signatures détectées
binwalk -e fichier.bin           # extraire (-> _fichier.bin.extracted/)
binwalk -Me firmware.bin         # extraction récursive (matriochka)
binwalk --dd='.*' fichier         # tout dumper
```

## Réflexe
Sur une image « bizarre » ou un firmware : `binwalk` puis `binwalk -e`. Si rien,
compléter avec `foremost`, `strings`, et les outils dédiés stégane
([[Stéganographie (steghide, zsteg, stegsolve)]]). Métadonnées : [[exiftool]].
