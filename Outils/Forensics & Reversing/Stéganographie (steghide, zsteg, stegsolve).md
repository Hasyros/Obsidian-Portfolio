---
titre: "Stéganographie (steghide, zsteg, stegsolve)"
tags: [Outils, forensics, stegano, CTF]
source: https://github.com/zed-0xff/zsteg
---

# Stéganographie — steghide · zsteg · stegsolve

Trousse pour extraire des données **cachées dans des images/audio** (classique en
CTF). Chaque outil couvre un cas.

> ⚠️ Sur fichiers autorisés uniquement. Cf. `README`.

## steghide — JPEG/WAV, avec passphrase
```bash
sudo apt install steghide
steghide info secret.jpg                       # y a-t-il des données cachées ?
steghide extract -sf secret.jpg                # extraire (demande la passphrase)
# passphrase inconnue -> brute-force avec stegseek (très rapide)
stegseek secret.jpg /usr/share/wordlists/rockyou.txt
```

## zsteg — PNG/BMP (LSB)
```bash
sudo gem install zsteg
zsteg image.png                                # teste tous les canaux LSB
zsteg -a image.png                             # tout, exhaustif
zsteg -E b1,rgb,lsb,xy image.png > out.bin      # extraire un canal précis
```

## stegsolve — inspection visuelle
Appli Java : parcourir les **plans de bits** et canaux couleur (révèle un texte/QR
caché dans un plan). `java -jar stegsolve.jar`.

## Réflexe
Ordre CTF image : [[exiftool]] → `strings` → [[binwalk]] `-e` → steghide/zsteg →
stegsolve. Ne pas oublier de tester `rockyou` comme passphrase (stegseek).
