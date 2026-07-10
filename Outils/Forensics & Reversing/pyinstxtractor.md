---
titre: "pyinstxtractor"
tags: [Outils, reversing, python, pyinstaller]
---

# pyinstxtractor

Extrait le contenu d'un exécutable **packé avec PyInstaller** (`.exe` Windows ou
ELF). Reconstruit l'archive `PYZ` et en sort les `.pyc`, à décompiler ensuite
pour retrouver le code Python d'origine. Employé dans le CTF
[[MidNight - Index|MidnightFlag]] sur `game.exe`.

> ⚠️ Reversing sur binaire autorisé uniquement. Cf. `README`.

## Chaîne de reversing
```bash
python pyinstxtractor.py game.exe        # -> dossier game.exe_extracted/
# récupérer le point d'entrée (.pyc principal) dans le dossier extrait
# puis décompiler :
pip install decompyle3 uncompyle6         # ou pycdc pour Python récent
decompyle3 game.exe_extracted/main.pyc > main.py
```

## Notes
- Les `.pyc` extraits peuvent manquer de l'en-tête magic selon la version de
  Python : le recopier depuis un `.pyc` de la même version si besoin.
- Pour Python 3.9+, `pycdc`/`pycdas` sont souvent plus fiables que uncompyle6.

> Script conservé dans `CTF/MidNight/reversing (game.exe)/pyinstxtractor.py`.
