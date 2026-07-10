---
titre: "pycdc (décompilation .pyc)"
tags: [Outils, reversing, python, pyc]
source: https://github.com/zrax/pycdc
---

# pycdc / pycdas — décompiler du Python

Reconstruit du **code source Python** à partir de bytecode `.pyc`. Suite logique de
mon [[pyinstxtractor]] : PyInstaller → `.pyc` extraits → **pycdc** → `.py` lisible.
`pycdc` gère les versions récentes de Python là où uncompyle6/decompyle3 s'arrêtent.

> ⚠️ Sur binaires autorisés uniquement. Cf. `README`.

## Installation
```bash
git clone https://github.com/zrax/pycdc && cd pycdc
cmake . && make            # produit ./pycdc et ./pycdas
# alternatives Python : pip install decompyle3   (Py<=3.8)  |  uncompyle6 (Py<=3.8)
```

## Utilisation
```bash
./pycdc  fichier.pyc > fichier.py     # décompilation (source)
./pycdas fichier.pyc                  # désassemblage du bytecode (si la décomp échoue)
```

## Réflexe
Chaîne complète d'un `.exe` Python : [[pyinstxtractor]] `game.exe` → repérer le
`.pyc` du point d'entrée → `pycdc`. Si `pycdc` cale sur une construction récente,
lire le **désassemblage** `pycdas` et reconstituer la logique à la main.
