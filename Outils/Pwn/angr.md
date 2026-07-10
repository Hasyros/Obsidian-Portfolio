---
titre: "angr"
tags: [Outils, pwn, reversing, symbolic-execution]
source: https://github.com/angr/angr
---

# angr

**Exécution symbolique & analyse binaire** en Python. Explore automatiquement les
chemins d'un programme pour trouver une entrée qui atteint un état voulu (ex.
« print Correct ») — parfait pour les challenges **reversing/crackme** au lieu de
lire tout le désassemblage à la main.

## Installation
```bash
pip install angr        # (venv recommandé : dépendances lourdes)
```

## Utilisation type (résoudre un crackme)
```python
import angr, claripy

proj = angr.Project('./chall', auto_load_libs=False)
flag = claripy.BVS('flag', 8*32)          # entrée symbolique
state = proj.factory.full_init_state(stdin=flag)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1),
              avoid=lambda s: b"Wrong"  in s.posix.dumps(1))

if simgr.found:
    print(simgr.found[0].posix.dumps(0))   # l'entrée qui mène à "Correct"
```

## Réflexe
Donner des adresses `find`/`avoid` précises (repérées dans
[[Ghidra]]/[[radare2 & Cutter]]) accélère et évite l'explosion combinatoire.
Contraindre les octets imprimables (`s.solver.add(...)`) si le flag est ASCII.
