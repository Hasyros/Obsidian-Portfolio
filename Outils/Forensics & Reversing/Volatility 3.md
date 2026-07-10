---
titre: "Volatility 3"
tags: [Outils, forensics, memoire, DFIR]
source: https://github.com/volatilityfoundation/volatility3
---

# Volatility 3

**Forensics mémoire** : analyse un **dump de RAM** pour reconstruire ce qui tournait
sur la machine (processus, connexions réseau, commandes, hashes, fichiers en
mémoire). Incontournable pour les challenges **DFIR/memory**.

> ⚠️ Sur dumps autorisés uniquement. Cf. `README`.

## Installation
```bash
pipx install volatility3
# ou : git clone https://github.com/volatilityfoundation/volatility3 && pip install -e .
```

## Plugins clés
```bash
vol -f mem.raw windows.info                 # OS/build (identifier le profil)
vol -f mem.raw windows.pslist               # processus
vol -f mem.raw windows.pstree               # arbre des processus
vol -f mem.raw windows.cmdline              # lignes de commande
vol -f mem.raw windows.netstat              # connexions réseau
vol -f mem.raw windows.hashdump             # hashes SAM
vol -f mem.raw windows.filescan             # fichiers en mémoire
vol -f mem.raw windows.dumpfiles --virtaddr 0x...   # extraire un fichier
# Linux : plugins 'linux.*' (ex. linux.bash pour l'historique)
```

## Réflexe
Commencer par `windows.info`, puis `pstree`/`cmdline` (repérer le process
suspect), `netstat` (C2 ?), et dumper ce qui est intéressant. Les hashes →
[[Hashcat]] ; fichiers extraits → [[binwalk]]/[[exiftool]].
