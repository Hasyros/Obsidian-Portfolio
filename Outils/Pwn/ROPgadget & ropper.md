---
titre: "ROPgadget & ropper"
tags: [Outils, pwn, ROP, gadgets]
source: https://github.com/JonathanSalwan/ROPgadget
---

# ROPgadget & ropper

**Recherche de gadgets ROP** dans un binaire (pour contourner NX en chaînant des
bouts de code se terminant par `ret`). Deux outils équivalents, choisir selon
l'ergonomie.

> ⚠️ Sur binaires autorisés (CTF/lab). Cf. `README`.

## Installation
```bash
pip install ROPgadget
pip install ropper
```

## Utilisation
```bash
# ROPgadget
ROPgadget --binary ./chall                       # tous les gadgets
ROPgadget --binary ./chall | grep ': pop rdi'     # gadget précis
ROPgadget --binary ./chall --ropchain             # tente une chaîne toute faite

# ropper
ropper -f ./chall --search "pop rdi"
ropper -f ./chall --search "syscall"
ropper -f ./libc.so.6 --search "pop rsi; pop r15" # gadgets dans la libc
```

## Réflexe
Sur x86-64, viser `pop rdi ; ret` (1er argument), `pop rsi ; ret`, un
`ret` seul (alignement de pile), puis `system`/`execve`. Assembler la chaîne avec
`ROP()` de [[pwntools]]. Pour un shell rapide via la libc : [[one_gadget]].
