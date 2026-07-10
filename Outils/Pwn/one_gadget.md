---
titre: "one_gadget"
tags: [Outils, pwn, libc, RCE]
source: https://github.com/david942j/one_gadget
---

# one_gadget

Trouve, dans une **libc**, les **« one-gadgets »** : des adresses qui, si on y
saute avec les bonnes contraintes de registres, exécutent directement
`execve("/bin/sh", …)`. Très utile quand on n'a qu'**un seul write/saut** (ex.
écrasement de `__malloc_hook`/`free_hook`/GOT).

> ⚠️ Sur binaires autorisés (CTF/lab). Cf. `README`.

## Installation
```bash
# nécessite Ruby
gem install one_gadget
```

## Utilisation
```bash
one_gadget /lib/x86_64-linux-gnu/libc.so.6
one_gadget ./libc.so.6            # la libc fournie par le challenge
```
Sortie type :
```
0xe3afe execve("/bin/sh", r15, r12)
constraints: [r15] == NULL && [r12] == NULL
```

## Réflexe
Choisir le gadget dont les **contraintes** sont satisfaites au moment du saut
(vérifier les registres avec [[GEF (GDB Enhanced Features)]]). `adresse one_gadget
= base libc + offset`. À combiner avec une fuite d'adresse libc.
