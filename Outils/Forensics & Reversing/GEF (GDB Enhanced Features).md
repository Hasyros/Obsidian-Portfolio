---
titre: "GEF (GDB Enhanced Features)"
tags: [Outils, reversing, exploit-dev, gdb, pwn]
source: https://github.com/hugsy/gef
---

# GEF (GDB Enhanced Features)

**Surcouche GDB pour le reversing et l'exploit dev.** Un jeu de commandes qui
modernise GDB (contexte registres/pile/désassemblage, analyse de heap, helpers
d'exploitation) pour x86-32/64, ARM/AARCH64, MIPS, PowerPC, SPARC. Fichier unique,
Python 3, sans dépendances. Utile pour la partie reversing de mes CTF
(cf. [[pyinstxtractor]] côté Python, GEF côté binaire natif).

## Téléchargement / installation
```bash
# en une ligne (curl)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
# ou wget
bash -c "$(wget https://gef.blah.cat/sh -O -)"
# manuel
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
echo "source ~/.gdbinit-gef.py" >> ~/.gdbinit
```
Prérequis : **GDB ≥ 10** compilé avec **Python ≥ 3.10**.

## Commandes utiles
```gdb
gef> checksec              # protections du binaire (NX, PIE, canary, RELRO)
gef> vmmap                 # mapping mémoire
gef> pattern create 200    # motif cyclique (trouver l'offset d'overflow)
gef> pattern search $rsp   # retrouver l'offset dans le motif
gef> heap chunks           # état du tas (chunks, bins)
gef> telescope $rsp 20     # dump de pile "intelligent"
gef> got                   # entrées GOT/PLT
gef> ropper / ropgadget    # recherche de gadgets ROP (si installés)
```
Au lancement, GEF affiche automatiquement le **contexte** (registres, pile, code,
threads) à chaque arrêt.

## Réflexe
`checksec` d'abord (il détermine la stratégie d'exploitation), puis `pattern`
pour l'offset, `vmmap`/`telescope` pour naviguer. Alternatives : pwndbg, peda.
