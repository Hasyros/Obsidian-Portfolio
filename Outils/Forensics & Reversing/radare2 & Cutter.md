---
titre: "radare2 & Cutter"
tags: [Outils, reversing, disassembler]
source: https://github.com/radareorg/radare2
---

# radare2 & Cutter

**radare2** (r2) = framework de reversing **en ligne de commande** (ultra-puissant,
courbe d'apprentissage raide). **Cutter** = son **interface graphique** (avec
décompileur via plugin), plus accessible. Alternative à [[Ghidra]].

## Installation
```bash
sudo apt install radare2         # r2
# Cutter : AppImage (releases GitHub) ou : sudo apt install cutter
```

## radare2 — commandes de survie
```bash
r2 -A ./chall            # ouvrir + analyser
[0x...]> aaa             # (ré)analyser tout
[0x...]> afl             # lister les fonctions
[0x...]> s main ; pdf    # aller à main + désassembler la fonction
[0x...]> iz              # strings du binaire
[0x...]> VV              # vue graphe (navigation visuelle)
[0x...]> ood ; db main ; dc   # debug : ouvrir, breakpoint, continue
```

## Réflexe
Mémo : `a`=analyse, `p`=print/disasm, `s`=seek, `d`=debug, `i`=info. Pour un
confort proche de Ghidra sans quitter r2 → **Cutter** (+ plugin décompileur
`r2ghidra`). Débogage bas niveau (pwn) plutôt avec [[GEF (GDB Enhanced Features)]].
