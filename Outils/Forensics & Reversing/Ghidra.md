---
titre: "Ghidra"
tags: [Outils, reversing, decompiler, NSA]
source: https://github.com/NationalSecurityAgency/ghidra
---

# Ghidra

**Suite de rétro-ingénierie de la NSA** (gratuite). Son atout : un
**décompilateur** qui reconstruit du pseudo-C lisible à partir de l'assembleur —
le must pour comprendre un binaire (crackme, malware, challenge reversing) sans
tout lire en ASM.

## Installation
```bash
sudo apt install ghidra          # Kali
# ou : télécharger le zip (releases GitHub) — nécessite un JDK 17+
```

## Flux type
1. **New Project** → *Import File* (le binaire) → laisser l'**auto-analyse**.
2. Double-clic sur le binaire → fenêtre **CodeBrowser**.
3. Volet **Symbol Tree** → `main` (ou `Functions`) ; le volet **Decompile**
   affiche le pseudo-C.
4. **L** pour renommer une variable/fonction, **;** pour commenter, **G** pour
   aller à une adresse, double-clic pour suivre un appel.
5. *Search → For Strings* pour repérer messages/format (souvent la piste du flag).

## Réflexe
Renommer au fur et à mesure (rend le décompilé lisible). Repérer les comparaisons
menant à « Correct » → contrainte à résoudre (à la main ou avec [[angr]]). Pour du
scripting/CLI, alternative : [[radare2 & Cutter]].
