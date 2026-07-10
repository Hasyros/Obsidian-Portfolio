---
titre: "Havoc"
tags: [Outils, C2, red-team, GUI]
source: https://github.com/HavocFramework/Havoc
---

# Havoc

**Framework C2 moderne avec GUI** (HavocFramework). Teamserver + client graphique
(Qt), agent **Demon** avec techniques d'évasion (sleep obfuscation, indirect
syscalls…). Alternative libre populaire à Cobalt Strike, dans le même esprit que
[[AdaptixC2]] et [[Sliver]].

> ⚠️ Outil offensif : **engagement red team autorisé / lab** uniquement. Cf. `README`.

## Installation
```bash
git clone https://github.com/HavocFramework/Havoc.git && cd Havoc
# dépendances (voir README) puis :
make ts-build && ./havoc server --profile profiles/havoc.yaotl   # teamserver
make client-build && ./havoc client                              # client GUI
```

## Flux type
1. Lancer le **teamserver** (profil yaotl : opérateurs, listeners).
2. Connecter le **client GUI**, créer un **listener** (HTTP/HTTPS/SMB).
3. **Payloads → Generate** l'agent Demon (exe/dll/shellcode).
4. Exécuter sur la cible de test → interagir (fichiers, process, BOF, pivot).

## Réflexe
GUI plus « clé en main » que Sliver pour débuter. Toujours dans le **scope**,
avec journalisation. Comparer avec [[Sliver]] (CLI/Go) et [[Mythic]] (modulaire/web).
