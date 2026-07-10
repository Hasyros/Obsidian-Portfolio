---
titre: "proxychains & sshuttle"
tags: [Outils, pivoting, socks, ssh]
source: https://github.com/rofl0r/proxychains-ng
---

# proxychains & sshuttle

Deux façons de router son trafic à travers un pivot.

## proxychains(-ng) — forcer un outil à passer par un SOCKS
```bash
sudo apt install proxychains4
# /etc/proxychains4.conf : mettre en dernier
#   socks5  127.0.0.1 1080
proxychains4 nmap -sT -Pn 172.16.0.5        # -sT obligatoire (pas de SYN via SOCKS)
proxychains4 firefox
proxychains4 impacket-secretsdump ...
```
Le SOCKS 1080 provient d'un tunnel [[chisel]] ou d'un `ssh -D`.

## sshuttle — « VPN du pauvre » via SSH
Route tout un sous-réseau via une session SSH, **sans proxychains** :
```bash
sudo apt install sshuttle
sshuttle -r user@10.10.14.3 172.16.0.0/24     # accès direct au subnet interne
sshuttle -r user@pivot 0.0.0.0/0              # tout le trafic (full tunnel)
```

## Réflexe
- **proxychains** = universel mais lent (TCP connect only, pas d'ICMP/ping).
- **sshuttle** = pratique si on a un accès SSH sur le pivot.
- Pour la vitesse et lancer n'importe quel outil sans contrainte : [[ligolo-ng]].
