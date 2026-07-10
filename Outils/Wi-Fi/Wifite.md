---
titre: "Wifite"
tags: [Outils, WiFi, automatisation]
source: https://github.com/derv82/wifite2
---

# Wifite

**Automatisation de l'audit Wi-Fi.** Orchestre [[aircrack-ng]], [[hcxtools]] et
reaver/bully pour attaquer automatiquement les réseaux à portée (WPA handshake,
PMKID, WPS) et lancer le crack. Le « tout-en-un » pratique.

> ⚠️ **Illégal sans autorisation.** Réseau propre / mandaté uniquement. Cf. `README`.

## Installation
```bash
sudo apt install wifite          # Kali : déjà présent
```

## Utilisation
```bash
sudo wifite                          # scanner puis choisir la cible (interactif)
sudo wifite --wpa                    # cibler seulement le WPA
sudo wifite --pmkid                  # attaque PMKID (sans client connecté)
sudo wifite -i wlan0mon --dict rockyou.txt   # interface + dictionnaire
```
Wifite met la carte en mode moniteur, capture (handshake/PMKID), et tente le crack.

## Réflexe
La **PMKID** ne nécessite pas de client connecté (pratique). Si le crack intégré
échoue, exporter et cracker sur GPU : [[hcxtools]] → [[Hashcat]] `-m 22000`.
Approche par ingénierie sociale (sans dico) : [[Fluxion]].
