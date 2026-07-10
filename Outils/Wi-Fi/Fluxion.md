---
titre: "Fluxion"
tags: [Outils, WiFi, WPA, evil-twin, social-engineering]
source: https://github.com/FluxionNetwork/fluxion
---

# Fluxion

**Audit Wi-Fi WPA/WPA2 par ingénierie sociale** (successeur de linset). Ne
brute-force pas le handshake : monte un **point d'accès jumeau (evil twin)** et
un **portail captif** qui demande la clé Wi-Fi à l'utilisateur, puis **valide** la
clé saisie contre le handshake capturé. Dans les dépôts Kali 2026.1.

> ⚠️ **Illégal sans autorisation écrite.** N'auditer que **son propre** réseau ou
> un réseau explicitement mandaté. Cf. `README`.

## Principe de l'attaque
1. Scan des réseaux cibles.
2. **Handshake Snooper** : capture le handshake WPA (déauth pour forcer une reconnexion).
3. **Captive Portal** : AP pirate imitant le SSID légitime + DNS spoof + fausse
   page de login, brouillage de l'AP d'origine, validation de la clé, arrêt auto
   quand la bonne clé est saisie.

## Téléchargement / installation
```bash
git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion
sudo ./fluxion.sh          # installe les dépendances manquantes automatiquement
sudo ./fluxion.sh -i       # installer seulement les dépendances
```
Arch/BlackArch : `pacman -S fluxion`.

## Prérequis
- Linux (Kali recommandé), **adaptateur Wi-Fi externe** supportant le mode moniteur + injection.
- ❌ Ne fonctionne **pas** sous WSL (pas d'accès à l'interface Wi-Fi).

## Réflexe
Le succès dépend de l'ingénierie sociale (victime qui saisit la clé). Vérifier la
légalité et le **mandat écrit** avant toute manip — l'evil twin affecte de vrais
utilisateurs.
