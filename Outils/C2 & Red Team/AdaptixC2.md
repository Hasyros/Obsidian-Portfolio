---
titre: "AdaptixC2"
tags: [Outils, C2, red-team, post-exploitation]
source: https://github.com/Adaptix-Framework/AdaptixC2
---

# AdaptixC2

**Framework de Command & Control** modulaire et extensible, pour l'émulation
d'adversaire et les opérations red team autorisées. Serveur (*teamserver*) en
**Go**, client **GUI multi-plateforme** en C++/Qt (Linux/Windows/macOS).

> ⚠️ Outil offensif dual-use : **uniquement** en engagement red team autorisé /
> lab perso. Cf. `README`.

## Fonctions clés
- Architecture **serveur/client multi-joueurs**, communications **chiffrées**
- **Listeners & agents en plugins** (Extender) — extensible côté client
- Agents Windows/Linux/macOS, stockage tâches & jobs, navigateurs de fichiers/process
- **SOCKS4/5**, port-forwarding local & reverse, support **BOF** (Beacon Object Files)

## Téléchargement / installation
```bash
git clone https://github.com/Adaptix-Framework/AdaptixC2.git
cd AdaptixC2
# script d'install serveur + client (Debian/Kali)
./pre_install_linux_all.sh
```
Prérequis : **Go 1.25+** pour compiler le serveur. Le teamserver tourne sur un
serveur Linux. Doc : https://adaptix-framework.gitbook.io/adaptix-framework/

## Utilisation (principe)
1. Lancer le **teamserver** (config du profil, port, mot de passe d'équipe).
2. Connecter le **client GUI**.
3. Créer un **listener** → générer un **agent** → l'exécuter sur la cible de test.
4. Piloter les agents (tâches, pivot SOCKS, port-forward, BOF).

## Réflexe
Comparable à Cobalt Strike / Havoc / Sliver. Rester strictement dans le **scope**
et journaliser toutes les actions (traçabilité de l'engagement).
