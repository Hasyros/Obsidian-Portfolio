---
titre: "Mythic"
tags: [Outils, C2, red-team, modulaire]
source: https://github.com/its-a-feature/Mythic
---

# Mythic

**Framework C2 modulaire, orienté web et Docker** (its-a-feature). Le serveur et
chaque **agent** / **profil C2** sont des conteneurs séparés → très extensible et
collaboratif. Interface web complète (tâches, fichiers, graphes). À côté de
[[AdaptixC2]], [[Sliver]], [[Havoc]].

> ⚠️ Outil offensif : **engagement red team autorisé / lab** uniquement. Cf. `README`.

## Installation
```bash
git clone https://github.com/its-a-feature/Mythic.git && cd Mythic
sudo ./mythic-cli install github https://github.com/MythicAgents/apollo   # installer un agent
sudo ./mythic-cli start                # démarre la stack Docker (UI web :7443)
sudo ./mythic-cli config get MYTHIC_ADMIN_PASSWORD     # identifiants admin
```

## Concepts
- **Agents** (Apollo, Medusa, Poseidon…) installés à la demande depuis *MythicAgents*.
- **C2 profiles** (HTTP, WebSocket, DNS…) installés séparément.
- Tout se pilote depuis l'**UI web** : créer un payload, un callback, ta.sker les agents.

## Réflexe
Le plus **modulaire** des quatre : on n'installe que les agents/profils voulus.
Idéal en équipe. Plus lourd à mettre en place (Docker) — pour un usage rapide,
[[Sliver]]/[[Havoc]].
