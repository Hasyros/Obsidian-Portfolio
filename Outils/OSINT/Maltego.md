---
titre: "Maltego"
tags: [Outils, OSINT, graph, cartographie]
source: https://www.maltego.com/
---

# Maltego

**Cartographie OSINT en graphe.** Outil visuel où l'on part d'une entité (domaine,
email, personne, IP…) et où l'on lance des **« transforms »** qui découvrent et
relient de nouvelles entités. Idéal pour **visualiser** les liens d'une enquête
là où les outils CLI donnent des listes brutes.

> ⚠️ Recherche d'infos publiques ; respecter la vie privée. Cf. `README`.

## Installation
```bash
sudo apt install maltego         # Kali (lanceur)
# créer un compte gratuit (Maltego CE) au 1er lancement
```

## Utilisation
1. Nouveau graphe → déposer une **entité** (ex. `Domain: cible.tld`).
2. Clic droit → lancer des **transforms** (DNS, sous-domaines, emails, réseaux
   sociaux…). Les résultats apparaissent comme nœuds reliés.
3. Itérer sur les nouveaux nœuds pour étendre le graphe.

## Réflexe
Maltego = **synthèse visuelle** ; il complète les collecteurs CLI ([[theHarvester]],
[[Amass]], [[Maigret]]) dont on peut importer les résultats. Les transforms gratuits
sont limités — installer des hubs/transforms selon le besoin.
