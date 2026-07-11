---
titre: "WhatsMyName"
tags: [Outils, OSINT, username, enumeration]
source: https://github.com/WebBreacher/WhatsMyName
---

# WhatsMyName (WMN)

**Énumération de nom d'utilisateur.** Jeu de données communautaire (créé par
Micah Hoffman, 2015) qui permet de vérifier si un **username** existe sur
**700+ sites**. Le cœur du projet est un unique fichier `wmn-data.json` décrivant,
pour chaque site, l'URL de profil, le marqueur de « trouvé » et de « non trouvé ».

> ⚠️ Recherche d'informations publiques ; respecter la vie privée. Cf. `README`.

## Utilisation

### Web (le plus simple, sans installation)
- **[whatsmyname.app](https://whatsmyname.app)** — saisir le pseudo, filtrer par
  catégorie, exporter en CSV.

### En ligne de commande (consomment le même JSON)
```bash
# Naminter (Python, concurrence + bypass Cloudflare)
pipx install naminter && naminter -u username
# Blackbird
git clone https://github.com/p1ngul1n0/blackbird && cd blackbird
pip install -r requirements.txt && python blackbird.py -u username
```
Autres intégrations : extension Chrome « Who Am I » (WMN + Sherlock + Maigret),
NameSeeker (desktop), LinkScope, versions Flask/Docker auto-hébergées.

## Réflexe
Même pseudo ≠ même personne : **vérifier chaque profil**. Croiser avec
[[sherlock]] (autre base de sites) pour maximiser la couverture.
