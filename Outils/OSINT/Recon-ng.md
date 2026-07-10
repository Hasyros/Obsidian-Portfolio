---
titre: "Recon-ng"
tags: [Outils, OSINT, recon, framework]
source: https://github.com/lanmaster53/recon-ng
---

# Recon-ng

**Framework de reconnaissance web open source.** Interface calquée sur
Metasploit (modules, workspaces, options) mais 100 % dédiée à l'**OSINT** — pas
d'exploitation. Entièrement modulaire, résultats stockés en base.

> ⚠️ Recon sur périmètre autorisé uniquement. Cf. `README`.

## Téléchargement / installation
```bash
# Kali : déjà présent
sudo apt install recon-ng
# ou depuis les sources
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng && pip3 install -r REQUIREMENTS
./recon-ng
```

## Utilisation (flux type)
```text
recon-ng                                  # lancer le framework
[recon-ng] > marketplace search           # lister les modules dispo
[recon-ng] > marketplace install all      # (ou un module précis)
[recon-ng] > workspaces create cible       # isoler la mission
[recon-ng] > db insert domains             # ajouter example.com
[recon-ng] > modules load recon/domains-hosts/hackertarget
[recon-ng] > run                            # énumère les sous-domaines
[recon-ng] > show hosts                     # voir les résultats
```
- **marketplace** : installer/màj les modules (certains demandent une clé API via `keys add`).
- **workspaces** : une base SQLite par mission ; les tables `domains`, `hosts`,
  `contacts`, `credentials`… se remplissent au fil des modules.
- Reporting : modules `reporting/csv`, `reporting/html`.

## Réflexe
Chaîner les modules (domain → hosts → ports → contacts). Renseigner les clés API
(`keys list`). Complémentaire de [[Spiderfoot]] (Recon-ng = ciblé/scriptable,
SpiderFoot = large/automatique).
