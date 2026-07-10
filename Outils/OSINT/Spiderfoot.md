---
titre: "SpiderFoot"
tags: [Outils, OSINT, recon, automatisation]
source: https://github.com/smicallef/spiderfoot
---

# SpiderFoot

**Automatisation OSINT.** Framework Python (licence MIT) qui interroge **200+
modules / sources de données** pour cartographier automatiquement la surface
d'exposition d'une cible (offensif : recon red team / pentest ; défensif :
mesurer sa propre exposition).

> ⚠️ Recon sur cibles/périmètre autorisés uniquement. Cf. `README`.

## Ce qu'il sait faire
- Énumération hosts / sous-domaines, DNS, zone transfers, subdomain takeover
- Emails, téléphones, noms de personnes, comptes réseaux sociaux
- Fuites de données (HaveIBeenPwned), threat intel / blacklists, GreyNoise
- Intégrations API : **SHODAN, HaveIBeenPwned, GreyNoise…**
- Buckets cloud (S3, Azure, DigitalOcean), géoloc IP, scan de ports/bannières
- Recherche dark web via TOR, adresses Bitcoin/Ethereum
- Moteur de **corrélation** (règles YAML), export CSV/JSON/GEXF, backend SQLite

## Téléchargement / installation
```bash
# Release stable
wget https://github.com/smicallef/spiderfoot/archive/v4.0.tar.gz
tar zxvf v4.0.tar.gz && cd spiderfoot-4.0
pip3 install -r requirements.txt

# ou version de dev
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot && pip3 install -r requirements.txt
```
Déjà packagé dans Kali (`sudo apt install spiderfoot`). Image Docker dispo.

## Utilisation
```bash
# Interface web (recommandé)
python3 ./sf.py -l 127.0.0.1:5001      # puis http://127.0.0.1:5001

# CLI / automatisation
python3 ./sf.py -s example.com -t DOMAIN_NAME   # scan ciblé
python3 ./sfcli.py                              # client CLI interactif
```
**Types de cibles** : IP, domaine, hostname, CIDR, ASN, email, téléphone,
username, nom, adresse crypto. Choisir un *use case* (Passive / Investigate /
Footprint / All) ou des modules précis.

## Réflexe
Renseigner ses **clés API** (Settings) pour débloquer Shodan/HIBP/etc. Lancer en
mode **passif** d'abord pour rester discret. À croiser avec [[Recon-ng]].
