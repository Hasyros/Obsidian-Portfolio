# 🔎 OsintForge

**Scanner OSINT modulaire en ligne de commande.** Détecte automatiquement le type
de cible — *username, email, nom, téléphone, domaine, image* — et lance les
moteurs adaptés (Maigret, Sherlock, WhatsMyName, Holehe, HIBP, PhoneInfoga,
SpiderFoot, Recon-ng, GHDB…). Résultats vérifiés, dédupliqués, exportables.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/os-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Status](https://img.shields.io/badge/status-actif-brightgreen)

> ⚠️ **Usage légal uniquement** : recherche autorisée, self-OSINT (vos propres
> comptes), tests de sécurité avec permission écrite. Voir [Avertissement](#-avertissement-légal).

---

## Sommaire

- [Idée centrale](#-idée-centrale)
- [Fonctionnalités](#-fonctionnalités)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Moteurs disponibles](#-moteurs-disponibles)
- [Types de findings](#-types-de-findings)
- [Exports](#-exports)
- [Configuration](#-configuration)
- [Structure du projet](#-structure-du-projet)
- [Dépannage](#-dépannage)
- [Avertissement légal](#-avertissement-légal)

---

## 💡 Idée centrale

La plupart des outils OSINT traitent **tous** les résultats de la même manière, ce
qui produit des faux positifs et des résultats mal étiquetés. OsintForge repose sur
un **finding typé** : chaque résultat porte un `kind` qui détermine comment il est
traité.

- Seuls les **profils candidats** (`profile`) passent la vérification de page HTTP
  (suivi des redirections, détection des soft-404, murs de login, pages
  d'inscription…).
- Les **comptes** (`account` — email/téléphone enregistré quelque part), les
  **fuites** (`breach`), les **archives**, les **dorks** et les **infos** ne sont
  **jamais** forcés dans les heuristiques de page de profil.

Résultat : moins de faux positifs, et chaque ligne dit clairement *ce qu'elle est*.

---

## ✨ Fonctionnalités

- **Détection auto** du type de cible (6 types).
- **19 moteurs** OSINT, dont plusieurs auto-vérifiés (WhatsMyName, DirectProbe).
- **Deep-verify** parallèle des profils candidats.
- **Déduplication** inter-moteurs + boost de confiance multi-sources.
- **Scan de variantes** d'un pseudo (leet, casse, séparateurs, suffixes).
- **Historique** SQLite, comparaison de deux scans, statistiques globales.
- **Menu Geo/OSM** : requêtes Overpass Turbo autour de coordonnées.
- **Exports** JSON, CSV, **HTML** (rapport autonome filtrable) et **CSV Maltego**.
- **TUI** riche + mode **CLI one-shot** scriptable.

---

## 📦 Installation

### Prérequis

- **Python 3.10+**
- **git** (pour les outils externes)

### 1. Cloner + dépendances de base

```bash
git clone https://github.com/Hasyros/OsintForge.git
cd OsintForge
python -m pip install -r requirements.txt
```

`rich` et `requests` suffisent à démarrer. C'est tout ce qu'il faut pour la TUI et
les moteurs de base (DirectProbe, WhatsMyName, HIBP, GHDB, GoogleDork, Wayback,
DNS/Whois, images…).

### 2. Dépendances optionnelles (moteurs Python supplémentaires)

```bash
python -m pip install maigret sherlock-project holehe socialscan pillow PyYAML
```

| Paquet | Active le moteur |
|--------|------------------|
| `maigret` | Maigret (3000+ sites) |
| `sherlock-project` | Sherlock (400+ sites) |
| `holehe` | Holehe (email → sites enregistrés) |
| `socialscan` | socialscan (username + email) |
| `pillow` | Jimpl/EXIF (métadonnées & GPS des photos) |
| `PyYAML` | support de `config.yaml` |

### 3. Outils externes (PhoneInfoga, SpiderFoot, Recon-ng)

Ces outils ne sont **pas** sur PyPI. Un script d'installation les met en place
dans `tools/` (idempotent, relançable sans risque) :

```bash
python tools/setup_tools.py            # installe les 3
python tools/setup_tools.py --list     # affiche l'état
python tools/setup_tools.py --only phoneinfoga
```

Le script :
- télécharge le binaire **PhoneInfoga** depuis les releases GitHub et **vérifie
  son SHA256** contre le fichier de checksums officiel ;
- clone **SpiderFoot** + installe ses dépendances (en évitant les pins obsolètes
  qui casseraient d'autres paquets) ;
- clone **Recon-ng** + installe ses dépendances + applique un **correctif Windows**
  nécessaire au chargement de ses modules.

> Détails et étapes manuelles équivalentes : [`tools/README.md`](tools/README.md).

### (Optionnel) GHunt

Compte Google via email. `pip install ghunt` puis `ghunt login` (authentification
Google interactive, une seule fois). Voir la doc GHunt.

---

## 🚀 Utilisation

### Interface interactive (TUI)

```bash
python -m osintforge
```

Menu principal : **Scan auto**, Sélectif, Variantes, Résultats, Revue, Export,
Filtrer, Ouvrir (navigateur), Deep test URL, **Geo/OSM**, Moteurs, Historique,
Comparer, Stats, Reset.

### Mode direct (one-shot, scriptable)

```bash
python -m osintforge busterpiment@gmail.com        # email
python -m osintforge john_doe                       # username
python -m osintforge "Jean Dupont"                  # nom
python -m osintforge +33612345678                   # téléphone
python -m osintforge exemple.com                    # domaine
python -m osintforge ./photo.jpg                    # image (EXIF/GPS)

python -m osintforge john_doe --json resultats.json # exporter le résultat
python -m osintforge exemple.com --no-verify        # sauter le deep-verify
python -m osintforge --config chemin/config.yaml    # config personnalisée
```

Le type est détecté automatiquement ; les moteurs compatibles sont sélectionnés,
exécutés en parallèle, les profils candidats vérifiés, puis tout est affiché,
sauvegardé en base et (optionnellement) exporté.

---

## 🧰 Moteurs disponibles

**Légende d'état** — `LIVE` : tourne tout seul · `SETUP` : nécessite un
binaire/login/clé · `ASSIST` : génère des liens/commandes (outils GUI ou image
qui ne peuvent pas tourner sans interaction).

| # | Moteur | Types | État par défaut |
|---|--------|-------|-----------------|
| 1 | Maigret | username | LIVE si installé |
| 2 | Sherlock | username | LIVE si installé |
| 3 | WhatsMyName | username | LIVE (auto-vérifié) |
| 4 | DirectProbe | username | LIVE (intégré, haute précision) |
| 5 | socialscan | username, email | LIVE si installé |
| 6 | Holehe | email | LIVE si installé |
| 7 | HIBP | email | LIVE (clé = fuites détaillées) |
| 8 | GHunt | email | SETUP (`ghunt login`) |
| 9 | Epieos | email | LIVE |
| 10 | GoogleDork | nom, username | LIVE |
| 11 | GHDB | tous | LIVE (offline) |
| 12 | PhoneInfoga | téléphone | LIVE après `setup_tools.py` |
| 13 | Wayback | username, email | LIVE |
| 14 | DNS/Whois + crt.sh | domaine | LIVE |
| 15 | SpiderFoot | email, domaine, nom, username | LIVE après `setup_tools.py` |
| 16 | Recon-ng | domaine, nom, username, email | LIVE après `setup_tools.py` |
| 17 | Jimpl/EXIF | image | LIVE (avec `pillow`) |
| 18 | TinEye / Lens / Yandex | image | ASSIST |
| 19 | Overpass Turbo | image + menu Geo | ASSIST |
| — | Maltego | export | CSV importable |

---

## 🏷️ Types de findings

| Kind | Signification | Deep-vérifié ? |
|------|---------------|:--:|
| `profile` | Page de profil réelle | ✅ (si non pré-vérifié) |
| `account` | Email/téléphone enregistré sur un service | ❌ |
| `breach` | Fuite de données (HIBP…) | ❌ |
| `archive` | Copie archivée (Wayback) | ❌ |
| `dork` | Requête de recherche prête à cliquer | ❌ |
| `link` | Lien externe / commande à lancer | ❌ |
| `info` | Donnée brute (nom, gaia ID, GPS, opérateur…) | ❌ |

Chaque finding porte aussi une **confiance** (HIGH / MEDIUM / LOW) et un drapeau
**HT** (*high-trust* : page qui n'existe que si le compte existe).

---

## 📤 Exports

Menu `5` (ou `--json`), dossier `reports/` par défaut :

- **JSON** — findings + éliminés, structuré.
- **CSV** — tableur.
- **HTML** — rapport autonome, filtrable (par type/confiance/mot-clé), thème
  clair/sombre, aucun fichier externe.
- **CSV Maltego** — importable comme entités dans Maltego.

---

## ⚙️ Configuration

Tout est optionnel. Copier l'exemple puis remplir ce qui est utile :

```bash
cp config.example.yaml config.yaml
```

Les clés API peuvent aussi passer par variables d'environnement :
`HIBP_API_KEY`, `OSINT_NUMVERIFY_KEY`, `OSINT_TINEYE_KEY`, `OSINT_GITHUB_TOKEN`…

Sans clé, les moteurs concernés basculent proprement en mode dégradé (lien à
ouvrir manuellement) au lieu de planter.

---

## 🗂️ Structure du projet

```
OsintForge/
├── osintforge/
│   ├── __main__.py        # points d'entrée (TUI + one-shot CLI)
│   ├── models.py          # Finding typé, InputType, Confidence…
│   ├── detect.py          # détection du type de cible
│   ├── pipeline.py        # orchestration collecte → verify → dédup → store
│   ├── verify.py          # deep-verify des profils candidats
│   ├── store.py           # persistance SQLite (historique)
│   ├── reporting.py       # exports JSON/CSV/HTML/Maltego
│   ├── tui.py             # interface interactive (rich)
│   └── engines/           # un fichier par moteur
├── tools/
│   ├── setup_tools.py     # installe PhoneInfoga / SpiderFoot / Recon-ng
│   └── README.md          # détails + correctifs Windows
├── config.example.yaml
├── requirements.txt
└── README.md
```

---

## 🩹 Dépannage

- **`RequestsDependencyWarning: urllib3 … doesn't match`** — avertissement cosmétique
  d'un paquet tiers, sans impact. `pip install -U requests urllib3` le fait
  disparaître.
- **Caractères bizarres / crash emoji sous Windows** — OsintForge force déjà l'UTF-8
  sur la sortie ; utilisez un terminal moderne (Windows Terminal) pour le meilleur
  rendu.
- **Un moteur reste en `SETUP`** — il manque son binaire/clé. Lancez
  `python tools/setup_tools.py --list` pour voir l'état des outils externes.

---

## ⚖️ Avertissement légal

OsintForge agrège des informations **publiquement accessibles**. Il est destiné à :

- la recherche sur **vos propres** comptes et données (self-OSINT) ;
- des **tests de sécurité autorisés** (avec permission écrite) ;
- la recherche et l'éducation.

L'utilisation pour harceler, traquer, usurper une identité ou porter atteinte à la
vie privée d'autrui est **interdite** et peut être illégale. Vous êtes seul
responsable du respect des lois applicables (RGPD, etc.) et des conditions
d'utilisation des services interrogés.

---

## 📄 Licence

Sous licence **MIT** — voir [LICENSE](LICENSE). Les outils externes (Maigret,
SpiderFoot, Recon-ng, PhoneInfoga…) conservent leurs licences respectives et ne
sont pas redistribués dans ce dépôt.
