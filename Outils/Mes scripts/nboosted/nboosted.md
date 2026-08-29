---
titre: "nboosted"
tags: [Outils, "Mes scripts", Recon, Cloudflare, nmap, python]
source: "projet perso — repo GitHub : https://github.com/Hasyros/nboosted (code aussi dans ce dossier : nboosted/)"
repo: "https://github.com/Hasyros/nboosted"
---

# nboosted

**Wrapper de recon** que j'ai développé (Python) : enchaîne
[CloakQuest3r](https://github.com/spyboy-productions/CloakQuest3r) (bypass
Cloudflare, IP réelle derrière un CDN) directement avec `nmap -sV -sC` en une
seule commande, pour aller de « nom de domaine » à « ports ouverts +
versions » sans étape manuelle entre les deux outils. **Repo :**
https://github.com/Hasyros/nboosted.

> ⚠️ N'utiliser que sur des domaines/IP **explicitement autorisés**. Le scan
> nmap ouvre jusqu'à 10 connexions simultanées vers la cible par défaut —
> comportement volontairement agressif, réglable via `--parallel`.

## L'idée clé
CloakQuest3r seul se contente d'imprimer du texte en console (avec des
`input()` interactifs) — impossible à chaîner tel quel. `nboosted` importe
`cloakquest3r.py` comme module (sans jamais exécuter son bloc `__main__`),
réimplémente la recherche de sous-domaines pour renvoyer des données
structurées (host / IP / certificat SSL) au lieu de juste les imprimer, puis
construit la liste d'IP réelles à scanner :
- domaine **pas** derrière Cloudflare → son IP visible est déjà la vraie IP,
  elle est incluse directement ;
- domaine **derrière** Cloudflare → son IP visible (l'edge Cloudflare) est
  ignorée, seules les IP réelles des sous-domaines trouvés comptent.

## Architecture (`nboosted/`)
- **cloak.py** — charge CloakQuest3r comme module, relance son scan de
  sous-domaines sans les prompts interactifs, construit la liste d'IP
  cibles (dédupliquées, avec la liste des hostnames par IP).
- **scanner.py** — lance jusqu'à 10 process `nmap -sV -sC -Pn` en parallèle
  (`ThreadPoolExecutor`, un process par IP), parse le XML (`-oX -`) plutôt
  que du texte pour un résultat fiable.
- **report.py** — affiche le résultat de chaque IP **dès que son scan
  se termine** (pas besoin d'attendre la fin du lot complet), puis un récap
  final trié par port avec la liste des hôtes/versions concernés.
- **cli.py** — la commande `nboosted` (argparse).

## Installation
```bash
git clone https://github.com/Hasyros/nboosted.git
cd nboosted
python3 -m venv venv && source venv/bin/activate
pip install -e .
```
Nécessite aussi un checkout de CloakQuest3r à côté (`../CloakQuest3r` par
défaut, sinon `--cloakquest3r-dir` / `$CLOAKQUEST3R_DIR`) et `nmap` dans le
`PATH`.

## Utilisation
```bash
nboosted cat.com                          # scan complet, 10 nmap en parallele
nboosted cat.com --top-ports 200          # scan rapide
nboosted cat.com --only-main-ip           # ignore les sous-domaines
nboosted cat.com --parallel 5             # moins agressif
nboosted cat.com --wordlist ma_liste.txt --skip-history -v
```

## Notes de conception
Design volontairement minimal : aucune dépendance à une clé API pour
fonctionner (ViewDNS/SecurityTrails restent best-effort, non bloquants),
sortie nmap parsée en XML (`xml.etree`) plutôt qu'en regex sur du texte,
threads plutôt que multiprocessing pour le parallélisme (I/O-bound). Outil
orchestré : [[Nmap - Network Enumeration]]. Voisin maison plus complet (pipeline
subfinder/dnsx/httpx/katana/nuclei) : [[WORKFLOW|Recon Mano — Workflow &
utilisation]]. CloakQuest3r n'a pas encore de fiche dédiée dans ce vault.
