# nboosted

Workflow de reconnaissance en une commande : trouve les IP réelles d'un domaine
protégé par Cloudflare (ou un autre CDN) via [CloakQuest3r](https://github.com/spyboy-productions/CloakQuest3r),
puis lance `nmap -sV -sC` sur ces IP et affiche les ports ouverts triés par
numéro de port.

```
domaine cible ──▶ CloakQuest3r ──▶ IP réelles uniques ──▶ nmap -sV -sC ──▶ rapport trié par port
```

## Prérequis

- Python 3.8+
- `nmap` installé et dans le `PATH` (`sudo apt install nmap` sous Kali/WSL)
- Un checkout de [CloakQuest3r](https://github.com/spyboy-productions/CloakQuest3r)
  quelque part sur la machine (par défaut, `nboosted` s'attend à le trouver dans
  un dossier `CloakQuest3r` **voisin** de `NmapBoosted`, ex :
  `/mnt/c/Users/alban/CloakQuest3r`)

## Installation

```bash
cd /mnt/c/Users/alban/NmapBoosted
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Ça installe les dépendances (`requests`, `colorama`, `beautifulsoup4`,
`cryptography`) et enregistre la commande `nboosted`.

Si CloakQuest3r n'est pas dans un dossier voisin, indique son chemin :

```bash
export CLOAKQUEST3R_DIR=/chemin/vers/CloakQuest3r
# ou, à chaque appel :
nboosted cat.com --cloakquest3r-dir /chemin/vers/CloakQuest3r
```

## Utilisation

```bash
nboosted <domaine>
```

Exemple :

```bash
nboosted cat.com
```

Déroulé :

1. **Recon CloakQuest3r** — vérifie si le domaine est derrière Cloudflare,
   récupère l'historique d'IP (ViewDNS / SecurityTrails si une clé API est
   configurée dans `config.ini`), scanne les sous-domaines à partir de la
   wordlist, et résout l'IP réelle de chaque sous-domaine actif.
2. **Sélection des cibles** — construit la liste des IP uniques à scanner :
   - si le domaine **n'est pas** derrière Cloudflare, son IP visible est
     directement incluse (c'est déjà l'IP réelle) ;
   - si le domaine **est** derrière Cloudflare, son IP visible (l'edge
     Cloudflare) est ignorée, seules les IP réelles des sous-domaines trouvés
     sont conservées.
3. **Scan nmap** — lance `nmap -sV -sC -Pn`, une instance par IP, avec **10
   processus nmap en simultané par défaut** (réglable via `--parallel`). Le
   résultat de chaque IP s'affiche **dès que son scan se termine** (pas besoin
   d'attendre que les 34 soient finis pour voir le premier port trouvé).
4. **Récap final** — une fois tous les scans terminés, un tableau reprend
   tous les ports ouverts triés par numéro de port, avec pour chaque port la
   liste des IP/hôtes concernés et la version du service détectée.

### Exemple de sortie

```
=== Recon CloakQuest3r: cat.com ===
Visible IP: 104.85.40.97
Derriere Cloudflare: non
Serveur web: UNKNOWN
Sous-domaines actifs trouves: 57
IP uniques a scanner: 45
    - 3.164.163.37  (media.cat.com)
    - 13.227.231.120  (account.cat.com)
    ...

[*] Lancement de nmap -sV -sC sur 45 IP(s), 10 en simultane...
    [1/45] 18.164.52.42 (sos.cat.com): 22/tcp ssh (OpenSSH 8.2), 443/tcp https (nginx 1.24)
    [2/45] 18.164.52.95 (ace.cat.com): aucun port ouvert
    [3/45] 104.85.40.97 (cat.com): 80/tcp http (Apache 2.4), 443/tcp https (Apache 2.4)
    ...

=== Recap: ports ouverts, tries par port ===

22/tcp ssh (3 hotes)
    └➤ 66.22.6.245 (conference.cat.com, hr.cat.com, tic.cat.com) - OpenSSH 8.2

443/tcp https (45 hotes)
    └➤ 3.164.163.37 (media.cat.com) - nginx 1.24
    ...

Total: 4 port(s) distinct(s) ouvert(s), 52 instance(s) au total.
```

Chaque ligne `[x/45] ...` apparaît dès que le scan de cette IP se termine
(l'ordre dépend de la vitesse de chaque scan, pas de l'ordre de la liste), le
tableau récap arrive une fois que tout est fini.

## Options

| Option | Description |
|---|---|
| `--wordlist FICHIER` | Wordlist de sous-domaines à utiliser (évite le prompt/téléchargement par défaut de CloakQuest3r) |
| `--cloakquest3r-dir CHEMIN` | Chemin vers le checkout de CloakQuest3r (sinon `$CLOAKQUEST3R_DIR` ou dossier voisin `../CloakQuest3r`) |
| `--skip-history` | Ne pas interroger ViewDNS/SecurityTrails pour l'historique d'IP |
| `--ports PLAGE` | Plage de ports pour nmap, ex `1-1000,8080,8443` (équivaut à `nmap -p`) |
| `--top-ports N` | Scanner seulement les N ports les plus communs (`nmap --top-ports`) |
| `--no-pn` | Ne pas passer `-Pn` à nmap (réactive la découverte d'hôte par ping — plus lent si les hôtes bloquent le ping) |
| `--parallel N`, `-j N` | Nombre de processus nmap lancés en simultané, un par IP (défaut : 10) |
| `--timeout SECONDES` | Timeout HTTP par sous-domaine testé (défaut : 20s) |
| `--only-main-ip` | Ne scanner que l'IP réelle du domaine principal, ignorer les IP des sous-domaines |
| `-v`, `--verbose` | Inclure la sortie des scripts NSE (`-sC`) dans le rapport, pas seulement service/version |

### Exemples

Scan rapide, ports les plus courants uniquement :

```bash
nboosted cat.com --top-ports 200
```

Wordlist personnalisée, sans historique d'IP, avec sortie des scripts NSE :

```bash
nboosted cat.com --wordlist ./ma_wordlist.txt --skip-history -v
```

Ne cibler que l'IP réelle du domaine principal (pas les sous-domaines) :

```bash
nboosted cat.com --only-main-ip
```

Réduire ou augmenter le nombre de scans nmap simultanés (défaut : 10) :

```bash
nboosted cat.com --parallel 5
```

## Notes

- Le scan nmap se fait sans `sudo` par défaut, donc en TCP connect scan (pas de
  SYN scan `-sS`). Lance `sudo -E nboosted <domaine>` (dans le venv) si tu veux
  que nmap tourne en root.
- 10 processus nmap simultanés, c'est plus rapide mais plus lourd en CPU/bande
  passante. Réduis avec `--parallel` si la machine ou le réseau cible ne suit
  pas (throttling, faux négatifs).
- La recherche de sous-domaines lance un thread HTTP par entrée de la
  wordlist (comme CloakQuest3r), donc les wordlists volumineuses prennent du
  temps et de la bande passante — pense à `--wordlist` avec une liste réduite
  pour des scans rapides.
- N'utilise cet outil que sur des domaines que tu es autorisé à tester.