---
titre: "BloodHound"
tags: [Outils, AD, windows, graph, privesc]
source: https://github.com/SpecterOps/BloodHound
---

# BloodHound (+ collecteurs)

**Cartographie des chemins d'attaque Active Directory** sous forme de **graphe**.
Révèle comment passer d'un utilisateur lambda à Domain Admin (ACL, sessions,
délégations…) que l'œil humain ne verrait pas.

> ⚠️ Uniquement en engagement/lab autorisé. Cf. `README`.

## Installation
```bash
# BloodHound CE (Docker recommandé)
curl -L https://ghst.ly/getbhce | docker compose -f - up
# interface : http://localhost:8080
```

## Collecte des données
```bash
# depuis Linux (à distance)
pip install bloodhound-ce      # collecteur Python
bloodhound-ce-python -u user -p 'pass' -d domain.local -ns 10.10.10.10 -c All

# depuis Windows (sur la cible)
SharpHound.exe -c All          # génère un .zip à importer

# via NetExec
nxc ldap 10.10.10.10 -u user -p pass --bloodhound --collection All
```

## Utilisation
1. Importer le `.zip` dans l'UI.
2. Marquer les comptes possédés (**Mark as Owned**).
3. Requêtes pré-construites : *Shortest paths to Domain Admins*, *Kerberoastable
   users*, *Find AS-REP roastable*…

## Réflexe
Suivre les *edges* du graphe (chaque arête = une technique concrète :
`GenericAll`, `WriteDACL`, `CanRDP`…). Données collectées par [[NetExec]] /
SharpHound. Exploitation via [[Impacket]].
