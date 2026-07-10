---
titre: "holehe"
tags: [Outils, OSINT, email, comptes]
source: https://github.com/megadose/holehe
---

# holehe

**Email → comptes existants.** Teste si une **adresse email** est utilisée sur
120+ sites (Twitter/X, Instagram, Snapchat…) en s'appuyant sur les fonctions
« mot de passe oublié » / inscription, **sans alerter** la cible.

> ⚠️ Recherche d'infos publiques ; respecter la vie privée. Cf. `README`.

## Installation
```bash
pipx install holehe
# ou : git clone https://github.com/megadose/holehe && python setup.py install
```

## Utilisation
```bash
holehe cible@example.com                     # liste les sites où l'email existe
holehe cible@example.com --only-used          # n'afficher que les comptes trouvés
holehe cible@example.com -C                    # export CSV
```

## Réflexe
Confirme qu'un email est **actif** et sur quels services → oriente le phishing
ciblé (en engagement autorisé) ou la suite de l'enquête. Le username associé →
[[Maigret]] ; fuites de mots de passe liées → HaveIBeenPwned.
