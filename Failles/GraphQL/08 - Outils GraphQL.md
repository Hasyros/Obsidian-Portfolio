---
titre: "Outils GraphQL — Arsenal complet"
aliases:
  - "Outils GraphQL — Arsenal complet"
plateforme: "Hack The Box Academy"
module: "Attacking GraphQL"
date: 2026-07-06
tags: [HTB, GraphQL, Outillage, graphw00f, InQL, Voyager, Notes]
---

# 🧰 Outils GraphQL — Arsenal complet

Lié : [[Attacking GraphQL - Index]] · [[01 - Méthodologie - Cheminement GraphQL]] · [[09 - Cheatsheet GraphQL]]

---

## Tableau récapitulatif

| Phase | Outil | Rôle | Utilisé dans le module |
|---|---|---|---|
| Découverte endpoint | **graphw00f** | Trouver `/graphql` + fingerprint moteur | ✅ |
| Découverte endpoint | **ffuf** (POST `__typename`) | Fuzzing si graphw00f échoue | ✅ (expliqué) |
| Fingerprint moteur | **graphw00f** | Identifier Graphene/Apollo/… + Threat Matrix | ✅ |
| Cartographie schéma | **Introspection** (queries `__schema`) | Lister types/queries/mutations/champs | ✅ |
| Visualisation schéma | **GraphQL Voyager** | Diagramme interactif des types et relations | ✅ |
| Audit config auto | **GraphQL-Cop** | Scanner faiblesses (DoS, CSRF, introspection…) | ✅ |
| Exploitation dans Burp | **InQL** | Éditer queries sans JSON, générer requêtes | ✅ |
| Reconstruction schéma | **Clairvoyance** | Reconstruire le schéma via field suggestions (si introspection off) | ❌ (mentionné) |
| Requêtes manuelles | **GraphiQL** (fourni par la cible) | IDE web interactif | ✅ |
| Requêtes manuelles | **curl + jq** | Appels directs en CLI | ✅ |
| Post-exploit | **md5sum**, **base64**, **hashcat** | Hash mdp, décodage Global IDs, crack | ✅ |
| Post-exploit | **sqlmap** | SQLi automatisée via GraphQL | ✅ (expliqué) |

---

## Détail par outil

### graphw00f — Fingerprint & découverte
- **Repo** : https://github.com/dolevf/graphw00f
- **Auteur** : Dolev Farhi
- **Install** :
  ```bash
  cd /opt && git clone https://github.com/dolevf/graphw00f.git
  cd graphw00f && pip3 install -r requirements.txt
  ```
- **Usage** :
  ```bash
  python3 main.py -d -f -t http://<TARGET>
  # -d = detect (trouver l'endpoint)
  # -f = fingerprint (identifier le moteur)
  ```
- **Sortie** : endpoint trouvé, moteur identifié, lien Threat Matrix.
- **Comment ça marche** : envoie des requêtes malformées et observe les messages d'erreur. Chaque moteur "signe" ses erreurs différemment.

### GraphQL Threat Matrix
- **URL** : https://github.com/nicholasaleks/graphql-threat-matrix
- **Quoi** : tableau communautaire des fonctionnalités à risque, moteur par moteur.
- **Colonnes clés** : Introspection (on/off par défaut), Field Suggestions, Query Depth Limit, Batching, Debug Mode.
- **Usage** : consulter la fiche du moteur identifié → savoir quoi tester en priorité.

### GraphQL Voyager — Visualisation du schéma
- **URLs** :
  - https://graphql-kit.com/graphql-voyager/
  - https://apis.guru/graphql-voyager/
- **Repo** : https://github.com/graphql-kit/graphql-voyager
- **Usage** :
  1. Lancer l'introspection totale (voir [[09 - Cheatsheet GraphQL]])
  2. Copier le JSON de réponse
  3. Sur Voyager : *Change Schema* → *Introspection* → coller → *Display*
- **Résultat** : diagramme de type "BDD" avec toutes les relations cliquables.
- **⚠️ OPSEC** : en engagement réel, héberger soi-même (`docker run`) pour ne pas envoyer le schéma client à un tiers.

### GraphQL-Cop — Audit de configuration
- **Repo** : https://github.com/dolevf/graphql-cop
- **Auteur** : Dolev Farhi (même auteur que graphw00f)
- **Install** :
  ```bash
  cd /opt && git clone https://github.com/dolevf/graphql-cop.git
  cd graphql-cop && pip3 install -r requirements.txt
  ```
- **Usage** :
  ```bash
  python3 graphql-cop.py -t http://<TARGET>/graphql
  ```
- **Sortie** : liste d'alertes classées par sévérité (HIGH/MEDIUM/LOW) avec le type de vulnérabilité. Couvre : introspection, batching, alias overloading, field duplication, directive overloading, field suggestions, GET method (CSRF), GraphiQL exposé.

### InQL — Extension Burp Suite
- **Repo** : https://github.com/doyensec/inql (aussi dans le BApp Store)
- **Install** : dans Burp → *Extender* → *BApp Store* → chercher "InQL" → *Install*.
- **Fonctionnalités** :
  - Onglet **GraphQL** dans Proxy History et Repeater → éditer les queries sans se battre avec l'enrobage JSON.
  - Clic droit sur une requête → *Extensions > InQL > Generate queries* → génère automatiquement toutes les queries et mutations du schéma.
  - Onglet **InQL** central avec le schéma détaillé par host scanné.

### Clairvoyance — Reconstruction sans introspection
- **Repo** : https://github.com/nikitastupin/clairvoyance
- **Quand** : introspection **désactivée** mais field suggestions **activées**.
- **Principe** : envoie des noms de champs approximatifs, récupère les suggestions (`Did you mean...?`), et reconstruit le schéma progressivement.
- **Usage** :
  ```bash
  pip3 install clairvoyance
  clairvoyance http://<TARGET>/graphql -o schema.json
  ```

### Altair GraphQL Client
- **URL** : https://altairgraphql.dev/
- **Quoi** : client GraphQL desktop/web, alternative à GraphiQL avec plus de fonctionnalités (variables, headers, collections, historique).
- **Usage** : quand la cible n'expose pas GraphiQL, ou pour un confort supérieur.

---

## Liens utiles

| Ressource | URL |
|---|---|
| GraphQL Spec officielle | https://graphql.org/learn/ |
| GraphQL Threat Matrix | https://github.com/nicholasaleks/graphql-threat-matrix |
| GraphQL Voyager (démo) | https://graphql-kit.com/graphql-voyager/ |
| GraphQL Voyager (alt) | https://apis.guru/graphql-voyager/ |
| HackTricks — GraphQL | https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html |
| PayloadsAllTheThings — GraphQL | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection |
| SecLists — graphql.txt | dans `/usr/share/seclists/Discovery/Web-Content/` |

---

## Réflexe d'installation (pattern commun)

```bash
cd /opt
git clone <url_github>
cd <dossier>
cat README.md                        # toujours lire d'abord
pip3 install -r requirements.txt     # si Python
python3 <script>.py --help
```

> Sur Exegol : vérifier si l'outil est déjà préinstallé avant de cloner (`which <tool>`, `find / -iname "<tool>*"`). Cloner dans un mount persistant pour survivre au redémarrage du conteneur.
