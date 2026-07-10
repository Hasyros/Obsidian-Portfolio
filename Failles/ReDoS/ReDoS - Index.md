---
titre: "ReDoS — Regular Expression DoS"
tags: [Failles, ReDoS, DoS, regex, index]
---

# ReDoS — Regular Expression Denial of Service

> ⚠️ Cibles autorisées uniquement (cf. `README`). **DoS : démontrer, ne pas
> réellement saturer la cible.**

Une regex mal écrite peut, sur certaines entrées, exploser en temps de calcul
(**catastrophic backtracking**) : le moteur teste un nombre **exponentiel** de
découpages. Une requête légère unique fait tourner le serveur des secondes/minutes
→ **DoS applicatif sans botnet**. L'**asymétrie** (input minuscule → CPU serveur
énorme) est le danger.

## Fiches
- [[1 - Repérage & détection (ReDoS)]] — repérer le pattern toxique, mesurer le temps
- [[2 - Exploitation & patterns (ReDoS)]] — construire l'input malicieux, outils d'analyse

## Le pattern toxique (à reconnaître)
Quantificateurs **imbriqués** : `(a+)+`, `(a*)*`, `(a+)*`, alternances qui se
chevauchent `(a|a)+`, souvent dans des validations d'**email/URL/téléphone**.

## Où ça frappe le plus fort
**Node.js** (mono-thread) : un seul ReDoS bloque **tout** le serveur. Impact =
disponibilité (le « A » de CIA).

## Remédiation
- Regex sans quantificateurs imbriqués ; moteurs à temps **linéaire** (RE2).
- **Timeout** sur l'évaluation regex + **limite de longueur** d'input.
- Valider emails/URLs par une lib éprouvée, pas une regex maison.
