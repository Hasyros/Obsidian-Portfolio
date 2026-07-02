---
titre: "Regular Expression DoS (ReDoS)"
aliases:
  - "Regular Expression DoS (ReDoS)"
plateforme: "Hack The Box Academy"
module: "Web Service & API Attacks"
date: 2026-07-02
tags: [HTB, API, ReDoS, DoS, Regex, Notes]
---

# 🧩 Regular Expression Denial of Service (ReDoS)

Lié : [[18 - Cheatsheet Payloads]]

---

## Principe

Une regex mal écrite peut, sur certaines entrées, exploser en temps de calcul (**catastrophic backtracking**) : le moteur teste toutes les combinaisons possibles pour matcher, et leur nombre croît **exponentiellement** avec la longueur de l'input.

Résultat : une requête normale répond en ms, un input malicieux fait tourner le serveur des **secondes/minutes** → DoS **applicatif** sans botnet, avec une seule requête légère. **Asymétrie** = danger.

---

## Le pattern toxique

Quantificateurs **imbriqués** : `(a+)+`, `(a*)*`, `(a+)*`, ou alternances qui se chevauchent `(a|a)+`.

Regex du module (validation d'email) :
```
/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/
                     └──── (x+)+ imbriqué ────┘
```
Le groupe `(([a-zA-Z0-9-])+.)+` a un `+` **dans** un groupe suivi d'un `+` → pattern classique du ReDoS.

---

## Détection (le signal = le TEMPS)

Contrairement aux autres vulns, on mesure le **délai**, pas un contenu :
```bash
# input court, valide → instantané
time curl "http://<TARGET>:3000/api/check-email?email=rien@rien.com"

# input long "presque valide" (finit par . invalide) → plusieurs secondes
time curl "http://<TARGET>:3000/api/check-email?email=jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555."
```

**Résultat observé :**
```
rien@rien.com   → 0.435s   success:true
payload long    → 16.548s  success:false     (~38x plus lent)
```

> 🔑 Le point final `.` rend l'input **invalide** → force le moteur à explorer **tous** les découpages avant de conclure "pas de match". Le CPU **serveur** brûle (curl côté client reste à ~0% CPU, il attend juste).
> 🔑 Corrélation : `success:false` = c'est **quand le match échoue** que le backtracking part en vrille.

> ❓ *Question HTB* : « plusieurs longueurs de payload déclenchent la vuln ? » → **Yes** (le temps croît avec la longueur, toute une plage fonctionne).

---

## Outils d'analyse

- **regex101.com** : coller la regex (sans les `/`), flavor **ECMAScript (JavaScript)**, tester deux inputs → observer le compteur de **"steps"** exploser (avertissement "catastrophic backtracking").
- **jex.im/regulex** : diagramme ferroviaire → on *voit* les boucles imbriquées.

Amplifier (avec timeout de sécurité) :
```bash
time curl -m 60 "http://<TARGET>:3000/api/check-email?email=jjjj@ccccccccccccccccccccccccccccccccccccc.5555555555555555555555555555555555555555555555555555555555555555."
```
> ⚠️ Ne pas réellement DoS la cible — juste démontrer.

---

## Où ça se cache

Validation d'emails, téléphones, URLs, tout champ passé par regex serveur. **Node.js (mono-thread)** y est particulièrement sensible : un seul ReDoS bloque **tout** le serveur (cette box tourne sous Node → cible idéale). Impact = disponibilité (le "A" de CIA).

---

## Remédiation

- Regex sans quantificateurs imbriqués ; moteurs à temps linéaire (RE2).
- Timeout sur l'évaluation regex ; limite de longueur d'input.
- Valider les emails par une lib éprouvée, pas une regex maison.
