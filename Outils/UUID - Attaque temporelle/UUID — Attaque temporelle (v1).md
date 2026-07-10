---
titre: "UUID — Attaque temporelle (UUIDv1)"
tags: [Outils, API, UUID, python, prédiction]
---

# UUID — Attaque temporelle (UUIDv1)

Outils que j'ai développés pour **prédire / brute-forcer un UUID version 1**,
lorsqu'une application l'utilise comme jeton « secret » (reset de mot de passe,
identifiant de ressource…). Un UUIDv1 n'est **pas aléatoire** : il encode un
timestamp (intervalles de 100 ns depuis le 15 oct. 1582), une `clock_seq` et
l'adresse MAC du nœud (`node`).

> ⚠️ Uniquement sur cible autorisée (ici le challenge Root-Me `ch59091`). Cf. `README`.

## Idée

1. Observer un UUID connu (ou la date de création d'une ressource) pour récupérer
   `clock_seq` et `node`, souvent **constants** entre deux générations proches.
2. Estimer le **timestamp** de la valeur cible (à partir d'un `Date:` HTTP, d'un
   log, ou d'une action déclenchée par nous).
3. Générer toutes les variantes d'UUID dans une **fenêtre de ± N ticks** autour de
   ce timestamp, puis les tester contre l'endpoint jusqu'à obtenir un `200`.

## Fichiers

| Script | Rôle |
|---|---|
| `Attaque_Temporelle_Version_1_UUID.py` | génère les variantes d'UUIDv1 autour d'une date cible (reconstruction `time_low`/`time_mid`/`time_hi`) |
| `Find_UUID.py` | reconstruit + **teste en ligne** les candidats contre `/api/profile` (cookies + headers à mettre à jour) |
| `import requests.py` | banc d'essai réseau |
| `CTF_UUID/attaque.py` | version du challenge résolu |
| `CTF_UUID/uuids_cible.txt` | liste de candidats générés |

## Utilisation

```bash
# 1. générer la liste
python Attaque_Temporelle_Version_1_UUID.py
# 2. tester en ligne (adapter DATE_CIBLE, CLOCK_SEQ, NODE_ID, COOKIES, WINDOW)
python Find_UUID.py
```

> Note : penser à corriger le fuseau horaire (`timezone.utc`) et à rafraîchir les
> cookies en cas d'erreur 403.

## Remédiation

Ne jamais utiliser d'UUIDv1 comme secret. Préférer un **UUIDv4** (aléatoire
cryptographique) ou un token issu de `secrets.token_urlsafe()`.
