---
titre: "Blind SQLi — Scripts d'automatisation"
tags: [Outils, SQLI, NoSQL, blind, python, automatisation]
---

# Blind SQLi — Scripts d'automatisation

Scripts Python que j'ai écrits pour automatiser l'extraction de données en
**blind SQL injection** (réponse booléenne uniquement), caractère par caractère.
Référencés depuis [[SQLI — Techniques avancées]] et [[16 - Arsenal Scripts SQLi]].

> ⚠️ À exécuter uniquement sur des cibles autorisées (labs Root-Me/HTB, scope de test). Cf. `README`.

## Principe commun

1. Une fonction `get_boolean_response(payload)` envoie l'injection et renvoie
   `True`/`False` selon la présence d'une chaîne de succès dans la réponse.
2. `get_length()` détermine la taille du résultat (`length((sous-requête)) = i`).
3. `extract_string()` teste chaque caractère de l'alphabet par position, souvent
   via `hex(substr(...,pos,1)) = hex('c')` pour éviter les problèmes de quotes.

## Fichiers

| Script | Cible / SGBD | Notes |
|---|---|---|
| `blind sqli v2.py` | générique | version la plus aboutie ; injection `n' OR {payload} --`, comparaison en `hex()` |
| `blind sqli MySQL and PostGreSQL.py` | MySQL / PostgreSQL | adaptation des fonctions `substr`/`substring` par SGBD |
| `blind sqli SQLite.py` | SQLite | fonctions spécifiques SQLite |
| `blind sqli script.py` | générique | version antérieure |
| `Chall second order rootme.py` | Root-Me | dédié au challenge [[SQLI Second Order]] |
| `NoSQL injection - En aveugle.py` | MongoDB | extraction blind via `$regex` (cf. [[NoSQL injection - Authentification]]) |
| `Script.py`, `test.py` | — | brouillons / bancs d'essai |

## Utilisation

Éditer en tête de script les constantes `TARGET_URL`, `SUCCESS_STR` et
l'`ALPHABET`, puis :

```bash
python "blind sqli v2.py"
```

Le caractère trouvé s'affiche en temps réel (`sys.stdout.flush()`).
