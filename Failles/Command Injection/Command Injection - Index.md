---
titre: "Command Injection"
tags: [Failles, command-injection, RCE, index]
---

# Command Injection

> ⚠️ Cibles autorisées uniquement (cf. `README`). Write-ups appliqués : dossier `CTF/`.

Exécution de **commandes système** sur le back-end : survient quand une entrée
utilisateur est utilisée pour construire/appeler une commande shell sans
assainissement. Débouche sur un **RCE** (le graal).

> 🎯 Leçon clé : la faille n'est pas toujours dans la fonction évidente (ex. `ping`
> bien protégée) mais dans **la façon de l'appeler**. Regarder au-delà.

## Fiches
- [[1 - Repérage (Command Injection)]] — repérer, confirmer (in-band / blind / OOB)
- [[2 - Exploitation & techniques (Command Injection)]] — séparateurs, reverse shell, cas PHP
- [[3 - Payloads & bypass (Command Injection)]] — cheatsheet + contournement de filtres

## En un coup d'œil
| Phase | Action |
|---|---|
| Repérage | injecter `;` `\|` `&&` `` ` `` `$()` ; blind → `sleep`/`ping` OOB |
| Exploiter | `id`, dump du code source, puis **reverse shell** propre |
| Bypasser | espaces (`${IFS}`), quotes, concat, encodage, wildcards |

Voisins : [[SSTImap]] (RCE via template), [[File Upload - Index]] (webshell → RCE).

## Remédiation
- Ne jamais construire une commande shell depuis un input ; **API natives**.
- Whitelister strictement les valeurs/fonctions appelables (jamais `call_user_func` sur input brut).
- `escapeshellarg`/`escapeshellcmd` — mais inutile si on court-circuite la fonction.
