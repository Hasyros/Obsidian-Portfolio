---
titre: "LFI — Local File Inclusion / Path Traversal"
tags: [Failles, LFI, path-traversal, index]
---

# LFI — Local File Inclusion / Path Traversal

> ⚠️ Cibles autorisées uniquement (cf. `README`). Write-ups appliqués : dossier `CTF/`.

Une **LFI** survient quand une application construit un **chemin de fichier** à
partir d'une entrée utilisateur sans validation. En injectant des `../`
(*path traversal*), on lit des fichiers arbitraires lisibles par le serveur, et
selon le contexte on va jusqu'au **RCE**.

> 🔁 Path Traversal ≈ **lire** un fichier hors du dossier prévu ; LFI = le fichier
> lu est **inclus/interprété** par l'app (PHP `include`) → potentiel RCE.

## Fiches
- [[1 - Repérage (LFI)]] — détecter le point d'inclusion, confirmer
- [[2 - Exploitation & techniques (LFI)]] — lecture de fichiers, wrappers, LFI→RCE
- [[3 - Payloads & bypass (LFI)]] — cheatsheet + contournement de filtres

## En un coup d'œil
| Phase | Action |
|---|---|
| Repérage | paramètres `?file=`, `?page=`, `?lang=` ; injecter `../` / `/etc/passwd` |
| Exploiter | lire configs/clés SSH ; `php://filter` (source PHP) ; log poisoning → RCE |
| Bypasser | encodage (`%2e%2e%2f`), double-encodage, `....//`, null-byte, filtre de préfixe |

## Vulnérabilités liées
[[XXE - Index]] (lecture via `file://`), [[SSRF - Index]] (via `http://`),
[[File Upload - Index]] (LFI + upload = RCE).

## Remédiation
- Ne jamais construire un chemin depuis un input : **mapping identifiant → fichier** côté serveur.
- `basename()`, whitelist de fichiers, `realpath()` + vérification du **préfixe autorisé**.
- Désactiver les wrappers dangereux (`allow_url_include=Off`).
