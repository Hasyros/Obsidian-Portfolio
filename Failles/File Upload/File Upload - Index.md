---
titre: "File Upload — Arbitrary File Upload → RCE"
tags: [Failles, file-upload, RCE, webshell, index]
---

# File Upload — Arbitrary File Upload → RCE

> ⚠️ Cibles autorisées uniquement (cf. `README`). Write-ups appliqués : dossier `CTF/`.

Si un service accepte un fichier **exécutable** (`.php`, `.jsp`, `.aspx`…) et le
rend atteignable/interprété, on uploade un **webshell** → **RCE**. Un des chemins
les plus critiques du web.

## Les 3 conditions pour un RCE
1. **Connaître l'emplacement** du fichier uploadé (URL révélée ou devinable).
2. Le fichier est **exécuté** (pas seulement stocké en texte).
3. **Pas de restriction** bloquante (extension/MIME/contenu) sur ce type.

## Fiches
- [[1 - Repérage (File Upload)]] — cartographier les protections, trouver l'emplacement
- [[2 - Exploitation & techniques (File Upload)]] — webshell, reverse shell, cas non-RCE
- [[3 - Payloads & bypass (File Upload)]] — extensions, MIME, magic bytes, cheatsheet

Voisins : [[LFI - Index]] (LFI + upload = RCE même sans exécution directe),
[[XXE - Index]] (upload SVG/DOCX), [[Command Injection - Index]].

## Remédiation
- Whitelist stricte d'extensions **et** de types MIME (vérifiés côté serveur).
- Renommer les fichiers (aléatoire), stocker **hors webroot** ou sans droit d'exécution.
- Ne jamais révéler le chemin final ; scanner le contenu ; `Content-Disposition: attachment`.
