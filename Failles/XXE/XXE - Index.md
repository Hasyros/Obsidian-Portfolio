---
titre: "XXE — XML External Entity Injection"
tags: [Failles, XXE, XML, index]
---

# XXE — XML External Entity Injection

> ⚠️ Cibles autorisées uniquement (cf. `README`). Write-ups appliqués : dossier `CTF/`.

Le XML supporte des **entités** (`&nom;` = variable remplacée par sa valeur). Les
entités **externes** (`SYSTEM`) vont chercher leur valeur ailleurs : une URL
distante ou un **fichier local** (`file://`). Si une app parse du XML **contrôlé**
sans désactiver cette fonctionnalité → XXE.

Une XXE combine plusieurs vecteurs : lecture de fichiers (comme [[LFI - Index]]),
requêtes réseau (comme [[SSRF - Index]]), parfois DoS (*billion laughs*).

> 🔑 Déclencheur : **tout endpoint qui accepte du XML** — login SOAP, upload de
> docs, RSS, SVG, DOCX/XLSX (= XML zippé). `Content-Type: application/xml`,
> `text/xml`, ou `text/plain` contenant du XML.

## Fiches
- [[1 - Repérage (XXE)]] — repérer le XML, tester déclaration + invocation
- [[2 - Exploitation & techniques (XXE)]] — file read, in-band vs OOB, SSRF, DoS
- [[3 - Payloads & bypass (XXE)]] — cheatsheet DTD interne/externe, `php://filter`

## Remédiation
- **Désactiver le traitement des entités externes + DTD** dans le parser (LA remédiation standard).
- Utiliser des parsers sûrs par défaut ; ne pas réfléchir les erreurs de parsing.
