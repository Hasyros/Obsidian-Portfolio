---
titre: "dalfox"
tags: [Outils, Web, XSS, scanner]
source: https://github.com/hahwul/dalfox
---

# dalfox

**Scanner XSS rapide en Go** (hahwul). Analyse les paramètres, teste
l'injection selon le contexte, vérifie l'exécution et gère l'encodage/DOM.
Complète [[XSStrike]] (Python) — dalfox brille par sa **vitesse** et son
intégration en pipeline.

> ⚠️ Sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
go install github.com/hahwul/dalfox/v2@latest
# ou : sudo apt install dalfox
```

## Utilisation
```bash
dalfox url "http://cible/page?q=test"                 # scan d'une URL
dalfox url "http://cible/" --data "q=test" -X POST     # POST
echo "http://cible/?q=1" | dalfox pipe                 # depuis un flux (recon)
dalfox url "http://cible/?q=1" -b https://COLLAB        # Blind XSS (callback)
dalfox file urls.txt --custom-payload payloads.txt      # liste + payloads perso
```

## Réflexe
Idéal en bout de chaîne recon : `... | httpx | dalfox pipe`. Alimenter
`--custom-payload` avec mon [[XSS Finder]]. Résultats à confirmer manuellement,
puis documenter dans [[XSS - Index]].
