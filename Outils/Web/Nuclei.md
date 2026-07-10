---
titre: "Nuclei"
tags: [Outils, Web, scanner, templates, CVE]
source: https://github.com/projectdiscovery/nuclei
---

# Nuclei

**Scanner de vulnérabilités par templates** (ProjectDiscovery). Envoie des
requêtes définies par des **templates YAML** (communauté = milliers de checks :
CVE, misconfigurations, exposures, panels…) et signale les correspondances.
Le scanner « large » de référence.

> ⚠️ Scan sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# ou : sudo apt install nuclei
nuclei -update-templates
```

## Utilisation
```bash
nuclei -u https://cible.tld                          # scan complet
nuclei -l urls.txt                                   # liste de cibles
nuclei -u https://cible.tld -tags cve,exposure       # filtrer par tags
nuclei -u https://cible.tld -severity critical,high  # par sévérité
nuclei -u https://cible.tld -t http/technologies/    # templates précis
nuclei -u https://cible.tld -o resultats.txt -j      # sortie fichier / JSON
```

## Réflexe
Chaîner avec la recon : `subfinder -d cible.tld | httpx | nuclei`
(cf. [[ProjectDiscovery (subfinder, httpx, naabu)]]). Écrire ses **propres
templates** pour rejouer une vuln repérée manuellement. Ne remplace pas l'analyse
manuelle (faux positifs/négatifs possibles).
