---
titre: "Arjun"
tags: [Outils, Web, parametres, discovery]
source: https://github.com/s0md3v/Arjun
---

# Arjun

**Découverte de paramètres HTTP cachés** (s0md3v). Beaucoup d'endpoints acceptent
des paramètres non documentés (debug, id, file, redirect…) qui ouvrent des failles
(IDOR, LFI, SSRF, injection). Arjun les trouve par fuzzing intelligent.

> ⚠️ Sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
pipx install arjun
# ou : sudo apt install arjun
```

## Utilisation
```bash
arjun -u https://cible.tld/api/endpoint                 # GET
arjun -u https://cible.tld/api/endpoint -m POST         # méthode
arjun -u https://cible.tld/api/endpoint -m JSON          # corps JSON
arjun -u https://cible.tld/endpoint -oT params.txt       # sortie
arjun -i urls.txt                                        # plusieurs cibles
```

## Réflexe
Un paramètre caché trouvé se teste ensuite pour **chaque** faille : le passer à
[[SSTImap]]/[[XSStrike]]/[[CLI — ffuf, sqlmap, nmap, curl|sqlmap]] selon le contexte,
ou vérifier IDOR/LFI/SSRF à la main (cf. [[Failles - Index]]).
