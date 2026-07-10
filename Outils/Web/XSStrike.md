---
titre: "XSStrike"
tags: [Outils, Web, XSS, scanner]
source: https://github.com/s0md3v/XSStrike
---

# XSStrike

**Scanner XSS avancé** (s0md3v). Contrairement aux scanners qui injectent une
liste fixe, XSStrike **analyse le contexte** d'injection et **génère** des
payloads adaptés. Embarque 4 parsers maison, un générateur intelligent, un moteur
de fuzzing et un crawler rapide. Complète bien ma fiche [[XSS - Index]] et mon
outil [[XSS Finder]].

> ⚠️ Scan uniquement sur cible autorisée (lab, scope bug bounty). Cf. `README`.

## Fonctions clés
- XSS réfléchi **et** DOM, analyse de contexte, génération de payloads
- Détection + **évasion de WAF**, fuzzing, crawler multi-thread
- Découverte de paramètres cachés, **Blind XSS**, scan de libs JS obsolètes
- Contrôle complet des en-têtes / méthodes HTTP

## Téléchargement / installation
```bash
git clone https://github.com/s0md3v/XSStrike
cd XSStrike
pip install -r requirements.txt --break-system-packages
```

## Utilisation
```bash
python xsstrike.py -u "http://cible/page?q=test"      # test d'un paramètre GET
python xsstrike.py -u "http://cible/search" --data "q=test"   # POST
python xsstrike.py -u "http://cible/" --crawl          # crawl + scan du site
python xsstrike.py -u "http://cible/?q=test" --fuzzer   # mode fuzzing
python xsstrike.py -u "http://cible/?q=test" --blind    # Blind XSS
# en-têtes custom : --headers ; paramètres cachés : --params
```

## Réflexe
Lancer d'abord sans `--crawl` sur un paramètre repéré manuellement, puis élargir.
Le moteur d'évasion WAF alimente utilement la section
[[4 - Bypass (WAF, sanitizers)]] de ma fiche XSS.
