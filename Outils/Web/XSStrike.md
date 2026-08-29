Scanner XSS avancé (s0md3v). Contrairement aux scanners qui injectent une
liste fixe, XSStrike analyse le contexte d'injection et génère des
payloads adaptés. Embarque 4 parsers maison, un générateur intelligent, un moteur
de fuzzing et un crawler rapide. Complète bien ma fiche XSS - Index et mon
outil XSS Finder.
⚠️ Scan uniquement sur cible autorisée (lab, scope bug bounty). Cf. `README`.

Fonctions clés

* XSS réfléchi et DOM, analyse de contexte, génération de payloads
* Détection + évasion de WAF, fuzzing, crawler multi-thread
* Découverte de paramètres cachés, Blind XSS, scan de libs JS obsolètes
* Contrôle complet des en-têtes / méthodes HTTP

Téléchargement / installation

```bash
git clone https://github.com/s0md3v/XSStrike
cd XSStrike
pip install -r requirements.txt --break-system-packages
```

Sur Debian/Kali récents, `pip` refuse d'installer au niveau système
("externally-managed-environment"). Deux options :
- rapide : `--break-system-packages` (ci-dessus)
- propre : venv dédié — `python3 -m venv ~/.venvs/xsstrike` puis
  `source ~/.venvs/xsstrike/bin/activate` avant de lancer `pip install`
  et `python3 xsstrike.py`

⚠️ WSL : si le dossier du projet est sous `/mnt/c/...` (filesystem Windows),
`python3 -m venv` échoue systématiquement (symlinks/permissions non supportés
par drvfs, même avec `--copies`). Dans ce cas, créer le venv à part sur le
filesystem Linux (ex: `~/.venvs/xsstrike`) et l'activer depuis le dossier
projet sous `/mnt/c` — `activate` n'a pas besoin d'être au même endroit que
le script.

Utilisation (mon setup — WSL Kali)

Projet dans `/mnt/c/Users/alban/workspace/scripts/XSStrike`, venv séparé
dans `~/.venvs/xsstrike` (voir note WSL ci-dessus). À chaque session :

```bash
source ~/.venvs/xsstrike/bin/activate
cd /mnt/c/Users/alban/workspace/scripts/XSStrike
python3 xsstrike.py -h
```

Utilisation

```bash
python xsstrike.py -u "http://cible/page?q=test"      # test d'un paramètre GET
python xsstrike.py -u "http://cible/search" --data "q=test"   # POST
python xsstrike.py -u "http://cible/" --crawl          # crawl + scan du site
python xsstrike.py -u "http://cible/?q=test" --fuzzer   # mode fuzzing
python xsstrike.py -u "http://cible/?q=test" --blind    # Blind XSS
# en-têtes custom : --headers ; paramètres cachés : --params
```

Réflexe
Lancer d'abord sans `--crawl` sur un paramètre repéré manuellement, puis élargir.
Le moteur d'évasion WAF alimente utilement la section
4 - Bypass (WAF, sanitizers) de ma fiche XSS.
