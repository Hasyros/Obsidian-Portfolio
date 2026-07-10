# Lancer Caido dans Exegol (sandbox activé)

  

## Pourquoi

  

Caido est basé sur Electron. Electron refuse de démarrer avec le sandbox

Chromium activé si le process tourne en root :

  

```

[FATAL] Running as root without --no-sandbox is not supported.

```

  

Deux options possibles :

- désactiver le sandbox (`--no-sandbox`) → non souhaité, on garde le sandbox actif

- lancer Caido depuis un utilisateur non-root → solution retenue

  

Une fois passé en non-root, un second problème est apparu : le navigateur

Chromium intégré à Caido (lancé depuis l'UI pour proxy le trafic) ne

démarrait pas. Cause : les dossiers de config/cache de Caido avaient été

créés par root lors des tests précédents, donc illisibles/inscriptibles

par le nouvel utilisateur non-root.

  

## Prérequis (à faire une seule fois par conteneur)

  

Ces étapes créent l'utilisateur dédié. À refaire uniquement si le

conteneur Exegol est recréé from scratch (état non persistant).

  

```bash

useradd -m -s /bin/bash caidouser

chown -R caidouser:caidouser /home/caidouser

```

  

## À faire à chaque session de travail

  

1. Autoriser l'accès X11 local (en root) :

  

```bash

xhost +local:

```

  

2. Basculer vers l'utilisateur non-root :

  

```bash

su - caidouser

```

  

3. Dans ce nouveau shell, exporter le display et lancer Caido :

  

```bash

export DISPLAY=:0

caido

```

  

## Si le navigateur intégré de Caido ne se lance toujours pas

  

Vérifier que les dossiers de config appartiennent bien à `caidouser`

(et pas à root, suite à un lancement précédent en root) :

  

```bash

ls -la ~/.local/share/caido

```

  

Si `root root` apparaît au lieu de `caidouser caidouser`, corriger avec

(en root, avant de refaire le `su`) :

  

```bash

chown -R caidouser:caidouser /home/caidouser/.local/share/caido

chown -R caidouser:caidouser /home/caidouser/.config/browser-launcher

chown -R caidouser:caidouser /home/caidouser/.config/chromium

chown -R caidouser:caidouser /tmp/caido-browser-chromium

```

  

## Résumé express (copier-coller)

  

```bash

# en root

xhost +local:

su - caidouser

  

# dans le shell caidouser

export DISPLAY=:0

caido

```