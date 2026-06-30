---
title: "Nmap — Network Enumeration (cours complet)"
tags:
  - nmap
  - pentest
  - enumeration
  - reconnaissance
  - firewall-evasion
  - ncat
aliases:
  - Nmap
  - Network Mapper
  - Énumération réseau
created: 2026-06-19
source: HTB Academy — Network Enumeration with Nmap
status: terminé
---

# 🛰️ Nmap — Network Enumeration

> [!abstract] Résumé
> **Nmap** (Network Mapper) est un scanner réseau open-source écrit en C, C++, Python et Lua. Il sert à découvrir les hôtes actifs, énumérer les ports et services, détecter les versions et l'OS, et interagir avec les services via des scripts (NSE). C'est l'outil de référence pour la phase d'**énumération** — la partie la plus critique d'un pentest, car on n'attaque bien que ce qu'on a bien cartographié.

## Sommaire
- [[#🧭 Phases d'un scan Nmap]]
- [[#📍 Spécification des cibles]]
- [[#📡 Host Discovery (découverte d'hôtes)]]
- [[#🔌 États d'un port]]
- [[#🎯 Techniques de scan]]
- [[#🚪 Spécification des ports]]
- [[#🔎 Détection de services et versions (-sV)]]
- [[#💻 Détection d'OS (-O)]]
- [[#📜 NSE — Nmap Scripting Engine]]
- [[#💾 Sauvegarde des résultats]]
- [[#⚡ Performance et timing]]
- [[#🥷 Firewall / IDS / IPS Evasion]]
- [[#🧪 Mécaniques des labs (vécu)]]
- [[#🔧 ncat — le couteau suisse réseau]]
- [[#📋 Cheat sheet]]

---

## 🧭 Phases d'un scan Nmap

Nmap déroule toujours, dans l'ordre, les étapes qu'on lui autorise :

1. **Host discovery** — quels hôtes sont vivants ?
2. **Port scanning** — quels ports sont ouverts ?
3. **Service / version detection** — quel service, quelle version ?
4. **OS detection** — quel système d'exploitation ?
5. **NSE** — interaction scriptée avec les services.

Syntaxe générale :

```bash
nmap <types de scan> <options> <cible>
```

> [!tip] Le réflexe documentation
> **Sauvegarde toujours tes scans** (`-oA`). Ça sert à comparer les méthodes, documenter, et rédiger le rapport. Différents outils donnent différents résultats — garder une trace permet de savoir qui a produit quoi.

---

## 📍 Spécification des cibles

| Forme | Exemple | Sens |
|---|---|---|
| IP unique | `10.129.2.18` | un seul hôte |
| Plusieurs IP | `10.129.2.18 10.129.2.19 10.129.2.20` | liste explicite |
| Plage d'octet | `10.129.2.18-20` | IP contiguës |
| CIDR | `10.129.2.0/24` | tout un sous-réseau (256 hôtes) |
| Liste fichier | `-iL hosts.lst` | lit les cibles depuis un fichier |

```bash
# Ping sweep d'un /24, extraction des IP vivantes
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

---

## 📡 Host Discovery (découverte d'hôtes)

Avant de scanner les ports, on détermine quels hôtes répondent. La méthode la plus efficace est l'**ICMP echo request**.

| Option | Effet |
|---|---|
| `-sn` | Désactive le scan de ports (= ping scan seul) |
| `-PE` | Force le ping via **ICMP Echo Request** |
| `-Pn` | Désactive le ping (**traite tous les hôtes comme vivants**) |
| `--disable-arp-ping` | Désactive l'ARP ping (sur LAN/segment local) |
| `--packet-trace` | Affiche tous les paquets envoyés/reçus |
| `--reason` | Affiche **pourquoi** Nmap classe l'hôte/port ainsi |

> [!warning] Le piège de l'ARP ping sur réseau local
> Quand tu fais `-sn` sur un segment local, Nmap envoie d'abord un **ARP request** avant l'ICMP. Il marque l'hôte « up » dès la **réponse ARP**, sans jamais envoyer le ping ICMP. Pour vraiment tester l'ICMP, combine `-PE --disable-arp-ping --packet-trace`.

```bash
# Voir la mécanique réelle : ARP d'abord
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace
# SENT ... ARP who-has ...  →  RCVD ... ARP reply ...

# Forcer l'ICMP en désactivant l'ARP
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
# SENT ... ICMP Echo request ...  →  RCVD ... ICMP Echo reply ...
```

> [!note] Hôtes « inactifs » ≠ éteints
> Si un hôte ne répond pas à l'ICMP, ça peut simplement être son **firewall** qui drop les echo requests. Nmap le marque alors « down » à tort. D'où l'intérêt de `-Pn` quand on sait que la cible existe.

---

## 🔌 États d'un port

Les **6 états** que Nmap peut attribuer :

| État | Signification |
|---|---|
| `open` | Connexion établie (TCP, datagramme UDP, ou association SCTP). |
| `closed` | Le paquet reçu contient un **RST** → port fermé (sert aussi à confirmer que l'hôte est vivant). |
| `filtered` | Nmap n'arrive pas à trancher : **aucune réponse** ou code d'erreur → un firewall drop/rejette probablement. |
| `unfiltered` | **Uniquement avec le scan ACK (`-sA`)** : le port est accessible mais on ne sait pas s'il est open/closed. |
| `open\|filtered` | Pas de réponse → ouvert ou filtré, indéterminé (fréquent en UDP). |
| `closed\|filtered` | **Uniquement en idle scan (IP ID)** : impossible de dire closed vs filtered. |

> [!info] Drop vs Reject (côté firewall)
> - **Drop** : le paquet est ignoré, **aucune** réponse → Nmap réessaie (`--max-retries`, défaut 10) → scan **lent** → `filtered`.
> - **Reject** : réponse explicite → **RST** (TCP) ou **ICMP error** (Net/Host/Port/Proto Unreachable, Net/Host Prohibited).

---

## 🎯 Techniques de scan

```
-sS  TCP SYN scan        (half-open, défaut en root)
-sT  TCP Connect scan    (handshake complet, défaut sans root)
-sA  TCP ACK scan        (mapping de règles firewall)
-sW  TCP Window scan
-sM  TCP Maimon scan
-sU  UDP scan
-sN/-sF/-sX  Null / FIN / Xmas scans
-sI  Idle (zombie) scan
-sY/-sZ  SCTP INIT / COOKIE-ECHO
-sO  IP protocol scan
-b   FTP bounce scan
--scanflags  flags TCP personnalisés
```

### SYN scan `-sS` (le défaut en root)
Envoie un paquet **SYN** et ne complète **jamais** le handshake (half-open) :
- réponse **SYN-ACK** → port **open**
- réponse **RST** → port **closed**
- **pas** de réponse → **filtered**

Très rapide (plusieurs milliers de ports/s), plus discret car pas de connexion complète → moins de logs applicatifs. Nécessite **root** (raw sockets).

```bash
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
# SENT ... :21 S (SYN)
# RCVD ... :21 RA (RST+ACK) → port closed
```

### Connect scan `-sT`
Complète le **three-way handshake** complet via la pile TCP de l'OS.
- ✅ Très **précis** (état exact open/closed/filtered).
- ✅ « Poli » : se comporte comme un vrai client, peu de risque de casser un service.
- ❌ Le **moins discret** : crée des logs, facilement détecté par IDS/IPS.
- ✅ Ne nécessite **pas** root.

> [!tip] Quand utiliser `-sT`
> Quand tu n'es pas root, ou quand la **précision** prime sur la discrétion, ou pour interagir proprement avec des services fragiles.

### ACK scan `-sA`
Envoie un paquet avec **seulement le flag ACK**. Beaucoup plus dur à filtrer : les firewalls laissent souvent passer les ACK (ils ne savent pas si la connexion vient de l'intérieur ou de l'extérieur).
- port joignable → **RST** renvoyé → `unfiltered`
- pas de réponse → `filtered` (paquet droppé)

C'est un outil de **cartographie de règles firewall**, pas de découverte de services.

### UDP scan `-sU`
- **ICMP port unreachable (type 3 / code 3)** → port **closed**.
- autre réponse ICMP → `open|filtered`.
- Lent (pas de handshake, beaucoup de retransmissions).

```bash
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 100 --reason
# RCVD ICMP Port unreachable → 100/udp closed
```

---

## 🚪 Spécification des ports

| Syntaxe | Effet |
|---|---|
| `-p 22,25,80,139,445` | ports listés |
| `-p 22-445` | plage de ports |
| `-p-` | **tous** les ports (1-65535) |
| `-F` | scan rapide : **top 100** ports |
| `--top-ports=10` | les N ports les plus fréquents (base Nmap) |
| `-r` | scan séquentiel (pas d'ordre aléatoire) |

> [!note] Défaut
> Sans `-p`, Nmap scanne les **top 1000** ports TCP. En root → `-sS` ; sans root → `-sT`.

---

## 🔎 Détection de services et versions (-sV)

`-sV` identifie le **service**, sa **version**, et parfois l'OS. Indispensable : une version exacte permet de chercher un exploit précis et de lire le code source de la version concernée.

```bash
sudo nmap 10.129.2.28 -p- -sV
```

### Comment ça marche (banner grabbing + signatures)
1. Après le handshake, beaucoup de services envoient spontanément une **bannière** (flag **PSH** côté serveur) → Nmap la lit.
2. S'il ne reconnaît pas via la bannière, il envoie des **sondes** et compare à une base de **signatures** (plus long).

| Option | Effet |
|---|---|
| `-sV` | détection de version |
| `--version-intensity <0-9>` | intensité des sondes (0 = minimal, 9 = tout) |
| `--version-light` | = intensité 2 (rapide) |
| `--version-all` | = intensité 9 (toutes les sondes) |
| `-v` / `-vv` | verbosité (affiche les ports dès découverte) |
| `--stats-every=5s` | statut du scan toutes les 5 s |
| `[Espace]` | pendant le scan : affiche la progression |

> [!example] Nmap peut « cacher » de l'info
> Avec `--packet-trace`, on voit parfois que le serveur a renvoyé **plus** que ce que Nmap affiche. Ex. SMTP :
> ```
> READ SUCCESS ... 220 inlane ESMTP Postfix (Ubuntu)
> ```
> Nmap n'affiche que `Postfix smtpd`, mais la bannière révélait **Ubuntu**. D'où l'intérêt de **grab la bannière à la main** (nc/ncat) et de capturer le trafic (tcpdump).

```bash
# Bannière manuelle + capture
sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28   # terminal 1
nc -nv 10.129.2.28 25                                   # terminal 2
# → 220 inlane ESMTP Postfix (Ubuntu)
```

---

## 💻 Détection d'OS (-O)

```bash
sudo nmap 10.129.2.28 -p 445 -O
```

Basé sur le **fingerprinting de la pile TCP/IP**. Peu fiable si Nmap ne trouve pas au moins **1 port ouvert et 1 port fermé** (`OSScan results may be unreliable`). Donne des « Aggressive OS guesses » avec un pourcentage de confiance.

> [!tip] Combiner avec une source IP alternative
> Si un sous-réseau est bloqué, tester une autre IP source peut débloquer la détection :
> ```bash
> sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
> ```

---

## 📜 NSE — Nmap Scripting Engine

Scripts en **Lua** pour interagir avec les services. **14 catégories** :

| Catégorie | Usage |
|---|---|
| `auth` | détermination d'identifiants d'authentification |
| `broadcast` | découverte d'hôtes par broadcast |
| `brute` | brute-force de login sur les services |
| `default` | scripts par défaut (`-sC`) |
| `discovery` | évaluation des services accessibles |
| `dos` | test de déni de service (⚠️ peut casser le service) |
| `exploit` | exploitation de vulnérabilités connues |
| `external` | utilise des services externes |
| `fuzzer` | envoi de champs variés (long, trouve des bugs) |
| `intrusive` | scripts pouvant impacter négativement la cible |
| `malware` | détection de malware sur la cible |
| `safe` | scripts défensifs, non intrusifs |
| `version` | extension de la détection de version |
| `vuln` | identification de vulnérabilités spécifiques |

```bash
sudo nmap <cible> -sC                       # scripts "default"
sudo nmap <cible> --script <catégorie>      # toute une catégorie
sudo nmap <cible> --script <nom1>,<nom2>    # scripts nommés
```

```bash
# Exemple : bannière + commandes SMTP
sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
# |_banner: 220 inlane ESMTP Postfix (Ubuntu)
# |_smtp-commands: PIPELINING, SIZE, VRFY, ETRN, STARTTLS, ...
```

> [!info] Scan agressif `-A`
> `-A` = `-sV` + `-O` + `--traceroute` + `-sC` (scripts default). Pratique mais **bruyant**.
> ```bash
> sudo nmap 10.129.2.28 -p 80 -A
> # → Apache 2.4.29, WordPress 5.3.4, title blog.inlanefreight.com, OS Linux 96%
> ```

> [!example] Évaluation de vulnérabilités
> ```bash
> sudo nmap 10.129.2.28 -p 80 -sV --script vuln
> # → http-enum (wp-login.php...), http-wordpress-users (admin),
> #   vulners (CVE-2019-0211, CVE-2017-15715, ...)
> ```

Doc des scripts : `https://nmap.org/nsedoc/index.html`

---

## 💾 Sauvegarde des résultats

| Option | Format | Extension |
|---|---|---|
| `-oN` | Normal (lisible) | `.nmap` |
| `-oG` | Grepable | `.gnmap` |
| `-oX` | XML | `.xml` |
| `-oA <nom>` | **les 3 à la fois** | `.nmap` `.gnmap` `.xml` |

```bash
sudo nmap 10.129.2.28 -p- -oA target
```

> [!tip] Du XML vers un rapport HTML
> ```bash
> xsltproc target.xml -o target.html
> ```
> Génère un rapport clair, lisible même par des non-techniques → parfait pour la doc.

---

## ⚡ Performance et timing

Crucial sur un grand réseau ou une bande passante faible.

| Option | Effet |
|---|---|
| `-T <0-5>` | template de timing (agressivité globale) |
| `--min-rate <n>` | au moins **n** paquets/seconde |
| `--max-rate <n>` | au plus **n** paquets/seconde |
| `--min-parallelism <n>` | fréquence min de sondes en parallèle |
| `--initial-rtt-timeout <t>` | RTT initial (défaut ~100 ms) |
| `--max-rtt-timeout <t>` | RTT max |
| `--max-retries <n>` | nb de retransmissions (défaut 10, peut → 0) |
| `--host-timeout <t>` | abandonne un hôte après ce délai |

### Templates de timing
| Template | Nom | Usage |
|---|---|---|
| `-T0` | paranoid | IDS evasion extrême (très lent) |
| `-T1` | sneaky | furtif |
| `-T2` | polite | ménage la cible/bande passante |
| `-T3` | **normal** | **défaut** |
| `-T4` | aggressive | rapide, réseaux fiables |
| `-T5` | insane | très rapide (risque de perte d'info) |

> [!warning] Vitesse ↔ exactitude
> Accélérer (`--max-retries 0`, RTT court, `-T5`) fait **rater** des hôtes/ports. Sur un black-box prudent, reste discret ; en white-box whitelisté, monte `--min-rate`.

---

## 🥷 Firewall / IDS / IPS Evasion

> [!abstract] Concepts
> - **Firewall** : laisse passer / drop / bloque selon des règles. Mesure **active**.
> - **IDS** : détecte et **alerte** sur des patterns/signatures (ex. scan de version). Passif.
> - **IPS** : complète l'IDS en prenant des **mesures défensives** automatiques (ex. bannir l'IP).

### Détecter la présence d'un IDS/IPS
On scanne agressivement depuis un **VPS**. Si l'IP se fait **bannir** (plus d'accès à la cible), c'est qu'un IPS est en place → on change de VPS et on devient plus discret. Recommandation : **plusieurs VPS** avec IP différentes.

### Techniques d'évasion

| Option | Technique |
|---|---|
| `-sA` | ACK scan (passe mieux les firewalls que SYN) |
| `-f` / `--mtu <n>` | **fragmentation** des paquets (MTU multiple de 8) |
| `-D <ip1>,<ip2>,RND:5` | **decoys** : noie ta vraie IP dans des leurres |
| `-S <ip>` | **spoof** de l'IP source |
| `-e <iface>` | force l'interface (ex. `tun0`) |
| `-g` / `--source-port <port>` | **port source** spoofé (déguisement) |
| `--data-length <n>` | ajoute des données aléatoires au paquet |
| `--spoof-mac <mac>` | usurpe l'adresse MAC |
| `--badsum` | checksum invalide (détecte certains firewalls) |
| `--ttl <n>` | fixe le TTL |
| `--dns-server <ns>,<ns>` | utilise des DNS choisis (utile en DMZ) |

### Decoys `-D`
Nmap insère des **IP leurres** dans les en-têtes, ta vraie IP est placée au hasard parmi elles.

```bash
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
# SENT depuis 102.52.161.59, 10.10.14.2 (toi), 210.120.38.29, ...
```

> [!warning] Limites des decoys
> Les leurres doivent être **vivants** (sinon SYN-flood → service injoignable). Les paquets spoofés sont souvent filtrés par les ISP/routeurs.

### Le port source (`--source-port` / `-g`) — la clé des labs
Beaucoup de firewalls font confiance au trafic **venant du port 53 (DNS)**, 80/443 (HTTP/S), etc. En usurpant le port source, on se **déguise** en réponse d'un service de confiance.

```bash
# Port filtré en scan normal...
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace
# → 50000/tcp filtered ibm-db2

# ...mais OUVERT depuis le port source 53
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --source-port 53
# → 50000/tcp open ibm-db2
```

### DNS Proxying
Nmap fait par défaut une **résolution DNS inverse** (sauf `-n`). Les requêtes DNS passent par l'**UDP 53**. Le **TCP 53** servait historiquement aux **zone transfers** / transferts > 512 octets ; avec IPv6 et DNSSEC, de plus en plus de requêtes passent en TCP 53. En DMZ, on peut pointer `--dns-server` vers les **DNS internes** (plus de confiance) pour interagir avec le réseau interne.

---

## 🧪 Mécaniques des labs (vécu)

> [!success] Ce qu'on a réellement débloqué pendant le Hard Lab
> Toute la difficulté tournait autour d'un service sur le **port 50000** (IBM Db2) derrière un firewall qui **ne fait confiance qu'au port source 53**, et d'un piège `tcpwrapped`.

### 1. `filtered` vs `tcpwrapped` vs `open`
- **`filtered`** : le SYN ne reçoit **aucune** réponse → le firewall jette le paquet **à l'entrée**. (C'est ce qu'on obtenait depuis les ports sources 80/443 → preuve que **seul 53** passe sur cette cible.)
- **`open`** (SYN scan) : handshake possible → mais ça ne prouve **pas** que les **données** passent.
- **`tcpwrapped`** : le **handshake aboutit** (SYN-ACK, visible avec `--reason` → `syn-ack ttl 63`), mais dès que Nmap envoie sa **sonde applicative**, la connexion est **reset** → pas de bannière lisible.

> [!danger] Pourquoi `tcpwrapped` persiste même avec `--version-all`
> `--version-all` change les **sondes**, pas le **canal**. Si le firewall reset toute connexion dont le **port source ≠ 53** sur le canal data, aucune sonde ne passera. Le vrai problème n'est pas la sonde.

### 2. La cause racine : le **bind du port source**
- En **`-sS`** (SYN scan), Nmap **forge** le port source en raw socket → `--source-port 53` marche sans rien binder.
- En **`-sV`** (et avec ncat), il faut une **vraie socket TCP** (`connect()`), donc **binder** le port 53 local. Si un service local occupe déjà le 53 → le bind échoue → Nmap **retombe sur un port source aléatoire** → le firewall reset les données → **`tcpwrapped`**.

C'est exactement ce que montrait l'erreur ncat :
```
libnsock mksock_bind_addr(): Bind to 0.0.0.0:53 failed: Address already in use (98)
```

### 3. Identifier qui occupe le port 53 local
```bash
sudo ss -tulnp | grep :53
# udp/tcp  10.0.3.1:53  users:(("dnsmasq",pid=1337,...))
```
Ici **`dnsmasq`** (pas `systemd-resolved`), bindé sur une **IP précise** `10.0.3.1` — pas en wildcard.

### 4. La solution propre : binder sur une autre IP avec `-s` (ncat)
Comme dnsmasq écoute sur `10.0.3.1:53` (IP précise), on peut binder le **port 53 sur l'IP tun0** sans conflit :
```bash
sudo ncat -nv -s 10.10.14.246 --source-port 53 10.129.2.47 50000
# Ncat: Connected to 10.129.2.47:50000.
# 220 HTB{...}   ← la bannière = la réponse
```

### 5. Variante 100 % nmap
Libérer le 53 (ou utiliser le script banner qui ne « parle » pas) :
```bash
sudo systemctl stop dnsmasq
sudo nmap -p 50000 -sV --source-port 53 -Pn -n --disable-arp-ping 10.129.2.47
# ou, plus propre pour afficher la bannière brute :
sudo nmap -p 50000 --script banner --source-port 53 -Pn -n --disable-arp-ping 10.129.2.47
```

> [!note] Hiérarchie pratique du bind de port source
> 1. Port autorisé **libre** localement → connexion directe, rien à faire.
> 2. Port autorisé occupé sur une **IP précise** → `-s <ton_ip_tun0>` pour binder ailleurs.
> 3. Port autorisé occupé en **wildcard `0.0.0.0`** → couper le service local ou changer de port.

### 6. Trouver quels ports sources passent (énumération empirique)
Un firewall ne déclare jamais sa whitelist. On l'**infère** en faisant varier le port source :
```bash
for sp in 20 21 22 25 53 80 88 123 443; do
  echo -n "source-port $sp : "
  sudo nmap -p 50000 -sS -Pn -n --disable-arp-ping --source-port $sp 10.129.2.47 \
    | grep '50000/tcp' | awk '{print $2}'
done
```

### 7. `firewalk` ≠ ce qu'on cherchait
```bash
sudo nmap --script=firewalk --traceroute -Pn -n 10.129.2.47
```
> [!warning] Distinction clé port source vs port destination
> `firewalk` cartographie le filtrage par **port destination** sur un chemin réseau (jusqu'au gateway intermédiaire), pas la whitelist de **port source** de la cible. Le HOP 0, c'est **toi** (ton tun0), pas la cible. Donc firewalk **ne répond pas** à « quels ports sources le firewall accepte ». Pour ça → la boucle ci-dessus.

> [!abstract] La leçon transversale
> `tcpwrapped` derrière un firewall qui filtre par **port source** = un problème de **bind du port source sur ta socket cliente**, que tu utilises nmap **ou** ncat. Une fois ça compris, le choix de l'outil n'est qu'une question d'ergonomie. Et **ne jamais présumer** quels ports un firewall autorise : on **teste**.

---

## 🔧 ncat — le couteau suisse réseau

> [!info] Pourquoi ncat ici
> `ncat` (réécriture moderne de `netcat`, livré **avec Nmap**) sert à ouvrir/écouter des connexions TCP/UDP brutes. Dans le contexte enum, il est le complément naturel de Nmap : là où `-sV` envoie des sondes « bruyantes » que le firewall reset, **ncat reste silencieux** — il ouvre la connexion et attend que le serveur parle. C'est souvent ce qui fait **tomber une bannière** que Nmap n'arrivait pas à lire (→ `tcpwrapped`).

### Différence avec Nmap (le point qui débloque les labs)
| | Nmap `-sV` | ncat |
|---|---|---|
| Comportement | envoie des **sondes** actives | **silencieux**, attend le serveur |
| Déclenche le reset du firewall | souvent **oui** | souvent **non** |
| Lit la bannière `220 ...` | parfois bloqué | **oui**, directement |

### Options essentielles
| Option                        | Effet                                                                         |
| ----------------------------- | ----------------------------------------------------------------------------- |
| `-n`                          | pas de résolution DNS                                                         |
| `-v` / `-vv`                  | verbosité (état de connexion)                                                 |
| `-s <ip>`                     | **bind sur une IP source précise** (clé pour éviter un conflit de port local) |
| `-p <port>` *(mode listen)*   | port d'écoute local                                                           |
| `--source-port <port>` / `-g` | **port source** sortant (déguisement, ex. 53)                                 |
| `-l`                          | mode **listen** (serveur)                                                     |
| `-u`                          | mode **UDP**                                                                  |
| `-w <t>`                      | timeout                                                                       |
| `-e <cmd>` / `-c <cmd>`       | exécute une commande sur connexion (⚠️ shells)                                |
| `--ssl`                       | connexion TLS                                                                 |

### Cas d'usage typiques

**1. Banner grabbing / atteindre un port filtré (le cas du lab)**
```bash
sudo ncat -nv -s 10.10.14.246 --source-port 53 10.129.2.47 50000
# 220 HTB{...}
```

**2. Banner grab simple (service qui parle en premier)**
```bash
nc -nv 10.129.2.28 25
# 220 inlane ESMTP Postfix (Ubuntu)
```

**3. Listener (réception d'un reverse shell, transfert)**
```bash
ncat -lvnp 4444            # écoute sur 4444
ncat -nv 10.10.10.5 4444   # se connecte au listener
```

**4. Transfert de fichier**
```bash
# Récepteur
ncat -lvnp 4444 > recu.bin
# Émetteur
ncat -nv 10.10.10.5 4444 < fichier.bin
```

**5. Chat / test de port brut**
```bash
ncat -lvnp 9000            # côté A
ncat 10.10.10.5 9000       # côté B → on tape, ça s'affiche en face
```

> [!tip] Le réflexe `-s` quand le bind échoue
> Si `Bind to 0.0.0.0:<port> failed: Address already in use`, c'est qu'un service local occupe ce port. Si ce service écoute sur une **IP précise** (vérifie avec `ss -tulnp`), `-s <ton_ip_tun0>` te laisse binder le même numéro de port **sur une autre IP**, sans rien couper.

> [!warning] netcat vs ncat
> Les `nc` traditionnels (OpenBSD, GNU, busybox) ont des options **différentes** (pas tous `-s`/`--source-port` pareils, `-e` souvent absent par sécurité). `ncat` (suite Nmap) est le plus complet et le plus cohérent.

---

## 📋 Cheat sheet

```bash
# --- Découverte ---
sudo nmap 10.129.2.0/24 -sn -oA sweep            # ping sweep
sudo nmap -iL hosts.lst -sn                       # depuis une liste

# --- Scan complet recommandé ---
sudo nmap 10.129.2.47 -p- -sS -Pn -n --disable-arp-ping -oA fullscan
sudo nmap 10.129.2.47 -p <ports_ouverts> -sV -sC -oA detailed

# --- États / debug ---
sudo nmap ... --packet-trace --reason -vv

# --- UDP ---
sudo nmap 10.129.2.47 -sU --top-ports 50 -Pn -n

# --- NSE ---
sudo nmap <cible> -sC                             # default
sudo nmap <cible> -p 80 -sV --script vuln
sudo nmap <cible> -p 25 --script banner,smtp-commands

# --- OS / agressif ---
sudo nmap <cible> -O
sudo nmap <cible> -A

# --- Performance ---
sudo nmap <cible> -p- --min-rate 1000 -T4
sudo nmap <cible> -F --max-retries 1

# --- Évasion firewall / IDS ---
sudo nmap <cible> -sA -Pn -n                      # mapping de règles
sudo nmap <cible> -f                              # fragmentation
sudo nmap <cible> -D RND:5 -Pn -n                 # decoys
sudo nmap <cible> -g 53 -Pn -n                    # port source 53
sudo nmap <cible> -S <ip> -e tun0 -Pn -n          # spoof source IP

# --- Le combo "tcpwrapped" du Hard Lab ---
sudo ss -tulnp | grep :53                         # qui occupe 53 ?
sudo ncat -nv -s <ip_tun0> --source-port 53 <cible> 50000
# ou 100% nmap :
sudo systemctl stop dnsmasq
sudo nmap -p 50000 --script banner --source-port 53 -Pn -n --disable-arp-ping <cible>

# --- Sauvegarde / rapport ---
sudo nmap <cible> -oA resultat
xsltproc resultat.xml -o resultat.html
```

### Options « hygiène de scan » (à connaître par cœur)
| Option | Rôle |
|---|---|
| `-Pn` | ne pas ping (traiter comme vivant) |
| `-n` | pas de résolution DNS |
| `--disable-arp-ping` | pas d'ARP ping (LAN) |
| `--packet-trace` | voir chaque paquet |
| `--reason` | voir le **pourquoi** d'un état |
| `-oA <nom>` | sauvegarder dans tous les formats |

---

> [!quote] À retenir
> L'énumération n'est pas une question d'outils mais d'**interprétation**. Nmap te donne des octets ; c'est à toi de comprendre *pourquoi* un port est `filtered` plutôt que `tcpwrapped`, *quel* déguisement passe le firewall, et *où* se situe la vraie contrainte (côté cible : port autorisé ; côté toi : port bindable). Les deux doivent être satisfaits en même temps.

**Liens utiles**
- Host discovery : `https://nmap.org/book/host-discovery-strategies.html`
- Techniques de scan : `https://nmap.org/book/man-port-scanning-techniques.html`
- Formats de sortie : `https://nmap.org/book/output.html`
- Performance : `https://nmap.org/book/man-performance.html`
- Templates timing : `https://nmap.org/book/performance-timing-templates.html`
- NSE : `https://nmap.org/nsedoc/index.html`
