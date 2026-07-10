---
titre: "Web Service & API — Méthodologie d'audit type"
aliases:
  - "Web Service & API — Méthodologie d'audit type"
plateforme: "Hack The Box Academy"
module: "Web Service & API Attacks"
date: 2026-07-02
tags: [HTB, API, WebService, Méthodologie, Recon, Checklist, Notes]
---

# 🔍 Méthodologie — Audit Type d'un Service Web / API

> Le fil rouge du module. Pendant l'apprentissage on a tâtonné ; voici la **démarche ordonnée** à suivre pour ne rien rater et gagner du temps. À dérouler dans l'ordre sur toute cible web/API.

Lié : [[API & Web Server - Index]] · [[17 - Outils ffuf sqlmap]]

---

## Phase 0 — Connectivité & cadrage

```bash
# VPN monté ?
ip a show tun0                 # doit afficher une IP 10.10.x.x
ping -c2 <TARGET_IP>           # la cible répond ?
```

- Note l'IP cible (elle **change à chaque respawn** — vérifie-la dans toutes tes commandes).
- Note ton IP `tun0` (utile pour SSRF / XXE / reverse shells).

---

## Phase 1 — Reconnaissance réseau (découvrir les ports)

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

## Phase 2 — Fingerprinting de chaque service web

Pour **chaque port HTTP** trouvé :

```bash
curl -i http://<TARGET_IP>:<PORT>/            # headers, techno, redirections
curl -s http://<TARGET_IP>:<PORT>/ | head -40 # corps de la page
whatweb http://<TARGET_IP>:<PORT>/            # techno (si dispo)
```

Ce que tu cherches : serveur (Apache/Nginx/Express), langage (`X-Powered-By: PHP/Express`), framework, présence d'une API (`{"status":"UP"}`), page d'auth, formulaire d'upload, XML dans les requêtes.

---

## Phase 3 — Découverte de contenu (3 surfaces distinctes)

> ⚠️ Erreur classique : confondre **chemins**, **paramètres** et **endpoints d'API**. Ce sont 3 fuzzing différents. Voir [[17 - Outils ffuf sqlmap]].

### 3.1 — Chemins / répertoires
```bash
dirb http://<TARGET_IP>:<PORT>
# ou
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://<TARGET_IP>:<PORT>/FUZZ
```
→ trouve `/wsdl`, `/uploads`, `/admin`, `xmlrpc.php`, etc.

### 3.2 — Paramètres GET cachés
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

### 3.3 — Endpoints d'API
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

### 3.4 — WSDL / doc de service (si SOAP)
```bash
curl http://<TARGET_IP>:<PORT>/wsdl          # souvent vide seul
curl http://<TARGET_IP>:<PORT>/wsdl?wsdl     # le paramètre débloque le contenu
```
Variantes : `?wsdl`, `/service.wsdl`, `/example.disco?disco`. Voir [[03 - WSDL Énumération]].

---

## Phase 4 — Analyse : mapper la surface d'attaque

Pour chaque endpoint/paramètre trouvé, note :
- **Méthode** (GET/POST), **format attendu** (JSON ? XML ? form ? Base64 ?)
- **Paramètres** et ce qu'ils semblent faire
- **Réflexions** : mon input revient-il dans la réponse ? (→ XSS / XXE in-band / SQLi error-based)
- Le **SGBD / langage** si un message d'erreur le révèle

Pour un service SOAP : lis le **WSDL** → il liste toutes les opérations et leurs paramètres (= tes points d'injection). Voir [[03 - WSDL Énumération]].

---

## Phase 5 — Test systématique des vulnérabilités (checklist)

Passe chaque paramètre/endpoint dans cette grille :

- [ ] **SQLi** → `'` puis `UNION SELECT` (voir [[08 - SQL Injection]])
- [ ] **Command Injection** → paramètre injecté dans une commande shell ? fonctions PHP appelables ? (voir [[05 - Command Injection]])
- [ ] **LFI / Path Traversal** → param = nom de fichier ? teste `..%2f..%2fetc%2fpasswd` (voir [[10 - LFI]])
- [ ] **XSS** → input réfléchi ? teste `<script>` puis encodages (voir [[11 - XSS]])
- [ ] **SSRF** → param qui fetch une ressource ? teste `http://TON_IP`, en clair / Base64 / encodé (voir [[12 - SSRF]])
- [ ] **XXE** → l'app parse du XML que je contrôle ? injecte un DOCTYPE (voir [[14 - XXE]])
- [ ] **File Upload** → upload possible ? teste `.php`, faux Content-Type, magic bytes (voir [[09 - File Upload]])
- [ ] **ReDoS** → validation par regex ? mesure le temps avec un input long (voir [[13 - ReDoS]])
- [ ] **SOAPAction Spoofing** → opération bloquée + filtre basé sur le header ? (voir [[04 - SOAPAction Spoofing]])
- [ ] **Auth bypass / IDOR** → énumération d'IDs, `' OR '1'='1`

### Règle d'or des ENCODAGES
Un paramètre qui **refuse** ton input ≠ paramètre **protégé**. Teste systématiquement, dans l'ordre :
1. En clair
2. **URL-encoding** simple (`%2f`, `%20`, `%3C`)
3. **Double URL-encoding** (`%252f`) — utile face à un WAF/proxy qui décode une couche
4. **Base64** (cf. SSRF : l'URL brute rejetée, la Base64 acceptée)
5. Variantes spécifiques (IP décimale/hexa, wrappers `php://`, casse mixte)

---

## Phase 6 — Exploitation

- Construis le PoC minimal qui **prouve** la faille (une connexion sur ton listener, un fichier lu, une commande exécutée).
- Puis **escalade** : RCE → reverse shell, LFI → clés SSH / log poisoning, SQLi → dump complet.
- Garde tes scripts (voir [[15 - Arsenal Shells Python]], [[16 - Arsenal Scripts SQLi]]).

---

## Phase 7 — Post-exploitation & documentation

- Récupère **le code source** dès que tu as un accès (`cat app.js`, `cat ping-server.php`) → comprends la faille + cherche creds en dur, autres endpoints, clés.
- Énumère : `id`, `hostname`, `uname -a`, `/etc/passwd`, `env`, ports internes (`ss -tulnp`).
- Documente : requête, payload, réponse, impact (triade CIA), remédiation.

---

## 🧭 Arbre de décision express

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
