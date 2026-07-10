---
titre: "Outils — ffuf, sqlmap, nmap, curl, wordlists"
aliases:
  - "Outils — ffuf, sqlmap, nmap, curl, wordlists"
plateforme: "Hack The Box Academy"
module: "Web Service & API Attacks"
date: 2026-07-02
tags: [HTB, API, Outillage, ffuf, sqlmap, nmap, curl, Notes]
---

# 🛠️ Outils — ffuf, sqlmap, nmap, curl, wordlists

Lié : [[01 - Méthodologie - Audit Type]] · [[API & Web Server - Index]]

---

# ffuf — Guide complet

Le fuzzer web à tout faire. Principe : le mot-clé **`FUZZ`** dans l'URL/headers/body est remplacé par chaque mot de la wordlist.

## Syntaxe de base
```bash
ffuf -w <wordlist> -u <URL_avec_FUZZ> [filtres]
```

## Les 4 modes selon la position de FUZZ

| But | Position de FUZZ | Exemple |
|---|---|---|
| **Répertoires/pages** | dans le path | `-u http://T/FUZZ` |
| **Paramètres GET** | nom du paramètre | `-u 'http://T/?FUZZ=test'` |
| **Endpoints API** | après /api/ | `-u 'http://T/api/FUZZ'` |
| **Valeurs** | valeur du paramètre | `-u 'http://T/?id=FUZZ'` |
| **VHost** | header Host | `-u http://T -H 'Host: FUZZ.T'` |

> ⚠️ Erreur vécue : `FUZZ` dans le mauvais endroit. `/FUZZ?=test` teste des **pages**, `/?FUZZ=test` teste des **paramètres**. Ne pas confondre. Et jamais de `http://http://`.

## Flags essentiels

| Flag | Rôle |
|---|---|
| `-w FILE` | wordlist (`-w file:KEYWORD` pour en nommer plusieurs) |
| `-u URL` | URL cible (guillemets simples si `?`/`&`) |
| `-H "H: V"` | header custom |
| `-X POST` | méthode HTTP |
| `-d "data"` | body (POST) |
| `-mc` / `-fc` | **match/filter** par code HTTP |
| `-ms` / `-fs` | **match/filter** par taille (size) ⭐ |
| `-mw` / `-fw` | match/filter par nombre de mots |
| `-ml` / `-fl` | match/filter par nombre de lignes |
| `-mr` / `-fr` | match/filter par regex |
| `-ac` | **auto-calibration** (détecte et filtre le bruit auto) |
| `-t 40` | threads (défaut 40) |
| `-rate N` | limite de req/s (discrétion) |
| `-recursion` | fuzzing récursif |
| `-e .php,.html` | extensions à ajouter |
| `-mode clusterbomb` | multi-wordlists (combinaisons) |

## La stratégie de filtrage ⭐ (la plus importante)

Quand **toutes les réponses ont la même taille** (l'app renvoie un texte constant, pas de 404) :
```bash
# 1) SANS filtre → repérer la taille "de base" qui se répète
ffuf -w LISTE -u 'http://T/?FUZZ=test'
# 2) filtrer cette taille → seule l'anomalie ressort
ffuf -w LISTE -u 'http://T/?FUZZ=test' -fs <TAILLE_DE_BASE>
```
Alternative auto : `-ac` (auto-calibration) fait ça tout seul.

## Exemples issus du module
```bash
# WSDL : paramètre débloquant le contenu (réponses vides filtrées)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u 'http://T:3002/wsdl?FUZZ' -fs 0 -mc 200

# Paramètre d'API (info disclosure)
ffuf -w .../burp-parameter-names.txt -u 'http://T:3003/?FUZZ=test' -fs 19

# Endpoints d'API
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u 'http://T:3000/api/FUZZ' -fs 15

# Fichiers via LFI
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
     -u "http://T:3000/api/download/FUZZ" -fs <TAILLE_ERREUR>
```

---

# sqlmap — l'essentiel

```bash
# API REST (paramètre GET)
sqlmap -u "http://T:3003/?id=1" --batch                    # détection
sqlmap -u "http://T:3003/?id=1" --dbs --batch              # bases
sqlmap -u "http://T:3003/?id=1" --dump -T users --batch    # dump table

# Requête complète depuis un fichier (SOAP, POST XML) avec * = point d'injection
sqlmap -r requete.txt --dump -T users --batch

# options utiles
--level=5 --risk=3      # plus agressif
--technique=U           # forcer UNION
--dbms=sqlite           # forcer le SGBD
--tamper=space2comment  # évasion
```
Détecte automatiquement SGBD, techno, nb de colonnes (a révélé MySQL/PHP dans le module).

---

# nmap — reconnaissance

```bash
nmap -p- --min-rate 5000 -T4 <IP>       # tous les ports, rapide
nmap -p <PORTS> -sV -sC <IP>            # versions + scripts par défaut
nmap -p <PORTS> -sV -A <IP>             # agressif (OS, traceroute)
```
Alternatives : `rustscan -a <IP> -- -sV` (plus rapide), `nc -zv -w1 <IP> <port>`.

---

# curl — astuces vécues

```bash
# éviter les erreurs d'espaces dans l'URL (SQLi en GET)
curl -G "http://T/" --data-urlencode "id=1 UNION SELECT ..."

# timeout (indispensable pour scan SSRF / hang)
curl -m 8 "http://T/..."

# POST avec header SOAPAction
curl -X POST http://T:3002/wsdl -H 'SOAPAction: "Login"' -d '<?xml ...?>...'

# upload de fichier
curl -X POST -F "file=@backdoor.php" http://T:3001/api/upload/

# voir headers + corps
curl -i http://T/           # -I = headers seuls
```

> ⚠️ `curl: (3) bad/illegal format` = espaces bruts dans l'URL → utiliser `-G --data-urlencode` ou URL-encoder.
> ⚠️ Échapper le `?` en shell : `curl http://T/wsdl\?wsdl` ou guillemets.

---

# Wordlists SecLists — lesquelles pour quoi

```
Discovery/Web-Content/common.txt                      → répertoires/pages (dirb-like)
Discovery/Web-Content/burp-parameter-names.txt        → noms de PARAMÈTRES
Discovery/Web-Content/api/api-endpoints.txt           → endpoints d'API
Discovery/Web-Content/api/objects.txt                 → objets d'API (plus large)
Discovery/Web-Content/common-api-endpoints-mazen160.txt → endpoints API (celle du cours)
Fuzzing/LFI/LFI-Jhaddix.txt                           → fichiers sensibles (LFI)
Passwords/Leaked-Databases/rockyou.txt                → brute-force mdp
```
Localiser dans Exegol :
```bash
find / -iname "*api*" -path "*seclists*" 2>/dev/null
find / -name burp-parameter-names.txt 2>/dev/null
```
> 💡 Pour l'API en conditions réelles, **Assetnote** (`wordlists.assetnote.io`, ex. `httparchive_apiroutes`) est plus moderne que SecLists. Un endpoint custom (ex. `userinfo`) peut n'être dans **aucune** wordlist → compléter par analyse du JS / Swagger / trafic Burp.
