# 📍 INDEX — Web Service & API Attacks

> **Module HTB Academy** — Attaques sur les services Web et les API
> Statut : ✅ **Terminé** (13/13 sections + Skills Assessment)
> Flag final : `FLAG{1337_SQL_INJECTION_IS_FUN_:)}`

Cette note est le **hub** (MOC — Map of Content) du vault. Tout est lié depuis ici.
L'objectif : ne pas être un simple write-up, mais un **arsenal réutilisable** — concepts, scripts, payloads et outils à ressortir en CTF / bug bounty.

---

## 🗺️ Comment utiliser ce vault

1. Tu tombes sur un service web / API inconnu → commence par [[01 - Méthodologie - Audit Type]]
2. Tu identifies un vecteur → ouvre la note de vulnérabilité correspondante (section 🧩)
3. Tu as besoin d'un shell / d'un script → [[15 - Arsenal Shells Python]] et [[16 - Arsenal Scripts SQLi]]
4. Tu as besoin d'une commande d'outil → [[17 - Outils ffuf sqlmap]]
5. Tu cherches un payload précis → [[18 - Cheatsheet Payloads]]

---

## 🔍 Méthodologie & Fondamentaux

- [[01 - Méthodologie - Audit Type]] — la démarche ordonnée pour un audit minutieux
- [[02 - Fondamentaux]] — Web Service vs API, SOAP / REST / XML-RPC / JSON-RPC, structure WSDL

## 🧩 Vulnérabilités (concepts + exploitation)

| # | Vulnérabilité | Port (module) | Techno | Note |
|---|---|---|---|---|
| 1 | Énumération WSDL | 3002 | SOAP | [[03 - WSDL Énumération]] |
| 2 | SOAPAction Spoofing | 3002 | SOAP / Node | [[04 - SOAPAction Spoofing]] |
| 3 | Command Injection | 3003 | PHP | [[05 - Command Injection]] |
| 4 | WordPress `xmlrpc.php` | 80 | WordPress | [[06 - WordPress xmlrpc]] |
| 5 | Information Disclosure (Fuzzing) | 3003 | PHP / MySQL | [[07 - Information Disclosure]] |
| 6 | SQL Injection (API & SOAP) | 3003 / 3002 | MySQL / SQLite | [[08 - SQL Injection]] |
| 7 | Arbitrary File Upload → RCE | 3001 | PHP | [[09 - File Upload]] |
| 8 | Local File Inclusion (LFI) | 3000 | Node | [[10 - LFI]] |
| 9 | Cross-Site Scripting (XSS) | 3000 | Node | [[11 - XSS]] |
| 10 | SSRF | 3000 | Node | [[12 - SSRF]] |
| 11 | ReDoS | 3000 | Node | [[13 - ReDoS]] |
| 12 | XXE Injection | 3001 | Node | [[14 - XXE]] |

> ⚠️ Les ports sont **indicatifs** : chaque section HTB spawn sa propre cible, donc un même port (ex. 3003) héberge des services différents selon la section. Ce qui compte, c'est le **type de service** derrière.

## ⚙️ Arsenal (scripts réutilisables)

- [[15 - Arsenal Shells Python]] — collection de **shells Python** pour la faille SOAP `/wsdl` (du plus simple au plus complet) + reverse shells one-liners
- [[16 - Arsenal Scripts SQLi]] — automatisation SQLi (colonnes, dump), énumération API, brute-force

## 🛠️ Outils

- [[17 - Outils ffuf sqlmap]] — `ffuf` (guide complet), `sqlmap`, `nmap`, `curl`, `dirb`, wordlists SecLists

## 📋 Référence rapide

- [[18 - Cheatsheet Payloads]] — tous les payloads du module en un endroit (SQLi MySQL+SQLite, LFI, XSS, SSRF, XXE, ReDoS, encodages)

---

## 🎯 Récap des cibles du module (mémo)

```
Port 3000  → API principale (/api/*) : LFI, XSS, SSRF, ReDoS       [Node/Express + axios]
Port 3001  → App auth XML + upload  : File Upload RCE, XXE          [Node]
Port 3002  → Service SOAP (/wsdl)   : WSDL enum, SOAPAction spoof, SQLi final  [Node + SQLite]
Port 3003  → API root (/?id=) + ping-server.php : Cmd Injection, Info Disclosure + SQLi  [PHP + MySQL]
```

## 🔑 Réflexes transversaux appris (les vraies leçons)

1. **Fuzzer CHAQUE paramètre / endpoint**, même ceux qui semblent anodins (`id` cachait une SQLi ET une info disclosure).
2. **Le format compte autant que le contenu** : un paramètre qui refuse un input n'est pas forcément protégé — teste URL-encoding, **Base64**, double encodage (cf. SSRF).
3. **Les messages d'erreur verbeux sont des cadeaux** : `SqliteError: ...same number of result columns` a littéralement donné la solution du flag + le SGBD + le chemin source.
4. **Filtrer le bruit avec `-fs`** : quand toutes les réponses ffuf ont la même taille, filtre-la pour isoler l'anomalie.
5. **Deux composants qui interprètent différemment une requête = faille** (SOAPAction spoofing = cousin du request smuggling).

---

Tags : #htb #web #api #soap #pentest #arsenal
