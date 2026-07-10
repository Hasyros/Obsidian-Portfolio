---
titre: "SSRF — Server-Side Request Forgery"
tags: [Failles, SSRF, index]
---

# SSRF — Server-Side Request Forgery

> ⚠️ Cibles autorisées uniquement (cf. `README`). Write-ups appliqués : dossier `CTF/`.

On force **le serveur** à émettre une requête vers une destination qu'on choisit.
Bascule mentale : ce n'est plus *toi* qui te connectes, c'est le *serveur* — qui a
accès à ce que toi non (services internes, métadonnées cloud, LAN). **OWASP Top 10.**

Impacts : scan de ports interne (**XSPA**), accès aux services loopback
(Redis/MySQL sans auth), **métadonnées cloud → creds**, lecture locale (`file://`),
fuite de hash NetNTLM (UNC Windows), parfois RCE.

## Fiches
- [[1 - Repérage (SSRF)]] — repérer les paramètres d'URL, confirmer (in-band / OOB)
- [[2 - Exploitation & techniques (SSRF)]] — scan interne, cloud metadata, schémas
- [[3 - Payloads & bypass (SSRF)]] — cheatsheet + contournement de filtres 127.0.0.1

## En un coup d'œil
| Phase | Action |
|---|---|
| Repérage | params `url=`,`next=`,`dest=`,`img=` ; pointer vers son listener (Collaborator/nc) |
| Exploiter | `127.0.0.1:<port>` (XSPA), `169.254.169.254` (cloud), `file://`, `gopher://` |
| Bypasser | `localhost`,`127.1`,`0`,`[::1]`, IP décimale/hexa, DNS rebinding, redirection |

## Vulnérabilités liées
[[XXE - Index]] (SSRF via entité `http://`), [[LFI - Index]] (via `file://`),
[[WordPress xmlrpc - Index]] (`pingback.ping` = SSRF).

## Remédiation
- Whitelist stricte des destinations (schéma, host, port).
- Bloquer IP privées/loopback/link-local ; résoudre **puis** re-vérifier (anti-DNS-rebinding).
- Désactiver les schémas inutiles (`file://`, `gopher://`, `dict://`).
