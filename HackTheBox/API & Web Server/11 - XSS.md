---
titre: "Cross-Site Scripting (XSS) — contexte API"
aliases:
  - "Cross-Site Scripting (XSS) — contexte API"
plateforme: "Hack The Box Academy"
module: "Web Service & API Attacks"
date: 2026-07-02
tags: [HTB, API, XSS, Encoding, Reflected, Notes]
---

# 🧩 Cross-Site Scripting (XSS)

Lié : [[18 - Cheatsheet Payloads]]

---

## Principe

Une XSS permet d'exécuter du **JavaScript arbitraire** dans le navigateur de la victime. Affecte apps web **et** API (quand une réponse d'API est rendue dans une page). Chaînée, elle peut mener à une compromission complète.

---

## Cas du module (endpoint réfléchi)

Même API que la LFI (port 3000), endpoint `/api/download/` :
```
http://<TARGET>:3000/api/download/test_value   → test_value réfléchi dans la réponse
```

Payload de base :
```html
<script>alert(document.domain)</script>
```
→ **encodé par l'app** (transformé en texte inoffensif). Bloqué.

Payload **URL-encodé une fois** :
```
%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```
→ l'app **décode une fois** → le `<script>` réapparaît **après** l'encodage de sortie → **JS exécuté** ✅.

---

## Le point subtil : encodage simple vs double

> ❓ *Question HTB* : « avec un double encodage, ça marche encore ? » → **No.**

Le nombre d'encodages doit **matcher exactement** le nombre de décodages du serveur :

| Décodages serveur | Encodage nécessaire |
|---|---|
| 1 fois (ce cas) | encoder **1 fois** ✅ |
| 2 fois | encoder 2 fois |

Payload **doublement encodé** (`%253C...`) : l'app décode une fois → obtient `%3C` (résiduel) → le navigateur affiche le texte `%3C`, pas de balise. ❌

**Quand le double encodage EST utile** : deux couches qui décodent successivement (WAF/proxy décode pour inspecter → laisse passer `%3C` qu'il ne reconnaît pas → l'app décode encore → `<script>` exécuté). Ici une seule couche → simple encodage seulement.

---

## Payloads utiles (bypass de filtres)

```html
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(document.domain)>
<body onload=alert(1)>
<button autofocus onfocus=alert(1)>       <!-- vu sur Root-Me -->
"><script>alert(1)</script>
javascript:alert(1)
```
Bypass avancés : encodage HTML, JSFuck, casse mixte, événements alternatifs. Voir [[18 - Cheatsheet Payloads]].

---

## Types (rappel)

- **Reflected** : payload dans la requête, renvoyé immédiatement (ce cas).
- **Stored** : payload persisté côté serveur, exécuté chez chaque visiteur.
- **DOM-based** : la manipulation se fait côté client (JS) sans aller-retour serveur.

---

## Remédiation

- **Encoder en sortie** selon le contexte (HTML, attribut, JS, URL).
- CSP stricte, `HttpOnly` sur les cookies de session.
- Ne jamais réfléchir un input non assaini.
