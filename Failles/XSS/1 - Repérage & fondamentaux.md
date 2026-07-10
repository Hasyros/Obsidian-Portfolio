---
titre: "XSS — Repérage & fondamentaux"
tags: [Failles, XSS]
---

# XSS — Repérage & fondamentaux

> ⬅ [[XSS - Index]]

## 2. Les trois types de XSS

|Type|Persistance|Passe par le serveur ?|Exemple typique|
|---|---|---|---|
|**Stored (Persistent)**|Oui — stockée en base|Oui (écriture + lecture)|Commentaires, posts, profils|
|**Reflected (Non-Persistent)**|Non|Oui (renvoyée immédiatement)|Résultat de recherche, message d'erreur|
|**DOM-based**|Non|**Non** — 100 % côté client|Paramètres traités en JS (`location.hash`, etc.)|

### Stored XSS (le plus critique)

La charge utile est **enregistrée dans la base de données** du serveur, puis réaffichée à chaque consultation de la page. Tout utilisateur visitant la page devient victime. C'est le plus grave car il touche un large public et persiste dans le temps (il faut parfois nettoyer la base manuellement pour le retirer).

### Reflected XSS

L'entrée utilisateur est renvoyée **immédiatement** dans la réponse du serveur, sans être stockée. L'attaque ne fonctionne que sur la requête contenant le payload — il faut donc amener la victime à cliquer sur un lien piégé (l'entrée transite souvent dans un paramètre GET de l'URL).

### DOM-based XSS

L'entrée est traitée **entièrement côté client** par du JavaScript, sans jamais atteindre le serveur back-end. Le payload n'apparaît pas dans la réponse HTTP du serveur — il est manipulé par le DOM lui-même (ex. `document.write(location.hash)`).

> **Mémo de classification** (utile pour les questions HTB) :
> 
> - _Est-ce persistant ?_ → Oui = Stored.
> - _Sinon, ça passe par une requête HTTP au serveur ?_ → Oui = Reflected / Non = DOM-based.

---

## 3. Payload de test de base

Le payload de référence pour détecter une XSS, parce qu'il est visuel et immédiat :

```html
<script>alert(window.origin)</script>
```

On utilise `window.origin` (plutôt qu'un simple `alert(1)`) car la popup affiche l'URL d'origine de la page où le script s'exécute — utile pour confirmer **dans quel contexte** le code tourne, notamment sur des applications avec plusieurs frames/origines.

Variante pour afficher le cookie (premier challenge du module) :

```html
<script>alert(document.cookie)</script>
```

> ⚠️ Si le cookie a le flag `HttpOnly`, `document.cookie` ne le renverra **pas** (popup vide sur le cookie de session). L'alerte se déclenche quand même, ce qui confirme l'injection — c'est juste le cookie qui n'est pas accessible en JS.

---

## 4. Méthodologie : identifier le contexte d'injection

C'est l'étape **la plus importante**, et celle qu'aucun scanner ne remplace. Avant de choisir un payload, il faut savoir **où** l'entrée atterrit dans le HTML.

Procédure :

1. Soumettre une valeur repère unique (ex. `test123`) dans le champ.
2. Afficher la **source de la page** (clic droit → afficher la source, ou inspecter).
3. Chercher où apparaît `test123` et adapter le payload au contexte :

|Contexte d'injection|Exemple HTML|Payload adapté|
|---|---|---|
|Corps HTML direct|`<p>test123</p>`|`<script>alert(1)</script>`|
|Dans un attribut|`value="test123"`|`"><script>alert(1)</script>`|
|Dans un attribut `src`/`href` (guillemets simples)|`src='test123'`|`'><script>alert(1)</script>`|
|Dans du JS existant|`var x = 'test123';`|`';alert(1)//`|

L'idée générale : **fermer** le contexte courant (attribut, balise, chaîne JS) avant d'injecter son propre code.

### Payloads alternatifs selon le contexte

Quand `<script>` ne convient pas (ex. injecté via `innerHTML`, qui ne réexécute pas les balises script) :

```html
<img src=x onerror=alert(document.cookie)>
<svg onload=alert(1)>
```

---

## 5. Note d'outillage : scanners vs. manuel

- **XSStrike** et autres scanners automatiques fuzzent des centaines de payloads et signalent les réflexions. Métriques à lire : `Efficiency` (les caractères passent sans filtrage) et `Confidence` (estimation d'exécution réelle).
- Lancer le scan sans interruption : flag `--skip`. Sauvegarder la sortie : `| tee resultat.txt`.
- **Limite** : un scanner confirme qu'un paramètre reflète, mais ne dit ni _où_ ni _dans quel contexte HTML_. Pour les modules pédagogiques (et en CTF / entretien), l'analyse manuelle du contexte est la vraie compétence à acquérir.

> Réflexe : sur une page d'inscription/formulaire, l'entrée n'est souvent pas reflétée sur la même page mais affichée ailleurs (confirmation, panneau admin) → c'est le scénario du Stored XSS, qu'un scanner cherchant une réflexion immédiate peut manquer.

---

## 6. Contournement de la validation côté client

Si un champ a `type="email"` (ou autre validation HTML5), le navigateur refuse une valeur non conforme. La parade : **intercepter la requête avec Burp Suite** et injecter directement dans le paramètre, ce qui court-circuite la validation côté client (qui n'est qu'une barrière cosmétique).

---

## 7. À retenir

- XSS = entrée non assainie + exécution côté client.
- Toujours **identifier le contexte** avant de choisir le payload.
- Stored = persistant ; Reflected = renvoyé immédiatement ; DOM-based = jamais côté serveur.
- Le scanner est un outil de reconnaissance, pas un substitut à l'analyse manuelle.
- La validation côté client se contourne avec un proxy d'interception.

---

## Liens vers les notes suivantes

- XSS
- XSS
- XSS

Lié : [[00 - Méthodologie & Arsenal]]

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
Bypass avancés : encodage HTML, JSFuck, casse mixte, événements alternatifs. Voir [[00 - Méthodologie & Arsenal]].

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
