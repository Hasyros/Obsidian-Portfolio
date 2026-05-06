# CTF SQL injection - Authentification - GBK

Le caractère chinois  __Wide Byte Injection__

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#wide-byte-injection-gbk](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#wide-byte-injection-gbk)

Dans ce challenge, l’application web est protégé par une commande qui rajoute un \\ quand on met une guillemet ‘ affin qu’il soit considéré comme un commentaire.

En hexadécimal (le langage machine), cela donne :

- Guillemet simple (') = 0x27
- Antislash (\\) = 0x5C

On envoie un %df avec le ‘ (%27) donc ca donne  %df%27.

Le système voit le %27 et protège en ajoutant un %5c avant. Ce qui donne %df%5c%27  

En GBK, le %df signifie le début d’un double octet et ensuite combine 0xdf + 0x5c pour former un caractère chinois. 

Truc cool, au lieu d’écrire :

Username=’admin’ 					(car on pourrait avoir un problème de ‘)

On peut faire :

Username=CHAR(97,100,109,105,110)		(avec les caractères en DECIMAL)

Je rentre cette combinaison :

login=admin%df'+OR+1=1+#&password=x

Comme ca on se connecte automatiquement au premier compte (ici on a de la chance c’est l’admin)

ATTENTION, sur burpsuite il est très important de faire « follow redirection » pour avoir la redirection de la réponse

Et hop on flag : iMDaFlag1337!
