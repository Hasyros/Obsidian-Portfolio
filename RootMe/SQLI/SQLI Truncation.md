# CTF : SQL Injection Truncation

Tout d’abord je regarde ce que troncation signifie. 

Lorsqu’on crée un compte parfois le code derrière ressemble à cela :

`username` varchar(20) not null

Donc que au dela de 20 caractères, le username ne prend plus rien en compte

Donc en créant un utilisateur : username : « admin +++++++++++++2 », password : « rien »

Le code va tester si « admin +++++++++++++2 » existe, et vu que c’est pas le cas, il va le donné à la base sql pour le mettre dans la base de donnée qui va enlever les caractères à partir du 20 ème. Et le SELECT prend admin++++++++ et admin de la même façon

![[SQLI_Truncation_01_cf3fd46f35.png]]

Et de ce fait on a un nouveau mdp admin.
