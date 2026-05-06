# API - Mass Assignment

Je commence par regarder partout dans l’app.

![[Mass_Assignment_01_5ca3ef1716.png]]

Je vais essayer d’envoyer OPTION à la place de GET,POST… 

Pour essayer de trouver un endroit ou je peux faire un PUT (qui ne serait pas prévu)

Je trouve le :	api/user

Je test en mettant 

{

	« status » : « admin »

}

Et il me dit qu’il ne comprend pas, et enft c’est par ce qu’il faut rajouter Content-Type :aplication/json

Et hop on prend le droit admin.
