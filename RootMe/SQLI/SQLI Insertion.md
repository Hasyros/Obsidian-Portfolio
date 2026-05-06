# CTF – SQL Injection par insertion

Tout d’abord j’ai vu que les injections par insertion consistent en le fait d’ajouter une fonction dans un des attribut d’un compte :

Exemple :

En back-en on a un truc comme ca :

INSERT INTO users (username, password, email) VALUES ('$username', '$password', '$email');

En faisant le CTF je m’aperçoit que le username et le pw sont protégés, donc je vais mettre mes fonctions dans email.

Il faut faire attention car avant de créer un utilisateur, le code check que le nom ne soit pas déjà utilisé, donc vu qu’on va créer deux utilisateurs à la fois à chaque fois, il faut que le premier soit différent à chaque tour et que le deuxième aussi mais nous indique aussi les valeurs qu’on cherche.

![[SQLI_Insertion_01_6286b6224d.png]]

La on fait ce qu’on a dit et on a un message de réussite du site donc tout est bon !

username=1zedcds&password=rien&email=reinnonplus'),('laversion','pass',version())--+-

Je me connecte et j’ai ca :

 ![[SQLI_Insertion_02_dd53531bbb.png]]

On va maintenant tout chercher :

Current_database🡪tables🡪colonnes🡪mdp de l’admin

username=1zeddccds&pzassword=rien&email=reinnonplus'),('ladatabasecurrent','pass',database())--+-

Bon… flemme de tout refaire mais maintenant on a l’idée.
