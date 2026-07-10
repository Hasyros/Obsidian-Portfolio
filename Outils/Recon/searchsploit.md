---
titre: "searchsploit"
tags: [Outils, exploit-db, recherche]
---

# searchsploit

Client en ligne de commande d'**Exploit-DB** : recherche d'exploits publics dans
une copie locale de la base (paquet `exploitdb`). Utile après énumération d'un
service pour trouver un exploit connu correspondant à une version.

> ⚠️ Un exploit ne s'utilise que sur une cible autorisée. Cf. `README`.

## Installation
```bash
sudo apt install exploitdb        # Kali/Exegol : déjà présent
searchsploit -u                   # met à jour la base locale
```

## Usage typique
```bash
searchsploit apache 2.4.49            # recherche par produit + version
searchsploit -t wordpress            # -t : chercher seulement dans le titre
searchsploit -x php/webapps/50383.py # -x : afficher l'exploit
searchsploit -m 50383                # -m : copier l'exploit dans le dossier courant
searchsploit --nmap scan.xml         # croiser directement un scan nmap (-oX)
```

## Réflexe
Toujours vérifier la version exacte (bannière, `nmap -sV`) avant de faire
confiance à un résultat, et **lire** l'exploit avant de l'exécuter.
