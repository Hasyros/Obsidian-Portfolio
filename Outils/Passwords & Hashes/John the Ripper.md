---
titre: "John the Ripper"
tags: [Outils, passwords, hashes, cracking]
source: https://github.com/openwall/john
---

# John the Ripper (jumbo)

**Cassage de mots de passe / hash** hors-ligne. La version **jumbo** ajoute des
centaines de formats et surtout les scripts `*2john` qui **extraient un hash
crackable** depuis un fichier (ZIP, PDF, clé SSH, KeePass, etc.).

> ⚠️ Cracker uniquement des hash qu'on est autorisé à posséder. Cf. `README`.

## Installation
```bash
sudo apt install john            # Kali : déjà présent (john-jumbo)
# sources :
git clone https://github.com/openwall/john && cd john/src && ./configure && make -s
```

## Utilisation
```bash
# 1) extraire le hash d'un fichier protégé
zip2john secret.zip > hash.txt
ssh2john id_rsa   > hash.txt      # (pdf2john, keepass2john, rar2john, office2john…)

# 2) cracker
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --format=raw-sha1 --wordlist=rockyou.txt hash.txt   # forcer le format
john --incremental hash.txt        # brute-force pur
john --rules --wordlist=rockyou.txt hash.txt   # mutations (règles)

# 3) résultats
john --show hash.txt
```

## Réflexe
Identifier le format avant (`--format=…`, cf. [[Identification de hash]]). Pour
la vitesse GPU brute, préférer [[Hashcat]]. Wordlist de référence : rockyou
([[SecLists]]).
