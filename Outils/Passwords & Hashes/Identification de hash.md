---
titre: "Identification de hash"
tags: [Outils, hashes, identification]
source: https://github.com/HashPals/Name-That-Hash
---

# Identification de hash (hashid / hash-identifier / Name-That-Hash)

Avant de cracker, il faut **savoir de quel type de hash** il s'agit (→ choisir le
`--format` de [[John the Ripper]] ou le `-m` de [[Hashcat]]).

## Outils
```bash
# hashid (rapide, propose des formats + le mode hashcat)
sudo apt install hashid
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
hashid -m -j 'HASH'          # -m : mode hashcat, -j : commande john

# hash-identifier (interactif)
hash-identifier

# Name-That-Hash (moderne, coloré, résumé + popularité)
pipx install name-that-hash
nth -t '2b$12$...'           # ou : nth -f hashes.txt
```

## Réflexe
Les résultats sont des **hypothèses** (une longueur/charset peut correspondre à
plusieurs algos) : tester du plus probable au moins probable. Indices de contexte
(préfixe `$2y$`=bcrypt, `$6$`=sha512crypt, `aad3b435...`=LM vide) souvent plus
fiables. En ligne : [dcode.fr](https://www.dcode.fr/identification-hash).
