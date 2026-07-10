---
titre: "Hashcat"
tags: [Outils, passwords, hashes, cracking, GPU]
source: https://github.com/hashcat/hashcat
---

# Hashcat

**Le cracker de hash le plus rapide** (accéléré **GPU**). Complémentaire de John :
Hashcat = vitesse brute et attaques par masque/règles, sur des centaines de modes
de hash.

> ⚠️ Cracker uniquement des hash qu'on est autorisé à posséder. Cf. `README`.

## Installation
```bash
sudo apt install hashcat          # Kali : déjà présent
# + pilotes GPU (OpenCL/CUDA) pour la vraie vitesse
hashcat -I                        # vérifier les devices détectés
```

## Utilisation
```bash
# -m = mode (type de hash), -a = attaque (0 wordlist, 3 masque)
hashcat -m 0    -a 0 hash.txt rockyou.txt        # MD5 + dictionnaire
hashcat -m 1000 -a 0 hash.txt rockyou.txt -r rules/best64.rule   # NTLM + règles
hashcat -m 22000 -a 3 hash.hc22000 '?d?d?d?d?d?d?d?d'   # WPA + masque 8 chiffres
hashcat -m 3200 -a 0 hash.txt rockyou.txt        # bcrypt
hashcat --show hash.txt                          # résultats déjà cassés
```
Trouver le **mode** : `hashcat --help | grep -i <type>` (ex. `sha256`, `ntlm`).

## Réflexe
Masques `?l?u?d?s` (min/maj/chiffre/spécial) pour cibler une politique de mdp.
Sur WPA, la chaîne d'entrée vient de [[hcxtools]]. Identifier le hash :
[[Identification de hash]].
