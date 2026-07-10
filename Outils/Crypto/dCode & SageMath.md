---
titre: "dCode & SageMath"
tags: [Outils, crypto, math, CTF]
source: https://www.dcode.fr/
---

# dCode & SageMath

Deux ressources crypto/maths complémentaires de [[CyberChef]] et [[RsaCtfTool]].

## dCode.fr — solveur en ligne
**[dcode.fr](https://www.dcode.fr/)** : des centaines de solveurs prêts à
l'emploi (chiffres classiques et outils modernes), sans installation.
- Identifier un chiffre : *Cipher Identifier*
- César / Vigenère / substitution / Playfair / Bacon…
- Bases & encodages, **identification de hash**, factorisation, RSA
- Utile quand on ne sait pas **quel** chiffre on a en face.

## SageMath — maths lourdes
Environnement Python spécialisé (théorie des nombres, courbes elliptiques,
polynômes) pour les challenges crypto **calculatoires**.
```bash
sudo apt install sagemath          # ou https://cocalc.com (en ligne)
sage                               # REPL
```
```python
# exemples typiques de CTF
factor(143)                        # factorisation
p = next_prime(2^256); GF(p)       # corps finis
E = EllipticCurve(GF(p), [a,b])    # courbes elliptiques
inverse_mod(e, (p-1)*(q-1))        # calcul de d (RSA)
crt([a1,a2],[m1,m2])               # théorème des restes chinois
```

## Réflexe
dCode pour **identifier/déchiffrer vite** un chiffre classique ; SageMath quand il
faut **calculer** (RSA custom, ECC, lattices via `L.LLL()`).
