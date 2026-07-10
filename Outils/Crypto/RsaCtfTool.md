---
titre: "RsaCtfTool"
tags: [Outils, crypto, RSA, CTF]
source: https://github.com/RsaCtfTool/RsaCtfTool
---

# RsaCtfTool

**Attaques RSA de CTF.** Récupère une clé privée à partir d'une **clé publique
faible** et/ou déchiffre un message, en essayant automatiquement une large
batterie d'attaques.

## Installation
```bash
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
cd RsaCtfTool
sudo apt install libgmp3-dev libmpc-dev
pip install -r requirements.txt
```

## Utilisation
```bash
# factoriser une clé publique faible et sortir la privée
python3 RsaCtfTool.py --publickey key.pub --private

# déchiffrer un message avec la clé publique (essaie toutes les attaques)
python3 RsaCtfTool.py --publickey key.pub --uncipher flag.enc

# donner n et e directement
python3 RsaCtfTool.py -n 0x... -e 0x... --uncipher 0x...

# attaque précise
python3 RsaCtfTool.py --publickey key.pub --attack wiener
```

## Attaques couvertes (extrait)
Factorisation de clés faibles, **Wiener** (petit `d`), **Hastad** (petit `e`),
**Fermat** (`p≈q`), **common modulus / common factor** (plusieurs clés), Boneh-Durfey,
ECM, SIQS, « past CTF primes »…

## Réflexe
Récupérer `n`, `e` (et `c`) via `openssl rsa -pubin -text -in key.pub`. Si `p≈q`
→ Fermat ; si `e` petit (3) → Hastad ; si `d` petit → Wiener. Encodage/déchiffrement
générique : [[CyberChef]].
