---
titre: "CyberChef"
tags: [Outils, crypto, encodage, CTF, forensics]
source: https://github.com/gchq/CyberChef
---

# CyberChef

**Le « couteau suisse » de la donnée** (GCHQ). App web qui enchaîne des
opérations (« recettes ») : encodage/décodage, chiffrement, compression,
extraction, analyse… Indispensable en CTF (crypto, forensics, stégane légère,
web) pour manipuler rapidement des données sans coder.

## Accès / installation
- En ligne : **[gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/)**
- Hors-ligne (recommandé pour données sensibles) : télécharger le
  `CyberChef.html` autonome depuis les *releases* GitHub, l'ouvrir dans un navigateur.

## Utilisation
1. **Input** : coller la donnée (texte, hex, base64…).
2. **Recipe** : glisser des opérations dans l'ordre. Exemples :
   - `From Base64` → `Gunzip` → `From Hex`
   - `Magic` (détecte automatiquement l'encodage/chiffrement probable) ⭐
   - `XOR Brute Force`, `ROT13 Brute Force`, `Vigenère Decode`
   - `From Charcode`, `URL Decode`, `JWT Decode`, `AES Decrypt`
3. **Output** : résultat en direct ; « Auto Bake » recalcule à chaque changement.

## Réflexe
L'opération **`Magic`** (avec « Intensive mode ») fait gagner un temps fou pour
identifier un encodage inconnu. Pour la crypto RSA de CTF, passer à [[RsaCtfTool]].
