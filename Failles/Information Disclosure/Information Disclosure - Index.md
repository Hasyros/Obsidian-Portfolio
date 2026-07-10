---
titre: "Information Disclosure"
tags: [Failles, information-disclosure, IDOR, fuzzing, index]
---

# Information Disclosure

> ⚠️ Cibles autorisées uniquement (cf. `README`). Write-ups appliqués : dossier `CTF/`.

Des misconfigurations, paramètres cachés ou contrôles d'accès manquants révèlent
des données sensibles. La clé : **fuzzer beaucoup** (paramètres, endpoints,
valeurs, IDs) et lire les **différences** de réponse.

## Fiches
- [[1 - Repérage (Information Disclosure)]] — fuzzing de params/endpoints, le piège de la taille constante
- [[2 - Exploitation & techniques (Information Disclosure)]] — IDOR, énumération d'IDs, escalade vers SQLi
- [[3 - Bypass (Information Disclosure)]] — contournement de rate limit / ACL par headers

## Sources fréquentes de fuite
```
paramètres cachés · endpoints non liés · IDOR (id incrémental) · verbose errors
.git/ exposé · backups .bak/.old/~ · /debug /actuator /swagger.json
en-têtes (Server, X-Powered-By) · commentaires HTML/JS · .env · listings de dossier
```
Voisins : [[SQLI - Index]] (un `id` fuité mène souvent à une SQLi),
[[git-dumper]]/[[TruffleHog]] (secrets), [[Wayback Machine]]/[[Google Hacking Database (GHDB)]].

## Remédiation
- Réponses cohérentes (404 pour l'inconnu, pas de fuite de structure).
- **Contrôle d'accès par objet** (éviter l'IDOR) ; ne pas exposer d'ID séquentiels devinables.
- Ne jamais faire confiance aux headers `X-Forwarded-*` pour l'autorisation.
