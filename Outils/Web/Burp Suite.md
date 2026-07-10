---
titre: "Burp Suite"
tags: [Outils, Web, proxy, interception]
source: https://portswigger.net/burp
---

# Burp Suite

**Le proxy d'interception web de référence** (PortSwigger). Intercepte, modifie et
rejoue les requêtes HTTP(S) entre le navigateur et le serveur. Alternative/complément
à mon [[Caido]]. C'est l'outil des labs [[CTF - Index|PortSwigger]].

> ⚠️ Sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
sudo apt install burpsuite       # Kali (Community)
# ou téléchargement : https://portswigger.net/burp/communitydownload
```
Configurer le navigateur (ou FoxyProxy) vers `127.0.0.1:8080` et installer le
**certificat CA Burp** (http://burp → CA Certificate) pour intercepter le HTTPS.

## Modules clés
- **Proxy** — intercepter/éditer les requêtes à la volée (onglet *Intercept*, *HTTP history*).
- **Repeater** — rejouer/modifier une requête manuellement (⭐ le plus utilisé).
- **Intruder** — automatiser l'injection sur un paramètre (fuzzing, brute-force ;
  bridé en Community). C'est ce que j'ai utilisé pour l'extraction NoSQL `$regex`.
- **Decoder / Comparer / Sequencer**, **Extensions** (BApp Store).

## Réflexe
Community suffit pour l'apprentissage (Repeater + Proxy). Pour l'automatisation
lourde, Intruder Pro ou passer à [[CLI — ffuf, sqlmap, nmap, curl|ffuf]]/[[Nuclei]]. Beaucoup préfèrent
aujourd'hui [[Caido]] (plus léger, moderne).
