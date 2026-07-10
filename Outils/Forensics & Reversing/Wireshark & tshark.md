---
titre: "Wireshark & tshark"
tags: [Outils, forensics, réseau, pcap]
source: https://gitlab.com/wireshark/wireshark
---

# Wireshark & tshark

**Analyse de captures réseau (pcap).** Wireshark = analyseur graphique ; tshark =
sa version CLI (scriptable). Réflexe pour les challenges **forensics/network** :
retrouver un flag, des credentials ou un fichier exfiltré dans un `.pcap`.

> ⚠️ Analyser uniquement des captures autorisées. Cf. `README`.

## Installation
```bash
sudo apt install wireshark tshark      # Kali : déjà présent
```

## Filtres d'affichage utiles (Wireshark)
```text
http.request                    # requêtes HTTP
http.request.method == "POST"   # formulaires (creds ?)
tcp.stream eq 3                  # suivre un flux (clic droit -> Follow TCP Stream)
dns                              # requêtes DNS (exfiltration ?)
ftp || telnet                   # protocoles en clair
frame contains "flag"           # recherche brute d'une chaîne
```

## tshark (CLI)
```bash
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap --export-objects http,/tmp/out   # extraire les fichiers HTTP
tshark -r capture.pcap -z follow,tcp,ascii,3            # dumper un flux
```

## Réflexe
« **Follow Stream** » est l'action n°1 pour reconstituer une conversation.
*File → Export Objects → HTTP* pour récupérer un fichier transféré. Décodage de
ce qu'on trouve : [[CyberChef]].
