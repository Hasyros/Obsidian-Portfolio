---
titre: "MetasploitMCP"
tags: [Outils, IA, MCP, metasploit, exploitation]
source: https://github.com/GH05TCREW/MetasploitMCP
---

# MetasploitMCP

**Pont IA ↔ Metasploit** via le **Model Context Protocol (MCP)**. Serveur MCP qui
expose les fonctions du Metasploit Framework comme des *tools* utilisables par un
assistant IA (Claude, etc.) : l'IA peut lister/lancer des exploits en langage
naturel. Un des premiers outils d'exploitation IA-intégrés dans Kali.

> ⚠️ Donne un accès direct aux capacités offensives de Metasploit :
> **cibles autorisées uniquement**, et garder l'humain dans la boucle. Cf. `README`.

## Tools exposés (extrait)
`list_exploits`, `list_payloads`, `run_exploit`, `run_auxiliary_module`,
`run_post_module`, `generate_payload`.

## Téléchargement / installation
```bash
# Kali
sudo apt install metasploitmcp
# ou depuis les sources
git clone https://github.com/GH05TCREW/MetasploitMCP.git
cd MetasploitMCP && pip install -r requirements.txt
```
Prérequis : le service **RPC de Metasploit** (`msfrpcd`) accessible.

## Utilisation
```bash
# démarrer le serveur MCP
python MetasploitMCP.py --transport http     # (ou --transport stdio pour un client local)
```
Puis déclarer le serveur MCP dans le client IA (endpoint HTTP ou commande stdio).
L'assistant découvre alors les tools et peut orchestrer un workflow.

## Réflexe
Valider **manuellement** chaque action proposée par l'IA (un exploit reste un
exploit). À rapprocher de [[Pentest Copilot]] (autre approche assistée par IA).
