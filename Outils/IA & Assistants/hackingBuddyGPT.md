---
titre: "hackingBuddyGPT"
tags: [Outils, IA, privesc, recherche]
source: https://github.com/ipa-lab/hackingBuddyGPT
---

# hackingBuddyGPT

**Agents de hacking pilotés par LLM, en ~50 lignes** (ipa-lab, projet de
recherche académique). Fournit des agents prêts (élévation de privilèges Linux/
Windows, tests web) qui se connectent à une machine et **itèrent** commande par
commande via un LLM. Excellent pour **apprendre** comment un agent offensif raisonne.

> ⚠️ Pour tests **autorisés** / labs uniquement. Cf. `README`.

## Installation
```bash
python -m venv venv && source venv/bin/activate
pip install hackingBuddyGPT
export OPENAI_API_KEY='...'
```

## Utilisation
```bash
wintermute list                       # lister les agents disponibles
# ex. élévation de privilèges Linux sur une VM de test (SSH)
wintermute LinuxPrivesc --llm.api_key=$OPENAI_API_KEY \
  --conn.host=10.0.0.5 --conn.username=low --conn.password=pass
```
Agents : `LinuxPrivesc`, `WindowsPrivesc`, tests web…

## Réflexe
Cadre **pédagogique/recherche** : observer le dialogue LLM↔shell pour comprendre la
méthodo (utile avec ta VM de lab). Voisins : [[PentestGPT]], [[pentestMCP]],
[[Pentest Copilot]].
