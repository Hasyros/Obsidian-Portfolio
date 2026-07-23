---
titre: "MetasploitMCP"
tags: [Outils, IA, MCP, metasploit, exploitation]
source: https://github.com/GH05TCREW/MetasploitMCP
---

# MetasploitMCP

**Pont IA ↔ Metasploit** via le **Model Context Protocol (MCP)**. Serveur MCP qui
expose les fonctions du Metasploit Framework comme des *tools* utilisables par un
assistant IA (Claude, DeepSeek, etc.) : l'IA peut lister/lancer des exploits en
langage naturel. Un des premiers outils d'exploitation IA-intégrés dans Kali.

> ⚠️ Donne un accès direct aux capacités offensives de Metasploit :
> **cibles autorisées uniquement**, et garder l'humain dans la boucle. Cf. `README`.

## Tools exposés (extrait)
`list_exploits`, `list_payloads`, `run_exploit`, `run_auxiliary_module`,
`run_post_module`, `generate_payload`.

## Architecture

```
DeepSeek (LLM)  ←→  Client MCP (Cline)  ←→  MetasploitMCP.py  ←→  msfrpcd  ←→  Metasploit
```

Le serveur MetasploitMCP est un simple **client** du démon RPC de Metasploit
(`msfrpcd`). Sans `msfrpcd` en écoute, il démarre mais plante à l'init
(`Connection refused` sur le port 55553).

## Installation (setup réel — WSL Ubuntu)

```bash
# 1. Récupérer les sources
git clone https://github.com/GH05TCREW/MetasploitMCP.git
cd MetasploitMCP

# 2. Environnement virtuel Python (WSL est en "externally-managed", d'où le venv)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt      # bien -r, pas "pip install requirements.txt"

# 3. Installer Metasploit Framework dans WSL (fournit msfrpcd)
sudo apt update
sudo apt install -y gnupg curl       # gnupg requis, sinon l'installeur échoue
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
sudo ./msfinstall

# 4. Vérifier
which msfrpcd
msfconsole -v
```

## Démarrage

**Démon RPC Metasploit**
```bash
msfrpcd -P password -S -a 127.0.0.1 -p 55553
```
- `-P` mot de passe RPC · `-S` sans SSL (HTTP) · `-a` adresse · `-p` port.
- Le mot de passe doit être **identique** à `MSF_PASSWORD` côté client.
- `msfrpcd` se **détache tout seul en arrière-plan** (`MSGRPC backgrounding... PID xxxx`)
  et rend la main au terminal. Pas besoin de `nohup ... &`, et `Ctrl+C` ne l'arrête
  **pas** (il tourne déjà en tâche de fond). Note le PID affiché pour l'arrêter ensuite.
- Au tout premier lancement, Metasploit initialise sa base PostgreSQL (`Database
  initialization successful`) — normal, une seule fois.

**Client MCP — Cline (extension VS Code) avec DeepSeek**
Config API : provider « OpenAI Compatible », Base URL `https://api.deepseek.com`,
modèle `deepseek-chat`, + ta clé DeepSeek.

Config du serveur MCP (`cline_mcp_settings.json`). VS Code tournant côté Windows,
on passe par `wsl.exe` pour exécuter le Python de WSL (sinon `spawn ... ENOENT`) :
```json
{
  "mcpServers": {
    "metasploit": {
      "command": "wsl.exe",
      "args": [
        "bash", "-lc",
        "MSF_PASSWORD=password /mnt/c/Users/alban/MetasploitMCP/.venv/bin/python /mnt/c/Users/alban/MetasploitMCP/MetasploitMCP.py --transport stdio"
      ]
    }
  }
}
```
> Alternative plus propre : ouvrir VS Code **connecté à WSL** (`code .` depuis WSL),
> puis utiliser directement `"command": "/mnt/.../.venv/bin/python"` sans `wsl.exe`.

Quand le point du serveur « metasploit » passe au **vert** dans Cline, l'IA voit
les tools et peut orchestrer un workflow en langage naturel.

## Pause / Relance

Il y a deux briques à gérer : le **démon `msfrpcd`** et le **serveur MCP** (lancé
par Cline).

**Mettre en pause**
- Serveur MCP : dans Cline → onglet MCP Servers, bascule l'interrupteur du serveur
  « metasploit » sur OFF (ou clique « Delete Server » pour le retirer). Il repasse
  au rouge / disparaît.
- Démon `msfrpcd` : il tourne en arrière-plan, donc **`Ctrl+C` ne l'arrête pas**.
  Il faut tuer le processus :
  ```bash
  kill <PID>          # le PID affiché au démarrage (ex : 1509)
  # ou, sans connaître le PID :
  pkill -f msfrpcd
  ```
  Vérifier qu'il ne répond plus :
  ```bash
  ss -tlnp | grep 55553      # ne doit plus rien afficher
  ```

**Relancer**
1. Redémarrer le démon :
   ```bash
   msfrpcd -P password -S -a 127.0.0.1 -p 55553
   ```
2. Dans Cline → MCP Servers → bascule « metasploit » sur ON, puis
   **« Retry Connection »**. Le point doit repasser au vert.

> L'ordre compte : `msfrpcd` d'abord, le serveur MCP ensuite. Si Cline tente de se
> connecter avant que le démon écoute, tu revois l'erreur `Connection refused`.
>
> Comme `msfrpcd` reste en tâche de fond, si tu le relances sans avoir tué l'ancien
> tu auras une erreur « port déjà utilisé » (55553). Tue-le d'abord (voir ci-dessus).

## Réflexe
Valider **manuellement** chaque action proposée par l'IA (un exploit reste un
exploit). Cibles autorisées uniquement. À rapprocher de [[Pentest Copilot]]
(autre approche assistée par IA).
