Agents IA autonomes de pentest (usestrix/strix, Apache 2.0, 32k+ stars).
Contrairement à un scanner classique qui remonte des faux positifs, Strix
agit comme un vrai pentester : il exécute le code dynamiquement, exploite
réellement les failles trouvées et ne remonte une vulnérabilité qu'accompagnée
d'une preuve de concept (PoC) reproductible. Orchestration multi-agents,
proxy d'interception (Caido) intégré, navigateur automatisé pour le client-side,
shell interactif, analyse statique + dynamique, dashboard web local.

⚠️ Authorized use only. Strix teste activement la cible pointée — ne l'utiliser
que sur des systèmes t'appartenant ou avec autorisation écrite explicite
(lab, scope bug bounty). Un test non autorisé est illégal dans la plupart
des juridictions.

Fonctions clés

* Couverture OWASP Top 10 et au-delà : injections, broken access control,
  XSS, SSRF, IDOR, failles de logique métier, auth/session, API, cloud/infra
* Validation réelle par exploitation (pas de remontée sans PoC fonctionnel)
* Multi-agents orchestrés, tests distribués sur plusieurs cibles en parallèle
* Proxy HTTP (Caido), navigateur automatisé, shell interactif, runtime
  d'exploit sur-mesure
* Génération automatique de correctifs + rapports "compliance-ready"
* Dashboard web local (pas d'upload cloud, accès par token privé)

Prérequis

* Docker (doit tourner)
* Une clé API LLM chez un provider supporté : OpenAI, Anthropic, Google,
  Vertex AI, Bedrock, Azure — ou modèle local (Ollama, LMStudio)
* Alternative sans clé API séparée : abonnement ChatGPT Plus/Pro
  (`strix auth login chatgpt`)

Téléchargement / installation

```bash
curl -sSL https://strix.ai/install | bash
```

(alternative : `pip install strix-agent`)

Configuration (variables d'environnement)

```bash
export STRIX_LLM="openai/gpt-5.4"
export LLM_API_KEY="ta-cle-api"

# optionnel
export LLM_API_BASE="url-api-custom"
export PERPLEXITY_API_KEY="ta-cle-perplexity"
export STRIX_REASONING_EFFORT="high"
```

La config est sauvegardée automatiquement dans `~/.strix/cli-config.json`
après le premier run — pas besoin de re-exporter à chaque session si le
fichier est déjà rempli. Serveurs MCP custom configurables via
`~/.strix/mcp-servers.json`.

Modèles recommandés

* OpenAI GPT-5.4
* Anthropic Claude Sonnet 4.6
* Google Gemini 3 Pro Preview

Utilisation

```bash
strix --target ./app-directory                  # code source local
strix --target https://github.com/org/repo       # repo distant
strix --target https://ton-app.com               # cible web live

# Test d'API
strix --target ./openapi.yaml --target https://api.ton-app.com
strix --target ./collection.postman_collection.json --target https://api.ton-app.com

# Authentifié
strix --target https://ton-app.com --instruction "authenticated testing: user:pass"

# Multi-cibles
strix -t https://github.com/org/app -t https://ton-app.com
strix --target-list ./targets.txt

# Headless / CI (sort avec code non-zéro si vulns trouvées)
strix -n --target ./
strix -n -t ./ --scan-mode quick   # compatible GitHub Actions

# Dashboard des résultats
strix view
```

Sortie / rapports

Résultats stockés dans `strix_runs/<nom-du-run>/`. `strix view` ouvre le
dashboard local (overview, liste des vulns, graphe des agents, contrôles
de pilotage en direct, historique, rapports partageables) — rien n'est
envoyé dans le cloud.

Réflexe
Lancer d'abord en mode `--scan-mode quick` sur une cible de lab pour
valider la config (clé API, Docker) avant un run complet, plus long et
plus coûteux en tokens LLM. Le mode headless (`-n`) + code de sortie
non-zéro est ce qu'il faut brancher dans un pipeline CI pour bloquer un
merge sur vuln critique trouvée.
