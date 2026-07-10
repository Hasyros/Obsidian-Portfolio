---
titre: "Google Hacking Database (GHDB)"
tags: [Outils, OSINT, dorks, recon]
source: https://www.exploit-db.com/google-hacking-database
---

# Google Hacking Database (GHDB)

**Base de « dorks » Google.** Maintenue par Exploit-DB
(**[exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)**),
elle catalogue des requêtes Google avancées qui exposent des informations
sensibles indexées par erreur : fichiers de conf, pages de login, caméras,
messages d'erreur SQL, fichiers de mots de passe, portails d'admin…

> ⚠️ Consulter des infos publiques ≠ s'y connecter. Ne pas exploiter hors périmètre autorisé. Cf. `README`.

## Opérateurs de base
```text
site:example.com            # restreindre à un domaine
inurl:admin                 # motif dans l'URL
intitle:"index of"          # motif dans le titre (listing de répertoire)
filetype:env                # type de fichier (ex. .env, .sql, .log, .bak)
intext:"DB_PASSWORD"        # motif dans le corps
cache:example.com           # version en cache
```

## Exemples de dorks
```text
site:example.com filetype:env intext:DB_PASSWORD
intitle:"index of" "backup"
inurl:"/wp-content/uploads/" filetype:sql
"sql syntax near" intext:error
```

## Réflexe
En pentest/bug bounty : **cadrer sur le scope** (`site:`). Recouper les trouvailles
avec la [[Wayback Machine]] (versions archivées). Pour le WordPress, enchaîner avec
[[WPProbe]].
