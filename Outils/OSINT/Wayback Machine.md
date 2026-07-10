---
titre: "Wayback Machine"
tags: [Outils, OSINT, archives, recon]
source: https://web.archive.org/
---

# Wayback Machine (Internet Archive)

**Archive historique du web.** Service de l'Internet Archive
(**[web.archive.org](https://web.archive.org/)**) qui conserve des **snapshots
datés** de pages web. Permet de retrouver du contenu **supprimé ou modifié** :
anciens endpoints, commentaires HTML, clés/API oubliées, versions vulnérables,
emails, organigrammes…

## Utilisation
### Web
Saisir l'URL → parcourir le calendrier des captures.

### En masse (recon) — récupérer toutes les URLs archivées d'un domaine
```bash
# API CDX
curl "http://web.archive.org/cdx/search/cdx?url=example.com*&output=text&fl=original&collapse=urlkey"

# Outils dédiés
go install github.com/tomnomnom/waybackurls@latest
echo example.com | waybackurls | sort -u

pipx install waymore   # waymore -i example.com  (plus complet : Wayback + autres sources)
```
Sauvegarder une page à la demande : bouton **« Save Page Now »**.

## Réflexe
Chercher dans les vieilles versions les **paramètres/chemins** disparus (→ à
fuzzer ensuite) et les **secrets** laissés dans le HTML/JS archivé. Croiser avec
[[Google Hacking Database (GHDB)]].
