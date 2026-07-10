# Obsidian Portfolio — Write-ups & outils de sécurité offensive

Vault Obsidian rassemblant mes write-ups de CTF, mes notes de failles web et les
outils que j'ai développés dans le cadre de ma formation en cybersécurité
(**ESILV — cursus cyber**). Le contenu couvre principalement la sécurité
applicative web : injections SQL/NoSQL, XSS, CORS, SSRF, XXE, file upload,
GraphQL, désérialisation, ainsi que du pyjail et un peu de reversing.

> Point d'entrée du vault : [[Bienvenue]].

---

## ⚠️ Avertissement légal et éthique — À LIRE AVANT TOUT

Ce dépôt est publié **exclusivement à des fins pédagogiques, de recherche
défensive et de documentation personnelle**. Il décrit des techniques
d'attaque afin de **comprendre les vulnérabilités pour mieux s'en protéger**.

### Cadre d'utilisation autorisé — et lui seul

Toutes les techniques, payloads, scripts et exploits présents ici ont été
conçus, testés et employés **uniquement** dans l'un des cadres suivants :

- des **plateformes d'entraînement légales** qui y consentent explicitement
  (Root-Me, Hack The Box, PortSwigger Web Security Academy, TryHackMe, CTF
  organisés) ;
- des **environnements de laboratoire personnels** que je possède et contrôle
  (machines virtuelles, conteneurs Docker isolés) ;
- des **engagements de test d'intrusion sous contrat**, avec une autorisation
  écrite, préalable et explicite du propriétaire du système, définissant un
  périmètre (*scope*) précis ;
- des **programmes de bug bounty** dont le règlement autorise formellement les
  tests, dans les limites de scope publiées.

### Ce qui est strictement interdit

**N'utilisez JAMAIS ces techniques contre un système, un réseau, une
application ou des données pour lesquels vous ne disposez pas d'une
autorisation écrite, explicite et préalable du propriétaire légitime.**

Cela vaut y compris pour :

- un site web « juste pour voir » ou « pour tester si c'est vulnérable » ;
- le réseau de votre école, de votre entreprise ou d'un tiers sans mandat écrit ;
- une cible hors du périmètre autorisé d'un pentest ou d'un bug bounty ;
- toute action de déni de service (DoS), d'exfiltration ou de destruction de
  données, même sur une cible par ailleurs « autorisée » pour d'autres tests.

Tester sans autorisation, **même sans intention de nuire et même sans aucun
dommage causé**, constitue une infraction.

### Rappel du cadre juridique

Accéder ou se maintenir frauduleusement dans un système de traitement
automatisé de données (STAD), en entraver le fonctionnement ou en altérer les
données est **pénalement réprimé** dans la quasi-totalité des juridictions.
À titre indicatif (liste non exhaustive, se référer au droit applicable) :

- **France** — articles **323-1 à 323-7 du Code pénal** : jusqu'à **5 ans de
  prison et 150 000 € d'amende** (accès/maintien frauduleux, entrave,
  altération de données), aggravés lorsque la cible est un service de l'État.
  S'y ajoutent le **RGPD** et la loi *Informatique et Libertés* pour tout ce qui
  touche aux données personnelles.
- **Union européenne** — **Directive 2013/40/UE** relative aux attaques contre
  les systèmes d'information.
- **États-Unis** — **Computer Fraud and Abuse Act (CFAA)**, 18 U.S.C. § 1030.
- **Royaume-Uni** — **Computer Misuse Act 1990**.

L'ignorance de la loi n'est pas un moyen de défense. Une autorisation verbale
ou implicite **n'en est pas une** : exigez toujours un document écrit et signé.

### Décharge de responsabilité

L'auteur met ce contenu à disposition « **en l'état** », sans aucune garantie.
**L'auteur décline toute responsabilité** quant à un usage abusif, illégal ou
malveillant qui serait fait de ces informations. Toute personne qui consulte,
copie ou exécute ce contenu en assume **l'entière responsabilité** et s'engage
à respecter les lois en vigueur ainsi que le cadre défini ci-dessus. Si vous
n'acceptez pas ces conditions, **n'utilisez pas ce dépôt**.

### En cas de découverte d'une vulnérabilité réelle

Si vous découvrez une faille sur un système en dehors d'un cadre de test
autorisé, adoptez une démarche de **divulgation responsable** (*responsible
disclosure*) : ne l'exploitez pas, ne l'ébruitez pas, et contactez le
propriétaire ou son équipe sécurité (ou un CERT/CSIRT national) de façon privée.

---

## Organisation du vault

| Catégorie | Contenu |
|---|---|
| **CTF/** | Write-ups de challenges résolus, classés par plateforme (Root-Me, PortSwigger, Hack The Box, MidnightFlag). |
| **Failles/** | Fiches de référence par type de vulnérabilité (SQLI, XSS, File Upload, SSRF, XXE, LFI, GraphQL…) : théorie, détection, exploitation, remédiation. |
| **Méthodo & Bypass/** | Méthodologies d'audit, arsenaux de payloads, techniques de contournement de filtres/WAF, cheatsheets. |
| **Outils/** | Scripts et outils que j'ai développés (automatisation de blind SQLi, attaque temporelle sur UUID, XSS Finder…) et notes d'outillage (Exegol, nmap, ffuf/sqlmap, Caido). |

---

## Sources & remerciements

Les techniques documentées s'appuient notamment sur
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings),
la [PortSwigger Web Security Academy](https://portswigger.net/web-security),
[HackTricks](https://book.hacktricks.xyz/) et les auteurs des challenges
Root-Me / Hack The Box. Merci à eux.
