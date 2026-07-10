---
titre: "PayloadsAllTheThings"
tags: [Outils, payloads, référence, cheatsheet]
source: https://github.com/swisskyrepo/PayloadsAllTheThings
---

# PayloadsAllTheThings (PATT)

**Encyclopédie de payloads et de techniques** par type de vulnérabilité. Pour
chaque faille (SQLi, XSS, SSTI, XXE, SSRF, upload, LFI, deserialization…) : payloads
prêts à l'emploi, bypass, notes d'exploitation. Déjà cité dans plusieurs de mes
write-ups (ex. la wide-byte GBK).

## Accès
- En ligne : **[github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)**
- Hors-ligne : `git clone https://github.com/swisskyrepo/PayloadsAllTheThings`

## Comment m'en servir
Un dossier par faille, chacun avec un `README.md` : `SQL Injection/`, `XSS
Injection/`, `Server Side Template Injection/`, `Upload Insecure Files/`,
`XXE Injection/`, `Server Side Request Forgery/`…

Correspondances avec mes fiches :
- `SQL Injection/` → [[SQLI - Index]] (dont *MySQL Injection.md#wide-byte-injection-gbk*)
- `XSS Injection/` → [[XSS - Index]]
- `Server Side Template Injection/` → [[SSTImap]]
- `Upload Insecure Files/` → [[File Upload - Index]]

## Réflexe
Quand un payload « standard » est filtré, la section **bypass** de la faille
concernée dans PATT donne des variantes. Complément « défensif/quick » :
[[HackTricks & revshells]].
