# 📚 Fondamentaux — Web Services & API

Lié : [[00 - INDEX]] · [[03 - WSDL Énumération]]

---

## Web Service vs API

- **API** (Application Programming Interface) : ensemble de règles pour faire communiquer deux logiciels. Peut fonctionner **hors ligne**.
- **Web Service** : un **type particulier d'API** qui **nécessite un réseau**.

> 🔑 Tout web service est une API, mais **l'inverse n'est pas vrai**.

| | Web Service | API (générale) |
|---|---|---|
| Réseau | requis | pas toujours |
| Accès dev externes | rare | fréquent |
| Protocole typique | SOAP | XML-RPC, JSON-RPC, SOAP, REST, gRPC, GraphQL |
| Format données | souvent XML | souvent JSON |

---

## Les 4 technologies clés

### XML-RPC — le plus simple
Appel de procédure distante encodé en **XML**, transport **HTTP**. Requête = `<methodCall>` avec `<methodName>` + `<params>`.
```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>examples.getStateName</methodName>
  <params><param><value><i4>41</i4></value></param></params>
</methodCall>
```
> 🎯 En pratique : c'est **exactement** ce qu'est `xmlrpc.php` de WordPress. Voir [[06 - WordPress xmlrpc]].

### JSON-RPC — pareil mais en JSON
Plus léger. 3 propriétés : `method`, `params`, `id` (le serveur renvoie le même `id`).
```json
{"method": "sum", "params": {"a":3, "b":4}, "id":0}
--> {"result": 7, "error": null, "id": 0}
```

### SOAP — lourd et structuré
XML rigide. Un message a une structure fixe : `Envelope` > `Header` (optionnel) + `Body` (obligatoire) + `Fault` (erreurs). Un fichier **WSDL** (optionnel) décrit comment l'utiliser.
```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="...">
  <SOAP-ENV:Body>
    <m:GetQuotation><m:QuotationsName>MicroSoft</m:QuotationsName></m:GetQuotation>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
Header HTTP spécial : **`SOAPAction`** = nom de l'opération. Source de la faille [[04 - SOAPAction Spoofing]].

### REST — le standard actuel
Pas un protocole strict, une **convention**. Utilise les **verbes HTTP** (`GET`/`POST`/`PUT`/`DELETE`) sur des ressources. XML ou JSON. ~90 % des API modernes.

---

## Anatomie d'un fichier WSDL (6 éléments)

> Pense au WSDL comme à la **doc d'une classe POO**. C'est la carte d'identité d'un service SOAP. Détails d'exploitation : [[03 - WSDL Énumération]].

| Élément | Rôle | Analogie POO |
|---|---|---|
| `<definitions>` | racine, namespaces, nom du service | fichier / package |
| `<types>` | structures de données échangées | struct / classe |
| `<message>` | wrapper input/output d'une opération | signature |
| `<portType>` | liste des **opérations** dispo (in/out) | **interface** |
| `<operation>` | une action SOAP + son encodage | **méthode** |
| `<binding>` | comment appeler (HTTP, soapAction) | implémentation |
| `<service>` | URL réelle du service | point d'entrée |

> ❓ *Question HTB* : une `<operation>` WSDL correspond à une **Méthode** en programmation.

---

## Vecteurs d'attaque par techno (vue d'ensemble)

| Techno | Vecteurs principaux |
|---|---|
| SOAP / XML-RPC | XXE, injection XML, SOAPAction spoofing, SQLi via messages, mauvaise gestion WSDL |
| REST / JSON | auth bypass, IDOR, SQLi, SSRF, LFI, rate limiting absent, info disclosure |
| JSON-RPC | manipulation de params, méthodes non documentées |
| WordPress xmlrpc | brute-force (`wp.getUsersBlogs`), SSRF (`pingback.ping`), amplification (`system.multicall`) |

Tags : #fondamentaux #soap #rest #wsdl #xmlrpc
