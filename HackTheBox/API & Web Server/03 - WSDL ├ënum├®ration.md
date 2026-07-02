# 🧩 WSDL — Énumération

Lié : [[02 - Fondamentaux]] · [[04 - SOAPAction Spoofing]] · [[08 - SQL Injection]]

---

## Principe

Le **WSDL** (Web Service Description Language) est un fichier XML qui documente **tout ce qu'un service SOAP sait faire** : opérations, paramètres, emplacement. C'est la **première cible** quand on audite du SOAP — il te donne la carte complète de la surface d'attaque.

Il n'est pas toujours exposé (sécurité par obscurité), mais souvent accessible via un chemin/paramètre à deviner.

---

## Détection

```bash
# 1) Fuzzing de répertoires → trouve /wsdl (souvent 200 mais taille 0)
dirb http://<TARGET>:3002

# 2) Requête directe → réponse vide
curl http://<TARGET>:3002/wsdl        # vide !

# 3) Fuzzing de PARAMÈTRE (le contenu est débloqué par ?wsdl)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u 'http://<TARGET>:3002/wsdl?FUZZ' -fs 0 -mc 200

# 4) Le paramètre gagnant → le fichier complet
curl 'http://<TARGET>:3002/wsdl?wsdl'
```

> 💡 `-fs 0` filtre les réponses vides (taille 0), `-mc 200` ne matche que les 200. Sans le paramètre, la page répond 200/vide → il fallait deviner qu'un **paramètre GET** débloque le contenu (convention `.NET` : `example.wsdl?wsdl`).

Variantes de nommage : `/service.wsdl?wsdl`, `/example.disco?disco` (DISCO = techno Microsoft de découverte).

---

## Lecture / exploitation du WSDL

Ce qu'on cherche dans le fichier :
- `<wsdl:operation name="...">` → les **opérations** dispo (points d'entrée)
- `<s:element name="...Request">` → les **paramètres** de chaque opération (points d'injection)
- `<soap:operation soapAction="...">` → le nom exact du header **SOAPAction** à envoyer

Exemple du module (service HacktheboxService) :
```
Login(username, password)   → opération d'auth       → point d'injection SQLi
ExecuteCommand(cmd)         → exécute une commande    → 🚨 RCE potentiel
```

Cette lecture révèle immédiatement deux vecteurs : **SQLi sur Login** (voir [[08 - SQL Injection]]) et **RCE via ExecuteCommand** (mais bloqué "internal networks only" → contourné par [[04 - SOAPAction Spoofing]]).

---

## Cas du module

- Skills Assessment : le WSDL exposait `Login(username, password)` → point d'injection SQLi → flag.
- Section SOAPAction spoofing : le WSDL exposait `ExecuteCommand(cmd)` bloqué en externe → spoofing pour l'atteindre.

---

## Aller plus loin

- Génère un client SOAP automatiquement depuis le WSDL (Python `zeep`, `python -m zeep <url>?wsdl`) pour lister les opérations proprement.
- Toujours tester **chaque** opération, y compris celles qui semblent internes/admin.

---

## Remédiation

- Ne pas exposer le WSDL publiquement (ou le protéger par authentification).
- Ne jamais compter sur l'obscurité seule.
- Valider/assainir les entrées de **chaque** opération côté serveur.

Tags : #soap #wsdl #énumération #recon
