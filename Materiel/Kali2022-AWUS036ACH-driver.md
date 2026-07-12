---
tags: [kali, wifi, awus036ach, rtl8812au, driver, virtualbox, nexuspi, setup]
type: procedure
statut: validé
date: 2026-07-12
kernel: 5.16.0-kali7-amd64
carte: Alfa AWUS036ACH (RTL8812AU)
---

# Setup VM Kali 2022.2 (figée) pour AWUS036ACH + NexusPi WiFi

Guide **de zéro à l'application qui tourne** : monter une VM VirtualBox Kali 2022.2,
faire fonctionner une Alfa **AWUS036ACH** (chipset Realtek **RTL8812AU**) en
monitor/injection, installer les outils, puis lancer le module WiFi de NexusPi —
**sans jamais casser le figeage 2022** (glibc/gcc/Perl intacts).

> [!TIP] Résultat obtenu
> Carte `wlan0` reconnue, monitor mode OK, capture **et injection** 2.4 GHz **et** 5 GHz
> fonctionnelles, tous les outils du projet présents, figeage 2022 préservé.

---

## Pourquoi ce guide existe (le problème central)

- **Carte** : Alfa AWUS036ACH → puce **Realtek RTL8812AU** (`0bda:8812`).
- **VM** : VirtualBox + **Kali 2022.2** (noyau `5.16.0-kali7-amd64`), volontairement
  **figée** pour préserver des dépendances *userland* (projet `rogue` / NexusPi).
- **Le nœud du problème** : compiler le driver exige les **headers du noyau 5.16**.
  Or Kali est *rolling* : le dépôt courant (2026) a **purgé** ces headers. Donc
  `apt install linux-headers-$(uname -r)` **échoue**, et contourner par un upgrade
  **casse la VM** (voir ci-dessous).

> [!CAUTION] Le piège à ne JAMAIS faire
> Ces commandes tirent toute la chaîne d'outils 2026 (glibc 2.42, gcc-15, dpkg-dev)
> → **cascade** → `dpkg` cassé (`Perl 5.36 required, only 5.34`), noyau non configuré,
> VM inutilisable :
> - ❌ `apt install linux-image-amd64 linux-headers-amd64`
> - ❌ `apt full-upgrade`
> - ❌ `apt install realtek-rtl88xxau-dkms` *(tire aussi `libc6` → même cascade — répondre `n`)*
>
> **Règle d'or : on ne passe jamais par `apt` pour le noyau / le driver / les outils.**
> On récupère les paquets **signés d'époque** depuis l'archive officielle `old.kali.org`
> et on les pose avec `dpkg -i`, qui **ne touche jamais à glibc** (il refuse proprement
> si une dépendance manque, au lieu de tout upgrader).

---

## Phase 0 — VirtualBox (passthrough USB)

VM **éteinte** :

1. Installer l'**Oracle VM VirtualBox Extension Pack** (support USB 2.0/3.0) —
   *Fichier → Préférences → Extensions*.
2. *Configuration → USB* : cocher **Activer le contrôleur USB**, choisir **USB 3.0 (xHCI)**
   (ou **USB 2.0** si instable), puis ajouter un **filtre USB** sur la carte Realtek
   (clé branchée).
3. Démarrer Kali. Si la carte n'est pas attachée : *Périphériques → USB → Realtek 0bda:8812*.

Vérifier dans Kali :
```bash
lsusb | grep -i realtek     # → Bus 00x Device 00x: ID 0bda:8812 ... RTL8812AU
```

> [!IMPORTANT]
> La VM doit être une **Kali 2022.2** (noyau `5.16.0-kali7-amd64`), sinon les headers
> `old.kali.org` ne correspondront pas. Vérifier **avant tout** :
> ```bash
> uname -r        # doit afficher : 5.16.0-kali7-amd64
> ```
> Si c'est autre chose (`7.0.x`…), tu as une ISO trop récente → la suite ne marchera pas.

---

## Phase 1 — Réparer la clé de signature Kali

Sur une image d'époque, `apt update` échoue avec `NO_PUBKEY ED65462EC8D5E4C5` : Kali a
**changé sa clé de signature en 2025**.

```bash
sudo gpg --keyserver hkps://keyserver.ubuntu.com --recv-key ED65462EC8D5E4C5
sudo gpg --export ED65462EC8D5E4C5 | sudo tee /usr/share/keyrings/kali-archive-keyring.gpg > /dev/null
sudo apt update
```
*(Alternative : `sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg`)*

> [!NOTE]
> `apt update` doit finir **sans erreur GPG**. On ne fait **aucun** `apt upgrade` derrière.

---

## Phase 2 — Récupérer les headers 5.16 (archive officielle)

```bash
mkdir -p ~/Downloads && cd ~/Downloads
wget https://old.kali.org/kali/pool/main/l/linux/linux-headers-5.16.0-kali7-amd64_5.16.18-1kali1_amd64.deb \
     https://old.kali.org/kali/pool/main/l/linux/linux-headers-5.16.0-kali7-common_5.16.18-1kali1_all.deb \
     https://old.kali.org/kali/pool/main/l/linux/linux-kbuild-5.16_5.16.18-1kali1_amd64.deb \
     https://old.kali.org/kali/pool/main/l/linux/linux-compiler-gcc-11-x86_5.16.18-1kali1_amd64.deb
```

> [!TIP]
> Si un `wget` renvoie une **404**, la version a bougé dans l'archive : parcourir
> https://old.kali.org/kali/pool/main/l/linux/ pour retrouver les 4 fichiers
> `...5.16.0-kali7...` / `linux-kbuild-5.16...` / `linux-compiler-gcc-11-x86...` et
> corriger le numéro de version.

Installer les 4 `.deb` (l'ordre gère les dépendances) :
```bash
sudo dpkg -i linux-headers-5.16.0-kali7-common_5.16.18-1kali1_all.deb \
             linux-kbuild-5.16_5.16.18-1kali1_amd64.deb \
             linux-compiler-gcc-11-x86_5.16.18-1kali1_amd64.deb \
             linux-headers-5.16.0-kali7-amd64_5.16.18-1kali1_amd64.deb
```
Vérifier :
```bash
ls /lib/modules/$(uname -r)/build     # doit exister
```

---

## Phase 3 — Compiler le driver depuis les sources

> [!NOTE] Pourquoi `make install` et pas DKMS
> DKMS ne sert qu'à **recompiler à chaque nouveau noyau**. Le noyau étant **figé**, un
> `make install` classique suffit, et il n'entraîne **aucune** dépendance apt 2026.

```bash
cd ~
git clone https://github.com/aircrack-ng/rtl8812au
cd rtl8812au
make                       # produit 88XXau.ko
sudo make install
sudo modprobe 88XXau
```

> [!IMPORTANT]
> - Le module s'appelle **`88XXau`** (pas `8812au`).
> - Les warnings `pahole-flags.sh: not found` et `Skipping BTF generation` sont
>   **sans conséquence** (infos de debug seulement).
> - Si erreur de version gcc (`compiler differs`) : `make clean && make CC=gcc-11`.

Vérifier :
```bash
lsmod | grep 88XXau        # module chargé
iwconfig                   # wlan0 apparaît
```

---

## Phase 4 — Monitor mode

```bash
sudo airmon-ng check kill  # coupe wpa_supplicant / NetworkManager
sudo airmon-ng start wlan0
iwconfig                   # Mode:Monitor
```

> [!WARNING]
> Avec ce driver, l'interface **reste `wlan0`** en monitor — il n'y a **pas** de `wlan0mon`.
> Donc `sudo airodump-ng wlan0` ✅ — et non `wlan0mon` ❌.

Test de capture (carte **bi-bande**) :
```bash
sudo airodump-ng wlan0              # 2.4 GHz
sudo airodump-ng --band a wlan0     # 5 GHz uniquement
sudo airodump-ng --band abg wlan0   # 2.4 + 5 GHz
```

Revenir en mode normal (réseau) :
```bash
sudo airmon-ng stop wlan0
sudo systemctl restart NetworkManager
```

> [!NOTE] Injection 5 GHz
> Sur cette install (driver aircrack `88XXau` + kernel 5.16), l'**injection 5 GHz
> fonctionne** (`aireplay-ng --test` sur ch 36 = 100 %). Seuls les canaux **DFS 52–144**
> restent no-IR (injection interdite par la **réglementation**, pas par la carte).

---

## Phase 5 — Outils du projet

Vérifier ce qui est présent (Kali en préinstalle la plupart) — **n'installe rien** :
```bash
for t in iw aircrack-ng airodump-ng aireplay-ng airmon-ng wifite \
         hcxdumptool hcxpcapngtool hashcat mdk4 tshark tcpdump \
         reaver wash pixiewps hostapd dnsmasq; do
  command -v "$t" >/dev/null 2>&1 && echo "✔ $t" || echo "✗ MANQUANT : $t"
done
```

Sur une Kali 2022.2 fraîche, il manque typiquement **4 outils** — à installer **eux aussi**
via `old.kali.org` (versions d'époque, pas de cascade) :

| Outil | Paquet | Version 2022 validée | Dossier pool |
|---|---|---|---|
| `hcxdumptool` | `hcxdumptool` | `6.2.5-2` | `h/hcxdumptool/` |
| `hcxpcapngtool` | `hcxtools` | `6.2.5-2` | `h/hcxtools/` |
| `mdk4` | `mdk4` | `4.2-3` | `m/mdk4/` |
| `hostapd` | `hostapd` *(source `wpa`)* | `2.10-8` | `w/wpa/` |

```bash
cd ~/Downloads
wget https://old.kali.org/kali/pool/main/h/hcxdumptool/hcxdumptool_6.2.5-2_amd64.deb \
     https://old.kali.org/kali/pool/main/h/hcxtools/hcxtools_6.2.5-2_amd64.deb \
     https://old.kali.org/kali/pool/main/m/mdk4/mdk4_4.2-3_amd64.deb \
     https://old.kali.org/kali/pool/main/w/wpa/hostapd_2.10-8_amd64.deb
sudo dpkg -i hcxdumptool_6.2.5-2_amd64.deb hcxtools_6.2.5-2_amd64.deb \
             mdk4_4.2-3_amd64.deb hostapd_2.10-8_amd64.deb
```

> [!CAUTION]
> Ne **jamais** faire `apt install hostapd mdk4 hcxdumptool hcxtools` : apt tirerait
> `libc6` 2026 → cascade. `dpkg -i` est sûr : il refuse proprement si une dépendance
> manque (colle alors le message, on prend le `.deb` de la dépendance sur `old.kali.org`).
> Le **cœur** (recon / deauth / wifite / hashcat) marche déjà **sans** ces 4 ; ils
> servent aux actions avancées (PMKID, evil-twin, floods mdk4).

---

## Phase 6 — Récupérer NexusPi et lancer

```bash
cd ~
git clone https://github.com/Hasyros/NexusPi.git nexuspi
cd nexuspi
./run-wifi.sh
```

- `run-wifi.sh` installe seul les dépendances Python (`fastapi`, `uvicorn`, `aiohttp`,
  `lxml`) en `pip --user` — **sans toucher au figeage système**. Il détecte
  automatiquement l'interface WiFi.
- Si « permission denied » sur le script : `bash run-wifi.sh`.
- Ouvrir le navigateur sur l'URL affichée (localhost:port).

---

## Après un reboot

Le module ne se recharge pas toujours seul. Si `wlan0` manque au démarrage :
```bash
sudo modprobe 88XXau
```

---

## Dépannage (symptômes réels rencontrés)

> [!WARNING] Monitor OK mais **0 réseau capturé** / injection « 0 APs »
> Ce n'est **pas** un bug logiciel → problème **RX physique** :
> - **Antenne(s) RP-SMA dévissée(s)** → revisser.
> - **Attach USB VirtualBox perdu** → *Périphériques → USB* : décocher / recocher la
>   Realtek `0bda:8812`.
> Vécu le 2026-07-12 : carte muette, puis **165 beacons** captés après revissage + ré-attach.

> [!WARNING] `iw set type monitor` renvoie **EPERM** alors que NetworkManager est coupé
> Symptôme d'une carte « coincée » (souvent après une VM restée trop longtemps allumée /
> ré-énumération USB `phy0→phy3`). Fallback fiable : passer par **`airmon-ng`**
> (`sudo airmon-ng check kill && sudo airmon-ng start wlan0`) et **vérifier** l'état via
> `iw dev wlan0 info`. Si la carte reste coincée → recréer la VM proprement.

> [!WARNING] `apt update` : `NO_PUBKEY ED65462EC8D5E4C5`
> Clé de signature Kali expirée → refaire la **Phase 1**.

> [!WARNING] `wget` d'un `.deb` → **404**
> La version a changé dans l'archive → parcourir le dossier pool correspondant sur
> https://old.kali.org/kali/pool/main/ et corriger le numéro de version.

---

## Points clés à retenir

- 🔑 **`old.kali.org`** = archive officielle **signée** qui conserve les vieux `.deb`
  du pool. C'est la pièce qui débloque tout (headers **et** outils).
- 🚫 **Jamais d'`apt install`** du noyau, du driver `*-dkms`, ou des outils manquants
  sur cette VM figée → cascade `glibc/gcc/Perl` → `dpkg` cassé. Toujours `dpkg -i`
  depuis `old.kali.org`.
- 📛 Module = **`88XXau`** ; interface (même en monitor) = **`wlan0`** (pas `wlan0mon`).
- 🔁 Après `make install`, le module se charge via udev. Vérifier après reboot que
  `wlan0` réapparaît seul ; sinon `sudo modprobe 88XXau`.
- 🧊 Le driver est en `make install` **manuel** (pas DKMS) : c'est voulu (noyau figé),
  et ça évite toute dépendance apt 2026.

---

## Cadre légal

Usage strictement limité aux **réseaux et équipements dont on est propriétaire** (ou avec
autorisation écrite). Émissions RF dans le cadre **ARCEP** ; l'accès non autorisé à un
système est un délit (art. 323-1 du Code pénal). Les actions offensives de NexusPi
restent verrouillées par défaut (*lab mode*).
