#!/usr/bin/env python3

from pwn import *

context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])

p = process('./chall')

gdb.attach(p, '''
    # set {unsigned long long}(&MASTER_KEY) = 0xbabadedadeadbeef
    set {unsigned long long}((void*)&MASTER_KEY+0x8) = 0xbabadedadeadbeef
    continue
''')
    
def check(p, la, lb):
    p.sendlineafter(b'> ',b'a'*la)
    p.sendlineafter(b'> ', b'0')
    p.sendlineafter(b'> ',b'a'*lb)
    p.sendlineafter(b'> ', b'1')
    p.recvuntil(b'Wrapped key: ')
    wrapped = p.recvline().strip().decode()
    p.recvuntil(b'Nonce: ')
    nonce = p.recvline().strip().decode()
    p.recvuntil(b'Ciphertext: ')
    ciphertext = p.recvline().strip().decode()
    leak = wrapped[2:16]
    P = 'babadedadeadbeef'
    for i in range(7):
        x = P[i*2+2:i*2+4] + P[i*2:i*2+2]
        if x in wrapped or x in nonce:
            print(f'Found: {la} {lb} {wrapped} {nonce}')
            return wrapped[2:16], nonce
    return wrapped[2:16], nonce

p.recvuntil(b'Wrapped key: ')
wrapped = p.recvline().strip().decode()
p.recvuntil(b'Nonce: ')
nonce = p.recvline().strip().decode()
p.recvuntil(b'Ciphertext: ')
ciphertext = p.recvline().strip().decode()

for i in range(0x100, 0x120, 0x2):
   for j in range(0x50, 0x400 ,0x2):
       check(p, i, j)

p.interactive()
