#!/usr/bin/env python3

import string

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote( '0.cloud.chals.io', 25330)
    else:
        p = process('./chall')
    return p

def guess(k, s):
    p = conn()
    p.sendlineafter(b':\n', str(k).encode())
    p.sendlineafter(b':\n', s.encode())
    ret = p.recvline()
    p.close()
    return ret.strip().decode('ascii')
    
C = 'TBTL'
for i in range(60):
    next = None
    for x in string.printable:
        g = guess(64, C+x)
        print(C+x, g)
        if g == 'Got it!':
            print(C+x)
            exit()
        elif g[0] == 'A':
            next = x
            break 
    assert next
    C += x
