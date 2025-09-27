#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 33121)
    else:
        p = process('./chall')
        gdb.attach(p, '''
            continue
        ''')
    return p

def find_num(c):
    i = 0
    while c != ord('='):
        c = (c + 13) % 256
        i += 1
    return i;

def unrot13(s, k):
    return bytes(((i - k*13) % 256 + 256) % 256 for i in s)

p = conn()
x = find_num(ord('F'))
for i in range(x):
    p.sendlineafter(b'> ', b'protect FLAG')
p.sendlineafter(b'> ', b'print FLAG=')
p.recvuntil(b'FLAG=')
data = p.recvuntil(b'\n> ')[:-2]
print([data])
flag=unrot13(data, x)
print(flag)
p.close()
