from pwn import *
import random

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 13594)
    else:
        p = process('./balanced')
    return p

FLAG = '🚩'.encode('utf-8')

def genrandom():
    x = ['0011', '0101']
    a = ''
    for i in range(25):
        a += random.choice(x)    
    return a

p = conn()
flag = []
p.sendlineafter(b':', FLAG) 
for i in range(68):
    p.sendlineafter(b':', str(int(genrandom(), 2)).encode())
    ret = p.recvline() + p.recvline()
    flag.append(ret[-2])
print(bytes(flag))
p.interactive()