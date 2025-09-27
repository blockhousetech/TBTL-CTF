#!/usr/bin/env python3

from pwn import *
from Crypto.Cipher import AES

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 31387)
    else:
        p = process('./chall')
        gdb.attach(p, '''              
            # set {unsigned long long}(&MASTER_KEY) = 0xbabadedadeadbeef
            # set {unsigned long long}((void*)&MASTER_KEY+0x8) = 0xbabadedadeadbeef  
            continue
        ''')
    return p

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
    P = 'babadedadeadbeef'
    for i in range(7):
        x = P[i*2+2:i*2+4] + P[i*2:i*2+2]
        if x in wrapped or x in nonce:
            print(f'Found: {la} {lb} {wrapped} {nonce}')
            return wrapped[2:16], nonce
    return wrapped[2:16], nonce

def unwrap(master_key, wrapped, ciphertext, nonce):
    anonce = unpack(wrapped[8:16])
    cipher = AES.new(master_key, AES.MODE_CTR, nonce=wrapped[8:16])
    key = cipher.decrypt(wrapped[16:32])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    if b'FortID' in plaintext:
        print(f'Plaintext: {plaintext}')

p = conn()

p.recvuntil(b'Wrapped key: ')
wrapped = p.recvline().strip().decode()
p.recvuntil(b'Nonce: ')
nonce = p.recvline().strip().decode()
p.recvuntil(b'Ciphertext: ')
ciphertext = p.recvline().strip().decode()

# for i in range(0x100, 0x120, 0x2):
#     for j in range(0x50, 0x400 ,0x2):
#         check(p, i, j)

key_8_16_hex = check(p, 256, 706)[1]
key_0_7_hex = check(p, 256, 194)[0]
print(f'key_0_7_hex: {key_0_7_hex}')
print(f'key_8_16_hex: {key_8_16_hex}')

key_0_7 = bytes.fromhex(key_0_7_hex)
key_8_16 = bytes.fromhex(key_8_16_hex)[::-1]

print('wrapped:', wrapped)
print('ciphertext:', ciphertext)
for f in range(256):
    master_key = bytes([f]) + key_0_7 + key_8_16
    unwrap(master_key, bytes.fromhex(wrapped), bytes.fromhex(ciphertext), bytes.fromhex(nonce)[::-1])

p.interactive()
