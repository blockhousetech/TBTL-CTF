# Free Candy &mdash; Solution

We are given instructions to connect to a remote server, along with the source
code of that server. Let's connect and see what happens.

```
$ nc 0.cloud.chals.io 19521



    ███      ▄█   ▄████████    ▄█   ▄█▄    ▄████████     ███             ▄████████    ▄█    █▄     ▄██████▄     ▄███████▄
▀█████████▄ ███  ███    ███   ███ ▄███▀   ███    ███ ▀█████████▄        ███    ███   ███    ███   ███    ███   ███    ███
   ▀███▀▀██ ███▌ ███    █▀    ███▐██▀     ███    █▀     ▀███▀▀██        ███    █▀    ███    ███   ███    ███   ███    ███
    ███   ▀ ███▌ ███         ▄█████▀     ▄███▄▄▄         ███   ▀        ███         ▄███▄▄▄▄███▄▄ ███    ███   ███    ███
    ███     ███▌ ███        ▀▀█████▄    ▀▀███▀▀▀         ███          ▀███████████ ▀▀███▀▀▀▀███▀  ███    ███ ▀█████████▀
    ███     ███  ███    █▄    ███▐██▄     ███    █▄      ███                   ███   ███    ███   ███    ███   ███
    ███     ███  ███    ███   ███ ▀███▄   ███    ███     ███             ▄█    ███   ███    ███   ███    ███   ███
   ▄████▀   █▀   ████████▀    ███   ▀█▀   ██████████    ▄████▀         ▄████████▀    ███    █▀     ▀██████▀   ▄████▀
                              ▀

        In our shop, you are guaranteed to win!


Choose an action:
    1) Get a free ticket
    2) Claim your prize

1
eyJwYXlsb2FkIjp7InRpY2tldF9pZCI6OTY5MTk4ODI3NDIyOTUyNTkwMjA0NDYyODc1NTY3ODQyNDQ5ODI2OTM3NzUwMTg0OTc3NjI5MzU3MjgyMjc3NjIxNjc3MjE5NjAyMTd9LCJzaWduYXR1cmUiOiJiMzk1NDM1N2Q1YTg2YThkODM0NTAwNTM2MTk5ZmVjZTk3NDA0ZmY4Y2Y3NDU3YjlkMjY2YjYyYTY5OTA5ZDk1MDQwOTk5NWFlMTE4MzhlMDRjMjM1MTUzNGI3MTlhYmI2MTJlYzJlODU5OWRhNTFiYjgzNTI5MDcxYTYyYjAwNSJ9

Choose an action:
    1) Get a free ticket
    2) Claim your prize

2
Enter your ticket:
eyJwYXlsb2FkIjp7InRpY2tldF9pZCI6OTY5MTk4ODI3NDIyOTUyNTkwMjA0NDYyODc1NTY3ODQyNDQ5ODI2OTM3NzUwMTg0OTc3NjI5MzU3MjgyMjc3NjIxNjc3MjE5NjAyMTd9LCJzaWduYXR1cmUiOiJiMzk1NDM1N2Q1YTg2YThkODM0NTAwNTM2MTk5ZmVjZTk3NDA0ZmY4Y2Y3NDU3YjlkMjY2YjYyYTY5OTA5ZDk1MDQwOTk5NWFlMTE4MzhlMDRjMjM1MTUzNGI3MTlhYmI2MTJlYzJlODU5OWRhNTFiYjgzNTI5MDcxYTYyYjAwNSJ9
You won some free candy:

                     /\.--./\
                     \/'--'\/

             /\.--./\        /\.--./\
             \/'--'\/        \/'--'\/


Choose an action:
    1) Get a free ticket
    2) Claim your prize
```

Looks like the challenge setup revolves around some tickets and prizes. Let's
dig around through the source code. This is the main function:

```python
def main():
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(120)

    print(BANNER)

    rng_ticket = RNG(int(Signer._n))
    rng_signer = copy(rng_ticket)

    signer = Signer(rng_signer)

    ticket_shop = Ticket(rng_ticket, signer)
    prize_pool = PrizePool(signer, ticket_shop);

    while True:
        print(MENU)
        option = int(input())
        if option not in [1, 2]:
            print("W00t?")
            continue

        if option == 1:
            print(f"{ticket_shop.fresh()}")
        else:
            print("Enter your ticket: ")
            ticket = input().strip()
            print(f"{prize_pool.claim_prize(ticket)}")



if __name__ == '__main__':
    main()
```

Looks like we need to investigate the `RNG`, `Signer`, `Ticket` and `PrizePool`
classes.

This is the `RNG` class:

```python

class RNG:
    def __init__(self, p):
        assert isPrime(p), "p must be prime"
        self.p = Integer(p)
        self.F = GF(self.p)
        self.H = QuaternionAlgebra(self.F, -1, -1)

        self.i = self.H.gen(0)
        self.j = self.H.gen(1)
        self.k = self.i * self.j

        self.half = self.F(1) / self.F(2)

        while True:
            a = self.F.random_element()
            b = self.F.random_element()
            c = self.F.random_element()
            d = self.F.random_element()
            if b != 0:
                break

        self.q = a + b*self.i + c*self.j + d*self.k
        self.n = Integer(0)

    def seed(self):
        self.n = ZZ.random_element(self.p)

    def print_params(self):
        print(f"seed = {self.n}")
        print(f"q = {self.q}")

    def gen(self):
        Q = self.q ** int(self.n)
        ret = -self.half * (self.i * Q).reduced_trace()
        self.n += 1
        return int(ret)

```

Looks like we're dealing with a custom random number generator built on top of
[quaternion algebra](https://en.wikipedia.org/wiki/Quaternion_algebra) over a
[finite field](https://en.wikipedia.org/wiki/Finite_field) $\mathbb{F}_p$.

On initialization in samples a random quaternion $q = a + b\mathbf{i} +
c\mathbf{j} + d\mathbf{k}$ with coefficients in $\mathbb{F}_p$.

The internal state is just an integer exponent $n$. Every time you call
`gen()`, it computes $q^n$, extracts the coefficient of $\mathbf{i}$ (the
x-coordinate) from that power, and returns it as the next pseudorandom number.
It also increments $n$.

In other words, the output stream is the $\mathbf{i}$-th component of
successive powers of a fixed random quaternion.

Let's take a look at `Signer`:

```python
class Signer:
    _p  = Integer(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    _a4 = Integer(0)
    _a6 = Integer(7)
    _n  = Integer(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
    _Gx = Integer(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
    _Gy = Integer(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

    def __init__(self, rng):
        self.rng = rng

        F = GF(self._p)
        self.E = EllipticCurve(F, [0, 0, 0, self._a4, self._a6])
        self.G = self.E(self._Gx, self._Gy)
        self.n = self._n

        self.d = Integer(1 + ZZ.random_element(self.n - 1))
        self.Q = (self.d * self.G)

        self.rng.seed()

    def _hash_to_int(self, msg):
        h = hashlib.sha256(msg).digest()
        return Integer(int.from_bytes(h, 'big')) % self.n

    def _next_k(self):
        while True:
            k = Integer(self.rng.gen())
            if k != 0:
                return k

    def sign(self, msg):
        z = self._hash_to_int(msg)

        while True:
            k = self._next_k()
            R = (k * self.G)
            if R.is_zero():
                continue
            r = Integer(R.xy()[0]) % self.n
            if r == 0:
                continue
            try:
                kinv = Integer(k).inverse_mod(self.n)
            except ZeroDivisionError:
                continue
            s = (kinv * (z + r * self.d)) % self.n
            if s == 0:
                continue
            return (int(r), int(s))

    def verify(self, msg, sig):
        r, s = map(Integer, sig)
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False

        z = self._hash_to_int(msg)
        try:
            w = Integer(s).inverse_mod(self.n)
        except ZeroDivisionError:
            return False
        u1 = (z * w) % self.n
        u2 = (r * w) % self.n
        V = u1 * self.G + u2 * self.Q
        if V.is_zero():
            return False
        xV = Integer(V.xy()[0]) % self.n
        return xV == r

    def pubkey(self):
        P = self.Q.xy()
        return (int(P[0]), int(P[1]))

    def privkey(self):
        return int(self.d)
```

This looks like an
[ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
implementation on the **secp256k1 curve** defined over the prime field
$\mathbb{F}_p,\quad p = 2^{256} - 2^{32} - 977$.

This is essentially a textbook ECDSA implementation, however it sticks out that
the random nonce value $k$ used during signing is generated using the
previously discussed `RNG`. Since choosing a cryptographically secure random
nonce when computing ECDSA signatures is essential for its security, this will
likely be an attack vector down the line.

Let's take a look at `Ticket` now:

```python
class Ticket:
    def __init__(self, rng, signer, cnt = 1):
        self.signer = signer
        self.cnt = cnt
        self.rng = rng
        rng.seed()

    def reset(self):
        self.cnt = 1

    def fresh(self):
        if self.cnt <= 0:
            return "No more tickets for you..."
        self.cnt -= 1

        ticket_id = int(self.rng.gen())

        payload = {"ticket_id": ticket_id}
        payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()

        r, s = self.signer.sign(payload_bytes)
        r_bytes = int(r).to_bytes(32, 'big')
        s_bytes = int(s).to_bytes(32, 'big')
        sig_hex = (r_bytes + s_bytes).hex()

        ticket = {
            "payload": payload,
            "signature": sig_hex,
        }

        ticket_json = json.dumps(ticket, separators=(',', ':'), sort_keys=True).encode()
        return base64.b64encode(ticket_json).decode()
```

This is a tiny ticket shop wrapper. On construction it stores a reference to
the `rng` and `signer`, seeds the `RNG`, and keeps a counter `cnt` limiting how
many tickets can be issued. Calling `fresh()` decrements the counter, draws a
`ticket_id = int(rng.gen())`, builds the canonical payload `{"ticket_id":
ticket_id}`, and asks the Signer to produce an ECDSA signature over the payload
bytes. The method encodes the signature as `r||s` (32 bytes each) hex, packs
`"payload"` and `"signature"` into a JSON object, base64-encodes that JSON and
returns it.

In short, each ticket is a signed, base64-JSON blob containing a single
RNG-derived integer and its ECDSA signature.

Finally, let's take a look at `PrizePool`:

```python
class PrizePool:
    def __init__(self, signer, ticket_shop):
        self.signer = signer
        self.ticket_shop = ticket_shop
        self._used = set()


    def claim_prize(self, ticket_b64):
        try:
            raw = base64.b64decode(ticket_b64, validate=True)
        except Exception:
            return "Invalid ticket: bad base64"

        try:
            ticket = json.loads(raw.decode())
        except Exception:
            return "Invalid ticket: bad JSON"

        if not isinstance(ticket, dict) or "payload" not in ticket or "signature" not in ticket:
            return "Invalid ticket: missing fields"

        payload = ticket["payload"]
        sig_hex = ticket["signature"]

        if not isinstance(payload, dict) or "ticket_id" not in payload:
            return "Invalid ticket: bad payload"

        tid = payload["ticket_id"]
        try:
            tid = int(tid)
        except Exception:
            return "Invalid ticket: ticket_id not integer"

        payload_bytes = json.dumps({"ticket_id": tid}, separators=(',', ':'), sort_keys=True).encode()

        if not isinstance(sig_hex, str):
            return "Invalid ticket: signature not a string"
        try:
            sig_bytes = bytes.fromhex(sig_hex)
        except (ValueError, binascii.Error):
            return "Invalid ticket: signature not hex"

        if len(sig_bytes) != 64:
            return "Invalid ticket: signature wrong length"

        r = int.from_bytes(sig_bytes[:32], 'big')
        s = int.from_bytes(sig_bytes[32:], 'big')

        if not self.signer.verify(payload_bytes, (r, s)):
            return "Invalid ticket: bad signature"

        if tid in self._used:
            print("Go away hacker!")
            exit(1)

        self._used.add(tid)

        if tid == bytes_to_long(hashlib.sha256(b"I'd like the flag please").digest()):
            flag = open("flag.txt", "r").read()
            flag_prize = f"""
       ░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░▒▓████████▓▒░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░
       ░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░       ░▒▓██████▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░

                    {flag}
            """

            return flag_prize

        if tid % 2 == 0:
            self.ticket_shop.reset()
            ticket = self.ticket_shop.fresh()
            return f"You won a brand new ticket: {ticket}"

        prize = """You won some free candy:

                     /\.--./\\
                     \/'--'\/

             /\.--./\        /\.--./\\
             \/'--'\/        \/'--'\/
        """

        return prize

```

This class is the ticket redemption endpoint. `claim_prize()` accepts a
base64-encoded JSON ticket, decodes and parses it, and performs structural
checks. It reconstructs the canonical payload bytes and verifies the ECDSA
signature via the `Signer`. If the ticket was already redeemed the server
immediately exits (replay protection). If the `ticket_id` equals the SHA-256
digest (interpreted as an integer) of the special string `"I'd like the flag
please"` the flag is returned.

This tells us we likely need to forge a signature for this string in order to
solve the challenge.

Otherwise, the function marks the `ticket_id` used and either
  * if the `id` is even it resets the shop and returns a newly issued ticket,
  * or if odd it returns a small ASCII “candy” prize.

In short, `PrizePool` enforces signature validity and replay prevention, contains
the flag check, and implements the prize logic.

Let's recap what we know:
  * we have a weird RNG implementation based on quaternions
  * this RNG is used for generating nonce values during signing
  * we somehow need to forge a correct signature over a given message

## RNG Vulnerability

This quaternion RNG hides a simple 2-term linear recurrence.
Due to [Cayley-Hamilton](https://en.wikipedia.org/wiki/Cayley%E2%80%93Hamilton_theorem), a quaternion $q = a + b\mathbf{i} + c\mathbf{j} + d\mathbf{k}$ satisfies its reduced characteristic equation

```math
q^2 - 2aq + N = 0
```
```math
N = a^2 + b^2 + c^2 + d^2
```

The $\mathbf{i}$-coefficients $X_n$ of $q^n$ thus behave like an order-2
[LFSR](https://en.wikipedia.org/wiki/Linear-feedback_shift_register).

```math
X_n = 2a X_{n-1} - N X_{n-2}
```

This means we should be able to crack the RNG if we get enough consecutive
outputs. In this case, it turns out four are enough, $k_{n-2}, k_{n-1}, k_n, k_{n+1}$.
They satisfy $k_{t+1} ≡ c \cdot k_t - N \cdot k_{t-1} \pmod n$ (where $c = 2a$).

Then we have

```math
N = ( k_{n+1} \cdot k_{n-1} - k_n^2 ) \cdot ( k_n \cdot k_{n-2} - k_{n-1}^2 )^{-1} \pmod n
```

```math
c = ( k_n + N \cdot k_{n-2} ) \cdot k_{n-1}^{-1} \pmod n
```

## Leaking ECDSA Private Key

ECDSA signatures satisfy, for each signature index $t$,

```math
k_t s_t ≡ z_t + r_t d \pmod n
```

where $z_t = H(m_t) \pmod n$, $d$ is the private key, and $k_t$ is the
per-signature nonce.

If the nonces follow the 2-term recurrence

```math
k_{t+1} ≡ c k_t - N k_{t-1} \pmod n
```

we can eliminate the unknown $k$'s across three consecutive signatures ($t -
1$, $t$, and $t + 1$). Writing $k_u = (z_u+r_ud)s_u^{-1}$ and substituting into
the recurrence yields a single linear congruence in $d$.

```math
Ad \equiv B \pmod n
```

from which we can recover the private key.

## Putting it all together

Looks like we should be able to crack it now. We will:
  1. Use the server's behaviour to obtain **4 chained tickets**.
  2. Extract 4 `ticket_id` integers.
  3. Extract 4 signatures `(r,s)` and canonical payload bytes for each ticket.
  4. Recover RNG taps $N$ and $c = 2a$ from the extracted values.
  5. Use three recovered signatures and recovered $(N, c)$, form the linear
     congruence in $d$, and extract the private key.
  6. Mint a ticket whose `ticket_id` equals what `int.from_bytes(SHA256(b"I'd
     like the flag please").digest(),"big")`, sign it with `d` and submit to
     `claim_prize()`.

Implementation of this idea:

```python
#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
import os
import re

from pwn import *

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

BRAND_RE = re.compile(r"brand new ticket:\s*([A-Za-z0-9+/=]+)")

def inv_mod(x, m):
    return pow(x % m, -1, m)

def is_on_curve(Pt):
    if Pt is None:
        return True
    x, y = Pt
    return (y*y - (x*x*x + A*x + B)) % P == 0

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1; x2, y2 = P2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if P1 == P2:
        lamb = (3 * x1 * x1 + A) * inv_mod(2 * y1, P) % P
    else:
        lamb = (y2 - y1) * inv_mod(x2 - x1, P) % P
    x3 = (lamb * lamb - x1 - x2) % P
    y3 = (lamb * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, Pt=G):
    k = k % N
    if k == 0 or Pt is None:
        return None
    Q = None
    addend = Pt
    while k:
        if k & 1:
            Q = point_add(Q, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return Q

def ecdsa_sign_raw(d, msg_bytes):
    z = int.from_bytes(hashlib.sha256(msg_bytes).digest(), 'big') % N
    while True:
        k = int.from_bytes(hashlib.sha256(b'k' + os.urandom(32)).digest(), 'big') % N
        if k == 0:
            continue
        R = scalar_mult(k, G)
        if R is None:
            continue
        r = R[0] % N
        if r == 0:
            continue
        s = inv_mod(k, N) * (z + r * d) % N
        if s == 0:
            continue
        return r, s

def extract_ticket_from_chunk(chunk: str) -> str | None:
    for m in re.finditer(r"([A-Za-z0-9+/=]{24,})", chunk):
        cand = m.group(1)
        try:
            raw = base64.b64decode(cand, validate=True)
            obj = json.loads(raw.decode())
            if isinstance(obj, dict) and "payload" in obj and "signature" in obj:
                return cand
        except Exception:
            continue
    return None

def parse_ticket(ticket_b64: str):
    raw = base64.b64decode(ticket_b64, validate=True)
    obj = json.loads(raw.decode())
    tid = int(obj["payload"]["ticket_id"])
    sig = bytes.fromhex(obj["signature"])
    if len(sig) != 64:
        raise ValueError("bad signature length")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    payload_bytes = json.dumps({"ticket_id": tid}, separators=(",", ":"), sort_keys=True).encode()
    return tid, r, s, payload_bytes

def sync_to_menu(io, where="(sync)"):
    io.recvuntil(b"Choose an action:")

def recv_until_menu(io, where="(post)"):
    return io.recvuntil(b"Choose an action:", drop=True, timeout=10).decode(errors="ignore")

def get_free_ticket(io) -> str:
    io.sendline(b"1")
    chunk = recv_until_menu(io, "[opt1]")
    t = extract_ticket_from_chunk(chunk)
    if not t:
        log.error("No ticket after option 1.\n---CHUNK---\n%s\n---------", chunk)
        raise RuntimeError("no ticket")
    log.info("free ticket ok")
    return t

def claim_ticket(io, ticket_b64: str):
    io.sendline(b"2")
    io.recvuntil(b"Enter your ticket:", timeout=10)
    io.sendline(ticket_b64.encode())
    chunk = recv_until_menu(io, "[opt2]")
    m = BRAND_RE.search(chunk)
    if m:
        return m.group(1), chunk
    t = extract_ticket_from_chunk(chunk)
    if t:
        return t, chunk
    return None, chunk

def derive_params_from_four(xs, p):
    xnm2, xnm1, xn, xnp1 = [x % p for x in xs]
    denom = (xn * xnm2 - (xnm1 * xnm1)) % p
    inv_denom = pow(denom, -1, p)
    Np = ((xnp1 * xnm1 - (xn * xn)) % p) * inv_denom % p
    inv_xnm1 = pow(xnm1 % p, -1, p)
    c = ((xn + (Np * xnm2) % p) % p) * inv_xnm1 % p
    inv2 = (p + 1) // 2
    a = (c * inv2) % p
    return c, Np, a

def d_from_triple(triple, c, Np, n):
    (r0, s0, z0), (r1, s1, z1), (r2, s2, z2) = triple
    Acoef = ( (s1 * s0 % n) * r2 - (c * s2 % n) * (s0 * r1 % n) + (Np * s2 % n) * (s1 * r0 % n) ) % n
    if Acoef == 0:
        raise ZeroDivisionError("degenerate triple (A==0)")
    Bcoef = ( (c * s2 % n) * (s0 * z1 % n) - (Np * s2 % n) * (s1 * z0 % n) - (s1 * s0 % n) * z2 ) % n
    return (Bcoef * inv_mod(Acoef, n)) % n

def sha256_int(b: bytes, n: int) -> int:
    return int.from_bytes(hashlib.sha256(b).digest(), "big") % n

def run(io):
    sync_to_menu(io, "(initial)")

    chain_tickets = []
    chain_ids = []

    t = get_free_ticket(io)
    tid, r, s, payload = parse_ticket(t)
    chain_tickets.append(t); chain_ids.append(tid)
    log.info(f"start chain: tid0={tid}")

    attempts = 0
    while len(chain_tickets) < 4 and attempts < 300:
        attempts += 1
        new_t, chunk = claim_ticket(io, t)
        if new_t is None:
            t = get_free_ticket(io)
            tid, r, s, payload = parse_ticket(t)
            chain_tickets = [t]; chain_ids = [tid]
            log.info(f"restart chain: tid0={tid}")
            continue
        t = new_t
        tid, r, s, payload = parse_ticket(t)
        chain_tickets.append(t)
        chain_ids.append(tid)
        log.info(f"chain len={len(chain_tickets)} last_tid={tid}")

    if len(chain_tickets) < 4:
        log.failure("Could not collect 4 chained tickets.")
        return

    log.success(f"Got 4 chained tids: {chain_ids}")

    c, Np, a = derive_params_from_four(chain_ids[-4:], N)
    log.success("Derived RNG params (mod n)")
    log.info(f"N  = {Np}")
    log.info(f"c=2a = {c}")
    log.info(f"a  = {a}")

    sigs = []
    for tb64 in chain_tickets:
        tid, r, s, payload = parse_ticket(tb64)
        z = sha256_int(payload, N)
        sigs.append((r % N, s % N, z))

    try:
        d = d_from_triple(sigs[0:3], c, Np, N)
    except ZeroDivisionError:
        d = d_from_triple(sigs[1:4], c, Np, N)

    log.success(f"Leaked ECDSA private key d = {d}")
    log.info(f"d (hex) = {hex(d)}")

    target_tid = int.from_bytes(hashlib.sha256(b"I'd like the flag please").digest(), "big")
    payload_obj = {"ticket_id": target_tid}
    payload_bytes = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode()

    r_new, s_new = ecdsa_sign_raw(d, payload_bytes)
    sig_hex = (r_new.to_bytes(32, "big") + s_new.to_bytes(32, "big")).hex()
    minted = {
        "payload": payload_obj,
        "signature": sig_hex,
    }
    minted_b64 = base64.b64encode(json.dumps(minted, separators=(",", ":"), sort_keys=True).encode()).decode()
    log.success("Minted special ticket, submitting...")

    io.sendline(b"2")
    io.recvuntil(b"Enter your ticket:", timeout=10)
    io.sendline(minted_b64.encode())
    out = io.recvuntil(b"Choose an action:", drop=True, timeout=10).decode(errors="ignore")

    print(out.strip())

def main():
    ap = argparse.ArgumentParser(description="Solve: chain tickets, leak key, mint ticket, claim flag")
    ap.add_argument("--local", action="store_true", help="run against ./server.py")
    ap.add_argument("--host", type=str, help="remote host")
    ap.add_argument("--port", type=int, help="remote port")
    ap.add_argument("--debug", action="store_true", help="enable pwntools debug")
    args = ap.parse_args()

    context.log_level = "debug" if args.debug else "info"

    if args.local:
        io = process(["python3", "./server.py"])
    else:
        if not (args.host and args.port):
            ap.error("Either use --local or provide --host and --port")
        io = remote(args.host, args.port)

    try:
        run(io)
    finally:
        io.close()

if __name__ == "__main__":
    import os
    main()
```

After running it a couple of time, we finally get lucky:

```text
[+] Opening connection to 0.cloud.chals.io on port 19521: Done
[*] free ticket ok
[*] start chain: tid0=53336616575417346505845743127088865852070765298691443990322342503930133296644
[*] chain len=2 last_tid=82193329954502979978022850807812153825386579027513935869259567236241902097528
[*] chain len=3 last_tid=79582332307933489445850305095087629762468600427204881631607913496000554369644
[*] chain len=4 last_tid=10620665678495759167849958490357545458918447594048747837565264846500606457485
[+] Got 4 chained tids: [53336616575417346505845743127088865852070765298691443990322342503930133296644, 82193329954502979978022850807812153825386579027513935869259567236241902097528, 79582332307933489445850305095087629762468600427204881631607913496000554369644, 10620665678495759167849958490357545458918447594048747837565264846500606457485]
[+] Derived RNG params (mod n)
[*] N  = 21703682740758170494859513259231426103193725067303774139615776866781749569599
[*] c=2a = 40676566559562865848831966637192574977378584051440997390314446900077677942921
[*] a  = 78234327898439530636201475822940241415108074165257950886459805020797919718629
[+] Leaked ECDSA private key d = 16818168871990817308932402468070352448401633172425907150114933845515802381829
[*] d (hex) = 0x252ebf0a3b9e12045e7987d6572095612f801ac7638848e8f6b28db113c60e05
[+] Minted special ticket, submitting...
░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░▒▓████████▓▒░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░
       ░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░       ░▒▓██████▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░

                    FortID{W1nn3r_Winn3r_Ch1ck3n_D1nn3r_64277d4d7650896a}
[*] Closed connection to 0.cloud.chals.io port 19521
```

Therefore, the flag is: `FortID{W1nn3r_Winn3r_Ch1ck3n_D1nn3r_64277d4d7650896a}`.
