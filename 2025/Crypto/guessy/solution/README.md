# Guessy &mdash; solution

## Intended

We are given instructions to connect to a remote server, along with the source
code of that server. Let's connect and see what happens.

```
$ nc 0.cloud.chals.io 32957

--- Test #0 ---
n = 5062378636682908710393286248762368013482697814279503004819782534609218163830665176043049589221506135202863440960229901227669268518510915275057615260734637
You can ask 7 questions:
2
You must give me an even number of numbers!
```

Ok, looks like we need to make sense of out from the source code. Let's inspect
it as well.

This is the main function:

```python
def main():
    signal.signal(signal.SIGALRM, timeout_handler)

    for i in range(10):
        test(i)

    flag = open('flag.txt', "r").read()
    print(f"Here you go: {flag}")

if __name__ == '__main__':
    main()
```

Looks like we get the flag when we solve 10 test cases. Let's see what they're
about:

```python
def test(t):
    print(f"--- Test #{t} ---")
    a = A()
    b = B()
    print(f"n = {b.n}")
    print("You can ask 7 questions:")

    qs = []
    for _ in range(7):
        l = list(map(int, input().strip().split()))
        if len(l) % 2 != 0:
            err("You must give me an even number of numbers!")
        if len(l) != len(set(l)):
            err("All numbers must be distinct!")
        qs.append(l)

    secret = getRandomRange(0, 2048)
    ans(secret, qs, a, b)

    print("Can you guess my secret?")
    user = int(input())

    if user != secret:
        err("Seems like you can't")
    else:
        print("Correct!")
```

So, in each test case we get some sort of a constant $n$, need to ask 7
questions where each question consists of an even number of numbers. After some
more computation, we get an opportunity to guess a random secret the server
generetes and we pass the test if we succeed.

Let's gather more details:

```python
N_BITS = 512

class A:
    def __init__(self, bits = N_BITS):
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 0x10001
        self.d = pow(self.e, -1, self.phi)


    def encrypt(self, m):
        return pow(m, self.e, self.n)


    def decrypt(self, c):
        return pow(c, self.d, self.n)


class B:
    def __init__(self, bits = N_BITS):
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
        self.lam = (self.p - 1) * (self.q - 1) // math.gcd(self.p - 1, self.q - 1)
        x = pow(self.g, self.lam, self.n_sq)
        L = (x - 1) // self.n
        self.mu = inverse(L, self.n)


    def encrypt(self, m):
        r = getRandomRange(1, self.n)
        while math.gcd(r, self.n) != 1:
            r = getRandomRange(1, self.n)
        c1 = pow(self.g, m, self.n_sq)
        c2 = pow(r, self.n, self.n_sq)
        return (c1 * c2) % self.n_sq


    def decrypt(self, c):
        x = pow(c, self.lam, self.n_sq)
        L = (x - 1) // self.n
        return (L * self.mu) % self.n


def err(msg):
    print(msg)
    exit(1)


def compute(e_secret, xs, a, b):
    ret = 1
    for x in xs:
        ret *= a.encrypt(b.decrypt(e_secret * x))
        ret %= a.n
    return ret


def ans(secret, qs, a, b):
    e_secret = b.encrypt(secret + 0xD3ADC0DE)
    for i in range(7):
        li = qs[i][:len(qs[i]) // 2]
        ri = qs[i][len(qs[i]) // 2:]

        print(f"{compute(e_secret, li, a, b)} {compute(e_secret, ri, a, b)}")

```

After inspecting the code, we can conclude the following:
  * Class `A` implements the [RSA cryptosystem](https://en.wikipedia.org/wiki/RSA_cryptosystem)
  * Class `B` implements the [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem)

The _question_ we send is a list of an even number of integers $X = (x_1,
\ldots, x_{2\ell})$ which the server splits into two halves $L=(x_1,\dots,x_\ell)$
and $R=(x_{\ell+1},\dots,x_{2\ell})$.

For any half $H \in {L, R}$ the server computes and prints

```math
Z_H
= \prod_{x \in H} Enc_R( Dec_P( Enc_P(s + C) \cdot x ) )
= \left( \prod_{x \in H} Dec_P( Enc_P(s + C) \cdot x ) \right)^e \bmod n_R
```

where $C$ is a constant (`0xD3ADC0DE`), and $s$ denotes the server generated
secret.

Both RSA and Paillier cryptosystem have some
[homomorphic](https://en.wikipedia.org/wiki/Homomorphic_encryption) properties.
More precisely:
  - **RSA** is **multiplicatively homomorphic**, i.e. $Enc_R(m_1) \cdot
    Enc_R(m_2) \equiv Enc_R(m_1 \cdot m_2) \pmod{n_R}$
  - **Paillier** is **additively homomorphic**, i.e. $Enc_P(m_1) \cdot Enc_P(m_2) \equiv Enc_P(m_1 + m_2) \pmod{n_P^2}$


We can use those properties to force the computed value of a half equal to zero
if it contains the secret.

For every index $j \in {0, \ldots, 2047}$ we'll pick $x_j$ as the Paillier
ciphertext $x_j = Enc_P( -(j + C) )$

Then for that $j$:

```math
Dec_P( e_s \cdot x_j ) \equiv (s + C) + (-(j + C)) \equiv s - j \pmod{n_P}
```

Therefore for the half $J_H$ containing an index corresponding to the secret:

```math
Z_H = \left( \prod_{j \in J_H} (s - j) \right)^e \bmod n_R
```

```math
Z_H = 0 \quad\Longleftrightarrow\quad \exists\, j \in J_H : s = j
```

This builds an oracle that reduces the challenge to a relatively popular
[balance puzzle](https://en.wikipedia.org/wiki/Balance_puzzle). In other words,
we can think about the *questions* as *weighings* on a scale. We have a set of
$2048$ coins, and one of them is heavier than the others (secret). From each
weighing we can deduce whether that coin is on the left side ($Z_L = 0$) of the
scale, right side ($Z_R = 0$) of the scale, or neither.

Since we can uniquely deduce the coin in $\lceil \log(c) \rceil$ weighings,
where $c$ is the number of coins, it turns out that this is possible to do in
$7$ questions we have at our disposal.

Putting it all in a solve script:

```python
#!/usr/bin/python3

import copy
import math

from Crypto.Util.number import *
from pwn import *

from tqdm import tqdm

class B:
    def __init__(self, n):
        self.n = n
        self.n_sq = self.n * self.n
        self.g = self.n + 1


    def encrypt(self, m):
        r = getRandomRange(1, self.n)
        while math.gcd(r, self.n) != 1:
            r = getRandomRange(1, self.n)
        c1 = pow(self.g, m, self.n_sq)
        c2 = pow(r, self.n, self.n_sq)
        return (c1 * c2) % self.n_sq


def ask(io, q, enc):
    assert len(set(q)) == len(q)
    assert len(q) % 2 == 0

    msg = " ".join([str(enc[qi]) for qi in q])
    io.sendline(msg.encode("utf-8"))

def get_ans(io):
    ret = ""
    for _ in tqdm(list(range(7))):
        L, R = map(int, io.recvline().decode("utf-8").strip().split())

        if L == 0:
            ret += 'L'
        elif R == 0:
            ret += 'R'
        else:
            ret += 'N'
    return ret


def solve_test(t, io):
    p = log.progress(f"Solving test #{t + 1}")

    io.recvuntil(b"n = ")
    n = int(io.recvline().decode("utf-8").strip())

    log.info("Parsed Paillier PK")

    io.recvuntil(b":")
    io.recvline()

    cipher = B(n)

    log.info("Encrypting payloads...")
    enc = [cipher.encrypt(-(i + 0xD3ADC0DE)) for i in tqdm(list(range(2048)))]

    def generate_vq(n = 2048):
        vq = []
        used = set()
        curr = 1
        for i in range(0, n, 2):
            while curr in used:
                curr += 1
            vq.append(curr)
            used.add(curr)

            inv_curr, pow3, x = 0, 1, curr
            while x > 0:
                inv_curr += pow3 * ((3 - (x % 3)) % 3)
                pow3 *= 3
                x //= 3

            assert inv_curr not in used

            vq.append(inv_curr)
            used.add(inv_curr)

        vq.append(0)
        return vq

    vq = generate_vq()
    vq_cpy = copy.copy(vq)

    def generate_qs(n = 2048):
        qs = []
        for i in range(7):
            l, r = [], []
            for j in range(n):
                if vq[j] % 3 == 1:
                    l.append(j)
                if vq[j] % 3 == 2:
                    r.append(j)
                vq[j] //= 3

            assert len(l) == len(r)
            assert len(l) > 0

            qs.append([x for x in l + r])

        return qs

    qs = generate_qs()

    for i, q in enumerate(qs):
        p.status(f"Asking question {i + 1}")
        ask(io, q, enc)

    p.status("Receiving answers...")
    ans = get_ans(io)
    p.status(f"Got answers: {ans}")

    val = 0
    for c in ans[::-1]:
        val *= 3
        if c == 'L':
            val += 1
        if c == 'R':
            val += 2

    ret = vq_cpy.index(val)

    io.recvuntil(b"Can you guess my secret?")
    io.recvline()
    io.sendline(str(ret).encode("utf-8"))

    resp = io.recvline().decode("utf-8").strip()

    p.success(f"got {resp}")


def main():
    # io = process("./server.py")
    io = remote("0.cloud.chals.io", 32957)

    for t in range(10):
        solve_test(t, io)

    io.recvuntil(b"Here you go: ")

    flag = io.recvline().decode("utf-8").strip()
    print(f"FLAG: {flag}")


if __name__ == '__main__':
    main()
```

Running this against the remote gets us:

```text
[+] Solving test #1: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:03<00:00, 538.02it/s]
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:16<00:00,  2.37s/it]
[+] Solving test #2: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:03<00:00, 546.15it/s]
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:16<00:00,  2.31s/it]
[+] Solving test #3: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:03<00:00, 532.59it/s]
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:16<00:00,  2.41s/it]
[+] Solving test #4: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:03<00:00, 518.34it/s]
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:16<00:00,  2.43s/it]
[+] Solving test #5: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:03<00:00, 526.39it/s]
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:16<00:00,  2.35s/it]
[+] Solving test #6: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:03<00:00, 524.08it/s]
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:17<00:00,  2.44s/it]
[+] Solving test #7: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:04<00:00, 446.89it/s]
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:19<00:00,  2.79s/it]
[+] Solving test #8: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:04<00:00, 492.50it/s]
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:17<00:00,  2.48s/it]
[+] Solving test #9: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:03<00:00, 526.72it/s
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:18<00:00,  2.68s/it]
[+] Solving test #10: got Correct!
[*] Parsed Paillier PK
[*] Encrypting payloads...
100%|███████████████████████████████████████████████████████████████████████████| 2048/2048 [00:03<00:00, 521.29it/s]
100%|██████████████████████████████████████████████████████████████████████████████████| 7/7 [00:16<00:00,  2.42s/it]
FLAG: FortID{Y0u_R_4_Phr3ak1n6_M1nd_R3ad3r!_orz_orz}
```

and reveals the flag: `FortID{Y0u_R_4_Phr3ak1n6_M1nd_R3ad3r!_orz_orz}`

## Unintended

This challenge was not meant to be easy, and the number of solves during the
contest surprised us. Turns out we've missed an easier approach, nicely
described by `@jiegec` in [this
writeup](https://jia.je/ctf-writeups/2025-09-12-fortid-ctf-2025/guessy.html)
