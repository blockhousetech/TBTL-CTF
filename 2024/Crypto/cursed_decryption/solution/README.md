# Cursed Decryption &mdash; Solution

## Challenge Setup

We are given a connection string to a remote server along with its source code.

Let's start by inspecting the `main` function in `server.py`:

```python3
def main():
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(1800)

    myprint(BANNER)

    cipher = Cipher()

    myprint(f"N = {cipher.n}")
    myprint(f"e = {cipher.e}")
    myprint(f"enc(flag) = {cipher.encrypt(bytes_to_long(FLAG))}\n")

    while True:
        user_ct = int(input("Enter ciphertext: "), 2)
        pt = cipher.decrypt_lol(user_ct)
        myprint(f"Decrypted: {pt}")

```

The server outputs some public parameters of the used cryptosystem, encrypts
the `FLAG` and allows us to query the service multiple times with a ciphertext
of choice.

For each query, the server "decrypts" the provided ciphertext using the
*cursed* `decrypt_lol` function.

This setup resembles the context suitable for mounting some kind of
[chosen-ciphertext
attack](https://en.wikipedia.org/wiki/Chosen-ciphertext_attack) on the
implemented crypto system.

## Cipher of Choice

Let's explore the internals of the custom Cipher implemented by the server:

```python3
class Cipher:
    BITS = 256

    def __init__(self):
        self.p = getPrime(Cipher.BITS)
        self.q = getPrime(Cipher.BITS)
        self.n = self.p * self.q
        self.e = 0x10001

        phi = (self.p - 1) * (self.q - 1)
        self.d = inverse(self.e, phi)

    def encrypt(self, pt):
        ct = pow(pt, self.e, self.n)
        return bin(ct)[2:]

    def decrypt_lol(self, ct):
        pt = pow(ct, self.d, self.n)

        pt_len = len(bin(pt)[2:])
        dec = list(map(int, bin(pt)[2:]))
        otp_key = list(map(int, bin(random.getrandbits(pt_len))[2:]))

        for i in range(len(otp_key)):
            dec[i] ^= otp_key[i]

        return "".join(list(map(str, dec)))
```

The implemented cipher strongly resembles the standard, textbook
[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)). More precisely:
  * The key generation algorithm looks fine, and we are given the public key
    $(N, e)$.
  * The encryption function looks fine.
  * The decryption function looks non-standard to say the least.

Our ticket to success must be hidden in `decrypt_lol`, let's inspect what it does:
  * First, the provided ciphertext is properly decrypted
  * Then the obtained plantext is again encrypted using the [one-time
    pad](https://en.wikipedia.org/wiki/One-time_pad)

Since one-time pad offers perfect secrecy, it would have been impossible to
deduce anything except the length of the plaintext if it was implemented
correctly.

Scrutinizing the implementation even further reveals the key mistake &mdash;
when the most significant bit of `random.getrandbits(pt_len)` is zero, the
`otp_key` ends up shorter than the length of the plaintext.

This breaks the security properties of the one-time pad and allows the attacker
to probabilistically deduce the least significant bit of the plaintext for a
given ciphertext. In other words, roughly 75% of the time, the least
significant bit of the "OTP-encrypted" plaintext will match the actual least
significant bit of the plaintext.

## LSB Oracle Attack

The observations from the previous chapter allow us to build a so-called LSB
Oracle:

```python3
def oracle(x):
    cnt = [0, 0]
    for _ in range(N_TRIES):
        r.recvuntil(b"Enter ciphertext: ")
        r.sendline(bin(x)[2:].encode("utf-8"))

        r.recvuntil(b"Decrypted: ")
        pt = r.recvline().decode("utf-8").strip()

        cnt[int(pt[-1])] += 1

    if cnt[0] > cnt[1]:
        return 0

    return 1
```

In other words, we can query the service a bunch of time for the same
ciphertext, count the frequencies of least significant bits outputted by the
service, take the most frequent bit as the true LSB of the plaintext.

Now we know whether the decryption of a chosen ciphertext is even or odd, but
how does that help?

The key idea is as follows:
  * Let's multiply the encrypted flag by $2^e$. Since RSA is homomorphic with
  respect to multiplication, we have effectively constructed the ciphertext of
  $2 \cdot flag$.
  * Passing that through the LSB Oracle reveals the following:
    * If the LSB is $0$, then $2 \cdot flag < n$,
    * otherwise, $2 \cdot flag > n$. (because $n$ must be odd)

In other words, by observing the LSB of $2 \cdot flag$, we now know if $flag
\le \frac{n}{2}$, thereby halving the possible interval of values where $flag$
lies.

Repeating this process $\mathcal{O}(\log(n))$ times narrows the flag to a
single possible value, effectively decrypting the ciphertext.

Putting it all together in a solve script yields:

```python3
from pwn import *
from Crypto.Util.number import *
from tqdm import tqdm

N_TRIES = 45

r = process("./server.py")

r.recvuntil(b"N = ")
N = int(r.recvline().decode("utf-8"))

e = r.recvuntil(b"e = ")
e = int(r.recvline().decode("utf-8"))

r.recvuntil(b"enc(flag) = ")
ct = int(r.recvline().decode("utf-8"), 2)


def oracle(x):
    cnt = [0, 0]
    for _ in range(N_TRIES):
        r.recvuntil(b"Enter ciphertext: ")
        r.sendline(bin(x)[2:].encode("utf-8"))

        r.recvuntil(b"Decrypted: ")
        pt = r.recvline().decode("utf-8").strip()

        cnt[int(pt[-1])] += 1

    if cnt[0] > cnt[1]:
        return 0

    return 1


lo, hi = 0, N
e = 0x10001

for i in tqdm(range(1, 513)):
    x = (ct * pow(2**i, e, N)) % N
    mid = (lo + hi) // 2
    if oracle(x) == 0:
        hi = mid
    else:
        lo = mid

print(long_to_bytes(lo))
print(long_to_bytes(hi))
```

Revealing the flag: `TBTL{1mpl_3rr0r_l3d_m3_t0_7h3_R54_LS8_0r4Cl3}`.
