# Kung-Fu Cipher &mdash; Solution

## Challenge Setup

We are given a connection string to a remote server along with its source code.

The server greets us with the following message:

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣦⣤⣖⣶⣒⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⣾⣿⣿⣿⣿⣿⣶⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⢜⡛⠈⠛⢙⣃⠙⢿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡏⢟⠀⠀⠹⠀⠀⠘⠃⣸⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⡈⠷⠀⠀⠀⠁⠀⠹⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣿⣏⢹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠟⠛⠛⠛⢦⣍⣃⣀⡴⠂⠀⣽⠙⠲⢤⣀⠀⠀⠀⠀⠀⠀⠀This is a sparing program...  ⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⡘⣿⣾⣇⠀⠀⠀⠀⠀⠀⠀⢠⡾⠁⠀⠀⠀⠀⡀⠙⢇⠁⠀⠀⠀⡿⠀⠀⠀⠈⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⡅⠻⠯⣿⠀⠀⠀⠀⠀⠀⣠⠏⣀⠀⠀⠀⠀⠀⠳⡄⠈⠳⡄⠀⣰⠃⢰⠆⠀⠀⢸⡇⠀⠀⠀It has the same basic rules as any⠀⠀
⠀⠀⠀⠀⠀⠉⠳⣆⠈⢻⣄⠀⠀⢀⡞⠁⠀⠘⢦⠀⠀⠀⠀⠀⠙⣆⠀⠙⢦⠏⢀⡞⠀⠀⠀⢸⠁⠀⠀⠀⠀⠀ other cryptographic program. ⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢨⡷⣾⠈⠳⣤⠟⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠈⠃⢀⡞⠀⣸⠃⠀⠀⠀⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠸⣟⠁⠀⠀⠈⠳⣄⡀⠀⠀⢀⡼⠆⠀⠀⠀⠀⠀⢀⡜⠀⣰⠇⠀⠀⠀⢀⡟⠀⠀⠀⠀⠀What you must learn is that some⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠈⠉⢀⡴⠋⣆⠀⠀⠀⠀⠀⢀⡞⠀⣠⠏⠀⠀⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⠀of these rules can be bent,⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⣠⠖⠉⠀⠀⢹⡀⠀⠀⠀⢀⡞⠀⣠⠏⠀⠀⠀⠀⠀⣼⣓⣶⣶⣦⠀⠀⠀⠀⠀ others can be broken.⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⢷⠀⠀⣠⠋⠀⡰⠏⠀⠀⠀⠀⠀⠀⣿⢹⡶⣾⡿⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⣾⣥⣄⡈⠁⠀⠀⠀⠀⠀⠀⠀⡏⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠛⠛⢿⣿⣿⣿⣿⣶⣶⣤⣤⣤⣼⠁⠀⠀⠀⠀⠀OPTIONS:                 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠃⠀⠀⠀⠀⠈⠉⠉⠛⢻⣿⣿⣿⠛⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠁⣰⡆⠀⠀⠀⠀⠀⠀⠀⣾⣿⠀⢿⣧⠀⠙⢦⡀⠀⠀⠀⠀⠀⠀1) Encrypt the FLAG  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣡⠞⠁⢣⠀⠀⠀⠀⠀⠀⠀⣿⣿⡇⠸⣿⣇⠀⠈⢣⡀⠀⠀⠀⠀⠀2) Encrypt arbitrary plaintext⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠟⠁⠀⠀⢸⡄⠀⠀⠀⠀⠀⠀⣿⣿⡇⠀⢿⣿⡀⠀⣀⣷⠀⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡏⠀⠀⠀⠀⠈⣇⠀⠀⠀⠀⠀⠀⣿⣿⣆⡀⠼⣿⣿⠉⠉⠈⢦⠀⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡞⠀⠀⠀⠀⠀⠀⠛⢻⠟⠛⠛⠛⠋⠉⠙⠛⢦⠀⣿⣿⡆⠀⠀⠈⢷⠀⠀⠀⠀   What are you waiting for?⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⠀⠀⠀⠀⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⡀⠈⠀⠀⠀⠀⠈⢳⡀⠀⠀You're a better hacker than this
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠁⠀⠀⠀⠀⠀⠀⣰⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠀⠀⠀⠀⠈⢳⡄⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⠀⠀⠀⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⠀⠀⢀⡾⠁⠀   Don't think you are,⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠃⠀⠀⠀⠀⠀⠀⣴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡏⠀⠀⠀⠀⠀⣼⠃⠀⠀      KNOW YOU ARE!  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠃⠀⠀⠀⠀⠀⠀⡼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡁⠀⠀⠀⠀⣸⣻⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠃⠀⠀⠀⠀⠀⠀⡼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠘⠉⡏⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣰⠃⠀⠀⠀⠀⠀⠀⡼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡇⠀⠀⠀⠀⠀⢈⡇⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣰⠃⠀⠀⠀⠀⠀⠀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡼⠃⠀⠀⠀⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣽⠦⣤⡀⠀⠀⢀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠋⠛⡶⠤⣤⣀⣸⡿⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣀⣀⡴⠖⠉⠀⠀⠀⠉⠑⡶⠎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡟⠀⠀⢧⡀⠀⠀⠁⠀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢻⣯⣥⡀⠀⣤⠤⠤⠤⠴⠞⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⢉⣳⣤⣄⡀⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠙⠓⠚⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠓⠒⠚⠛⠋⠁⠀⠀⠀                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

Let's start by inspecting the `main` function in `server.py`:

```python3
def main():
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(300)

    myprint(BANNER)

    cipher = KungFuCipher()

    myprint(f"n = {hex(cipher.n)}\n")

    assert len(FLAG) % 4 == 0

    k = len(FLAG) // 4
    pt = [bytes_to_long(FLAG[i * k : (i + 1) * k]) for i in range(4)]

    flag_ct = cipher.encrypt(pt)

    for _ in range(10):
        action = input("> ")
        if action == "1":
            for i in range(2):
                for j in range(2):
                    myprint(f"ct[{i}][{j}] = {hex(flag_ct[i][j])}")
        elif action == "2":
            user_pt = []
            for i in range(2):
                for j in range(2):
                    try:
                        x = int(input(f"pt[{i}][{j}] = "), 16)
                    except Exception as _:
                        myprint("kthxbai")
                        exit(0)
                    user_pt.append(x)

            user_ct = cipher.encrypt(user_pt)
            for i in range(2):
                for j in range(2):
                    myprint(f"ct[{i}][{j}] = {hex(user_ct[i][j])}")
            pass
        else:
            break

    myprint("kthxbai")
```

Apparently we can query the server 10 times. In each query we can either get
the encrypted flag, or we can encrypt an arbitrary plaintext of choice.

Basically, it looks like we need to mount some kind of [chosen-plaintext
attack](https://en.wikipedia.org/wiki/Chosen-plaintext_attack) and decrypt the
flag.

Let's see what information we have on the encryption scheme used in the
challenge. To do so, let's inspect the `KungFuCipher` class:

```python3
class KungFuCipher:
    BITS = 512

    def __init__(self):
        rng = random.SystemRandom()
        self.p = KungFuCipher.get_prime(rng)
        self.q = KungFuCipher.get_prime(rng)
        self.n = self.p * self.q
        self.e = getPrime(100)

    def get_prime(rng):
        DIGITS = 80
        while True:
            ret = 0
            for _ in range(DIGITS):
                ret *= 10
                ret += rng.choice([5, 7, 9])
            if isPrime(ret):
                return ret

    def encrypt(self, pt):
        def mul(A, B, mod):
            return (A * B).apply_map(lambda x: x % mod)

        M = matrix(ZZ, 2, 2, pt).apply_map(lambda x: x % self.n)
        C = identity_matrix(ZZ, M.nrows())

        e = self.e
        while e > 0:
            if e & 1:
                C = mul(C, M, self.n)
            M = mul(M, M, self.n)
            e //= 2

        return C
```

This is obviously some custom-made encryption scheme heavily influenced by the
RSA cryptosystem. However, there are a few oddities in this implementation:

1. The algorithm for generating prime numbers is non-standard.
2. The encryption is done over $2\times2$ matrices defined over $Zn$, where
   $n$ is the RSA modulus.
3. We are given the modulus $n$, but don't have access to the public RSA exponent $e$.

Let's address these one at a time...

## Factoring the RSA Modulus

The (insecure) way of generating the prime numbers $p$ and $q$ lets us know
that these primes consist only of digits $5$, $7$, and $9$, significantly
reducing the overall search space.

We can retrieve the factors using a
[DFS](https://en.wikipedia.org/wiki/Depth-first_search)-like algorithm that
searches for $p$ and $q$ one digit at a time, while pruning the search tree
whenever possible.

The relevant section of our solve script looks like this:

```python3
def factorize_n():
    l = pwn.log.progress("Factorizing RSA modulus")

    r.recvuntil(b"n = ")
    n = int(r.recvline().decode("utf-8").strip(), 16)

    def fact(p, q, mod):
        if p * q > n:
            return None
        if p * q == n:
            return p, q

        for pp, qq in itertools.product([5, 7, 9], repeat=2):
            if ((pp * (mod // 10) + p) * (qq * (mod // 10) + q)) % mod == n % mod:
                nxtp = pp * (mod // 10) + p
                nxtq = qq * (mod // 10) + q
                ret = fact(nxtp, nxtq, mod * 10)
                if ret:
                    return ret

        return None

    p, q = fact(0, 0, 10)
    assert p * q == n

    l.success()

    return (n, p, q)
```

The algorithm is fast because the number of transitions from each state is
reduced since we only need to consider a limited number of possible digits.
It is also correct because $n = pq$ still holds modulo any positive integer (in
this case, we consider powers of 10).

## Finding out the Public Exponent

Since the encryption is basically matrix exponentiation with $e$ as an
exponent, we can leak the value $e$ by thinking about matrix exponentiation in
the context of linear recurrences.

For example, consider the simple recurrence:

$$
\begin{equation}
  f(k)=\begin{cases}
    f(k - 1) + 1, & \text{if $k>0$}.\\
    0, & \text{otherwise}.
  \end{cases}
\end{equation}
$$

Using matrix multiplication, we can write the transition as follows:

```math
\begin{bmatrix}
f(k) & 1 \\
0 & 0
\end{bmatrix}

\times

\begin{bmatrix}
1 & 0 \\
1 & 1
\end{bmatrix}

=

\begin{bmatrix}
f(k+1) & 1 \\
0 & 0
\end{bmatrix}
```

Since matrix multiplication is associative, from here we have:

```math
\begin{bmatrix}
f(k) & 1 \\
0 & 0
\end{bmatrix}

\times

\begin{bmatrix}
1 & 0 \\
1 & 1
\end{bmatrix}^e

=

\begin{bmatrix}
f(k+e) & 1 \\
0 & 0
\end{bmatrix}
```

Meaning we can leak the value $e$ by sending the `[[1, 0], [1, 1]]` matrix to
the encryption oracle. The relevant section of the solve script looks like this:

```python3
def leak_e():
    l = pwn.log.progress("Leaking public exponent (e)")

    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"pt[0][0] = ", b"1")
    r.sendlineafter(b"pt[0][1] = ", b"0")
    r.sendlineafter(b"pt[1][0] = ", b"1")
    r.sendlineafter(b"pt[1][1] = ", b"1")

    r.recvuntil(b"ct[1][0] = ")
    e = int(r.recvline().decode("utf-8"), 16)

    l.success()

    return e
```

## Decrypting the Flag

Now we know the public exponent and have factored the RSA modulus, which
normally completely breaks the security of RSA.

However, attempting to decrypt the flag "normally", i.e. by calculating the
private exponent $d$ by as the multiplicative inverse of $e$ modulo
$\phi = (p - 1)(q - 1)$ won't work.

Instead, we need to consider the orders of the two relevant general linear
groups of degree $2$, $GL_2(\mathbb{Z}_p)$ and $GL_2(\mathbb{Z}_q)$,
thus replacing the "standard" $\phi$ value with
$(p^2 - p)(p^2 - 1)(q^2 - q)(q^2 - 1)$.

You can read through the omitted bits of mathematics
[here](https://www.gcsu.edu/sites/files/page-assets/node-808/attachments/pangia.pdf).

Finally, putting everything in a solve script gives us:

```python3
from Crypto.Util.number import *
from sage.all import *

import itertools
import pwn

r = pwn.process("./server.py")


def factorize_n():
    l = pwn.log.progress("Factorizing RSA modulus")

    r.recvuntil(b"n = ")
    n = int(r.recvline().decode("utf-8").strip(), 16)

    def fact(p, q, mod):
        if p * q > n:
            return None
        if p * q == n:
            return p, q

        for pp, qq in itertools.product([5, 7, 9], repeat=2):
            if ((pp * (mod // 10) + p) * (qq * (mod // 10) + q)) % mod == n % mod:
                nxtp = pp * (mod // 10) + p
                nxtq = qq * (mod // 10) + q
                ret = fact(nxtp, nxtq, mod * 10)
                if ret:
                    return ret

        return None

    p, q = fact(0, 0, 10)
    assert p * q == n

    l.success()

    return (n, p, q)


def leak_e():
    l = pwn.log.progress("Leaking public exponent (e)")

    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"pt[0][0] = ", b"1")
    r.sendlineafter(b"pt[0][1] = ", b"0")
    r.sendlineafter(b"pt[1][0] = ", b"1")
    r.sendlineafter(b"pt[1][1] = ", b"1")

    r.recvuntil(b"ct[1][0] = ")
    e = int(r.recvline().decode("utf-8"), 16)

    l.success()

    return e


def decrypt_flag(n, d):
    l = pwn.log.progress("Decrypting flag")

    def mul(A, B):
        return (A * B).apply_map(lambda x: x % n)

    r.sendlineafter(b"> ", b"1")
    ct = []
    for _ in range(4):
        r.recvuntil(b" = ")
        ct.append(int(r.recvline().decode("utf-8"), 16))

    C = matrix(ZZ, 2, 2, ct).apply_map(lambda x: x % n)
    M = identity_matrix(ZZ, C.nrows())

    while d > 0:
        if d & 1:
            M = mul(M, C)
        C = mul(C, C)
        d //= 2

    flag = (
        long_to_bytes(M[0][0])
        + long_to_bytes(M[0][1])
        + long_to_bytes(M[1][0])
        + long_to_bytes(M[1][1])
    )

    l.success(flag.decode("utf-8"))


n, p, q = factorize_n()
e = leak_e()

phi = (p**2 - 1) * (p**2 - p) * (q**2 - 1) * (q**2 - q)
d = inverse(e, phi)

decrypt_flag(n, d)
```

Revealing the flag: `TBTL{1_Kn0W_H0w_2_Br34k_7h3_KUn6_F00_C1ph3R}`.
