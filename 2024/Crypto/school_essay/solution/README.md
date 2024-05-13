# School Essay &mdash; Solution

We are given a text file called `description.txt` with the following contents:

```
My Favorite Classmate
=====================

My favorite person in this class has a beautiful smile,
great sense of humour, and lots of colorful notebooks.

However, their most distinctive feature is the fact that
you can represent their name as an integer value, square
it modulo 1839221045943946468749590061514704444096822140639024607242755810381377444892113085421174752142441,
and you'll get 1804671962891598586831251656431345607187951389706305029952427287330950271224234433906630527235349.

By now, all of you have probably guessed who I'm talking about.
```

We are also given a file called `chall.py` which was obviously used to generate the `description.txt`:

```python3
from Crypto.Util.number import *
from redacted import FLAG

ESSAY_TEMPLATE = """
My Favorite Classmate
=====================

My favorite person in this class has a beautiful smile,
great sense of humour, and lots of colorful notebooks.

However, their most distinctive feature is the fact that
you can represent their name as an integer value, square
it modulo %d,
and you'll get %d.

By now, all of you have probably guessed who I'm talking about.
"""

N = 1839221045943946468749590061514704444096822140639024607242755810381377444892113085421174752142441

name_int = bytes_to_long(FLAG)

assert 1 < name_int < N

value_1 = (name_int**2) % N

print(ESSAY_TEMPLATE % (N, value_1))
```

Basically, we know the value $x = flag^2 \mod n$, and we also know the modulus
$n$. This means we need to calculate the [modular square
root](https://www.rieselprime.de/ziki/Modular_square_root) of $y$ to get the
flag.

Luckily, the modulus $n$ is prime, meaning we could simply apply the
[Tonelli-Shanks
Algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm) and
get the flag: `TBTL{J0hn_J4c0b_J1n6leH31mer_Schm1d7_<3}`.
