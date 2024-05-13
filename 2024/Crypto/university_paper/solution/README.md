# University Paper &mdash; Solution

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
On the Estemeed Scientifc Role Model of Mine
============================================

Within the confines of this academic setting, the individual whom
I hold in highest regard not only boasts an engaging smile but also
possesses a remarkable sense of humor, complemented by an array of
vibrant notebooks.

Yet, it is their distinct quantifiable attribute that stands out
most prominently: their name, when converted into an integer value
and squared modulo %d,
astonishingly results in %d.

Furthermore, the greatest integer that does not surpass the cube root
of the aforementioned squared name equals %d.
This computational detail adds another layer of distinction.

It is likely that by this point, many of you have discerned the identity
of this distinguished role model.
"""


def invpow3(x):
    lo, hi = 1, x
    while lo < hi:
        mid = (lo + hi) // 2 + 1
        if (mid**3) <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


N = 13113180816763040887576781992067364636289723584543479342139964290889855987378109190372819034517913477911738026253141916115785049387269347257060732629562571

name_int = bytes_to_long(FLAG)

assert 1 < name_int < N

value_1 = (name_int**2) % N
value_2 = invpow3(name_int**2)

assert (value_2**3) <= (name_int**2)
assert ((value_2 + 2) ** 3) > (name_int**2)

print(ESSAY_TEMPLATE % (N, value_1, value_2))
```

Same as in the challenge *School Essay*, we know the value $x = flag^2 \mod n$,
and we also know the modulus $n$. However, this time the modulus is not a prime
number (in fact is an RSA modulus), and is too large to be factored, meaning we
can't simply calculate the *modular square root* of $x$.

Additionally, we know the value $y = \lfloor {flag^{\frac{2}{3}}} \rfloor$.

This allows us to significantly bound the value of $flag$ to an inerval $[l,
r]$ such that $r - l < \frac{3}{2}n^{\frac{1}{3}}$. Setting $flag = l + k$, factored
$k < \frac{3}{2}n^{\frac{1}{3}}$ gives us $(l + k)^2 = l^2 + 2lk + k^2 \equiv x \mod n$.

The bounds are now small enough that we can use
[Coppersmith](https://en.wikipedia.org/wiki/Coppersmith_method) after
additionally splitting the interval into constant number of subintervals.

P.S. This challenge is ~taken~ inspired by [this
problem](https://qoj.ac/contest/1440/problem/7874) from Universal Cup, as its
setup is more typical for CTFs than competitive programming.
