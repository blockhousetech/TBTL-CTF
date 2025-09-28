# Crypto &mdash; solution

In this challenge we are given two
[RSA](https://en.wikipedia.org/wiki/RSA_cryptosystem) public keys in
[PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) format along with
two ciphertexts called `flag1.enc` and `flag2.enc` assumingly encrypted using
these keys.

The challenge description says:

```text
These keys look completely different, yet they have something in common...
```

This strongly hints that the two public keys are somehow related. Let's see if
we can find that relationship and break the cipher.

Since this is a beginner challenge, we'll first check whether their respective
moduli share a common prime factor, which also fits nicely with the `something
in common...` wording from the description.

```python
from Crypto.Util.number import GCD
from Crypto.PublicKey import RSA

pub1_pem = open("key1.pub", "r").read()
pub2_pem = open("key2.pub", "r").read()

pub1 = RSA.import_key(pub1_pem)
pub2 = RSA.import_key(pub2_pem)
n1, e1 = pub1.n, pub1.e
n2, e2 = pub2.n, pub2.e

print(GCD(n1, n2))
```

Running this script outputs:

```
157482927699718602640088331842982511720749137882363104355375472655572779409848098023896649862219443901409568928994108295850960179567278859509076754066170017980047330953696384924944515124197398577024097727817199712212896201636870820434216603205942296902702695868546559464131230485440461937109949888755283710369
```

That's it! We've found the common prime factor, thereby essentially mannaged to
factor the RSA moduli allowing us to calculate the private exponents and
decrypt the flag.

The only other caveat was that the encryption was not done by textbook RSA, so
we needed to try out some common flavours. After some trial and error, we
manage to decrypt the ciphertext using
[OAEP](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
with [SHA256](https://en.wikipedia.org/wiki/SHA-2) as the hash function.

Putting it all together in a solve script:

```python
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import GCD, inverse
from Crypto.PublicKey import RSA

e = 0x10001

def construct_private_from_shared(n: int, e: int, shared_prime: int) -> RSA.RsaKey:
    p = shared_prime
    q = n // p
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return RSA.construct((n, e, d, p, q))

def decrypt(priv: RSA.RsaKey, ct: bytes) -> bytes:
    pt = PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(ct)
    return pt

pub1_pem = open("key1.pub", "r").read()
pub2_pem = open("key2.pub", "r").read()

c1 = bytes.fromhex(open("./flag1.enc", "r").read().strip())
c2 = bytes.fromhex(open("./flag2.enc", "r").read().strip())

pub1 = RSA.import_key(pub1_pem)
pub2 = RSA.import_key(pub2_pem)
n1, e1 = pub1.n, pub1.e
n2, e2 = pub2.n, pub2.e

g = GCD(n1, n2)

priv1 = construct_private_from_shared(n1, e1, g)
priv2 = construct_private_from_shared(n2, e2, g)

pt1 = decrypt(priv1, c1)
pt2 = decrypt(priv2, c2)

print(pt1 + pt2)
```

Running it reveals the flag:
`FortID{4nd_1_Sa1d_Wh47_Ab07_4_C0mm0n_Pr1m3_F4ct0r?}`.
