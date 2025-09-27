# Cascader &mdash; solution

You are given a [paper](./../materials/public/cascader.pdf) describing a novel
recurrence-based [key exchange](https://en.wikipedia.org/wiki/Key_exchange)
protocol.

You are also given the following JavaScript implementation, along with
`output.txt` assumingly containing the data outputted by the script after its
invocation:

```js
"use strict";

const { createHash, createCipheriv, randomBytes } = require('node:crypto');

const KEY_SIZE_BITS = 256n;
const MAX_INT = 1n << KEY_SIZE_BITS;
const MOD = MAX_INT - 189n; // Prime number
const SEED = MAX_INT / 5n;

function linearRecurrence(seed, exponents) {
    let result = seed;
    let exp = 1n;
    while (exponents > 0n) {
        if (exponents % 2n === 1n) {
            let mult = 1n;
            for (let i = 0; i < exp; i++) {
                result = 3n * result * mult % MOD;
                mult <<= 1n;
            }
        }
        exponents >>= 1n;
        exp++;
    }
    return result;
}
// Generate a random 256 - bit BigInt
function random256BitBigInt() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    let hex = '0x';
    for (const byte of array) {
        hex += byte.toString(16).padStart(2, '0 ');
    }
    return BigInt(hex);
}
const alicePrivate = random256BitBigInt();
const bobPrivate = random256BitBigInt();
const alicePublic = linearRecurrence(SEED, alicePrivate);
const bobPublic = linearRecurrence(SEED, bobPrivate);
const aliceShared = linearRecurrence(bobPublic,
    alicePrivate);
const bobShared = linearRecurrence(alicePublic, bobPrivate);
console.log("Alice private ", alicePrivate.toString());
console.log("Bob private ", bobPrivate.toString());
console.log("Alice public ", alicePublic.toString());
console.log("Bob public ", bobPublic.toString());
console.log("Alice Shared ", aliceShared.toString());
console.log("Bob Shared ", bobShared.toString());
console.log("Alice's and Bob's shared secrets equal? ",
    aliceShared === bobShared);

function bigIntToFixedBE(n, lenBytes) {
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const buf = Buffer.from(hex, "hex");
  if (buf.length > lenBytes) {
    return buf.slice(-lenBytes);
  } else if (buf.length < lenBytes) {
    const pad = Buffer.alloc(lenBytes - buf.length, 0);
    return Buffer.concat([pad, buf]);
  }
  return buf;
}

function sha256(buf) {
  return createHash("sha256").update(buf).digest();
}

function encryptAESGCM(key, plaintext) {
   const iv = randomBytes(12);
   const cipher = createCipheriv('aes-256-gcm', key, iv);
   const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
   const tag = cipher.getAuthTag();
   return { iv, ciphertext, tag };
}

const sharedBytes = bigIntToFixedBE(aliceShared, 32);
const aesKey = sha256(sharedBytes);

const FLAG = "FortID{<REDACTED>}"

const { iv, ciphertext, tag } = encryptAESGCM(aesKey, FLAG);
console.log("ct (hex):   ", Buffer.concat([iv, ciphertext, tag]).toString("hex"));
```

Looks trivial, the script outputs private keys and a shared secret, so it
should be very easy to reconstruct the AES key that encrypts the flag.

Not so fast:

```
Alice private  <REDACTED>
Bob private  <REDACTED>
Alice public  81967497404473670873986762408662347640688858544889917659709378751872081150739
Bob public  25638634989672271296647305730621408042240305773269414164982933528002524403752
Alice Shared  <REDACTED>
Bob Shared  <REDACTED>
Alice's and Bob's shared secrets equal?  true
ct (hex):    e2f84b71e84c8d696923702ddb1e35993e9108289e2d14ae8f05441ad48d1a67ead74f5f230d39dbfaae5709448c2690237ac6ab88fc26c8f362284d1e8063491d63f7c15cc3b024c62b5069605b73dd2c54fdcb2823c0c235b20e52dc5630c5f3
```

We only get access to public key material and the flag ciphertext. This means
we need to completely break the security of the cascader.

Let's see how Cascader works.

First, notice that the `linearRecurrence(seed, a)` essentially computes $seed
\cdot f(a)$ modulo $MOD$. Therefore, it turns out that Alice's public key is
equal to $pk_A = seed \cdot f(sk_A)$. We can easily express $f(sk_A) = pk_A
\cdot seed^{-1}$. Since $MOD$ is a prime number, the multiplicative inverse of
$seed$ can be [easily
calculated](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Using_Euler's_theorem).
Similarly, we can calculate $f(sk_B)$ from Bob's public key.

The shared secret is calculated as $seed \cdot f(sk_A) \cdot f(sk_B)$. Since
all these values are known, we can easily calculate it.

Once we have the shared secret, it's game over, we just need to replicate the
way the flag encryption key is generated and decrypt the flag.

Putting it all together in a solve script:

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES

from hashlib import sha256

ALICE_PUBLIC = int("81967497404473670873986762408662347640688858544889917659709378751872081150739")
BOB_PUBLIC   = int("25638634989672271296647305730621408042240305773269414164982933528002524403752")
CT_HEX = (
    "e2f84b71e84c8d696923702ddb1e35993e9108289e2d14ae8f05441ad48d1a67"
    "ead74f5f230d39dbfaae5709448c2690237ac6ab88fc26c8f362284d1e806349"
    "1d63f7c15cc3b024c62b5069605b73dd2c54fdcb2823c0c235b20e52dc5630c5f3"
)

MAX_INT = 1 << 256
MOD = MAX_INT - 189
SEED = MAX_INT // 5

def to_fixed_be(n: int, length: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
    if len(b) > length:
        return b[-length:]
    if len(b) < length:
        return b'\x00' * (length - len(b)) + b
    return b

def derive_shared_from_publics(alice_pub: int, bob_pub: int) -> int:
    inv_seed = inverse(SEED, MOD)
    return (alice_pub * bob_pub * inv_seed) % MOD

def decrypt_gcm(key: bytes, blob: bytes) -> bytes:
    iv = blob[:12]
    tag = blob[-16:]
    ct = blob[12:-16]

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt

def main():
    shared = derive_shared_from_publics(ALICE_PUBLIC, BOB_PUBLIC)

    shared_bytes = to_fixed_be(shared, 32)
    aes_key = sha256(shared_bytes).digest()

    blob = bytes.fromhex(CT_HEX)
    plaintext = decrypt_gcm(aes_key, blob)

    print(plaintext.decode('utf-8'))

if __name__ == "__main__":
    main()
```

Running it reveals the flag: `FortID{St0p_B31n6_4_H1ps73r_4nd_5t1ck_70_Th3_G00d_0ld_D1ff1e_H3l1man}`.
