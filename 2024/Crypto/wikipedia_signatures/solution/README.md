# Wikipedia Signatures &mdash; Solution

This challenge deals with the common misconception on how secure digital signatures can be easily obtained from public key encryption. Although this is exactly what RSA authors claim in the [original paper](https://people.csail.mit.edu/rivest/Rsapaper.pdf), it is known that the *textbook RSA signatures* are not secure in the sense of what is today expected of digital signatures.

Specifically, in this task you need to create a digital signature for a fixed message, given the ability to ask for a signature of *any other* message (i.e., you need to perform [selective forgery using a chosen-message attack](https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Digital%20Signatures/A_Digital_Signature_Scheme_Secure_Against_Adaptive_Chosen-Message_Attack.pdf)).

```python
def rsa(m, n, x):
    if not 0 <= m < n:
        raise ValueError("Value too large")
    return int(pow(Integer(m), x, n))

def wikipedia_sign(message, n, d):
    return rsa(message, n, d)

def wikipedia_verify(message, signature, n, e):
    return rsa(signature, n, e) == bytes_to_long(message)

def main():
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(300)

    rsa_key = RSA.generate(1024)
    public_key = (rsa_key.n, rsa_key.e)

    myprint(f"RSA public key: {public_key}")
    myprint("Options:")
    myprint(f"1 <sig> -- Submit signature for {TARGET} and win")
    myprint("2 <msg> -- Sign any other message using wikipedia-RSA")

    for _ in range(10):
        line = input("> ")
        action, data = map(int, line.split())
        if action == 1:
            if wikipedia_verify(TARGET, data, rsa_key.n, rsa_key.e):
                myprint(f"{FLAG}")
                exit(0)
            else:
                myprint(f"Nope. Keep trying!")
        elif action == 2:
            if data % rsa_key.n == bytes_to_long(TARGET):
                myprint(f"Nope. Won't sign that!")
            else:
                sig = wikipedia_sign(data, rsa_key.n, rsa_key.d)
            myprint(sig)
        else:
            break
```

One of the simplest approaches is to use the multiplicative property of the RSA function -- $RSA(a, d, N)RSA(b, d, N) = RSA(ab, d, N)$, where multiplications are done modulo $N$. It follows directly that product of two signatures is the signature of the product of two messages. Model solution factors the target message, obtains signatures for the factors and multiplies them.

```python
#!/usr/bin/env python3

from pwn import *

from Crypto.Util.number import *

TARGET = b'I challenge you to sign this message!'

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 31148)
    else:
        p = process('./server.py')
    return p

target_int = bytes_to_long(TARGET)
a = 29
b = target_int//29
assert target_int == a*b

p = conn()
p.recvuntil(b'public key: ')
line = p.recvline()
n, e = eval(line)
print(f'{n=} {e=}')

p.recvuntil('RSA')

p.sendlineafter(b'> ', '2 {}'.format(a).encode())
siga = int(p.recvline())
p.sendlineafter(b'> ', '2 {}'.format(b).encode())
sigb = int(p.recvline())

print(f'{a=} {siga=}')
print(f'{b=} {sigb=}')

sig = (siga*sigb) % n
p.sendlineafter(b'> ', '1 {}'.format(sig).encode())
p.interactive()

```
