#!/usr/bin/env python3

import argparse, secrets, random, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PHRASE = b"They're not birds! They're keys! Winged keys."
NONCE = b"*chirpchirp*"
FLAG = b"FortID{Y0u_F0unD_4_S3cre7_K3Y_H1dd3n_In_Un1c0d3_Var147i0n_S3l3ct0r5}"

def byte_to_vs(b:int)->str:
    return chr(0xFE00+b) if b < 0x10 else chr(0xE0100+(b-16))

HIDDEN_CLUSTER = "\U0001F426" + "".join(byte_to_vs(b) for b in PHRASE)
HIDDEN_BYTES   = HIDDEN_CLUSTER.encode()

KEY = hashlib.sha256(PHRASE).digest()[:16]
CIPHERTEXT  = AESGCM(KEY).encrypt(NONCE, FLAG, None)

def rust_array(data: bytes, per: int = 12) -> str:
    rows = [", ".join(f"0x{x:02X}" for x in data[i:i+per])
            for i in range(0, len(data), per)]
    return ",\n    ".join(rows)

def build_haystack(path: str, size: int, bird_prob: float = 0.001):
    print(f"Hidden Cluster: {HIDDEN_CLUSTER}")

    if size < len(HIDDEN_BYTES):
        raise ValueError("haystack too small")
    insert = secrets.randbelow(size - len(HIDDEN_BYTES) + 1)
    bird = "🐦".encode()

    buf = bytearray()
    i = 0
    while i < insert:
        if random.random() < bird_prob and i + len(bird) <= insert:
            buf.extend(bird); i += len(bird)
        else:
            buf.append(secrets.randbelow(256)); i += 1

    buf.extend(HIDDEN_BYTES); i += len(HIDDEN_BYTES)

    while i < size:
        if random.random() < bird_prob and i + len(bird) <= size:
            buf.extend(bird); i += len(bird)
        else:
            buf.append(secrets.randbelow(256)); i += 1

    with open(path, "wb") as f:
        f.write(buf)
    print(f"[+] wrote {path} ({len(buf)} B), secret at offset {insert}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out",  required=True)
    ap.add_argument("--size", type=int, default=100_000)
    args = ap.parse_args()

    build_haystack(args.out, args.size)
    print("\nPaste this into src/main.rs (CIPHERTEXT):\n")
    print(rust_array(CIPHERTEXT))
