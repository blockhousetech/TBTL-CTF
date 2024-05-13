#!/usr/bin/env python3

from electrum import mnemonic
from electrum import keystore
from electrum import util

PATTERN = 'west peanut {} cousin napkin unfair camera wire {} convince act oppose'

wordlist = mnemonic.Wordlist.from_file(mnemonic.filenames['en'])
ct = open('flag.enc', 'rt').read()

for a in wordlist:
    if a[-1] != 'y':
        continue
    for b in wordlist:
        if len(b) > 4:
            continue
        phrase = PATTERN.format(a, b)
        try:
            ks = keystore.from_seed(phrase, None, False)
            print(ks.decrypt_message((0, 0), ct, None))
        except (util.BitcoinException, util.InvalidPassword):
            pass
