# Days of Yore &mdash; solution

We are given a single file called `ciphertext.txt` along with the following challenge description:

```text
Long before cryptography became a playground of prime numbers and elliptic curves, it was more like a craft project 🎨. People would shuffle letters, invent quirky alphabets, or scribble secret notes that only their friends could read. It was messy, creative, and surprisingly fun.

This challenge is a little trip back to that era. What you’re staring at once began as a few plain paragraphs of English text 📖. Nothing fancy, just words on a page. But now those words carry a secret, tucked away like a treasure waiting to be found 🏴.

Unfortunately, the encryption/decryption key is forever lost, hope that's not too much of an inconvenience...

Can you put yourself in the shoes of an old-school codebreaker and bring the hidden message back to life?
```

From the looks of it, the challenge revolves around some kind of custom
encryption inspired by [classical
ciphers](https://en.wikipedia.org/wiki/Classical_cipher). We also know that the
original text was written in English.

Let's take a look at `ciphertext.txt` and see if we can come up with something:

```text
939, 970, 986
63, 253, 310, 391, 432, 490, 542, 576, 643, 753, 805, 1082, 1118, 1168, 1244, 1261, 1351, 1539, 1563, 1595, 1639, 1783, 1794
14, 61, 67, 73, 116, 128, 168, 173, 212, 244, 293, 295, 345, 352, 357, 362, 447, 461, 569, 582, 641, 668, 672, 710, 741, 821, 886, 887, 972, 1008, 1032, 1116, 1123, 1222, 1239, 1253, 1364, 1389, 1420, 1422, 1456, 1461, 1500, 1685, 1743, 1753, 1771, 1803, 1820
679
68, 136, 484, 610, 705, 829, 860, 923, 1087, 1169, 1355, 1663, 1715
478, 836, 910, 935
1866
457, 458, 834, 835, 1175, 1176, 1482, 1483, 1878
267
946
108, 175, 265, 358, 456, 514, 594, 677, 783, 833, 897, 1047, 1174, 1291, 1393, 1481, 1570, 1691, 1877
5, 32, 78, 119, 180, 188, 194, 205, 215, 320, 330, 335, 343, 354, 375, 396, 415, 426, 475, 503, 507, 519, 557, 580, 608, 624, 650, 656, 690, 713, 718, 786, 801, 808, 851, 856, 874, 884, 900, 904, 961, 1079, 1101, 1120, 1145, 1178, 1189, 1195, 1213, 1218, 1266, 1316, 1319, 1334, 1396, 1426, 1438, 1454, 1512, 1546, 1551, 1554, 1573, 1601, 1612, 1636, 1673, 1694, 1737, 1779
...
```

We can see it consists of $54$ lines, where each line contains a list of
integers. We can also note that no integer appears twice in `ciphertext.txt`,
and (when sorted) the file contains all integers from $1$ to $1879$.

```python
lines = open("./ciphertext.txt", "r").readlines()

l = []
for line in lines:
    l += map(int, line.split(", "))

print(sorted(l))
assert(sorted(l) == list(range(1, 1879)))
```

The next assumption we are going to make is that integers written in the same
line of `ciphertext.txt` are somehow related. We'll also notice that different
lines have vastly different lengths.

Also, knowing the inspiration came from classical ciphers, and the fact that we
are given the information that the text is in English, it's not far fetched to
assume that some sort of [frequency
analysis](https://en.wikipedia.org/wiki/Frequency_analysis) will be part of the
solution.

Once we have that in mind, a natural idea appears &mdash; what if we're dealing
with an *in-between* step of a [substition
cipher](https://en.wikipedia.org/wiki/Substitution_cipher), i.e. each line
represents one character, and the list of integers corresponds to where that
character appears in the plaintext. If we compare the sizes of lists in each
line with a character frequency histogram for English text (including
interpunction, spaces, etc.), we get further evidence that this is a good
approach.

From this point, the challenge becomes a classic *break a substitution cipher
assuming an English plaintext* with an additional caveat that we also need to
take into account special characters (e.g. spaces, commas, etc.) and letter
casings. Using standard techniques it's not that hard to **almost** decrypt the
ciphertext. In other words, using frequency analysis, abusing common patterns
in English (e.g. `the` as a common trigram), online tools, and common sense, we
can quickly get this far:

```
In the early days of cryptography messages were not protected by advanced mathematics or powerful computers. Instead they relied on clever rearrangements of letters and words. Ciphers such as the Caesar shift and the Vigenere square once seemed impossible to crack. Entire campaigns in war and diplomacy were built on the trust that these methods would hold. Today we know they are fragile but they still inspire the way we think about secrecy and puzzles.

Modern Capture the Flag events borrow from that history. A challenge may present a block of text that looks ordinary but hides a secret. Competitors have to notice what is unusual and bring the right tools to decode it. Sometimes the answer is revealed through frequency analysis and sometimes by looking for a repeating key. The process teaches both patience and creativity.

For example within this very passage there is a hidden marker. The phrase FortI??Y?u?H?v????T?l?n??F?r??r?ak?n??Cl?ss?c?l?C?ph?rs???????d?You?Wer?n?t???rn??n?Anc??n????m?? does not look like an ordinary sentence. Yet in a puzzle setting it might be woven into a cipher or concealed behind some transposition that makes it far less obvious.

What makes these challenges fun is that they do not require a deep background in number theory or computer science. A player can often reach the solution with logic careful observation and a willingness to test ideas. That mix of simplicity and depth explains why classical methods endure in competitions.

It is easy to underestimate how satisfying it feels to break through the final barrier. The text may appear to be nothing more than a few plain paragraphs but a closer look can reveal something extraordinary. The excitement of uncovering a flag from within ordinary words continues a tradition that began long before modern computers and it will likely continue as long as people enjoy puzzles.
```

Basically, we've almost decrypted it, but the actual flag is still not
readable. However, we know the following:
  * which characters are not in the flag (otherwise we'd decrypt them)
  * the flag format
  * the fact it's likely a phrase in [1337](https://en.wikipedia.org/wiki/Leet) using `_` as a word delimiter.
  * once we uncover a new character, we know all of its appearances in the plaintext.

Taking all of that into account, we can slowly but surely reach the final flag. We'll just use some examples of reasoning here
  * `FortI??Y?u` &mdash; from the flag format we know it's `FortID{Y?u`. The
  remaining question mark likely is a letter `o`, however it's certainly not
  lowercase `o`, but can be `O` or `0`.
  * `C?ph?rs` &mdash; likely spells `Ciphers`, but lowercase letters are surely
  not correct because we already have them in the text. The uppercase `I` is
  also in the text which only leaves `1`, and we've uncovered a new character.

Similar reasoning gets us to the point where we know almost the entire flag,
with a handful of options to guess. Finally we get accepted with
`FortID{Y0u_H4v3_4_T4l3n7_F0r_Br3ak1nG_Cl4ss1c4l_C1ph3rs_700_B4d_You_Wer3n't_B0rn_1n_Anc13n7_R0m3}`.
