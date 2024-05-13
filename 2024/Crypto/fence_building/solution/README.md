# Fence Building &mdash; Solution

We are given what looks like a permutated flag
(`T0n40g5BG03cmk0D1hr}T{dFe_3g_3buL_5_n0`) along with the description linking
to the [Wikipedia article](https://en.wikipedia.org/wiki/Split-rail_fence)
about rail fences.

The description should give us enough clues that the fag was encrypted using
the [Rail Fence Cipher](https://en.wikipedia.org/wiki/Rail_fence_cipher).

The only thing left is to guess the "number of rails" used during encryption
process, but this number must be smaller than the length of the ciphertext
making it easy to bruteforce.

There are also numerous online tools (e.g.
[dcode.fr](`https://www.dcode.fr/rail-fence-cipher`)) that will help with the
decryption process, finally revealing:
`TBTL{G00d_F3nce5_m4k3_g00D_n31ghb0ur5}`.
