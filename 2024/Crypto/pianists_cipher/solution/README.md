# Pianist's Cipher &mdash; Solution

We are given an `.mp3` file containing a simple melody played on a piano, and a
`.pdf` sheet music file assumingly corresponding to the played melody.

This is an example of a [steganographic
message](https://en.wikipedia.org/wiki/Steganography), i.e. the flag is
concealed *in plain sight* within a piece of music to avoid detection.

As usual, these types of challenges require the solver to ~read the author's
mind~ think creatively and out-of-the box in order to figure out the method in
which the original message was hidden.

The title, description, audio file and sheet music are meant to hint heavily at
the significance of a Piano. In other words, let's consider the musical
instrument for which the piece of music was intended.

One key (pun intended) feature of a piano is that it contains black and white
keys. On a high-level, the steganographic idea used in this challenge was to
consider the way the piece would have been played on a piano, and interpret
white keys as binary zeroes, and black keys as binary ones.

Once you come up with that high-level idea, it should be relatively simple to
confirm the hypothesis. First notice the [key
signature](https://upload.wikimedia.org/score/a/t/atosv1fnl4e4l45x90blard1l5oedua/atosv1fn.png)
with two sharps, `F#` and `C#`. Somewhat simplified, this means that each time
we see notes `F` or `C` on the staff, we should interpret them as `F#` and `C#`
respectively. These are also the only two notes that would be played on black
keys on a piano as there are no [accidentals](https://en.wikipedia.org/wiki/Accidental_(music)).

Now consider the first bar, the music instructs us to play $7$ eight-notes
&mdash; `F#, A, F#, D, C#, D, E`, which would translate to binary `1010100`,
which corresponds to ASCII value of the letter `T`.

Repeating this method for each bar of the music should reveal the flag.

A slight caveat appears in bars where we see notes of higher duration, but it
should be easy to see at that point that we are meant to take that duration
into account (e.g., a quarter note on a black key represents two consecutive
binary ones).

This is somewhat hinted by the time signature of the piece (`7/8`), which
should be interpreted as *There are 7 beats in a bar, and each beat corresponds
to an eight-note*. Get it, another pun, `beat = bit`.

Anyways, here is the whole thing [solved by hand](solved_sheet.pdf),
revealing the flag: `TBTL{51n6_u5_4_50n6}`.
