# Security Camera Revisited &mdash; Solution

We are given a ~40 minute
[video](https://drive.google.com/file/d/1xc8POr3KggG-t7cnrkjdvkLPcx9kAYW-/view)
of an office workstation in which seemingly nothing interesting happens.

The challenge was inspired by a [similar
challenge](https://github.com/blockhousetech/TBTL-CTF/tree/master/2023/Misc/security_camera)
from last year, but this one should have been a bit simpler.

Probably the hardest part of the solution was figuring out that something
indeed happens on the video. The magic happens around `16:08`, when the
[MasterKeys Pro M White LED
Keyboard](https://www.coolermaster.com/catalog/peripheral/keyboards/masterkeys-pro-m-white/)
connected to the laptop starts flashing.

The light show lasts for a few seconds, and nothing remarkable happens on the
video afterwards.

Extracting the frames from the interesting part of the video reveals that the
keys flashing keys correspond to flag characters, with the exception of `_`
which is rendered with the whole keyboard lighting up.

Carefully reading the characters from the frames reveals the flag:
`TBTL{BL1NK_4ND_Y0U_WI1L_M15S_17}`.
