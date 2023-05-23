# Security Camera &mdash; Solution

We are given an hour-long
[video](https://drive.google.com/file/d/1-IJrGdyG2trFLLIrIKZfSTd7eo9IMwlV/view)
of an office workstation in which seemingly nothing interesting happens.

Looking at the video more carefully, you will notice that the brightness level
of the laptop screen seems to be changing from time to time. Could it be that some
secret data is getting exfiltrated through the screen brightness?

Turns out that is exactly what happens, and this challenge is all about careful
implementation. The high-level approach we will take is as follows:
  * Write a program that lets the user select a pixel on the video.
  * Keep track of the brightness of that pixel for each frame.
  * Hope that changes in the brightness level leak data.

Just by looking at the brightness level of some pixel, you'll see that it
alternates around two values &mdash; these represent binary zeroes and ones. To
figure out the throughput of leaked bits, we will try to approximate the
shortest amount of time one of those values is achieved. It turns out this
value is roughly $30$ frames, and since the video is shot at $30$ FPS, this
would indicate that one bit gets leaked every second.

Armed with this knowledge, we can easily devise the following strategy:
  * We will keep track of the brightness level of a particular bit across all
    frames.
  * At each frame, we will attempt to classify the brightness level into a $0$
    bit or a $1$ bit.
  * The length of each consecutive interval of same-valued bits should roughly be
    a multiple of the frame rate, and we should be able to deduce the actual number
    of same-valued bits being leaked.

This simple strategy is good enough to determine the leaked bits. Some details that
might help increase precision are:
  * Ignore obvious outliers in brightness values.
  * When unsure how to classify a bit (e.g. it is somewhere between values for zero and
    one), classify it as the last bit you were confident about.
  * Do the same thing for multiple bits, consider the majority value as correct
    classification.

Here is one ugly and barely-readable such implementation:

```python
import cv2
import numpy as np
import matplotlib.pyplot as plt

from Crypto.Util.number import long_to_bytes

zero_b = 0
one_b = 0

zs = []
os = []

def bit(b_level):
    global zero_b, one_b, zs, os
    if one_b == 0:
        if b_level >= zero_b + 3:
            one_b = b_level
            return 1
        else:
            return 0

    if (b_level - zero_b) / (one_b - zero_b) <= 0.35:
        zs.append(b_level)
        zero_b = min(zero_b, b_level)
        return 0

    if (b_level - zero_b) / (one_b - zero_b) >= 0.65:
        os.append(b_level)
        one_b = max(one_b, b_level)
        return 1

    return None

cap = cv2.VideoCapture('video.mp4')

clicked = False
def get_pixel(event, x, y, flags, param):
    global clicked, pixel_x, pixel_y
    if event == cv2.EVENT_LBUTTONDOWN:
        pixel_x, pixel_y = x, y
        clicked = True

cv2.namedWindow('frame')
cv2.setMouseCallback('frame', get_pixel)

while not clicked:
    ret, frame = cap.read()
    if not ret:
        break
    cv2.imshow('frame', frame)
    if cv2.waitKey(1) == ord('q'):
        break

frame_count = 0

start = False
data = ""
b_data = b""

bs = []
curr = 0
cnt = 0

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    frame_count += 1

    if len(data) >= 8:
        b_data += long_to_bytes(int(data[:8], 2))
        data = data[8:]
        print(b_data)

    if zero_b != 0 and one_b != 0:
        brightness = frame[pixel_y, pixel_x].mean()
        b = bit(brightness)
        if b == curr or b == None:
            cnt += 1
        else:
            for _ in range(round(cnt / 31.5)):
                data += str(curr)
            cnt = 1
        if b != None: curr = b
        continue


    brightness = frame[pixel_y, pixel_x].mean()
    bs.append(brightness)

    if frame_count % ((cap.get(cv2.CAP_PROP_FPS) + 1) // 1) == 0:
        bs.sort()
        brightness = bs[len(bs) // 2]
        bs = []
        if zero_b == 0: zero_b = brightness
        b = bit(brightness)


        if not start and b == 1:
            data = "0"
            start = True
        if start:
            data += str(b)

while len(data) >= 8:
    b_data += long_to_bytes(int(data[:8], 2))
    data = data[8:]
    print(b_data)

cap.release()
cv2.destroyAllWindows()
```

Tracking pixel $(1133, 499)$ leaks the following data:

```
b'Exfiltrating contents of current directory...\n\nDumping ./workspace/flag1.txt...\n\nTBTL{5an1t7y_ch3ck_pa55ed!_D0_y0u_h4v3_wh47_1t_74k35_f0r_p4r7_2?}\n\nDumping ./workspace/flag2.zip...\n\nPK\x03\x04\n\x00\t\x00\x00\x00\xbcb\xa3V9gW\xa7*\x00\x00\x00\x1e\x00\x00\x00\x08\x00\x1c\x00flag.txt\xd5T\t\x00\x03\xc35Rd\xaf5Rdux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00\xe0\xf7\x02\xf6\xbbX\xadI.2\x0b\xb2y;G\xa9\xf4+\xe2\xde\x87^\xb9\xbd\xabU\xfb\xa2i\xcf\x1d\xbccv\x88\x04\x14\xe7z\x8a!\x8dPK\x07\x089gW\xa7*\x00\x00\x00\x1e\x00\x00\x00PK\x01\x02\x1e\x03\n\x00\t\x00\x00\x00\xbcb\xa3V9gW\xa7*\x00\x00\x00\x1e\x00\x00\x00\x08\x00\x18\x00\x00\x00\x00\x00\x01\x00\x00\x00\xa4\x81\x00\x00\x00\x00flag.txtUP\x05\x00\x03\xc35Rdux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00N\x00\x00\x00|\x00\x00\x00\x00\x00'
```

The first flag is immediately visible:
`TBTL{5an1t7y_ch3ck_pa55ed!_D0_y0u_h4v3_wh47_1t_74k35_f0r_p4r7_2?}`, and lets
teams score points with less precise algorithms.

The second flag seems to be a `.zip` archive, but we need a password to extract
it. The password is written on a post-it note in the video &mdash; `TBTLPWD123`.

The extracted file `flag.txt` contains the second flag:
`TBTL{1_don7_m1nd_7h3_41r_g4p}`.

**Fun fact:** The challenge author got excited about turning this into a
legitimate method for data exfiltration from air-gapped machines, but it turns
out this [has already been done](https://arxiv.org/pdf/2002.01078.pdf).
