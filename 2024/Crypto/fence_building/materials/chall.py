from Crypto.Util.number import *
from redacted import FLAG

ESSAY_TEMPLATE = """
My Favorite Classmate
=====================

My favorite person in this class has a beautiful smile,
great sense of humour, and lots of colorful notebooks.

However, their most distinctive feature is the fact that
you can represent their name as an integer value, square
it modulo %d,
and you'll get %d.

By now, all of you have probably guessed who I'm talking about.
"""

N = 1839221045943946468749590061514704444096822140639024607242755810381377444892113085421174752142441

name_int = bytes_to_long(FLAG)

assert 1 < name_int < N

value_1 = (name_int**2) % N

print(ESSAY_TEMPLATE % (N, value_1))
