# Your papers, please &mdash; Solution

In this challenge, the remote server is expecting to receive a [JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token), specifically one conforming to a [ISO-18013-5 mobile driver's license](https://en.wikipedia.org/wiki/Mobile_driver%27s_license) standard. If the JWT is a valid, cryptographically authenticated, unexpired mobile driver's license, we are given the flag. We are also given an example JWT, however with an expiry date in the past.

At the first glance, the verification is solid --- a public key is embedded in the binary, and the signature in the JWT is verified against the public key. The problem is that the signature verification algorithm used depends on the JWT header.
```python
PUBLIC_KEY = u'''-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBGOtycGkAMpTEDsjFykEywLecIdCX
1QIShxmJB0qJj9K2yFNwJj/eRR6yzIZcHJPZWzQU6Mad62y1MsJ8uOgdZ2sBmkS0
HJtT4FZq/EQbtkHeahsDnSLbFpPfoN/t8hmKrVmDzDRGe3PNl7OQVuzoY2TVSxVK
IKmpZ9Pw9/5HOzSmOxs=-----END PUBLIC KEY-----
'''

def decode(token):
    signing_input, crypto_segment = token.rsplit(".", 1)
    header_segment, payload_segment = signing_input.split(".", 1)
    header_data = base64.urlsafe_b64decode(header_segment)
    header = json.loads(header_data)
    alg = header["alg"]
    return jwt.decode(token, algorithms=[alg], key=PUBLIC_KEY)


def main():
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(300)

    myprint("Your papers, please.")
    token = input()
    try:
        mdl = decode(token)
        assert mdl["docType"] == "iso.org.18013.5.1.mDL"
        family_name = mdl["family_name"]
        given_name = mdl["given_name"]
        expiry_date = datetime.datetime.strptime(mdl["expiry_date"], "%Y-%m-%dT%H:%M:%S.%f")
    except Exception as e:
        myprint("Your papers are not in order!")
        exit(0)
    myprint("Hello {} {}!".format(given_name, family_name))
    delta = expiry_date - datetime.datetime.now()
    if delta <= datetime.timedelta(0):
        myprint("Your papers expired {} ago!".format(humanize.naturaldelta(delta)))
        exit(0)

    flag = open("flag.txt", "r").read().strip()
    myprint("Your papers are in order, here is your flag: {}".format(flag))
    exit(0)
```

Let's look at the token up close. JWT consists of three parts, header, payload and the signature. Decoding the example JWT we are given, yields the following header and payload.
```json
{
  "alg": "ES512",
  "typ": "JWT"
}
{

  "version": "1.0",
  "docType": "iso.org.18013.5.1.mDL",
  "family_name": "TURNER",
  "given_name": "SUSAN",
  "birth_date": "1998-08-28",
  "issue_date": "2018-01-15T10:00:00.00",
  "expiry_date": "2022-08-27T12:00:00.00",
  "issuing_country": "US",
  "issuing_authority": "CO",
  "document_number": "542426814",
  "driving_privileges": [
    {
      "codes": [
        {
          "code": "D"
        }
      ],
      "vehicle_category_code": "D",
      "issue_date": "2019-01-01",
      "expiry_date": "2027-01-01"
    }
  ],
  "un_distinguishing_sign": "USA"
}
```

In turns out that [JWT standard](https://www.rfc-editor.org/rfc/rfc7518.txt), besides digital signatures, allows using [MACs](https://en.wikipedia.org/wiki/Message_authentication_code) to authenticate tokens.

MACs are symmetric primitives --- the same key is used for generating the tag and for verifying it. Hence, we solve this challenge by launching a [key confusion attack](https://nvd.nist.gov/vuln/detail/CVE-2016-5431) --- we construct the required payload, specify in the header that a MAC is used for verifying authenticity, and MAC the token using the bytes of the public key as a symmetric MAC key.

```python
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
```

Presenting the MACed JWT to the service, wins us the flag.
```bash
$ python3 solve.py | nc 0.cloud.chals.io 16356
Your papers, please.
Hello SUSAN TURNER!
Your papers are in order, here is your flag: TBTL{1n_H34d3rS_W3_Tru$7}
```

Note that pyjwt library authors actively try to [prevent this attack](https://github.com/jpadilla/pyjwt/blob/ab8176abe21e550dbc1c9a6bb7e78ad80853bfb1/jwt/algorithms.py#L258) by checking if a MAC algorithm is used with something that looks like an asymmetric public key. However, this challenge bypasses their [regex-based public key detection logic](https://github.com/jpadilla/pyjwt/blob/ab8176abe21e550dbc1c9a6bb7e78ad80853bfb1/jwt/utils.py#L119) by removing a newline character from the penultimate line of the public key string.
