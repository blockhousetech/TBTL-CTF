
# No Admin No Problem -- Solution

## Check source code

In provided source code, we can see that all tokens are signed with the same public key, and all JWT tokens have the **admin** parameter set to *False*.

An interesting part is related to **admin** check. We will get the flag if we provide a token where the **admin** parameter is set to *True* and token verification is successful. We can also see that test will pass if we provide the original token.

## JWT Tokens

JSON Web Tokens are an open, industry-standard RFC 7519 method for representing claims securely between two parties. (https://jwt.io/)

JWT tokens support different algorithms for signing. When we do `decode` in source code, we do not provide an algorithm, which is a security issue.

## Replace private/public key algorithm with a symmetric key algorithm

The idea is to inject the wrong algorithm in the token, and verification will use the wrong algorithm. Instead of using a private/public key (private key for a sign, the public key for verification), we try to use a symmetric key where the symmetric key is the public key. We can do this if we set the `HS256` algorithm.

## Create a new malicious token

We can copy/paste provided token from the site into some JWT tools (e.g., https://jwt.io/).
We can change **admin** parameter to `True` and sign the token with a public key that we can also find in the original token (first, we need to decode from `base64`).

If we upload a malicious token that is signed with a known public key, and the algorithm is set to `HS256`, we will get the flag: **TBTL{4DM1N_I5_PUBL1C_F1GUR3}**.
