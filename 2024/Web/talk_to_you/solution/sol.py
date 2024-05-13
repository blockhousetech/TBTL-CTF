import requests

r = requests.get('http://127.0.0.1:5000/?page=database.sqlite')
print(r.text)
