# Rev &mdash; solution

We are given a 64-bit Linux command line executable, let's run it, give it some
input and see what happens.

```text
$ ./chall
Enter flag: FortID{123}
Nope
```

The binary is a flag checker, meaning it will let us know when we supply the
correct flag. Let's open the binary using a disassembler such as [IDA
Free](https://hex-rays.com/ida-free) and try to examine its logic.

Using IDA's built-in decompiler, we get the following `main` function:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  int v6; // [rsp+8h] [rbp-288h]
  int i; // [rsp+Ch] [rbp-284h]
  int v8; // [rsp+10h] [rbp-280h]
  int v9; // [rsp+14h] [rbp-27Ch]
  int j; // [rsp+18h] [rbp-278h]
  int v11; // [rsp+1Ch] [rbp-274h]
  char s[600]; // [rsp+20h] [rbp-270h] BYREF
  unsigned __int64 v13; // [rsp+278h] [rbp-18h]

  v13 = __readfsqword(0x28u);
  printf("Enter flag: ");
  __isoc99_scanf("%s", s);
  if ( strlen(s) > 0x46 )
    goto LABEL_14;
  v6 = 0;
  for ( i = 0; i < strlen(s); ++i )
  {
    v8 = 0;
    v9 = 255;
    while ( 1 )
    {
      v11 = (v8 + v9) / 2;
      if ( v11 == s[i] )
        break;
      v4 = v6++;
      if ( v11 >= s[i] )
      {
        s[v4 + 80] = 60;
        v9 = v11 - 1;
      }
      else
      {
        s[v4 + 80] = 62;
        v8 = v11 + 1;
      }
    }
    v3 = v6++;
    s[v3 + 80] = 61;
  }
  if ( v6 == 448 )
  {
    for ( j = 0; (unsigned __int64)j <= 0x1BF; ++j )
    {
      if ( s[j + 80] != target[j] )
        goto LABEL_14;
    }
    puts("Correct!");
    return 0;
  }
  else
  {
LABEL_14:
    puts("Nope");
    return 0;
  }
}
```

It's not hard to figure out what the program is doing. Firstly, we notice it
iterates through each character of user input. For each iteration, it does some
sort of computation which appends some characters to the `s` buffer. In the
end, it compares those characters to a `target` buffer which is baked in the
binary.

Let's see what `target` actually contains.

```text
.rodata:0000000000002020 target          db '<><<<>>=<>>=<>>><<>=<>>><><=<><<><=<><<<><=<>>>>=<<>><=<>><<<=<<>'
.rodata:0000000000002020                                         ; DATA XREF: main+1E2↑o
.rodata:0000000000002061                 db '>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><><>>=<<>><=<>><=<>><=<<>'
.rodata:00000000000020A2                 db '><<=<>><<>=<<>><>=<>=<<>><><=<>><>>>=<>><<><=<>=<><<>><=<<>><=<>>'
.rodata:00000000000020E3                 db '><<>=<>><>>>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><<<>>=<>>><>=<'
.rodata:0000000000002124                 db '>><>>>=<>><<><=<<>><><=<>><>>=<<>><=<>><>>>=<<>>=<<>><><=<<>><<=<'
.rodata:0000000000002165                 db '>=<><><=<<>><=<>><<<=<>>><<>=<>><<=<>><><<=<>=<><<<<=<>><>><=<>><'
.rodata:00000000000021A6                 db '=<<>><<<=<>>><<>=<<>><<=<<>>=<>><><<=<>><>>=<<>><>=<>>>>>=',0
```

Let's now figure out what exactly happens during each iteration, i.e. let's demystify the following piece of code:

```c
    v8 = 0;
    v9 = 255;
    while ( 1 )
    {
      v11 = (v8 + v9) / 2;
      if ( v11 == s[i] )
        break;
      v4 = v6++;
      if ( v11 >= s[i] )
      {
        s[v4 + 80] = 60;
        v9 = v11 - 1;
      }
      else
      {
        s[v4 + 80] = 62;
        v8 = v11 + 1;
      }
    }
    v3 = v6++;
    s[v3 + 80] = 61;
```

First, notice that $60$, $61$, and $62$ constants are ascii values for
characters `<`, `=`, and `>` respectively, which are also the only characters
appearing in the `target` buffer.

The code also resembles a [binary
search](https://en.wikipedia.org/wiki/Binary_search) implementation over a
range from $0$ to $255$.

Basically, it compares the current `mid` value to the fixed character inputted
by the user at this iteration, and stores whether it was `<`, `>` or `=` in the
resulting buffer. This means that the `target` buffer contains all information
we need to figure out which characters are expected.

Here is a simple implementation:

```c
#include <stdio.h>
#include <string.h>

const char target[] =
    "<><<<>>=<>>=<>>><<>=<>>><><=<><<><=<><<<><=<>>>>=<<>><=<>><<<=<<>>=<>=<><>"
    "><=<<>><<<=<>>><>=<>>><<>=<>=<><><>>=<<>><=<>><=<>><=<<>><<=<>><<>=<<>><>="
    "<>=<<>><><=<>><>>>=<>><<><=<>=<><<>><=<<>><=<>>><<>=<>><>>>=<>=<><>><=<<>>"
    "<<<=<>>><>=<>>><<>=<>=<><<<>>=<>>><>=<>><>>>=<>><<><=<<>><><=<>><>>=<<>><="
    "<>><>>>=<<>>=<<>><><=<<>><<=<>=<><><=<<>><=<>><<<=<>>><<>=<>><<=<>><><<=<>"
    "=<><<<<=<>><>><=<>><=<<>><<<=<>>><<>=<<>><<=<<>>=<>><><<=<>><>>=<<>><>=<>>"
    ">>>=";

int main(void) {
  int lo = 0, hi = 255;
  int target_len = strlen(target);

  for (int i = 0; i < target_len; ++i) {
    int mid = (lo + hi) / 2;
    if (target[i] == '=') {
      printf("%c", mid);
      lo = 0, hi = 255;
    }
    if (target[i] == '<') {
      hi = mid - 1;
    }
    if (target[i] == '>') {
      lo = mid + 1;
    }
  }

  printf("\n");
  return 0;
}
```

Running this reveals the flag:
`FortID{3a7_Y0ur_V3gg1e5_4nd_L3rn_Y0ur_Fund4m3n741_S3arch_Alg0r17hm5}`, which is also confirmed by the `chall` binary.

```
$ ./chall
Enter flag: FortID{3a7_Y0ur_V3gg1e5_4nd_L3rn_Y0ur_Fund4m3n741_S3arch_Alg0r17hm5}
Correct!
```
