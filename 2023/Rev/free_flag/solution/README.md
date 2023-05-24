# Free Flag &mdash; Solution

We're given a 64-bit Linux command line executable, let's run it, give it some
input and see what happens. 

```$ ./free_flag
Enjoy your free flag: TBTL{
```

The first few letters of the flag are slowly printed, and this is where the
program seems to hang. It looks like the flag is computed very inefficiently,
let's open the binary using a disassambler such as [IDA
Free](https://hex-rays.com/ida-free/) and try to retrieve/examine the source
code or the assembly. We quickly identify the `main` function, and decompiling
using the IDA's cloud decompiler feature we gain access to the logic behind
the few user-defined functions.

First, the main function:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v3; // al
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 38; ++i )
  {
    v3 = f(N[i], X[i], M[i]);
    putchar((char)(v3 - D[i]));
    fflush(_bss_start);
  }
  putchar(10);
  return 0;
```

Looks like the flag has 39 characters, each of which is being computed by some
function `f` that takes three arguments `N[i], X[i], M[i]` sourced from globally
defined arrays.

Let's decompile the function `f`:

```c
__int64 __fastcall f(__int64 a1, unsigned int a2, unsigned int a3)
{
  unsigned int v5; // [rsp+10h] [rbp-10h]
  unsigned int v6; // [rsp+14h] [rbp-Ch]
  __int64 i; // [rsp+18h] [rbp-8h]

  v5 = 0;
  v6 = 1;
  for ( i = 0LL; i < a1; ++i )
  {
    v5 = add(v5, v6, a3);
    v6 = mul(v6, a2, a3);
  }
  return v5;
}
```

Also a very simple function, but we must first decompile `add` and `mul` to get
the whole picture:

```c
__int64 __fastcall add(int a1, int a2, int a3)
{
  if ( a3 <= a1 + a2 )
    return (unsigned int)(a1 + a2 - a3);
  if ( a1 + a2 >= 0 )
    return (unsigned int)(a1 + a2);
  return (unsigned int)(a2 + a1 + a3);
}

__int64 __fastcall mul(int a1, int a2, int a3)
{
  return a1 * (__int64)a2 % a3;
}
```

Obviously, `add(a1, a2, a3)` computes `a1 + a2` modulo `a3`, while `mul(a1, a2,
a3)` computes `a1 * a2` modulo `a3`.

This means that the function `f(n, x, m)` simply computes the value of the
polynomial $1 + x + x^2 + \ldots + x^n$ modulo $m$. Since this function is
implemented with time complexity of $O(n)$, and the order of
magnitude of values in array `N` is roughly $10^{18}$, it is safe to conclude
that we don't have enough time to simply let the program run.

We need a more efficient way of calculating $f(x)$ modulo $m$.

At this point you might be tempted to use the formula for the sum of first $n$
elements of the [geometric
series](https://en.wikipedia.org/wiki/Geometric_series).  Unfortunately, this
won't work because you need to divide with $1 - x$, and the moduli are not
prime numbers, so $1 - x$ might not have a [multiplicative
inverse](https://en.wikipedia.org/wiki/Multiplicative_inverse) modulo $m$.

Instead, we'll use an idea similar to [exponentation by
squaring](https://en.wikipedia.org/wiki/Exponentiation_by_squaring)

Suppose $n$ is even, i.e. $n = 2k$.

```math
f(x) = 1 + x + \ldots + x^k + x^{k+1} + \ldots + x^{2k - 1} + x^{2k}
     = (1 + x + \ldots + x^k) + x^k \cdot (1 + x + \ldots + x^k)
     = (1 + x + \ldots + x^k)(1 + x^k)
```

In other words, we have managed to compute `f(n, x, m)` using `f(n / 2, x, m)`,
thereby cutting the problem space in half.

When $n$ is odd, we will simply compute $x^n$ and add it to the solution of
`f(n - 1, x, m)`.

This gives us an algorithm of time complexity $O(\log n)$ which is
very efficient. Of course, we will need to use the aforementioned exponentation by
squaring when computing $x^n$.

Putting it all together, we get the following solution:

```c
#include <stdio.h>

const long long N[] = {
    24,
    976752,
    185416352,
    146834912,
    1470976384,
    7694658407053708544,
    1116260420086255572,
    8706625694362523392,
    1183110813291677984,
    7054653962180895534,
    5175297709711155980,
    6559849580083590952,
    5653693831503405792,
    4319724537448811328,
    242899095079433040,
    4959970480122654686,
    5593186226772728816,
    513339901597496232,
    2227144246302157312,
    4438190183933454080,
    2154906796158709888,
    739674153475818496,
    734633783254264576,
    4211826844688048128,
    3904050380321069312,
    2644279516313868784,
    8969630588291717120,
    878244494138079744,
    4509216622000658888,
    609708521729902148,
    8427710787133598080,
    4680811048617071760,
    6653898510887490688,
    5658826252879238208,
    62840954077758456,
    1980395599040577538,
    8197609442706622160,
    2515556291832209408,
    4936671994830718256,
};

const int X[] = {
    142, 68, 69, 176, 154, 49,  114, 156, 155, 101, 127, 3,   186,
    118, 35, 95, 36,  11,  132, 14,  100, 4,   45,  76,  192, 148,
    26,  23, 30, 78,  35,  72,  149, 101, 181, 197, 83,  177, 189,
};

const int M[] = {
    871593969, 585223051, 884675382, 339469467, 304777725, 444142170, 350166219,
    507757723, 499723930, 718623384, 334418583, 509146921, 102835028, 135297145,
    33629109,  318416718, 11319320,  278538953, 414413612, 85756989,  301071632,
    231230041, 809644038, 666254343, 292121212, 274537839, 933146630, 686809051,
    205105622, 168712916, 824324470, 595762152, 219378893, 24817709,  605039323,
    836708976, 607097417, 34343502,  807432778,
};

const int D[] = {
    90774414,  152135400, 669183124, 223948433, 243296512, 123975001, 162085049,
    321618967, 463342505, 698183439, 2170439,   328017648, 91546940,  75940356,
    18169995,  195872305, 9843831,   48604561,  231942074, 24294178,  215979137,
    66110937,  555503997, 339655466, 128537946, 252616454, 14447577,  90765161,
    554652,    75468023,  208385441, 535456797, 102609435, 7663323,   281911161,
    696464787, 119795566, 6004776,   587742265,
};

int add(int a, int b, int m) {
  if (a + b >= m) return a + b - m;
  if (a + b < 0) return a + b + m;
  return a + b;
}

int mul(int a, int b, int m) { return (long long)a * b % m; }

int fastpow(int a, long long b, int m) {
  int ret = 1;
  while (b) {
    if (b & 1LL) {
      ret = mul(ret, a, m);
      --b;
    }
    a = mul(a, a, m);
    b /= 2;
  }
  return ret;
}

int f_fast(long long n, int x, int m) {
  if (n <= 0LL) return 0;
  if (n % 2 == 1)
    return add(fastpow(x, n - 1, m), f_fast(n - 1, x, m), m);

  long long mid = n / 2LL;
  int half = f_fast(mid, x, m);
  int midpow = fastpow(x, mid, m);
  return mul(half, add(midpow, 1, m), m);
}

int main(void) {
  for (int i = 0; i < 39; ++i) 
    printf("%c", (char)(f_fast(N[i], X[i], M[i]) - D[i]));
  printf("\n");
  return 0;
}
```

Executing the code we get:

```
$ time ./sol
TBTL{1_F33l_7h3_n33ed_7h3_N3ed_4_5p33d}

real	0m0.008s
user	0m0.008s
sys	0m0.000s
```

Some significantly less efficient solutions (e.g. in $O(M)$ time complexity) were also able to obtain the flag.
