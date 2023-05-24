# Baby Flag Checker -- Solution

We're given a 64-bit Linux command line executable, let's run it, give it some input and see what happens. 

```$ ./check_flag 
Enter flag: hello 
Incorrect!
```

As the name of the challenge suggests, the binary seems to be a tool that checks the validity of the flag. Let's open the binary using a disassambler such as [IDA Free](https://hex-rays.com/ida-free/) and try to retrieve/examine the source code or the assembly. We quickly identify the `main` function, and decompiling using the IDA's cloud decompiler feature discovers the relatively simple logic for checking the flag validity.

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+0h] [rbp-10h]
  int i; // [rsp+4h] [rbp-Ch]
  int j; // [rsp+8h] [rbp-8h]
  int k; // [rsp+Ch] [rbp-4h]

  printf("Enter flag: ");
  __isoc99_scanf("%s", &flag);
  if ( strlen(&flag) != 43 )
    no();
    ct[0] = flag;
    dword_201044 = byte_201141;
    v3 = 0;
    for ( i = 2; i < 43; ++i )
    {
      if ( *(&flag + i) )
      {
        for ( j = i; j < 43; j += i )
        {
          if ( *(&flag + j) )
          {
            ct[j] = *(&flag + j) ^ KEY[v3];
            *(&flag + j) = 0;
          }
        }
        ++v3;
      }
    }
    for ( k = 0; k < 43; ++k )
    {
      if ( ct[k] != EXP[k] )
        no();
    }
    yes();
  }
```

The flag is "encrypted" by XOR-ing bytes of the flag with the certain bytes of the key embedded in the binary, and the resulting ciphertext is compared to the expected ciphertext (also embedded in the binary). The two for loops resemble the [sieve of Eratosthenes](https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes), and the j-th byte of the flag is XOR-ed with the k-th byte of the key where k is the index of the lowest prime diving j. 

These details, however, are not needed to find the flag -- since each byte of the flag is XOR-ed with one byte of the key, we can reverse the process by running the same algorithm on the expected ciphertext:
```python
KEY = [144, 140, 211, 197, 239, 11, 16, 1, 209, 25, 90, 164, 58, 218, 0, 0]
EXP = [84, 66, 196, 192, 235, 150, 226, 241, 228, 228, 160, 218, 167, 99, 245, 226, 163, 99, 175, 32, 207, 202, 164, 191, 243, 170, 207, 185, 163,  42, 161, 52, 166, 211, 233, 227, 229, 251, 248, 191, 226, 9, 237]

C = [EXP[0], EXP[1]] + [0]*41

k = 0
for i in range(2, 43):
    if EXP[i] == 0:
        continue
    for j in range(i, 43, i):
        if EXP[j]:
            C[j] = EXP[j] ^ KEY[k] 
            EXP[j] = 0
    k += 1

print(bytes(C))
```

```
$ python3 solve.py 
b'TBTL{Er4th057hen3s?!_F4ncy_5331n6_y0u_h3r3}'
```