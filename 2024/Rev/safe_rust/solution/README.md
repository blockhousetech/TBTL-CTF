# Safe Rust &mdash; Solution

## Binary and Tools

We will use the `Binary Ninja` software to analyze a given binary for this task.
We will use `gdb` in the second step to get the exact flag.

## Binary Analysis

We will disassembly to the C, and we will find the main function:

```
00008898      void** rlimits_1 = rlimit::unix::check_supported::h691e5e1819b82c3b(0x16, 3)
000088a1      void** const rlimits
000088a1      if (rlimits_1 == 0)
000088a7          rlimits = 0x800000
000088b0          int64_t var_68_1 = 0x800000
000088cb          if (setrlimit64(resource: RLIMIT_STACK, rlimits: &rlimits) == 0)
000088db              int64_t rbx = rust::generate_key::hb8d203faab29ab07(0xbabadeda)
000088de              int64_t i = 0
00008974              int64_t var_58_1
00008974              do
0000890b                  int64_t rax_3 = *(i + &data_45050) ^ rbx
00008914                  if (rax_3 u>= 0x100)
000089d8                      core::result::unwrap_failed::h64cf1fb744306b7f("called `Result::unwrap()` on an …", 0x2b, &rlimits)
000089d8                      noreturn
0000891a                  i = i + 8
0000891e                  int32_t var_74 = rax_3.d
00008927                  int32_t* var_40 = &var_74
00008933                  int64_t (* var_38_1)(int32_t* arg1, int64_t* arg2) = _$LT$char$u20$as$u20$cor.....Display$GT$::fmt::h31fc29e86d07d652
00008938                  rlimits = &data_54288
0000893d                  int64_t var_68_2 = 1
00008946                  int64_t var_50_1 = 0
0000894f                  int32_t** var_60_1 = &var_40
00008954                  var_58_1 = 1
00008960                  std::io::stdio::_print::h92c7e8e4bebf488d(&rlimits)
0000896a                  rbx = rust::generate_key::hb8d203faab29ab07(rbx)
00008974              while (i != 0xe0)
0000897d              rlimits = &data_54260
00008982              int64_t var_68_3 = 1
00008992              char const* const var_60_2 = "TryFromIntErrorsrc/main.rs"
0000899a              var_58_1.o = zx.o(0)
000089b8              return std::io::stdio::_print::h92c7e8e4bebf488d(&rlimits)
000089e8          rlimits_1 = std::sys::pal::unix::os::errno::h431b56158173dd7c() << 0x20 | 2
000089ec      rlimits = rlimits_1
00008a10      core::result::unwrap_failed::h64cf1fb744306b7f("called `Result::unwrap()` on an …", 0x2b, &rlimits)
00008a10      noreturn

```

We can see some interesting parts. The first thing is that binary calls `setrlimit64` with the `RLIMIT_STACK` parameter, https://www.gnu.org/software/libc/manual/html_node/Limits-on-Resources.html.

The program is changing stack size! If everything goes well, binary calls `rust::generate_key::hb8d203faab29ab07` function multiple calls.

We can also spot this line: `int64_t rax_3 = *(i + &data_45050) ^ rbx`, where some values are calculated, and some prints: `std::io::stdio::_print::h92c7e8e4bebf488d(&rlimits)`.

## Run binary

If we run binary, one of the messages we can have is:

```
thread 'main' has overflowed its stack
fatal runtime error: stack overflow
Aborted (core dumped)
```

This is somehow connected with the stack size. Now we can assume that binary will decrease stack size,
and binary cannot be executed because stack is to small.

Let's try to increase stack size: `ulimit -s unlimited`.
And we got this error message: `Segmentation fault (core dumped)`.

Now we can run gdb.

First, we will set the breakpoint at the main function: `b _ZN4rust4main17h1eef4902b3075149E`.
Next, we will `run` binary. After we stop at breakpoint, we can call `disassemble`:

```
0x000055555555c880 <+0>:     push   %rbp
0x000055555555c881 <+1>:     push   %r15
0x000055555555c883 <+3>:     push   %r14
0x000055555555c885 <+5>:     push   %r13
0x000055555555c887 <+7>:     push   %r12
0x000055555555c889 <+9>:     push   %rbx
0x000055555555c88a <+10>:    sub    $0x48,%rsp
0x000055555555c88e <+14>:    mov    $0x16,%edi
0x000055555555c893 <+19>:    mov    $0x3,%esi
0x000055555555c898 <+24>:    call   *0x4e342(%rip)        # 0x5555555aabe0
0x000055555555c89e <+30>:    test   %rax,%rax
0x000055555555c8a1 <+33>:    jne    0x55555555c9ec <_ZN4rust4main17h1eef4902b3075149E+364>
0x000055555555c8a7 <+39>:    movq   $0x800000,0x8(%rsp)
0x000055555555c8b0 <+48>:    movq   $0x800000,0x10(%rsp)
0x000055555555c8b9 <+57>:    lea    0x8(%rsp),%rsi
0x000055555555c8be <+62>:    mov    $0x3,%edi
0x000055555555c8c3 <+67>:    call   *0x4e277(%rip)        # 0x5555555aab40
0x000055555555c8c9 <+73>:    test   %eax,%eax
0x000055555555c8cb <+75>:    jne    0x55555555c9de <_ZN4rust4main17h1eef4902b3075149E+350>
0x000055555555c8d1 <+81>:    mov    $0xbabadeda,%edi
0x000055555555c8d6 <+86>:    call   0x55555555c670 <_ZN4rust12generate_key17hb8d203faab29ab07E>
0x000055555555c8db <+91>:    mov    %rax,%rbx
0x000055555555c8de <+94>:    xor    %r15d,%r15d

```

Lets jump to this address: `0x000055555555c8d1 <+81>:   mov    $0xbabadeda,%edi`:

`set $pc = 0x000055555555c8d1`

We can finish our program now, and we got the flag on stdout: `TBTL{Dr0p_m3_l1k3_ru5t_d035}`.

## More information

This task was inspired by `Rust` drop mechanism on `Rc`:
https://stackoverflow.com/questions/57781630/how-to-prevent-a-stack-overflow-from-a-recursive-deallocation-when-using-rc-in-r
