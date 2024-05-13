# Vault -- Solution

We are given a Linux command line executable written in Rust --- when we run it, it says `Unlocking vault...` and just seems to freeze. Let's fire up the debugger to see what's going on.

```bash
gef➤  run
Starting program: /src/vault 
warning: Error disabling address space randomization: Operation not permitted
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Unlocking vault...
[New Thread 0x7ffff7d5d640 (LWP 127)]
[New Thread 0x7ffff7b5c640 (LWP 128)]
[New Thread 0x7ffff7958640 (LWP 129)]
[New Thread 0x7ffff7751640 (LWP 130)]
[New Thread 0x7ffff754d640 (LWP 131)]
[New Thread 0x7ffff7349640 (LWP 132)]
[New Thread 0x7ffff7145640 (LWP 133)]
[New Thread 0x7ffff6f41640 (LWP 134)]
^C
Thread 1 "vault" received signal SIGINT, Interrupt.
...
gef➤  info threads
  Id   Target Id                                 Frame 
* 1    Thread 0x7ffff7d5f340 (LWP 124) "vault"   __futex_abstimed_wait_common64 (private=0x80, cancel=0x1, abstime=0x0, op=0x109, expected=0x7f, futex_word=0x7ffff7d5d910) at ./nptl/futex-internal.c:57
  2    Thread 0x7ffff7d5d640 (LWP 127) "slot 12" syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38
  3    Thread 0x7ffff7b5c640 (LWP 128) "slot 26" syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38
  4    Thread 0x7ffff7958640 (LWP 129) "slot 29" syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38
  5    Thread 0x7ffff7751640 (LWP 130) "slot 36" syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38
  6    Thread 0x7ffff754d640 (LWP 131) "slot 2"  syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38
  7    Thread 0x7ffff7349640 (LWP 132) "slot 7"  syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38
  8    Thread 0x7ffff7145640 (LWP 133) "slot 3"  syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38
  9    Thread 0x7ffff6f41640 (LWP 134) "slot 24" syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38

```

## Resolving deadlocks

There are several threads in our program: one waiting, and eight blocked with a system call. We can examine their stack frames to get more information on the program state.

```bash
gef➤  thread 2
[Switching to thread 2 (Thread 0x7ffff7d5d640 (LWP 127))]
#0  syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38
38      ../sysdeps/unix/sysv/linux/x86_64/syscall.S: No such file or directory.
gef➤  bt
#0  syscall () at ../sysdeps/unix/sysv/linux/x86_64/syscall.S:38
#1  0x000055555555c414 in std::sys::unix::futex::futex_wait () at library/std/src/sys/unix/futex.rs:62
#2  std::sys::unix::locks::futex_mutex::Mutex::lock_contended () at library/std/src/sys/unix/locks/futex_mutex.rs:56
#3  0x0000555555564b37 in std::sys::unix::locks::futex_mutex::Mutex::lock (self=0x7fffffffde70) at /rustc/82e1608dfa6e0b5569232559e3d385fea5a93112/library/std/src/sys/unix/locks/futex_mutex.rs:28
#4  0x0000555555560775 in std::sync::mutex::Mutex<vault::LockedVar>::lock<vault::LockedVar> (self=0x7fffffffde70) at /rustc/82e1608dfa6e0b5569232559e3d385fea5a93112/library/std/src/sync/mutex.rs:273
#5  0x0000555555561e66 in vault::do_with_mutexes<vault::mix_vars::{closure_env#0}> (thread_id=..., first=0x7fffffffdd90, second=0x7fffffffde70, f=...) at src/main.rs:54
#6  0x000055555556f38f in vault::mix_vars (thread_id=..., vars=..., first=0xc, second=0x1a, prng=0x7ffff7d5caa0) at src/main.rs:115
#7  0x0000555555562785 in vault::make_threads::{closure#0} () at src/main.rs:231
#8  0x0000555555565bd9 in core::ops::function::FnOnce::call_once<vault::make_threads::{closure_env#0}, ()> () at /rustc/82e1608dfa6e0b5569232559e3d385fea5a93112/library/core/src/ops/function.rs:250
...

```

It looks like thread number 1 started threads 2-9, who are all deadlocked attempting to lock a mutex. Function calls `vault::mix_vars` and `vault::do_with_mutexes` sound like they could be the interesting parts --- we need to dig into the binary to discover what are they attempting to do. Let's open the binary using a disassembler such as [Ghidra](https://ghidra-sre.org/), and use it alongside gdb to disassemble and analyze said functions. 

*...few hours of tedious analysis later...*

Function `vault::mix_vars` seems to take as arguments: an array of `LockedVar` of size 37, two indices `first` and `second`, reference to a random number generator `prng`. As far as the function body, it seems to be doing little more than calling `vault::do_with_mutexes` after resolving indices to pointers.

```bash
gef➤  set language rust
gef➤  info frame
Stack level 6, frame at 0x7ffff7d5ca90:
 rip = 0x55555556f38f in vault::mix_vars (src/main.rs:115); saved rip = 0x555555562785
 called by frame at 0x7ffff7d5cac0, caller of frame at 0x7ffff7d5ca00
 source language rust.
 Arglist at 0x7ffff7d5c9f8, args: thread_id=..., vars=..., first=0xc, second=0x1a, prng=0x7ffff7d5caa0
 Locals at 0x7ffff7d5c9f8, Previous frame's sp is 0x7ffff7d5ca90
 Saved registers:
  rip at 0x7ffff7d5ca88
gef➤  print vars
$7 = &[std::sync::mutex::Mutex<vault::LockedVar>] {
  data_ptr: 0x7fffffffdcd0,
  length: 0x25
}
gef➤  print prng
$8 = (*mut fastrand::Rng) 0x7ffff7d5caa0
```

```c
void vault::mix_vars(undefined4 thread_id,long vars,ulong length,ulong first,ulong second, undefined8 prng)
{
...
  do_with_mutexes(thread_id,vars + first * 0x10,vars + second * 0x10,(undefined4 *)&local_first_ref)
...
  return;
}
```

Function `vault::do_with_mutexes` seems to take as arguments: references to two specific `LockedVar`s, and a reference to a calling closure from `vault::mix_vars`. Analysis of the function (and its call tree) reveals that it:
1. locks the first `LockedVar`,
2. locks the second `LockedVar`, 
3. modifies the content of the two variables using one of the three mixing functions and the `prng`,
4. unlocks the first `LockedVar`,
6. unlocks the second `LockedVar`.

```bash
gef➤  info frame
Stack level 5, frame at 0x7ffff7d5ca00:
 rip = 0x555555561e66 in vault::do_with_mutexes<vault::mix_vars::{closure_env#0}> (src/main.rs:54); saved rip = 0x55555556f38f
 called by frame at 0x7ffff7d5ca90, caller of frame at 0x7ffff7d5c8c0
 source language rust.
 Arglist at 0x7ffff7d5c8b8, args: thread_id=..., first=0x7fffffffdd90, second=0x7fffffffde70, f=...
 Locals at 0x7ffff7d5c8b8, Previous frame's sp is 0x7ffff7d5ca00
 Saved registers:
  rip at 0x7ffff7d5c9f8
gef➤  print first
$11 = (*mut std::sync::mutex::Mutex<vault::LockedVar>) 0x7fffffffdd90
gef➤  print second
$12 = (*mut std::sync::mutex::Mutex<vault::LockedVar>) 0x7fffffffde70
gef➤  print f
$13 = vault::mix_vars::{closure_env#0} {
  _ref__first: 0x7ffff7d5ca40,
  _ref__second: 0x7ffff7d5ca48,
  _ref__prng: 0x7ffff7d5caa0
}
```

```c
void vault::do_with_mutexes (undefined4 thread_id,undefined8 first,undefined8 second,undefined4 *f_closure)
{
  ...
  /* lock first variable */
  std::sync::mutex::Mutex<T>::lock((char)first_mutex,(char)first);
  first_mutex_guard = core::result::Result<T,E>::unwrap(first_mutex,&PTR_DAT_00174740);
  local_26 = 1;
  /* try { // try from 0010ddde to 0010de7b has its CatchHandler @ 0010de05 */
  local_a8 = extraout_DL;
  deref_mutex = <std::sync::mutex::MutexGuard<T>as_core::ops::deref::DerefMut>::deref_mut
                          (&first_mutex_guard);
  LockedVar::locked_by(deref_mutex,thread_id);
  duration = core::time::Duration::from_millis(0x32);
  /* sleep a bit */
  std::thread::sleep(SUB128(duration,0),SUB124(duration >> 0x40,0));
  ...
  /* lock second variable */
  std::sync::mutex::Mutex<T>::lock((char)local_78,(char)second);
  second_mutex_guard = core::result::Result<T,E>::unwrap(local_78,&PTR_DAT_00174758);
  local_27 = 1;
  /* try { // try from 0010dea7 to 0010df08 has its CatchHandler @ 0010dece */
  local_80 = extraout_DL_00;
  deref_mutex = <std::sync::mutex::MutexGuard<T>as_core::ops::deref::DerefMut>::deref_mut
                          (&second_mutex_guard);
  LockedVar::locked_by(deref_mutex,thread_id);
  ...
  /* Modify the locked variables */
  mix_vars::{{closure}}(&first_idx_ref,first_cell_ref,second_cell_ref);
  ...
  /* Unlock first variable */
  deref_mutex = <std::sync::mutex::MutexGuard<T>as_core::ops::deref::DerefMut>::deref_mut
                          (&first_mutex_guard);
  LockedVar::unlocking(deref_mutex);
  /* Unlock second variable */
  deref_mutex = <std::sync::mutex::MutexGuard<T>as_core::ops::deref::DerefMut>::deref_mut
                          (&second_mutex_guard);
  LockedVar::unlocking(deref_mutex);
  local_27 = 0;
  core::mem::drop(second_mutex_guard,local_80);
  local_26 = 0;
  core::mem::drop(first_mutex_guard,local_a8);
  return;
}
```

Now that we have some idea what `vault::mix_vars` could be doing, we go back to runtime analysis. Let's set the breakpoint on `vault::mix_vars` and zoom out a little bit. We also instruct gdb to disallow background threads from running (`set scheduler-locking on`) and manually continue the threads up until `vault::mix_vars` breakpoint.

```bash
gef➤  info threads
  Id   Target Id                                 Frame 
  1    Thread 0x7ffff7d5f340 (LWP 210) "vault"   clone () at ../sysdeps/unix/sysv/linux/x86_64/clone.S:83
  2    Thread 0x7ffff7d5d640 (LWP 211) "slot 12" vault::mix_vars (thread_id=..., vars=..., first=0xc, second=0x1a, prng=0x7ffff7d5caa0) at src/main.rs:115
  3    Thread 0x7ffff7b59640 (LWP 212) "slot 26" vault::mix_vars (thread_id=..., vars=..., first=0x1a, second=0xc, prng=0x7ffff7b58aa0) at src/main.rs:115
  4    Thread 0x7ffff7958640 (LWP 214) "slot 29" vault::mix_vars (thread_id=..., vars=..., first=0x1d, second=0x24, prng=0x7ffff7957aa0) at src/main.rs:115
  5    Thread 0x7ffff7757640 (LWP 215) "slot 36" vault::mix_vars (thread_id=..., vars=..., first=0x24, second=0x1d, prng=0x7ffff7756aa0) at src/main.rs:115
  6    Thread 0x7ffff7550640 (LWP 216) "slot 2"  vault::mix_vars (thread_id=..., vars=..., first=0x2, second=0x7, prng=0x7ffff754faa0) at src/main.rs:115
  7    Thread 0x7ffff734f640 (LWP 218) "slot 7"  vault::mix_vars (thread_id=..., vars=..., first=0x7, second=0x2, prng=0x7ffff734eaa0) at src/main.rs:115
  8    Thread 0x7ffff714b640 (LWP 219) "slot 3"  vault::mix_vars (thread_id=..., vars=..., first=0x3, second=0x18, prng=0x7ffff714aaa0) at src/main.rs:115
* 9    Thread 0x7ffff6f47640 (LWP 220) "slot 24" vault::mix_vars (thread_id=..., vars=..., first=0x18, second=0x3, prng=0x7ffff6f46aa0) at src/main.rs:115
```

The reason for the deadlock now becomes clear --- the program schedules four group of two threads, where the two threads in the group try to mix the same pair of variables. For example, the thread 2 above will lock variable `0xc` and sleep a bit before attempting to lock variable `0x1a`, thread 3 will lock variable `0x1a` and sleep a bit before attempting to lock variable `0xc` --- a typical deadlock.
Notice that the four groups use different variables, deadlocks are only caused by the two threads within the group.

We can try to avoid/resolve deadlocks in two different ways: manually scheduling the threads via gdb so that, for example, thread 2 finishes before thread 3 enters `vault::do_with_mutexes`, or we can allow the deadlock to happen and then resolve it by manually calling `Mutex::wake` directly from gdb.

Next step is to resolve the deadlocks (using one of the two methods above) so the program continues executing. It turns out that, after these 8 threads complete, another 8 threads are spawned with the similar pattern of four groups of two. This happens 9 times in the program for a total of 72 spawned threads.

After manually scheduling the 72 threads in the increasing order we realize two things:
- The program has completed, but did not give us the flag :(.
- Some gdb scripting is absolutely essential here in order to make progress.
```bash
  Id   Target Id                                 Frame 
* 1    Thread 0x7ffff7f6f340 (LWP 48117) "vault" vault::catch_panic<alloc::vec::Vec<u8, alloc::alloc::Global>, vault::main::{closure_env#2}> (f=...) at src/main.rs:73
[Switching to thread 1 (Thread 0x7ffff7f6f340 (LWP 48117))]
#0  vault::catch_panic<alloc::vec::Vec<u8, alloc::alloc::Global>, vault::main::{closure_env#2}> (f=...) at src/main.rs:73
73	in src/main.rs
Shutting down vault...
No flag for you! Come back, one year!
[Inferior 1 (process 48117) exited with code 01]
No threads.
```

The reasonable conclusion is that we have to find the *one* specific order of execution that will give us the flag. Specifically, there will be 36 groups of two thread, and for each group we have to pick one order of execution for the two threads.

## Tracing data

Let's analyze a bit what exactly is happening withe data in the variables. First of all, the data in each `LockedVar` is a single character, and the initial content of the 37 variables is set from the seed `v/dQw4w9WgXcQ/awcx-gTQDLM/ryNxl-lpOME` at the beginning of the `vault::main` function. 

```
...
memcpy(local_seed,"v/dQw4w9WgXcQ/awcx-gTQDLM/ryNxl-lpOMEUnlocking vault...\n",0x25);
...
```

As expected, mixing two variables with indices `first` and `second` only changes the contents of the corresponding variables and nothing else. We'll skip the details of the mixing logic in the writeup, but it's not hard to extract it from the decompiled source.

Finally, after all the threading and mixing is completed, the data in the 37 variables in collected into an array and xor-ed with a pad hardcoded in the binary.
```c
...
0x0010e70
  uVar2 = core::result::Result<T,E>::unwrap(idx,&PTR_DAT_001747a0);
  return uVar2 & 0xffffffffffffff00 | (ulong)(extraout_DL ^ bVar1);
...
```

There are at least two different ways to solve the problem now.

## Model solution

The intended solution was to find the clue to the correct thread scheduling order in the binary. The clue is hidden in the seed above --- items separated by slashes are actually ids of YouTube videos. In the middle, nested between two YouTube classics, is the [Always bed on black](https://www.youtube.com/watch?v=awcx-gTQDLM) line from [Passenger 57](https://www.imdb.com/title/tt0105104/).

Black slots, of course, refer to a [roulette wheel](https://en.wikipedia.org/wiki/Roulette#/media/File:French_Layout-Single_Zero_Wheel.jpg). Scheduling threads by preferring the black-colored ones will unlock the vault! The code below adds a gdb command that examines active threads and unlocks a black one, calling it repeatedly will eventually cause the program to print the flag.

```python
# Based on: https://github.com/DamZiobro/gdb-automatic-deadlock-detector/blob/master/gdbDisplayLockedThreads.py

import gdb
import re

BLACK = list(range(2,10+1,2)) + list(range(11, 18+1, 2)) + list(range(20, 28+1, 2)) + list(range(29, 36+1, 2))
R = re.compile(r'slot (\d+)')

def is_black_thread(thread):
    if (m := R.match(thread.name)):
        x = int(m.groups()[0])
        return x in BLACK
    return False

class Undeadlock(gdb.Command):
    def __init__(self):
        super(Undeadlock, self).__init__("solve", gdb.COMMAND_SUPPORT,gdb.COMPLETE_NONE,True)

    def invoke(self, arg, from_tty):
        print("\n********************************************************************************")
        print("Solving...")
        for process in gdb.inferiors():
            for thread in process.threads():
                if not thread.is_valid() or not thread.is_stopped():
                    continue
                if not is_black_thread(thread):
                    continue
                print(f"Thread {thread.name} is black-numbered")                
                thread.switch()
                frame = gdb.selected_frame()
                while frame:
                    frame.select()
                    name = frame.name()
                    if name == "std::sys::unix::locks::futex_mutex::Mutex::lock":
                        mutex_ptr = frame.read_var("self")
                        print("Unlocking", mutex_ptr)
                        gdb.execute("set language rust")
                        gdb.execute(f"set *({mutex_ptr} as *mut u32) = 0")
                        gdb.execute(f"set *(({mutex_ptr}+8) as *mut u32) = 0")
                        gdb.execute(f"call std::sys::unix::locks::futex_mutex::Mutex::wake({mutex_ptr})")
                        return
                    frame = frame.older()
Undeadlock()

```

## Branch and bound solution

If you completely missed the clue (like the author of this writeup) there is another approach --- search through all possible scheduling orders. This requires additional time and effort to fully extract the mixing logic, including how the random generators used in the mixing functions work and are seeded. 

Furthermore, straightforward brute force will not be sufficient as there are $2^{36}$ possible orderings to examine. However, we can take the advantage of shallow dependency graph between variables, as well the knowledge of the flag prefix to construct an efficient branch-and-bound algorithm to find the flag. Full implementation is given below.

```python
#!/usr/bin/env python3

import re
import string

THREAD_DATA = """2    Thread 0x7ffff7bff640 (LWP 152600) "slot 12" vault::mix_vars (thread_id=..., vars=..., first=0xc, second=0x1a, prng=0x7ffff7bfeaa0) at src/main.rs:115
3    Thread 0x7ffff79fe640 (LWP 152601) "slot 26" vault::mix_vars (thread_id=..., vars=..., first=0x1a, second=0xc, prng=0x7ffff79fdaa0) at src/main.rs:115
4    Thread 0x7ffff77fd640 (LWP 152603) "slot 29" vault::mix_vars (thread_id=..., vars=..., first=0x1d, second=0x24, prng=0x7ffff77fcaa0) at src/main.rs:115
5    Thread 0x7ffff75fc640 (LWP 152604) "slot 36" vault::mix_vars (thread_id=..., vars=..., first=0x24, second=0x1d, prng=0x7ffff75fbaa0) at src/main.rs:115
6    Thread 0x7ffff73fb640 (LWP 152605) "slot 2"  vault::mix_vars (thread_id=..., vars=..., first=0x2, second=0x7, prng=0x7ffff73faaa0) at src/main.rs:115
7    Thread 0x7ffff71fa640 (LWP 152607) "slot 7"  vault::mix_vars (thread_id=..., vars=..., first=0x7, second=0x2, prng=0x7ffff71f9aa0) at src/main.rs:115
8    Thread 0x7ffff6ff9640 (LWP 152672) "slot 3"  vault::mix_vars (thread_id=..., vars=..., first=0x3, second=0x18, prng=0x7ffff6ff8aa0) at src/main.rs:115
9    Thread 0x7ffff6df8640 (LWP 152674) "slot 24" vault::mix_vars (thread_id=..., vars=..., first=0x18, second=0x3, prng=0x7ffff6df7aa0) at src/main.rs:115
10   Thread 0x7ffff6df8640 (LWP 152778) "slot 9"  vault::mix_vars (thread_id=..., vars=..., first=0x9, second=0xa, prng=0x7ffff6df7aa0) at src/main.rs:115
11   Thread 0x7ffff6ff9640 (LWP 152779) "slot 10" vault::mix_vars (thread_id=..., vars=..., first=0xa, second=0x9, prng=0x7ffff6ff8aa0) at src/main.rs:115
12   Thread 0x7ffff71fa640 (LWP 152780) "slot 18" vault::mix_vars (thread_id=..., vars=..., first=0x12, second=0x21, prng=0x7ffff71f9aa0) at src/main.rs:115
13   Thread 0x7ffff73fb640 (LWP 152782) "slot 33" vault::mix_vars (thread_id=..., vars=..., first=0x21, second=0x12, prng=0x7ffff73faaa0) at src/main.rs:115
14   Thread 0x7ffff75fc640 (LWP 152783) "slot 27" vault::mix_vars (thread_id=..., vars=..., first=0x1b, second=0x23, prng=0x7ffff75fbaa0) at src/main.rs:115
15   Thread 0x7ffff77fd640 (LWP 152784) "slot 35" vault::mix_vars (thread_id=..., vars=..., first=0x23, second=0x1b, prng=0x7ffff77fcaa0) at src/main.rs:115
16   Thread 0x7ffff79fe640 (LWP 152794) "slot 4"  vault::mix_vars (thread_id=..., vars=..., first=0x4, second=0x19, prng=0x7ffff79fdaa0) at src/main.rs:115
17   Thread 0x7ffff7bff640 (LWP 152795) "slot 25" vault::mix_vars (thread_id=..., vars=..., first=0x19, second=0x4, prng=0x7ffff7bfeaa0) at src/main.rs:115
18   Thread 0x7ffff7bff640 (LWP 152922) "slot 14" vault::mix_vars (thread_id=..., vars=..., first=0xe, second=0x1f, prng=0x7ffff7bfeaa0) at src/main.rs:115
19   Thread 0x7ffff79fe640 (LWP 152923) "slot 31" vault::mix_vars (thread_id=..., vars=..., first=0x1f, second=0xe, prng=0x7ffff79fdaa0) at src/main.rs:115
20   Thread 0x7ffff77fd640 (LWP 152925) "slot 16" vault::mix_vars (thread_id=..., vars=..., first=0x10, second=0x11, prng=0x7ffff77fcaa0) at src/main.rs:115
21   Thread 0x7ffff75fc640 (LWP 152926) "slot 17" vault::mix_vars (thread_id=..., vars=..., first=0x11, second=0x10, prng=0x7ffff75fbaa0) at src/main.rs:115
22   Thread 0x7ffff73fb640 (LWP 152928) "slot 19" vault::mix_vars (thread_id=..., vars=..., first=0x13, second=0x16, prng=0x7ffff73faaa0) at src/main.rs:115
23   Thread 0x7ffff71fa640 (LWP 152929) "slot 22" vault::mix_vars (thread_id=..., vars=..., first=0x16, second=0x13, prng=0x7ffff71f9aa0) at src/main.rs:115
24   Thread 0x7ffff6ff9640 (LWP 152930) "slot 15" vault::mix_vars (thread_id=..., vars=..., first=0xf, second=0x17, prng=0x7ffff6ff8aa0) at src/main.rs:115
25   Thread 0x7ffff6df8640 (LWP 152932) "slot 23" vault::mix_vars (thread_id=..., vars=..., first=0x17, second=0xf, prng=0x7ffff6df7aa0) at src/main.rs:115
26   Thread 0x7ffff6df8640 (LWP 153091) "slot 21" vault::mix_vars (thread_id=..., vars=..., first=0x15, second=0x1c, prng=0x7ffff6df7aa0) at src/main.rs:115
27   Thread 0x7ffff6ff9640 (LWP 153092) "slot 28" vault::mix_vars (thread_id=..., vars=..., first=0x1c, second=0x15, prng=0x7ffff6ff8aa0) at src/main.rs:115
28   Thread 0x7ffff71fa640 (LWP 153094) "slot 6"  vault::mix_vars (thread_id=..., vars=..., first=0x6, second=0x1e, prng=0x7ffff71f9aa0) at src/main.rs:115
29   Thread 0x7ffff73fb640 (LWP 153095) "slot 30" vault::mix_vars (thread_id=..., vars=..., first=0x1e, second=0x6, prng=0x7ffff73faaa0) at src/main.rs:115
30   Thread 0x7ffff75fc640 (LWP 153097) "slot 8"  vault::mix_vars (thread_id=..., vars=..., first=0x8, second=0x20, prng=0x7ffff75fbaa0) at src/main.rs:115
31   Thread 0x7ffff77fd640 (LWP 153098) "slot 32" vault::mix_vars (thread_id=..., vars=..., first=0x20, second=0x8, prng=0x7ffff77fcaa0) at src/main.rs:115
32   Thread 0x7ffff79fe640 (LWP 153099) "slot 5"  vault::mix_vars (thread_id=..., vars=..., first=0x5, second=0xb, prng=0x7ffff79fdaa0) at src/main.rs:115
33   Thread 0x7ffff7bff640 (LWP 153101) "slot 11" vault::mix_vars (thread_id=..., vars=..., first=0xb, second=0x5, prng=0x7ffff7bfeaa0) at src/main.rs:115
34   Thread 0x7ffff7bff640 (LWP 153279) "slot 13" vault::mix_vars (thread_id=..., vars=..., first=0xd, second=0x22, prng=0x7ffff7bfeaa0) at src/main.rs:115
35   Thread 0x7ffff79fe640 (LWP 153280) "slot 34" vault::mix_vars (thread_id=..., vars=..., first=0x22, second=0xd, prng=0x7ffff79fdaa0) at src/main.rs:115
36   Thread 0x7ffff77fd640 (LWP 153281) "slot 1"  vault::mix_vars (thread_id=..., vars=..., first=0x1, second=0x14, prng=0x7ffff77fcaa0) at src/main.rs:115
37   Thread 0x7ffff75fc640 (LWP 153283) "slot 20" vault::mix_vars (thread_id=..., vars=..., first=0x14, second=0x1, prng=0x7ffff75fbaa0) at src/main.rs:115
38   Thread 0x7ffff73fb640 (LWP 153284) "slot 2"  vault::mix_vars (thread_id=..., vars=..., first=0x2, second=0xc, prng=0x7ffff73faaa0) at src/main.rs:115
39   Thread 0x7ffff71fa640 (LWP 153285) "slot 12" vault::mix_vars (thread_id=..., vars=..., first=0xc, second=0x2, prng=0x7ffff71f9aa0) at src/main.rs:115
40   Thread 0x7ffff6ff9640 (LWP 153287) "slot 11" vault::mix_vars (thread_id=..., vars=..., first=0xb, second=0xe, prng=0x7ffff6ff8aa0) at src/main.rs:115
41   Thread 0x7ffff6df8640 (LWP 153288) "slot 14" vault::mix_vars (thread_id=..., vars=..., first=0xe, second=0xb, prng=0x7ffff6df7aa0) at src/main.rs:115
42   Thread 0x7ffff6df8640 (LWP 153356) "slot 6"  vault::mix_vars (thread_id=..., vars=..., first=0x6, second=0x12, prng=0x7ffff6df7aa0) at src/main.rs:115
43   Thread 0x7ffff6ff9640 (LWP 153357) "slot 18" vault::mix_vars (thread_id=..., vars=..., first=0x12, second=0x6, prng=0x7ffff6ff8aa0) at src/main.rs:115
44   Thread 0x7ffff71fa640 (LWP 153358) "slot 31" vault::mix_vars (thread_id=..., vars=..., first=0x1f, second=0x20, prng=0x7ffff71f9aa0) at src/main.rs:115
45   Thread 0x7ffff73fb640 (LWP 153360) "slot 32" vault::mix_vars (thread_id=..., vars=..., first=0x20, second=0x1f, prng=0x7ffff73faaa0) at src/main.rs:115
46   Thread 0x7ffff75fc640 (LWP 153361) "slot 10" vault::mix_vars (thread_id=..., vars=..., first=0xa, second=0x19, prng=0x7ffff75fbaa0) at src/main.rs:115
47   Thread 0x7ffff77fd640 (LWP 153362) "slot 25" vault::mix_vars (thread_id=..., vars=..., first=0x19, second=0xa, prng=0x7ffff77fcaa0) at src/main.rs:115
48   Thread 0x7ffff79fe640 (LWP 153364) "slot 34" vault::mix_vars (thread_id=..., vars=..., first=0x22, second=0x23, prng=0x7ffff79fdaa0) at src/main.rs:115
49   Thread 0x7ffff7bff640 (LWP 153365) "slot 35" vault::mix_vars (thread_id=..., vars=..., first=0x23, second=0x22, prng=0x7ffff7bfeaa0) at src/main.rs:115
50   Thread 0x7ffff7bff640 (LWP 153445) "slot 9"  vault::mix_vars (thread_id=..., vars=..., first=0x9, second=0x1d, prng=0x7ffff7bfeaa0) at src/main.rs:115
51   Thread 0x7ffff79fe640 (LWP 153446) "slot 29" vault::mix_vars (thread_id=..., vars=..., first=0x1d, second=0x9, prng=0x7ffff79fdaa0) at src/main.rs:115
52   Thread 0x7ffff77fd640 (LWP 153447) "slot 16" vault::mix_vars (thread_id=..., vars=..., first=0x10, second=0x14, prng=0x7ffff77fcaa0) at src/main.rs:115
53   Thread 0x7ffff75fc640 (LWP 153449) "slot 20" vault::mix_vars (thread_id=..., vars=..., first=0x14, second=0x10, prng=0x7ffff75fbaa0) at src/main.rs:115
54   Thread 0x7ffff73fb640 (LWP 153450) "slot 17" vault::mix_vars (thread_id=..., vars=..., first=0x11, second=0x1b, prng=0x7ffff73faaa0) at src/main.rs:115
55   Thread 0x7ffff71fa640 (LWP 153451) "slot 27" vault::mix_vars (thread_id=..., vars=..., first=0x1b, second=0x11, prng=0x7ffff71f9aa0) at src/main.rs:115
56   Thread 0x7ffff6ff9640 (LWP 153453) "slot 4"  vault::mix_vars (thread_id=..., vars=..., first=0x4, second=0x17, prng=0x7ffff6ff8aa0) at src/main.rs:115
57   Thread 0x7ffff6df8640 (LWP 153454) "slot 23" vault::mix_vars (thread_id=..., vars=..., first=0x17, second=0x4, prng=0x7ffff6df7aa0) at src/main.rs:115
58   Thread 0x7ffff6df8640 (LWP 153517) "slot 15" vault::mix_vars (thread_id=..., vars=..., first=0xf, second=0x1e, prng=0x7ffff6df7aa0) at src/main.rs:115
59   Thread 0x7ffff6ff9640 (LWP 153518) "slot 30" vault::mix_vars (thread_id=..., vars=..., first=0x1e, second=0xf, prng=0x7ffff6ff8aa0) at src/main.rs:115
60   Thread 0x7ffff71fa640 (LWP 153519) "slot 5"  vault::mix_vars (thread_id=..., vars=..., first=0x5, second=0x1c, prng=0x7ffff71f9aa0) at src/main.rs:115
61   Thread 0x7ffff73fb640 (LWP 153521) "slot 28" vault::mix_vars (thread_id=..., vars=..., first=0x1c, second=0x5, prng=0x7ffff73faaa0) at src/main.rs:115
62   Thread 0x7ffff75fc640 (LWP 153522) "slot 1"  vault::mix_vars (thread_id=..., vars=..., first=0x1, second=0x21, prng=0x7ffff75fbaa0) at src/main.rs:115
63   Thread 0x7ffff77fd640 (LWP 153524) "slot 33" vault::mix_vars (thread_id=..., vars=..., first=0x21, second=0x1, prng=0x7ffff77fcaa0) at src/main.rs:115
64   Thread 0x7ffff79fe640 (LWP 153525) "slot 7"  vault::mix_vars (thread_id=..., vars=..., first=0x7, second=0x16, prng=0x7ffff79fdaa0) at src/main.rs:115
65   Thread 0x7ffff7bff640 (LWP 153526) "slot 22" vault::mix_vars (thread_id=..., vars=..., first=0x16, second=0x7, prng=0x7ffff7bfeaa0) at src/main.rs:115
66   Thread 0x7ffff7bff640 (LWP 153791) "slot 13" vault::mix_vars (thread_id=..., vars=..., first=0xd, second=0x24, prng=0x7ffff7bfeaa0) at src/main.rs:115
67   Thread 0x7ffff79fe640 (LWP 153792) "slot 36" vault::mix_vars (thread_id=..., vars=..., first=0x24, second=0xd, prng=0x7ffff79fdaa0) at src/main.rs:115
68   Thread 0x7ffff77fd640 (LWP 153793) "slot 19" vault::mix_vars (thread_id=..., vars=..., first=0x13, second=0x18, prng=0x7ffff77fcaa0) at src/main.rs:115
69   Thread 0x7ffff75fc640 (LWP 153795) "slot 24" vault::mix_vars (thread_id=..., vars=..., first=0x18, second=0x13, prng=0x7ffff75fbaa0) at src/main.rs:115
70   Thread 0x7ffff73fb640 (LWP 153796) "slot 3"  vault::mix_vars (thread_id=..., vars=..., first=0x3, second=0x8, prng=0x7ffff73faaa0) at src/main.rs:115
71   Thread 0x7ffff71fa640 (LWP 153798) "slot 8"  vault::mix_vars (thread_id=..., vars=..., first=0x8, second=0x3, prng=0x7ffff71f9aa0) at src/main.rs:115
72   Thread 0x7ffff6ff9640 (LWP 153799) "slot 21" vault::mix_vars (thread_id=..., vars=..., first=0x15, second=0x1a, prng=0x7ffff6ff8aa0) at src/main.rs:115
73   Thread 0x7ffff6df8640 (LWP 153800) "slot 26" vault::mix_vars (thread_id=..., vars=..., first=0x1a, second=0x15, prng=0x7ffff6df7aa0) at src/main.rs:115
"""

SEED = b"v/dQw4w9WgXcQ/awcx-gTQDLM/ryNxl-lpOME"
PAD = b'"Rd\xb5r\xe4\xfen/y\x05\x0b$t_f\xd8\x99\x85\tb\xc8N|\x7f\xf3\nM\xce\xaf9VPh\x00-\xad'
RNG = {1: [5, 5, 7, 2], 2: [2, 3, 3, 0], 3: [7, 7, 6, 5], 4: [3, 5, 1, 6], 5: [5, 6, 4, 2], 6: [2, 1, 0, 0], 7: [3, 2, 3, 5], 8: [0, 0, 6, 3]}

def parse_calls():
    REGEX = 'first=0x([0-9a-fA-F]+), second=0x([0-9a-fA-F]+), prng=0x([0-9a-fA-F]+)'
    data = []
    for i, line in enumerate(THREAD_DATA.splitlines()):
        first, second, prng = re.findall(REGEX, line)[0]
        first = int(first, 16)
        second = int(second, 16)
        prng = int(prng, 16)
        data.append((i, first, second, prng))
    return data

CALLS = parse_calls()


def mix1(S, first, second, rng):
    first_value = S[first];
    second_value = S[second];
    x = RNG[rng][0]
    S[first] = first_value ^ (((second_value << (x & 7))&0xff) | second_value >> 8 - (x & 7))
    x = RNG[rng][1]
    S[second] = second_value ^ (((first_value << (x & 7))&0xff) | first_value >> 8 - (x & 7))


def mix2(S, first, second, rng):
    first_value = S[first]
    second_value = S[second]
    x = RNG[rng][0]
    x = first_value * (((second_value << (x & 7))&0xff) | second_value >> 8 - (x & 7))
    x = x&0xff
    rand2 = RNG[rng][1]
    S[first] = ((x << (rand2 & 7))&0xff) | x >> 8 - (rand2 & 7)
    x = RNG[rng][2]
    second_value = (second_value * (((first_value << (x & 7))&0xff) | first_value >> 8 - (x & 7)))&0xff
    first_value = RNG[rng][3]
    S[second] = ((second_value << (first_value & 7))&0xff) | second_value >> 8 - (first_value & 7);


def mix3(S, first, second, rng):
    first_value = S[first]
    second_value = S[second]
    S[first] = ((first_value << (second_value & 7))&0xff) | first_value >> 8 - (second_value & 7);
    x = RNG[rng][0]
    first_value = (first_value + x & 7)&0xff
    S[second] = ((second_value << first_value)&0xff) | second_value >> 8 - first_value;


def depends(data, i):
    target = {i}
    depends = []
    for item in data[::-1]:
        if item[1] in target or item[2] in target:
            target.add(item[1])
            target.add(item[2])
            idx, first, second, _ = item
            if idx % 2 == 0:
                depends.append((idx, first, second))
    return depends


def gen_events(data):
    events = []
    done = set()
    for i in range(0x25):
        dep = depends(data, i)
        for idx, f, s in dep[::-1]:
            if idx not in done:
                events.append(('try', idx, f, s))
                done.add(idx)
        events.append(('check', i))
    return events


F = [mix1, mix2, mix3]

def apply(idx, f, s, S):
     rng = idx % 8+1
     fidx = (f+s) % 3
     F[fidx](S, f, s, rng)


PREFIX = "TBTL{"
WHITELIST = string.ascii_letters+string.digits+'-_ {}'

def search(events, k, S):
    if k == len(events):
        print(bytes(S))
        return
    if events[k][0] == 'check':
        i = events[k][1]
        old = S[i]
        S[i] ^= PAD[i]
        if (i < 5 and chr(S[i]) == PREFIX[i]) or (i >= 5 and chr(S[i]) in WHITELIST):
            search(events, k+1, S)
        S[i] = old
        return
    _, idx, f, s = events[k]
    
    oldf, olds = S[f], S[s]
    apply(idx, f, s, S)
    apply(idx+1, s, f, S)    
    search(events, k+1, S)   
    S[f], S[s] = oldf, olds

    apply(idx+1, s, f, S)
    apply(idx, f, s, S)
    search(events, k+1, S)
    S[f], S[s] = oldf, olds


events = gen_events(CALLS)
search(events, 0, [x for x in SEED])
```