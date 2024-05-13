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
