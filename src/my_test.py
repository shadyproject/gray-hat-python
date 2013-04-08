import my_debugger
from my_debugger_defines import *
import os

debugger = my_debugger.debugger()

pid = raw_input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))

printf_address = debugger.func_resolve("msvcrt.dll", "printf")
print "[*] Address of printf: 0x%08x" % printf_address

debugger.set_hw_bp(printf_address, 1, HW_EXECUTE)

debugger.run()
debugger.detach()

print "Press Return to quit"
raw_input()