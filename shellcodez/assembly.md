[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/shellcodez/intro) : [Part 2](https://plackyhacker.github.io/shellcodez/arch)

# Writing Shellcode, A Little Bit of Assembly Code

Assembly language statements are made up of a **mnemonic**, **operands**, and **comments** (although comments aren't sent to the CPU). The following is a simple example:

```asm
mov eax, 0x10     ; move the value 0x10 into the eax register
```

For ease, I will refer to this as an **instruction**. I will explain what the most common assembly instructions are when writing shellcode for Windows 32 bit.

## Python, and the Keystone Engine

I learned the following workflow when doing the Offensive Security [EXP-301: Windows User Mode Exploit Development](https://www.offensive-security.com/courses/exp-301/) course. We create a python script that allows us to write assembly code, inject it into the python process and examine it using Windbg.

The python script is shown below:

```python
import ctypes, struct
from keystone import *
import numpy

# Your instructions go in the CODE variable
CODE = b""

ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                            ctypes.c_int(len(shellcode)),
                                            ctypes.c_int(0x3000),
                                            ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("Press enter to execute shellcode...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
```

When the script is executed, we can attached Windbg to the **python.exe** process and step through the instructions:

```
python.exe template.py
Shellcode located at address 0x4180000
Press enter to execute shellcode...
```

Details on Keystone Engine can be found [here](https://www.keystone-engine.org). This is a great way to debug and test your shellcode as you develop it.

You can use any 32 bit debugger, it doesn't have to be Windbg, that's just my favourite! And of course you need to install Python on the your Windows development machine.

OK, On to the assembly language.

## Assembly Primer!

Coming soon!

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/shellcodez/intro) : [Part 2](https://plackyhacker.github.io/shellcodez/arch)
