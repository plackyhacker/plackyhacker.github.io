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

Details on Keystone Engine can be found [here](https://www.keystone-engine.org). This is a great way to debug and test your shellcode as you develop it, just add a breakpoint to the memory address, in this case `bp 0x4180000`.

You can use any 32 bit debugger, it doesn't have to be Windbg, that's just my favourite! And of course you need to install Python on the your Windows development machine.

OK, On to the assembly language.

## Assembly Primer

Assembly Code can look a bit daunting at first, but it isn't that bad. Stick with it, practice and it will become much easier.

### Stack Instructions

There are two instructions for adding and removing values to/from the stack. As previously stated the stack is a **Last in First Out** memory structure. When you push a value on the stack, the stack grows, when you pop a value from the stack the stack shrinks (as it pops the last pushed value from the stack). The **extended stack pointer (esp)** is the register that points to the memory location at the top of the stack. **esp** is updated automatically when values are pushed and popped.

If we want to push something on to the stack we can use the **push** instruction:

```asm
push 0x11111111     ; push the value 0x11111111 on to the stack
push eax            ; push the value stored in eax on to the stack
push dword ptr[eax] ; push the 32 bit value located at the address 
                    ; stored in eax on to the stack
```

As seen above, we can push values, values stored in registers and values stored in memory pointed to by the addresses in registers.

We can also **push** words (16 bit) on to the stack:

```asm
pushw ax            ; push the value in ax on to the stack
```

If we want to pop something from the stack we can use the **pop** instruction:

```asm
pop eax             ; pop the last added value from the stack in to eax
```

When we **pop** a value from the stack we tell it which register to pop it in to.

### Move Instructions

The **mov** instruction is used to move data from one operand to another, for example:

```asm
mov eax, 0x11111111 ; move the value 0x11111111 into eax
mov eax, ecx        ; move the value in ecx into eax 
mov [ebp-0x38], eax ; move the value in eax into the memory located
                    ; at an offset of -0x38 from ebp
```

When data is moved, it is not deleted from the source. It is not possible to move data between memory locations using the **mov** instruction, for this we can use the **movs** instruction.

The **xchg** instruction can be used to exchange the values in two registers:

```asm
xchg eax, ecx       ; exchange eax with ecx
```

### Jump Instructions

Coming very soon!

### Call Instructions

Coming very soon!

### Arithmetic Instructions

Coming very soon!

### XOR Instructions

Coming very soon!

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/shellcodez/intro) : [Part 2](https://plackyhacker.github.io/shellcodez/arch)
