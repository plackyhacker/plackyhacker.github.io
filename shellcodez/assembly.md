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

Jump instructions can be unconditional and they can be conditional. Unconditional jumps can be short or long, we will discuss these in a later article when we are trying to avoid bad characters (specifically `0x00`) in our shellcode.

The **jmp** instruction is used to jump over other instructions unconditionally. To do this we use labels in our assembly code, this way we avoid having to use definite memory locations which just won't work:

```asm
start:
  jmp end           ;
  mov eax, 0x10     ;
  mov ecx, 0x10     ;
  add eax, ecx      ;
end:
  mov eax, 0x20     ;
```

In the above example only two instructions will be executed, `jmp end` and `mov eax, 0x20`.

Before we discuss conditional jumps we need to understand the **test** and **cmp** instructions. Perhaps the best way to do this is to show some outputs from Windbg when stepping through instructions:

```
eax=00000010 ebx=00000010 ecx=00000020 edx=04880000 esi=04880000 edi=04880000
eip=0488001a esp=04a7fc20 ebp=04a7fe30 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
0488001a 85c0            test    eax,eax
```

The **test eax, eax** instruction is first up! If we examine the **zero flag** after stepping over the instruction we see that it is `0`; meaning that the **zero flag** is not set:

```
0:005> r zf
zf=0
```

When the **test** instruction is used with the two same operands at tests to see if the value is `0`. In this example **eax** is `0x10` so the **zero flag** is not set.

Next we **test eax** against **ebx**:

```
eax=00000010 ebx=00000010 ecx=00000020 edx=04880000 esi=04880000 edi=04880000
eip=0488001c esp=04a7fc20 ebp=04a7fe30 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
0488001c 85d8            test    eax,ebx
```

On this occassion the **zero flag** is also `0`:

```
0:005> r zf
zf=0
```

The **test** instruction is referred to as a logical instruction. It uses **AND** logic to compare each bit. As the bits are the same the **zero flag** is not set.

Finally we **test eax** against **ecx**, this time the values in the registers are different and the **zero flag** is set to `1`:

```
eax=00000010 ebx=00000010 ecx=00000020 edx=04880000 esi=04880000 edi=04880000
eip=0488001e esp=04a7fc20 ebp=04a7fe30 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
0488001e 85c8            test    eax,ecx
```

```
0:005> r zf
zf=1
```

It should be ovbious that we can use the **jump not zero (jnz)** instruction to enact logical comparisons.

Now we move on to the **compare** instruction:

First we compare **eax** with itself:

```
eax=00000010 ebx=00000010 ecx=00000020 edx=04880000 esi=04880000 edi=04880000
eip=04880020 esp=04a7fc20 ebp=04a7fe30 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
04880020 39c0            cmp     eax,eax
```

The values stored in the two operands (the same in this case) are equal, so the **zero flag** is set to `1`:

```
0:005> r zf
zf=1
```

The **cmp** instruction is an arithmetic instruction, it subtracts one operand from the other and sets the **zero flag** if the value is not `0`.

```
eax=00000010 ebx=00000010 ecx=00000020 edx=04880000 esi=04880000 edi=04880000
eip=04880022 esp=04a7fc20 ebp=04a7fe30 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
04880022 39d8            cmp     eax,ebx

0:005> r zf
zf=1
```

Note that **eax** and **ebx** store the same value so the **zero flag** is set to `1`.

```
eax=00000010 ebx=00000010 ecx=00000020 edx=04880000 esi=04880000 edi=04880000
eip=04880024 esp=04a7fc20 ebp=04a7fe30 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
04880024 39c8            cmp     eax,ecx

0:005> r zf
zf=0
```

OK, so now we understand **test** and **cmp** we can use them to make decisions:

```asm
start:
  mov eax, 0x10     ;
  mov ecx, 0x20     ;
  cmp eax, ecx      ;
  jnz func1         ; jump is not taken, zf=0
  ; do some stuff
  cmp eax, ecx      ;
  jz end            ; jump is take, zf=0
func1:
  ; do some other stuff
end:
  ; this is the end, my only friend
```

The above example shows how we can use the **cmp** instruction to make decisions and jump over other instructions if needed. Note that it is also possible to jump backwards, not only forwards.

There are other flags that can be used with **test** and **cmp**. Do some research if you want to know more!

### Call Instructions

Coming very soon!

### Arithmetic Instructions

Coming very soon!

### XOR Instructions

Coming very soon!

### The End!

Phew that was a fairly chunky post. I hope it helped readers understand basic x86 32 bit assembly.

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/shellcodez/intro) : [Part 2](https://plackyhacker.github.io/shellcodez/arch)
