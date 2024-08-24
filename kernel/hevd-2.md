[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 3](https://plackyhacker.github.io/kernel/hevd-3)

# HEVD Type Confusion Walkthrough on Windows 2022 (Part 2)

## We Have Code Execution

At the end of part 1 we had code execution, we were able to pass a 16 byte buffer into the driver vio an IOCTL. If our target was Windows 7 we could simply write some shellcode, allocate some memory in user space, copy our shellcode to this memory, and trigger the type confuusion bug to execute our code. In modern Windows OSes, such as Server 2022, we can't do that.

## Supervisor Mode Execution Prevention

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

typedef uint64_t QWORD;

QWORD GetKernelBase()
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);

    return (QWORD)drivers[0];
}

int main() {
  // get the base of the kernel
  QWORD kernelBase = GetKernelBase();
  printf("[+] Kernel base: 0x%p\n", kernelBase);

  // let's not trigger the bug yet!
  return;

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
}
```

Now we have the base address of the kernel we can search for code chunks or gadgets that we can chain together to acheive our goal.

## Return Oriented Programming

todo

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 3](https://plackyhacker.github.io/kernel/hevd-3)
