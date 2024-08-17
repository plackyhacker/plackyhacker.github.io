[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2) : [Part 3](https://plackyhacker.github.io/kernel/hevd-2)

# HEVD Type Confusion Exploit in Windows 2022

## Introduction

Why should we be interested in driver exploits? The answer to that is that on Windows architecture drivers execute their code in kernel space. This is very desirable for a threat actor, if there is a vulnerability in the driver code and it can be exploited it can be used to gain privilege escalation from user mode. This is because user mode can interact with kernel mode via drivers.

Chances are if you have taken an interest in kernel exploitation you have heard of the **Hacksys Extreme Vulnerable Driver**.

The [GitHub page](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) for the driver states "The HackSys Extreme Vulnerable Driver (HEVD) is a Windows Kernel driver that is intentionally vulnerable. It has been developed for security researchers and enthusiasts to improve their skills in kernel-level exploitation". I don't need to say anything else about this great resource.

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

Loading the `HEVD.sys` file into IDA we can locate dthe `DriverEntry` function and examine the pseudocode (using the menu: View > Open subviews > Genertae psuedocode):

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

In `C++`he `->` operator is used with pointers to access members (variables or methods) of an object, in this instance `DriverObject`. Effectively this code registers a new dispatch routine called `HEVDDeviceControl`. Notice from our **Windbg** output that `IRP_MJ_DEVICE_CONTROL` is equal to `0x0e` (go back and take a look). Let's go back to the `HEVDDriverSetup` pseudocode and pick out the bits we need:

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

I have renamed `a1` to `DriverObject`. We can see that starting it an offset of `0x0e` some functions are being assigned to memory, these are the dispatch routines. If we add `0x0e` (the base offset, and `0x0e` which we believe to be our `IRP_MJ_DEVICE_CONTROL` dispatch function we get `0x1c`. If we follow this we end up at the following function:

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

[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2) : [Part 3](https://plackyhacker.github.io/kernel/hevd-2)
