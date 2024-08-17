# HEVD Type Confusion Exploit in Windows 2022

## Introduction

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
