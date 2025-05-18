[Home](https://plackyhacker.github.io)

# Windows Defender Exploit Guard - StackPivot Bypass

## Introduction

Windows Defender Exploit Guard (WDEG) is a security feature designed to mitigate common exploitation techniques in Windows environments. One notable mitigation is **StackPivot**, which protects against stack pivoting attacks often used in Return-Oriented Programming (ROP) exploits. By monitoring for suspicious changes to the stack pointer (`rsp`) during execution, StackPivot ensures the stack remains within legitimate boundaries, preventing attackers from redirecting control flow to malicious code. This strengthens the overall resilience against memory-based exploits.

As my exploit in [previous post](https://plackyhacker.github.io/binary/controlling-the-stack) uses stack pivoting this seems like a good place to start at at attempting to bypass mitigations.

The version of Windows I am working on is:

```
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.17763 N/A Build 17763
```

**Note:** I should be clear that this post is more study notes than research. Allthough the final bypass technique used is my own, research leading up to this was carried out by much cleverer people than me.

## Enabling StackPivot

I am running the vulnerable lab in Windows 10. We can override system settings in WDEG. The first mitigation I am going to apply to the binary is StackPivot:

<img width="645" alt="Screenshot 2025-01-27 at 15 09 25" src="https://github.com/user-attachments/assets/62bf8dd5-01c5-44d1-a6c6-2f166df5c7cc" style="border: 1px solid black;" />

When I run the binary in `WinDbg` it crashes:

<img width="1119" alt="Screenshot 2025-01-27 at 15 14 07" src="https://github.com/user-attachments/assets/790feaf1-fd81-4f5f-bb07-5f43bd8afaf5" style="border: 1px solid black" />

The error code is `0x33 FAST_FAIL_PAYLOAD_RESTRICTION_VIOLATION`. I tested the application again in the debugger, stepping through the ROP chain. The exception occurred whilst `VirtualAlloc` was being executed, but not `GetProcAddress`, we can find more detail in the Windows Event Viewer (`Applications and Services > Microsoft > Windows > Security-Mitigations > User Mode`). An event is logged with ID `20`:

```
Process 'Z:\AWE Projects\VulnAsF\VulnAsF\x64\Release\VulnAsF.exe'
(PID 7516) was blocked from calling the API 'VirtualProtect' due to return-oriented programming (ROP) exploit indications.
```

That's definitely my process and it is definitely not happy that `VirtualProtect` is being called from a pivoted stack on the heap. It looks like the **StackPivot** mitigation in **WDEG** is doing it's job!

We can also observe that the binary has imported the `PayloadRestrictions` module which is injected into the process to implement WDEG mitigations:

<img width="1109" alt="Screenshot 2025-01-27 at 15 28 33" src="https://github.com/user-attachments/assets/164eb393-74bb-4166-8825-27d6433321dc" style="border: 1px solid black" />

The `PayloadRestrictions` module is not loaded into processes where WDEG is not being used for mitigation.

## How WDEG is Implemented

### Function Hooking

To understand how WDEG is implemented we should look at functions that might be protected when stack pivoting. If we look at `GetProcAddresStub` and `VirtualProtectStub` when WDEG is not enabled we see the following:

<img width="1109" alt="Screenshot 2025-01-27 at 15 28 33" src="https://github.com/user-attachments/assets/a90a65cf-aed5-4409-9c1e-4c324efc5539" style="border: 1px solid black" />

This is pretty normal, but look what we observe when WDEG Stack Pivot is enabled:

<img width="1109" alt="Screenshot 2025-01-27 at 15 28 33" src="https://github.com/user-attachments/assets/e7468d3e-5678-42ef-9d79-b3bf93a5e942" style="border: 1px solid black" />

Interestingly there is no change to `GetProcAddressStub`, but `VirtualProtectStub` has been hooked. Function hooking is a technique used to intercept calls to specific functions by redirecting execution to custom code (in this case WDEG) before, after, or instead of the original function. WDEG is pacthing functions at runtime (specifically those that can be used for malicious purposes) to mitigate against Stack Pivoting.

WDEG calls these functions 'critical functions'. These are listed in [EMET 4.1 Uncovered](https://web.archive.org/web/20221026145909/http://0xdabbad00.com/wp-content/uploads/2013/11/emet_4_1_uncovered.pdf) p.16, and I suspect that the list is pretty similar in WDEG.

Two things of note:

- WDEG is implemented in user space using the `PayloadRestrictions` module.
- Not all Win32 APIs, such as `GetProcAddress`, are protected.

Can it be abused? Read on!

### g_MitLibState

Enhanced Mitigation Experience Toolit (EMET) was the predecessor to WDEG and [OffSec](https://www.offsec.com) documented some research on [how to bypass it](https://web.archive.org/web/20221026145648/https://www.offensive-security.com/vulndev/disarming-enhanced-mitigation-experience-toolkit-emet/) by NULLing out a global variable.

The research states "we noticed that the ROP mitigations provided are controlled by two global variables in the .data section, which are located at static offsets. Of these two variables, the first one is probably the most interesting as it acts as a switch to enable or disable the entire set of ROP protections at runtime. To make things even easier, this global variable is located on a memory page marked with read/write permissions".

Is this still the case for WDEG? Well, yes it is but slightly more protected.

Using Binary Ninja and searching the data sections of the `PayloadRestrictions` module we find:

```
.mrdata section started  {0xe4000-0xe57ec}
000e4000  char g_MitLibState = 0x0
000e4001  char data_e4001 = 0x0
000e4002  char data_e4002 = 0x0
000e4003  char data_e4003 = 0x0
000e4004  char data_e4004 = 0x0
000e4005  char data_e4005 = 0x0
...
```

Setting a breakpoint just before the UaF is triggered we can examine this memory location in WinDbg:

```
db PayloadRestrictions+0xe4000 L6
00007ffb`e7984000  01 00 01 00 01 00
```

This appears to be some sort of global flag(s) that switches on mitigations for WDEG in the `PayloadRestrictions` module, similar to the EMET implementation.

It is difficult to confirm this from open sources, however there is a code snippet on GitHub by [spiralBLOCK](https://github.com/SpiralBL0CK/Bypass-PayloadRestrictions.dll-wdeg-rop-mitigation-/blob/main/main.c) that seems to attempt null out this memory location (although it looks like incomplete/erroneous code):

```c
HMODULE payload = GetModuleHandleA("Payloadrestrictions.dll");
// ...
UINT_PTR adr = (UINT_PTR)payload+0xe4004;
// ...
image = VirtualAlloc(NULL, 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(image, "\x00\x00\x00\x00\x00\x00\x00\x00\x00", 8);
// ...
```

Long story, short... It turns out that if we overwrite these flags to `0x00` we can switch off WDEG. There is a problem, as expected the protect level on this memory location is `PAGE_READONLY` so we can't simply overwrite the values using a write primitive:

```
!vprot PayloadRestrictions+0xe4000
BaseAddress:       00007ffbe7984000
AllocationBase:    00007ffbe78a0000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        0000000000002000
State:             00001000  MEM_COMMIT
Protect:           00000002  PAGE_READONLY
Type:              01000000  MEM_IMAGE
```

We need a way to change the memory protections on the memory and zero out the flag(s).

## Bypassing WDEG

### API Calls

App > Win32 > NDTLL > Kernel

### NtProtectVirtualMemory

Cut out the middle function. Offset the call...

### Switch WDEG Off

ROP chain...

## Conclusion


## References

- [EMET 4.1 Uncovered](https://web.archive.org/web/20221026145909/http://0xdabbad00.com/wp-content/uploads/2013/11/emet_4_1_uncovered.pdf)
- [Bypassing EMET 4.1](https://web.archive.org/web/20220710085735/https://bromiumlabs.files.wordpress.com/2014/02/bypassing-emet-4-1.pdf)
- [Disarming and bypassing EMET 5.1](https://web.archive.org/web/20221017011819/https://www.offensive-security.com/vulndev/disarming-and-bypassing-emet-5-1/)
- [Bypass-PayloadRestrictions.dll-wdeg-rop-mitigation](https://github.com/SpiralBL0CK/Bypass-PayloadRestrictions.dll-wdeg-rop-mitigation-/blob/main/main.c)

[Home](https://plackyhacker.github.io)
