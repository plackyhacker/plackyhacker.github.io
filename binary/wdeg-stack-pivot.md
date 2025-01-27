

# Windows Defender Exploit Guard - StackPivot

## Introduction

Intro to WDEG...

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

That's definitely my process and it is definitely not happy that `VirtualProtect` is being called from a pivoted stack oon the heap. It looks like the **StackPivot** mitigation in **WDEG** is doing it's job!

We can also observe that the binary has imported the `PayloadRestrictions` module which is injected into the process to implement WDEG mitigations:

<img width="1109" alt="Screenshot 2025-01-27 at 15 28 33" src="https://github.com/user-attachments/assets/164eb393-74bb-4166-8825-27d6433321dc" style="border: 1px solid black" />


