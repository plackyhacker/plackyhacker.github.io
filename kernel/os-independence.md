[Home](https://plackyhacker.github.io)

# OS Independent Kernel Read/Writes

In this post I am going to explore how a kernel memory disclosure bug (along with a kernel read/write bug) can be weaponised to write OS version independent code in Windows.

## Introduction

Kernel read/write primitives heavily depend on memory disclosure bugs, and depending on what address is disclosed from kernel space will depend upon how an adversary might weaponise the read/write primitives.

Genrally, when you find  memory disclosure in kernel address space you want to find the base address of the `nt` module. This serves as an anchor to base subsequent read/writes from.

Say you want to escalate your privileges and you have the base address of the `nt` module, your next move might be to locate `PsInitialSystemProcess` which points to the `System` process. From here you can steal the `NT Authority/SYSTEM` token and apply it to your exploit process by enumerating the `ActiveProcessLinks` list. This is a standard approach to privilege escalation.

In order to get the `PsInitialSystemProcess` offset from the base address of the `nt` module you need to know which version of `ntoskrnl.exe` is running - this is not OS independent, meaning you would have to change the code for each target OS.

There are projects out there that have already solved this problem but I wanted to look at this myself in the interests of further developing my skills.

## Loading ntoskrnl.exe Locally

By far the easiest...

## Pattern Finding

Pattern finding seems like the obvious place to start, and I have used this successfully when developing code for BYOVD-type drivers that expose an arbitrary `__rdmsr` instruction and return value to user-mode.

Weaponising a ReadMSR bug is straight-forward, you send the MSR (Model Specific Register) you want to read via a `DeviceIOControl` call and the kernel sends back the response; the caveat is you have to reverse engineer the structs the kernel code expects.

There is an interesting MSR (the `IA32_LSTAR`) at address `0xc0000082` which returns the address of the `KiSystemCall64` (or a variation of) back to the caller. If we know the offset of `KiSystemCall64` then we can calculate the base address of the `nt` module. The problem is we cannot simply load the `ntoskrnl.exe` locally and locate the `KiSystemCall64` address using `GetProcAddress`. The symbol is not in the export address table (EAT) and cannot be resolved in this way.

Useful in finding 

Need to load the local ntoskrnl from disk, find the pattern offset, calculate the actual base address of NT.

Has limitations, especially when finding functions such as psp...

Usefull to find ROP gadgets, where you can still execute them...

## Assembly Decoding

Similar to pattern finding but it takes a lot of effort, also has limitations, code finder functions for each symbol...

## Program Database Files (PDB)

### Locating the PDB

### 

[Home](https://plackyhacker.github.io)
