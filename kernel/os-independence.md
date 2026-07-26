[Home](https://plackyhacker.github.io)

# OS Independent Kernel Read/Writes

Kernel read/write primitives heavily depend on memory disclosure bugs, and depending on what address is disclosed from kernel space will depend upon how an adversary might weaponise the read/write primitives.

Genrally, wehn you find  memory disclosure in the kernel address space youu want to find the base address of NT module. This serves as an anchor to base your subsequent read/writes from.

Say you want to escalate your privileges and you have the base address of the nt module, your next move might be to locate `PsInitialSystemProcess` which points to the `System` process with the `PID` of `4`. From hear you can steal the `NT Authority/SYSTEM` token and apply it to your explot process by enumerating the `ActiveProcessLinks` list.

In order to get the `PsInitialSystemProcess` offset from the base of the `nt` module you need to know which version of `ntoskrnl.exe` is running - this is not OS independent, meaning you would have to change the code for each target OS.

## Pattern Finding

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
