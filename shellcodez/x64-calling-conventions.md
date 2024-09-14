# Exploring x64 Calling Conventions

It is a really useful to be able to include `asm` or 'shellcode' in your Visual Studio projects when you are studying or writing exploits for known bugs/CVEs, I'd go as far as to say it is a prerequisite.

Calling conventions define how functions receive parameters and return values, ensuring consistency between caller and callee. They standardise the use of registers and stack memory.

Write a basic function in `asm`.

Call the function from C code.

Break in the function and examine the registers and stack in Windbg.

**Be patient, I am writing this!**
