[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2)

# HEVD Type Confusion Walkthrough on Windows 2022 (Part 3)

In this final part I am going to concentrate on writing the shellcode that we execute in user space once `ret`ing from our ROP chain. Two common techniques are:

- Token Stealing.
- NULLint out ACLs.

Token stealing involves locating the `System` process, or another elevated process, and stealing the security token. We are actually referencing the high privilege token from our low privilege process, not stealing it. 

NULLing out ACLs doesn't actually work on Windows 10 1607 and above. Microsoft patched this. The OS will BSOD if the security descriptor of a privileged process is set to NULL. We can however change the ACL on a security descriptor to give our low privileged process access to the high privileged process to inject shellcode into it to spawn a privileged shell.

There's lots of resources online for writing token stealing shellcode, so I'm going to go the other route, I'll call this **Privileged Process Discretionary ACL Manipulation**.

I first read about this [here](https://blog.improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-2), so I can't take any credit for the technique.

## Stopping Bugchecks

Recently I learned from [this blog](https://www.linkedin.com/safety/go?url=https%3A%2F%2Fwafzsucks.medium.com%2Fhow-a-simple-k-typeconfusion-took-me-3-months-long-to-create-a-exploit-f643c94d445f&trk=flagship-messaging-web&messageThreadUrn=urn%3Ali%3AmessagingThread%3A2-NmRhNTQ0YTItNDAzYi00NDYzLWIzZDQtMjNiNThiOWZmYmI1XzAxMg%3D%3D&lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base%3B%2BbayF5W%2FTdqVBXlFeoIMxg%3D%3D) that trying to step through code when the stack is pivoted can be a pain, with bugchecks commonplace. So we can step through our shellcode without generating a BSOD, we should restore the stack as early as possible in our shellcode:

```
BITS 64
SECTION .text

global main

main:
restore_stack:
    ; restore stack early to avoid stack pivot debugging errors
    mov rsp, r11

; our main shellcode will go in here

the_end:
    ret
```

Remember from previous posts that we only have to move `r11` in to `rsp` to restore the stack. If we do this we can insert breakpoints in our shellcode and step through it now that the stack has been restored to its previous state.

## Theory

todo

## Shellcode

### Finding KPROCESS

todo

### Locating winlogon.exe

todo

### Patching the DACL

todo

### Patching the Mandatory Policy

todo

## Process Injection

todo

### Getting the PID of winexec.exe

todo

### Locating WinExec

todo

### User Mode Shellcode

todo

### Win32 APIs

todo

## Final Exploit

todo

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2)
