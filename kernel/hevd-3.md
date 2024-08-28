[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2)

# HEVD Type Confusion Walkthrough on Windows 2022 (Part 3)

In this final part I am going to concentrate on writing the shellcode that we execute in user space once `ret`ing from our ROP chain. Two common techniques are:

- Token Stealing.
- NULLint out ACLs.

Token stealing involves locating the `System` process, or another elevated process, and stealing the security token. We are actually referencing the high privilege token from our low privilege process, not stealing it. 

NULLing out ACLs doesn't actually work on Windows 10 1607 and above. Microsoft patched this. The OS will BSOD if the security descriptor of a privileged process is set to NULL. We can however change the ACL on a security descriptor to give our low privileged process access to the high privileged process to inject shellcode into it to spawn a privileged shell.

There's lots of resources online for writing token stealing shellcode, so I'm going to go the other route, I'll call this **Privilged Process Discretionary ACL Manipulation**.

## Stopping Bugchecks

todo

## Theory

todo

## Shellcode

todo

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2)
