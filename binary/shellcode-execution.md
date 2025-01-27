[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/binary/all-the-leaks) : [Part 2](https://plackyhacker.github.io/binary/controlling-the-stack) : Part 3

# Shellcode Execution

In this blog post I will be exploring getting shellcode execution in my vulnerable DLL.

## Introduction

This series of posts has started to grow arms and legs. I have so many ideas where I can take this. This is good because I am learning lots of new techniques. It also bad because I don't seem to have enough time to write about it all! In this post I will be using the vulnerable functions in the DLL to allocate a shellcode buffer on the stack, write a ROP chain using the arbitrary write primitive, I will demonstrate how to resolve `VirtualProtect` using a ROP chain and the IAT. After this I will call `VirtualProtect` on the shellcode buffer and execute it.

## Allocating a Shellcode Buffer

## Arbitrarily Writing a ROP Chain

## GetProcAddress

## VirtualProtect

## Testing the Exploit

## What Next?

Although we have shellcode execution, when we exit the shellcode the binary crashes, and while the shellcode is running the binary does not continue to function. This is fine in my little lab and is fine to proof-of-concept vulnerabilities but using these techniques against an operational system alone is going to crash it. I really want to start exploring Windows mitigations, but I also want the exploit in a finished state before I move on. I need time to think!

Goodbye!

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/binary/all-the-leaks) : [Part 2](https://plackyhacker.github.io/binary/controlling-the-stack) : Part 3
