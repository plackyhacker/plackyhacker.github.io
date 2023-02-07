[Previous - Introduction](https://plackyhacker.github.io/shellcodez/intro) : [Home](https://plackyhacker.github.io) : [Next - Finding Kernel32](https://plackyhacker.github.io/shellcodez/finding-kernel32)

# Writing Custom Shellcode, x86 32-Bit Introduction

Assembly language is a low-level programming language and is not generally used by developers to write full blown applications. Applications are written in high-level programming language, such as C, and are compiled into machine code. Machine code is binary that is encoded into instructions that are understood by the CPU. Assembly language is a human-readable representation of machine code.

We write shellcode in assembly language because we want to inject small pieces of code into memory without all of the overhead of a fully compiled application.

## Registers

Coming very soon

## Stack Basics

Coming very soon

## Just Enough Assembly

Assembly language statements are made up of a **mnemonic**, **operands**, and **comments** (although these aren't sent to the CPU. The following is a simple example:

```asm
mov eax, 0x10     ; move the value 0x10 into the eax register
```

I will refer to this as an **opcode**.

[Previous - Introduction](https://plackyhacker.github.io/shellcodez/intro) : [Home](https://plackyhacker.github.io) : [Next - Finding Kernel32](https://plackyhacker.github.io/shellcodez/finding-kernel32)
