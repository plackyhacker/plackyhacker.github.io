[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/shellcodez/intro)

# Writing Custom Shellcode, x86 32-Bit Architecture

Assembly language is a low-level programming language and is not generally used by developers to write full blown applications. Applications are written in high-level programming language, such as C, and are compiled into machine code. Machine code is binary that is encoded into instructions that are understood by the CPU. Assembly language is a human-readable representation of machine code.

We write shellcode in assembly language because we want to inject small pieces of code into memory without all of the overhead of a fully compiled application.

## Basic x86 Architecture

The following diagram shows a high-level view of x86 architecture.

<img width="851" alt="Screenshot 2023-02-07 at 19 30 59" src="https://user-images.githubusercontent.com/42491100/217346384-a46f91c6-f238-40b3-aaa9-32e3a1de5a9d.png">

The three buses are used to carry data, control instructions, and addressing. These aren't that important in the context of writing shellcode, so will not be discussed.

The next sections will give enough information to begin writing basic shellcode in x86 assembly language.

## The ALU

The Arithmetic Logic Unit is the brains of the CPU. The ALU carries out calculations, compares values, increments values etc. Once the values have been processed they are generally stored in a general purpose register, for example the following opcode will be processed by the ALU and the CPU control unit (which we will not discuss) will save the result in the **eax** register:

```asm
add eax, ecx    ; add the value in the ecx register 
                ; to the value in the eax register and store in the eax register
```

## Registers

Registers are a type of memory that is rapid for other parts of the CPU to access, but is expensive (and therefore the capacity is small). RAM is cheaper (and therefore the capacity is larger) but slower to access (in CPU terms). For this reason the CPU contains registers that can be used for rapid storage of values upto and including 32 bits in length.

The registers that we use the most when writing shellcode are the general purpose registers:

<img width="693" alt="Screenshot 2023-02-07 at 20 04 13" src="https://user-images.githubusercontent.com/42491100/217353012-2aaf1778-e4d7-4062-965f-3dbcf464e503.png">

If we want to access only the lower 16 bits of the **eax** register we refer to it as **ax**, the lower 8 bits as **al**, and the higher 8 bits of **ax** we refer to as **ah**. This can be useful in shellcode, which will be discussed in a later article.

We can move values into registers and carry out arithmetic operations on them. For example:

```asm
mov eax, 0x10   ; move the value 0x10 into the eax register
add eax, 0x20   ; the eax register now stores the value 0x30
```

Two registers of note are **esp**; the extended stack pointer and **ebp**; the extended base pointer. These will be discussed in the stack section.

Most people that have done any sort of buffer overflow study will know what the **eip** pointer is. It is the extended instruction pointer, and points at the address of thext instruction to be executed.

## Flags

Flags are used to control the flow of code. These are the instructions that are compiled from conditional statements and loops in `C`:

```c
if (x > 10) { // do something }
```

When the CPU carries out mathematical operations it changes the state of flag registers depending upon the result of the operation. Consider the following:

```asm
mov ecx, 0x10   ; assign the value 0x10 to the ecx register
mov eax, 0x10   ; assign the value 0x10 to the eax register
cmp eax, ecx    ; compare the value in eax to the value in ecx
                ; the values are the same so the zero-flag (ZF) is set to 1
```

We can then control the flow of the instructions using a **jnz** (jump not zero) instruction:

```asm
jnz do_something ; jump to do_something if the ZF is 1
```

These flags will be discussed when we use them in our shellcode. Note that `do_something`, like comments, is not a machine code, it is used in assembly language to label group instructions (referred to as functions). This makes it easier to organise your shellcode when writing it.

**Note:** not all flags are used by conditional instructions, for example the **interupt flag** determines whether external inputs should be processed or not.

## Random Access Memory

Coming very soon

## The Stack

Coming very soon

## Just Enough Assembly

Assembly language statements are made up of a **mnemonic**, **operands**, and **comments** (although comments aren't sent to the CPU). The following is a simple example:

```asm
mov eax, 0x10     ; move the value 0x10 into the eax register
```

I will refer to this as an **opcode**.

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/shellcodez/intro)
