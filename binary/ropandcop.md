[Home](https://plackyhacker.github.io)

# Mixing it up: ROP and COP

We all know what ROP chains are right? No? If you want to do binary exploitation of any kind then you need to understand ROP, this post is about COP so I'm going to be lazy and post a link: [Return-oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming).

Studying for my OffSec Exploitation Expert (OSEE) exam, more specifically the VMWare escape use case, we find that one of the ROP chains contains a `call rsi` instruction. Becasue of the way `call` instructions work this presents a problemm as they modify the stack which disrupts the normal flow of a ROP chain. 

## The Problem

The case presented was to build a ROP chain to call the WIndows `GetProcAddress` API, the API has the following signature:

```c
FARPROC GetProcAddress(
  [in] HMODULE hModule,
  [in] LPCSTR  lpProcName
);
```

Using the `__stdcall` calling convention this means moving the module address into `rcx` and a pointer to the function name string into `rdx`, fairly standard stuff so far. The problem is that there are no gadgets which contain `mov rdx, r63`. There is actually one gadget but it presents a problem:

```
mov rdx, rx ; call rsi ;
```

The problem is that a valid call address must be in `rsi` before this is called and `call` instructions push the saved return address on to the stack which alters the ROP chain on the stack.

## Analysis

I decided to understand this a bit better. I decided to step through and document the stack/registers as I went along. I started with the following ROP chain snippet (notice the `call` instruction and the absence of a `ret` instruction in that gadget):

```
pop rsi ; ret ;
pop rax ; ret ; (executed by call rsi)
mov rdx, rax; call rsi ;
pop rax ;
[temporary storage address of kernelbase.dll base address]
```

This is what the stack and the registers look like at this point, remember that the objective is to get the value in `rax` moved into `rdx`:

<img width="815" alt="Screenshot 2024-12-18 at 09 25 00" src="https://github.com/user-attachments/assets/446d81d4-8b66-4efb-913d-dd25386e7fef" style="border: 1px solid black;" />

[todo]

## Worflow

[todo]

I am always sure to step through ROP/COP chains to understand how they work and that I get the intended result.

[Home](https://plackyhacker.github.io)
