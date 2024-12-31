[Home](https://plackyhacker.github.io)

# Mixing it up: ROP and COP

We all know what ROP chains are right? No? If you want to do binary exploitation of any kind then you need to understand ROP, this post is about Call-oriented programming (COP) so I'm going to be lazy and post a link: [Return-oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming).

Studying for my OffSec Exploitation Expert (OSEE) exam, more specifically the VMWare escape use case, we find that one of the ROP chains contains a `call rsi` instruction. Becasue of the way `call` instructions work this presents a problemm as they modify the stack which disrupts the normal flow of a ROP chain. Whenever I hear the term 'call-oriented programming' I get a little bit shaky/nervous, turns out I needn't!

## The Problem

The case presented was to build a ROP chain to call the WIndows `GetProcAddress` API, the API has the following signature:

```c
FARPROC GetProcAddress(
  [in] HMODULE hModule,
  [in] LPCSTR  lpProcName
);
```

Using the `__stdcall` calling convention this means moving the module address into `rcx` and a pointer to the function name string into `rdx`, fairly standard stuff so far. The problem is that there are no gadgets which contain `mov rdx, r62`. There is actually one gadget but it presents a problem:

```
mov rdx, rax ; call rsi ;
```

The problem is that a valid call address must be in `rsi` before this is called and `call` instructions push the saved return address on to the stack which alters the ROP chain on the stack.

## Analysis

I decided to understand this a bit better. I decided to step through and document the stack/registers as I went along. I started with the following ROP chain snippet (notice the `call` instruction and the absence of a `ret` instruction in that gadget):

```
...
pop rsi ; ret ;
pop rax ; ret ; (executed by call rsi)
mov rdx, rax; call rsi ;
pop rax ;
[temporary storage address of kernelbase.dll base address]
mov rcx, [rax] ; mov rax, [rax + 8] ; add rax, rcx ; ret ;
...
```

This is what the stack and the registers look like at this point, remember that the objective is to get the value in `rax` moved into `rdx`:

<img width="818" alt="Screenshot 2024-12-18 at 10 24 33" src="https://github.com/user-attachments/assets/84b5edc8-29c2-4a8b-95f7-2fdb4addcf7d" style="border: 1px solid black;" />

When the `pop rsi ; ret ;` gadget is executed the `address of pop rax ; ret ;` gadget will be popped in to `rsi`. This adds `0x10` to `rsp`, the stack/registers now look like the following:

<img width="823" alt="Screenshot 2024-12-18 at 10 27 57" src="https://github.com/user-attachments/assets/46861e0b-8523-4372-8b6e-abcdb5269c71" style="border: 1px solid black;" />

The next gadget `mov rdx, rax ; call rsi ;` moves `rax` into `rdx` (as intended) and then makes the call to the address we popped in to `rsi`.

When a `call` is made the saved return address is pushed on to the stack and `rsp` points to it, effectively not moving the stack pointer from our viewpoint but the gadget address we are executing has been overwritten (which is fine). The clever part comes next:

<img width="821" alt="Screenshot 2024-12-18 at 10 34 19" src="https://github.com/user-attachments/assets/1f913f05-e1a8-4719-a131-6d9af2be4874" style="border: 1px solid black;" />

We have pushed a `pop ret` gadget into `rsi` so when the gadget is executed it pops the saved return address into `rax`, which adds `0x8` to `rsp` restoring our ROP chain nicely:

<img width="820" alt="Screenshot 2024-12-18 at 10 35 58" src="https://github.com/user-attachments/assets/7933529b-136c-4d20-80c4-7d257653b3e4" style="border: 1px solid black;" />

This gadget pops the `KerneBase.dll` address into `rax`, and the final ROP gadget in our snippet dereferrences the address in to `rcx` and our objective is completed:

<img width="829" alt="Screenshot 2024-12-18 at 10 37 51" src="https://github.com/user-attachments/assets/7ee6dfcd-b78a-4f67-848d-00dc8cf70110" style="border: 1px solid black;" />

Now I understood this I wondered if there was a 'general' workflow I could apply to these scenarios.

## Worflow

If I need to use Call-oriented programming gadgets in my ROP chains I will be sure to step through them to understand how they work and that I get the intended result. As a general rule for the scenario discussed I think this works:

<img width="1046" alt="Screenshot 2024-12-18 at 10 45 49" src="https://github.com/user-attachments/assets/a376e69e-99b5-4283-8176-335a91575d26" style="border: 1px solid black;" />

Granted, I need to test this theory out with more examples.

Thank you, and goodnight!

[Home](https://plackyhacker.github.io)
