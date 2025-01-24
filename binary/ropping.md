[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/binary/all-the-leaks) : Part 2

# Ropping

In the previous part I buit a vulnerable DLL to demonstrate how an information disclosure bug and a read primitive can be used to leak multiple module base addresses. I have developed the vulnerable DLL a bit more and added some more dodgy functionalitiy with which to explore exploitation without having to worry about great deal about bug discovery:

<img width="1381" alt="Screenshot 2025-01-23 at 18 35 42" src="https://github.com/user-attachments/assets/bed35364-45c3-44d1-9722-06c84c7a87f6" style="border: 1px solid black;" />

- **Allocate**: this allocates memory of an arbitrary size on the LFH and copies an arbitrary buffer to it.
- **ArbitraryRead**: this was demonstrated in the previous post and simulates and arbitrary read bug.
- **ArbitraryWrite**: this demonstrates and arbitrary write bug.
- **FreeAllocation**: this is used to simulate a Use After Free by freeing a very specific LFH allocation.
- **GlobalAllocate**: this function allocates memory (general buffer) on the default process heap of arbitrary size and copies a buffer to it.
- **LeakModuleAddress**: this was demonstrated in the last post and leaks the DLL base address.
- **TriggerUaf**: this function attempts to call the function pointer in the specific LFH allocation. If the allocation is freed then the app will crash.
- **Global Pointer**: there is also a global pointer which points to the general buffer.

I am starting with only basic mitigations, such as ASLR and DEP/NX.

## Use After Free Simulation

The code I have created does not use C++ classes so does not generate a real UaF (you can learn about those [here](https://plackyhacker.github.io/classes/use-after-free)), instead the initial allocation points to the `GetLastError` Win32 API. If the `FreeAllocation` function is not called then a call to the `TriggerUaF` function will not crash the application. Let's free the allocation and run it in `WinDbg` using the following code:

```c
FreeAllocation();

TriggerUaF();
```

Running this with the debugger attached we get a crash:

<img width="1113" alt="Screenshot 2025-01-23 at 18 46 38" src="https://github.com/user-attachments/assets/74cae532-1a68-4e8c-9fb9-0cda513c3b46" style="border: 1px solid black;" />

Doing a bit of gentle reverse engineering in IDA we can see that in the `TriggerUaF` function there is a `jmp` instruction at offset `0x1192` in the `DLL` file:

<img width="570" alt="Screenshot 2025-01-23 at 18 49 23" src="https://github.com/user-attachments/assets/ddcd5398-275f-4300-babf-854c83f4e2d5" style="border: 1px solid black;" />

We can put a breakpoint on this address and rerun the application with the debugger attached:

<img width="891" alt="Screenshot 2025-01-23 at 18 50 51" src="https://github.com/user-attachments/assets/faff2ae4-8d6b-472d-86c6-1715f3913774" style="border: 1px solid black;" />

We can see that `rax` points to the freed allocation, and that the allocation was of size `0xd0`. For reasons I don't really understand (yet), the actual allocation was `0xb0`; to overwrite this pointer we need to make the correct allocation request.

## Reallocation

I wrote a [blog post](https://plackyhacker.github.io/binary/lfh-win7-and-beyond) a few weeks ago about how we can attempt to reallocate to freed addresses on the LFH. I am running my application in Windows 10 so I need to brute force the LFH to attempt to overwrite the previously allocated pointer:

```c
FreeAllocation();

// attempt to reallocate to the freed memory
LPVOID alloc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xb0);
if (alloc != NULL)
{
    memset(alloc, 0x41, 0xb0);
    *(LONGLONG*)alloc = (LONGLONG)0x1337133713371337;
}

// brute force the LFH
for (size_t c = 0; c < 0x100; c++)
{
    Allocate(alloc, 0xb0);
}

TriggerUaF();
```

Setting a breakpoint at the same memory location and running the application we can see that we have brute forced the function pointer with `0x1337133713371337`:

<img width="1120" alt="Screenshot 2025-01-23 at 19 02 45" src="https://github.com/user-attachments/assets/08429b24-d983-4e5e-9217-27831eb9e6f3" style="border: 1px solid black;" />

This is, of course, invalid memory and will still crash. We can also view the LFH allocation that contains the fake function pointer:

<img width="1115" alt="Screenshot 2025-01-23 at 19 10 48" src="https://github.com/user-attachments/assets/824bba5b-53e2-459e-8849-89cc54081ac9" style="border: 1px solid black;" />

What we need next is a stack pivot gaget that begins execution of a ROP chain. First we need somewhere to store a ROP chain to pivot to.

## ROP Chain Location

We know there is a `GlobalAllocate` function in the vulnerable DLL, but what does it allow us to do. Some more gentle reverse engineering:

<img width="482" alt="Screenshot 2025-01-23 at 19 15 35" src="https://github.com/user-attachments/assets/f6829a52-00dc-48e9-ab05-56e07820d00d" style="border: 1px solid black;" />

The last block in the `GlobalAllocate` function calls `HeapAlloc` using the arguments we send and we also see that the return value (in `rax`) which is the address of the allocation is stored in a global variable called `g_general_buffer`. We can easily locate this buffer using IDA:

<img width="1121" alt="Screenshot 2025-01-23 at 19 18 50" src="https://github.com/user-attachments/assets/00fc7409-8fe8-4d04-b4f1-e11ba6d5515b"  style="border: 1px solid black;" />

Global variables are located in the `.data` section and the addresses of these are at a static offset from the base address of the module. In the last post I demonstrated that we can get the DLL base aaddress so we can dynamically calculate the address of the global variable that points to the buffer that we can allocate using the vulnerable `GlobalAllocate` function.

We can also use the arbitrary read to dereference this global variable and 'leak' the allocated address for the general buffer. If we can pivot the stack to this address it will make a perfect location for a fake stack with which to execute a ROP chain, and becasue we have an arbitrary read/write primitive we can write temporary values to it.

Let's see if we can allocate some memory, run the application in the debugger, and see if we can locate it using the global variable address:

```c
FreeAllocation();

// ...

// allocate to the general buffer
LPVOID globalAlloc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
if (globalAlloc != NULL)
{
    memset(globalAlloc, 0x42, 0x1000);
    GlobalAllocate(globalAlloc, 0x1000);
}

DebugBreak();

TriggerUaF();
```

I simply created a buffer of `0x1000` bytes and written `0x42` to every byte. When the debugger breaks we can see if the global variable points to the allocated buffer:

<img width="1065" alt="Screenshot 2025-01-23 at 19 29 05" src="https://github.com/user-attachments/assets/83ccc4e3-03b1-4a3e-8a81-656dc77b697c" style="border: 1px solid black;" />

It does! And interestingly when we get to the `jmp` instruction which jumps to our reallocated pointer, `rbx` also points to our buffer:

<img width="1139" alt="Screenshot 2025-01-23 at 19 32 46" src="https://github.com/user-attachments/assets/db12b083-7c9b-4a97-b867-609571a52472" style="border: 1px solid black;" />

If we could find a `mov rsp, rbx` gadget then we could pivot the stack to this general buffer, and you know that is going to be possible - this is a simulation after all!

## Stack Pivoting


We an use `rp-win.exe` to look for ROP gadgets that might help us pivot the stack:

<img width="866" alt="Screenshot 2025-01-24 at 08 00 48" src="https://github.com/user-attachments/assets/3b466861-a8fc-459c-90ae-025746a1d8fc" style="border: 1px solid black;" />

And I find the correct gadget in `VulnDLL.dll`:

<img width="897" alt="Screenshot 2025-01-24 at 08 02 35" src="https://github.com/user-attachments/assets/1c074fb5-2efd-4d6c-b437-7b14ac1de8e0" style="border: 1px solid black;" />

This should come as no surpirse. I am exploring exploit development techniques, so I simply planted this rop chain in my code (in a more realistic scenario this is going to be a bit more difficult to find a ROP gadget that will achieve our objective). I added an `asm` function to the vulnerable DLL:

```asm
.CODE

ROPGadgets PROC

	mov rsp, rbx;
	ret;

ROPGadgets ENDP

END
```

Now we have a ROP gadget to pivot the stack we can change our exploit code to brute force the freed LFH chunk with our stack pivot gadget:

```c
// attempt to reallocate to the freed memory
LPVOID alloc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xb0);
if (alloc != NULL)
{
    memset(alloc, 0x41, 0xb0);
    *(LONGLONG*)alloc = (LONGLONG)(dllBase + 0x1290);                           // mov rsp, rbx ; ret ;
}                                                                               // rbx points to our general buffer (rop chain)

// brute force the LFH
for (size_t c = 0; c < 0x100; c++)
{
    Allocate(alloc, 0xb0);
}
```

Testing this in `WinDbg` by adding a breakpoint on `VulnDll + 0x1290` we can test our theory out:

<img width="944" alt="Screenshot 2025-01-24 at 08 10 42" src="https://github.com/user-attachments/assets/33da2c65-c882-476f-8e74-ff107c4ee367" style="border: 1px solid black;" />

When we run the application we hit our breakpoint. We can step through `mov rsp, rbx` and then `ret` and we get an `Access Violation`; this is good! If we look at where `rsp` now points, it points to the general buffer. This means we have pivoted our stack to an area of memory that we control. We can write a test ROP chain to this memory next.

## Test ROP Chain

In the final part of this blog I will write to the general buffer with a test ROP chain; basically some ROP NOPs and an `int3` instruction. Just to prove that it works as intended.:

```c
// allocate to the general buffer
LPVOID globalAlloc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
if (globalAlloc != NULL)
{
    memset(globalAlloc, 0x42, 0x1000);

    // build rop chain in the general buffer
    DWORD index = 0;
    PDWORD64 rop = (PDWORD64)(globalAlloc);

    rop[index] = dllBase + 0x1007; index += 1;                                  // ret ; (rop nop)
    rop[index] = dllBase + 0x1007; index += 1;                                  // ret ; (rop nop)
    rop[index] = dllBase + 0x1007; index += 1;                                  // ret ; (rop nop)
    rop[index] = dllBase + 0x1007; index += 1;                                  // ret ; (rop nop)
    rop[index] = ntdllBase + 0xa3060; index += 1;                               // int3 ; ret ; (debug)

    GlobalAllocate(globalAlloc, 0x1000);
}
```

Instead of allocating and writing `0x1000` `B` characters I have allocated and written a very small ROP chain to test that everything works as intended. Let's test this!

<img width="954" alt="Screenshot 2025-01-24 at 08 20 10" src="https://github.com/user-attachments/assets/93d02e13-424e-4166-98f1-1bfa211dd845" style="border: 1px solid black;" />

Everything looks to be working as intended. We break on the brute forced stack pivot, we step through the pivot and note that the stack is now located at our allocated general buffer, when we continue execution we hit the `int3` ROP gadget. We now have code execution!

Hopefully this helps illustrate what has happened so far:

<img width="1061" alt="Screenshot 2025-01-24 at 08 35 17" src="https://github.com/user-attachments/assets/5c6b5e40-09dc-4d4c-a59e-a739eeca32df" style="border: 1px solid black;" />

## What Next?

In the next part things will start to get interesting. If all goes to plan, I will write about how I will execute shellcode in the general buffer, repair the registers and the stack (so the app doesn't crash), and start switching on mitigations! This is the main reason I am writing all of this. It is good to solidify my understanding of the exploitation techniques so far, but I need to understand the mitigations in Windows and how I might be able to work around them.

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/binary/all-the-leaks) : Part 2
