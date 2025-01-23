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

This is, of course, invalid memory and will still crash. What we need is a stack pivot, but first we need somewhere to store a ROP chain to pivot to.

## ROP Chain



[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/binary/all-the-leaks) : Part 2
