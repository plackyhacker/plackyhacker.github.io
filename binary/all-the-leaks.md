[Home](https://plackyhacker.github.io) : Part 1 : [Part 2](https://plackyhacker.github.io/binary/ropping)

# All the Leaks

I am still studying towards OSEE. Here's another post exploring some basics: Leaking module base addresses.
 
## Introduction

Modern exploitation generally requires the attacker to chain multiple vulnerabilites together to reach a specific goal (most likely code execution). To help me understand different exploitation techniques and mitigations in Windows (perhaps a little later) I have decided to create an application that focuses on exploitation techniques rather than finding bugs. So I am interested in how I can use those bugs to chain together exploitation code.

I am starting quite small. My application will contain three primitives/bugs, an information disclosure bug, an arbitrary read primitive, and an arbitrary write primitive.

<img width="618" alt="Screenshot 2025-01-21 at 16 24 25" src="https://github.com/user-attachments/assets/2507bc12-1b79-47ac-bbb5-2d5465f88068" style="border: 1px solid black;" />

I am writing the vulnerable functions in a DLL so I don't need to write code that wraps the vulnerable functions in a TCP server, although it could be done at a later date:

<img width="959" alt="Screenshot 2025-01-21 at 16 25 57" src="https://github.com/user-attachments/assets/78ac6057-6697-4e73-863d-49edefbfeb9f" style="border: 1px solid black;" />

Again, this is so I can focus on the parts I need to learn more. I want to be able to easily write exploits without first having to reverse engineer the applications and find the bugs. This is an important discipline but I want to concentrate on exploitation at this moment in time.

## Vulnerable DLL Code

Let's take a very quick look at the vulnerable DLL, and I mean vulnerable - of course there would need to be some mechanism for attackers to interact with these functions, such as a TCP server that calls them! BUT there's no messing about, it is VERY vulnerable, by design.

```c
#include "pch.h"
#include <windows.h>

extern "C" {
    __declspec(dllexport) HMODULE LeakModuleBase();
    __declspec(dllexport) LONGLONG ArbitraryRead(LONGLONG memory);
    __declspec(dllexport) void ArbitraryWrite(LONGLONG memory, LONGLONG hexValue);
}

static HMODULE g_hModule = NULL;

// Simulate an info disclosure vulnerability, current module base address
__declspec(dllexport) HMODULE LeakModuleBase() {
    return g_hModule;
}

// Simulate an arbitrary read primitive
__declspec(dllexport) LONGLONG ArbitraryRead(LONGLONG memory) {
    return (LONGLONG) * (LONGLONG*)memory;
}

// Simulate an arbitrary write primitive
__declspec(dllexport) void ArbitraryWrite(LONGLONG memory, LONGLONG hexValue) {
    *(LONGLONG*)memory = hexValue;
}


// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            g_hModule = hinstDLL;
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        }
    return TRUE;
}
```

It doesn't need much explaining. We can leak the base address of the DLL, we can make an arbitrary read from memory, and we can make an arbitrary write to memory.

## Test Application Code

The application I am using to simulate vulnerability, and eventually exploit, is shown below:

```c
#include <iostream>
#include <windows.h>

typedef HMODULE(*LeakModuleBaseFunc)();
typedef LONGLONG(*ArbitraryReadFunc)(LONGLONG);
typedef void(*ArbitraryWriteFunc)(LONGLONG, LONGLONG);

int main()
{
    // load in the vulnerable DLL ---------------------------------------------------------------
    HMODULE dll = LoadLibrary(L".\\VulnDLL.dll");

    // Get function pointers to the vulnerable functions in the DLL ------------------------------
    LeakModuleBaseFunc LeakModuleBase = (LeakModuleBaseFunc)GetProcAddress(dll, "LeakModuleBase");
    ArbitraryReadFunc ArbitraryRead = (ArbitraryReadFunc)GetProcAddress(dll, "ArbitraryRead");
    ArbitraryWriteFunc ArbitraryWrite = (ArbitraryWriteFunc)GetProcAddress(dll, "ArbitraryWrite");

    // Note: there is absolutely no error checking in LoadLibrary and getting function pointers; for brevity
}
```

This is very simple. It imports the vulnerable DLL and it creates pointers to the functions that we will call. Let's move on to information disclosure bugs and how to abuse them.

## Information Disclosures

An information disclosure vulnerability is a vulnerability that leaks the base address, or an address that allows us to calculate the base address, of a loaded module in memory. It is an important bug because it can be chained with other vulnerabilities. There are many uses for information disclosure bugs, but the two that most people will know about are defeating ASLR and DEP/NX.

**Defeating Address Space Layout Randomisation (ASLR)**

ASLR randomises the base address of the stack, the heap, and modules. This makes it harder for attackers to predict the location of code and data allocations in memory. Leaking memory addresses (e.g., module base, stack address, or heap pointers) helps attackers to bypass ASLR by using Return-oriented Programming (ROP).

It is also worth noting that if we have an arbitrary write primitive and we know where certain pointers are (think global pointer to a heap allocation) then we can write data into the target process at predictable locations.

**Locating Gadgets for ROP**

ROP is a common technique used to bypass non-executable memory (DEP/NX) by chaining small code fragments (gadgets) already present in memory. If we can leak module addresses then we can locate ROP gadgets and develop a ROP chain.

Our task is to leak the DLL base address, this is the easy bit as it's just a function call. This DLL is tiny, and has a very small code base, if we were looking to build a ROP chain using this DLL alone, we would fail in spectacular fashion. What we need is the base address of other modules that we can use. We will leak `kernel32.dll` and `NTDLL.dll` by chaining the information disclosure bug with the arbitrary read bug.

## Leaking the DLL Base

The first part involves simply calling `LeakModuleBase()` in the DLL:

```c
// Simulate Exploitation ---------------------------------------------------------------------
// Leak the module address
HMODULE dllBase = LeakModuleBase();
printf("dllBase: 0x%p\n", (void*)dllBase);

DebugBreak();
```

Running the compiled application in `WinDbg` helps us to test if the exploit simulation works:

<img width="1112" alt="Screenshot 2025-01-21 at 18 10 00" src="https://github.com/user-attachments/assets/593dafdd-cde1-4d39-8aa3-c84c30015cf4" style="border: 1px solid black;" />

Nothing really compilcated here, this allows us to use `VulnDLL` to build a ROP chain, but how many gadgets are available?

<img width="1119" alt="Screenshot 2025-01-22 at 07 16 26" src="https://github.com/user-attachments/assets/431bd753-d7d1-4ae7-b27e-3b5aa2206946" style="border: 1px solid black;" />

Not many of course, 425 gadgets. So how do we leak `kernel32.dll` from this leak.

## Leaking Kernel32.dll

This is where we can use the Import Address Table in the `VulnDLL` binary. If we load this into `IDA` we can look at the Imports tab (don't forget to rebase the module):

<img width="1114" alt="Screenshot 2025-01-21 at 18 14 00" src="https://github.com/user-attachments/assets/530f61fe-feb1-4072-b8c8-043a61ad7e2c" style="border: 1px solid black;" />

Here we can see that at an offset of `0x2040` is the IAT entry for `GetCurrentThreadId`. If we use our abitrary read primitive we can read this address (because we have leaked the base address of the module) to reveal the address of the `GetCurrentThreadId` function:

```c
// GetCurrentThreadId IAT offset 0x02040 - found using IDA
LONGLONG GetCurrentThreadIdAddr = ArbitraryRead((LONGLONG)dllBase + 0x02040);
printf("GetCurrentThreadIdAddr: 0x%p\n", (void*)GetCurrentThreadIdAddr);

DebugBreak();
```

If we test this again in `WinDbg` we see that the address that we have leaked from the IAT is correct:

<img width="1119" alt="Screenshot 2025-01-21 at 18 18 42" src="https://github.com/user-attachments/assets/e4c3e31e-cedf-4053-ba16-d7dc57fb3c57" style="border: 1px solid black;" />

We are making progress. We have leaked the address of a function in `kernel32.dll` from the IAT. How can we use this to leak the base address of `kernel32.dll`. The code that makes up this function is ALWAYS at the same offset from the base of the module, ASLR rebasing randomises alot of things, such as the actual base address of the module, but it does not randomise the offsets of the code from the base address. To get the base address we simply need to find the offset of the function from the `kernel32.dll` base address:

<img width="1113" alt="Screenshot 2025-01-21 at 18 22 30" src="https://github.com/user-attachments/assets/41f06941-4df8-4a05-a1ca-71241ce2ddba" style="border: 1px solid black;" />

We can use the following code to leak the `kernel32.dll` base address:

```c
// Offset of GetCurrentThreadId from Kernel32 is 0x015ae0 - found using WinDbg
LONGLONG kernel32Base = GetCurrentThreadIdAddr - 0x015ae0;
printf("kernel32Base: 0x%p\n", (void*)kernel32Base);

DebugBreak();
```

Running this once again gives us the leaked address:

<img width="1112" alt="Screenshot 2025-01-21 at 18 26 26" src="https://github.com/user-attachments/assets/744f9fbf-f3f2-49ed-acde-398f47c213eb" style="border: 1px solid black;" />

We now have lots of code to search for ROP gadgets in:

<img width="1115" alt="Screenshot 2025-01-22 at 07 17 24" src="https://github.com/user-attachments/assets/331c4306-e8d9-4a71-b168-46e77ed49efb" style="border: 1px solid black;" />

The original brief I set myself was to also leak `NTDLL.dll`. How do we do that? YES! We read the IAT for `kernel32.dll` which references functions in `NTDLL.dll`.

## Leaking NTDLL.dll

I chose `NtOpenJobObjectAddr`. It's a random choice and as long as you can find the offset of the function using `WinDbg` you can choose any function:

```c
// NtOpenJobObjectAddr IAT offset 0x07a678 - found using IDA
LONGLONG NtOpenJobObjectAddr = ArbitraryRead((LONGLONG)kernel32Base + 0x07a678);
printf("NtOpenJobObjectAddr: 0x%p\n", (void*)NtOpenJobObjectAddr);

// Offset of NtOpenJobObjectAddr from NTDLL is 0x0a1970 - found using WinDbg
LONGLONG ntdllBase = NtOpenJobObjectAddr - 0x0a1970;
printf("ntdllBase: 0x%p\n", (void*)ntdllBase);
```

This code should look very familiar. Testing the full app we can see how easy it is to leak multiple module addresses when we discover an information disclosure vulnerability:

<img width="867" alt="Screenshot 2025-01-21 at 18 31 24" src="https://github.com/user-attachments/assets/8002d8bf-ec12-4053-b1c2-ad4959fcd38a" style="border: 1px solid black;" />

Lovely!

## What's Next?

Next up, I am going to introduce some sort of bug in the DLL where we can overwrite `rip`, not sure what yet, probably some form of UaF or overwriting of a function pointer. That isn't important, as long as we can disclose a heap allocation and use our arbitrary write we will attempt to do a bit of ROPping.

You still here?

[Home](https://plackyhacker.github.io) : Part 1 : [Part 2](https://plackyhacker.github.io/binary/ropping)
