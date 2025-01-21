[Home](https://plackyhacker.github.io)

# All the Leaks

## Introduction

Modern exploitation generally requires the attacker to chain multiple vulnerabilites together to reach a spacific goal (most likely code execution). To help me understand different exploitation techniques and mitigations in Windows (perhaps a little later) I have decided to create an application that focuses on exploitation techniques rather than finding bugs. So I am interested in how I can use those bugs to chain together exploitation code.

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



Our task is to leak the DLL base address, this is the easy bit as it's just a function call. This DLL is tiny, and has a very small code base, if we were looking to build a ROP chain using this DLL only we will fail in spectacular fashion. What we need is the base address of other modules that we can use. We will leak `kernel32.dll` and `NTDLL.dll` by chaining the information disclousre bug with the arbitrary read bug.

## Leaking the DLL Base

## Importy Address Tables

## Leaking Kernel32.dll

## Leaking NTDLL.dll

## What's Next?

[Home](https://plackyhacker.github.io)
