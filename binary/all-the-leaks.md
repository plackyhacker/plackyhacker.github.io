[Home](https://plackyhacker.github.io)

# All the Leaks

## Introduction

## Information Disclosures

## Vulnerable DLL Code

Let's take a very quick look at the vulnerable DLL, and I mean vulnerable - of course there would need to be some mechanism for attackers to interact with these functions, such as a TCP server that called them! BUT there's no messing about, it is VERY vulnerable, by design.

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

## Leaking the DLL Base

## Importy Address Tables

## Leaking Kernel32.dll

## Leaking NTDLL.dll

## What's Next?

[Home](https://plackyhacker.github.io)
