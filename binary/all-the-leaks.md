[Home](https://plackyhacker.github.io)

# All the Leaks

## Introduction

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

## Leaking the DLL Base

## Importy Address Tables

## Leaking Kernel32.dll

## Leaking NTDLL.dll

## What's Next?

[Home](https://plackyhacker.github.io)
