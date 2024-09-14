[Home](https://plackyhacker.github.io)

# Exploring x64 Calling Conventions

It is a really useful to be able to include `asm` or 'shellcode' in your Visual Studio projects when you are studying or writing exploits for known bugs/CVEs, I'd go as far as to say it is a prerequisite.

Calling conventions define how functions receive parameters and return values, ensuring consistency between caller and callee. They standardise the use of registers and stack memory.

In x86 (32-bit) calling conventions, function parameters are typically passed on the stack, and the `eax` register is used for the return value. In contrast, x64 (64-bit) conventions use registers: the first four parameters are passed in `rcx`, `rdx`, `r8`, and `r9`, with additional parameters passed on the stack. The return value is stored in the `rax` register. x64 also has a "shadow space" for the first four parameters, pre-allocated on the stack by the caller.

If you are like me and find it easier to visualise a concept then creating a short `C` program and debugging it is a great way to explore this concept.

## A Function in Assembly

Before we can add ass embly to our project we need to make sure we have enabled the `masm` build customisation file. This can be done by *right clicking* our project and clicking the *Build Dependencies > Build Customizations* sub menu:

![image](https://github.com/user-attachments/assets/bf1e6377-1796-4fac-96dd-b55c346b2b40)

Now we have this configured we can add a new `.asm` file:

```asm
PUBLIC MyFunction

.CODE

MyFunction PROC
	int 3						; examine registers
	mov rax, 4747474747474747h			; return value
	ret;
MyFunction ENDP

END
```

This function is pretty basic and it doesn't do much in terms of useful functionality but it will allow us to break into the program when we call the function from our `C` code and examine the registers and the stack.

## The C Code

The `C` code is very simple:

```c
#include <iostream>
#include "Windows.h"

// defer MyFunction resolution to the linker
extern "C" ULONGLONG MyFunction(ULONGLONG rcx,
	ULONGLONG rdx,
	ULONGLONG r8,
	ULONGLONG r9,
	ULONGLONG stack1,
	ULONGLONG stack2);

int main()
{
    // call the MyFunction
    ULONGLONG ret = MyFunction(0x4141414141414141,
        0x4242424242424242,
        0x4343434343434343, 
        0x4444444444444444, 
        0x4545454545454545,
        0x4646464646464646);

    // display the return value
    printf("MyFunction returned 0x%p\n", ret);

    return 0;
}
```

First we need to ensure the compiler is aware of `MyFunction` by adding an `extern` to the code; without this the compiler will error with `identifier 'MyFunction' is undefined.

I have named the parameters in the function to show where we would expect to see the values we pass in to it.

The `main` function calls `MyFunction` and displays the returned value.

If we compile the program we can now open it in **WinDbg** (make sure you open the *Debug* build as this will include the debugging symbols):

![image](https://github.com/user-attachments/assets/596febcc-801a-4cf7-8a91-3c86946220f9)

## WinDbg

**Be patient, I am writing this!**

[Home](https://plackyhacker.github.io)
