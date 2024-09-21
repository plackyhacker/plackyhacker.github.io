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

First we need to ensure the compiler is aware of `MyFunction` by adding an `extern` to the code; without this the compiler will error with `identifier 'MyFunction' is undefined`.

I have named the parameters in the function to show where we would expect to see the values we pass in to it.

The `main` function calls `MyFunction` and displays the returned value. Notice that we are passing six different 64 bit values in via the parameters, this is so we can examine them in the registers and on the stack.

## WinDbg

If we compile the program we can now open it in **WinDbg** (make sure you open the *Debug* build as this will include the debugging symbols):

![image](https://github.com/user-attachments/assets/596febcc-801a-4cf7-8a91-3c86946220f9)

Upon running the program **WinDbg** will break, enter the `g` command to continue execution. We will hit the breakpoint in our function:

![image](https://github.com/user-attachments/assets/cfd8f873-74ac-4be1-8359-44192f7a00c6)

We can use the `r` command to examine the registers:

```
0:000> r
rax=4545454545454545 rbx=0000000000000000 rcx=4141414141414141
rdx=4242424242424242 rsi=0000000000000000 rdi=0000000000000000
rip=00007ff68ce51ad0 rsp=0000009783d3f708 rbp=0000009783d3f740
 r8=4343434343434343  r9=4444444444444444 r10=0000000000000012
r11=0000009783d3f7e0 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
```

Upon examining the registers we can observer that our first four parameters passed to `MyFunction` are in the registers `rcx`, `rdx`, `r8`, and `r9`. But wait, the fifth parameter is in `rax`. If we open the binary in **IDA** we can see the following assembly:

```asm
mov     rax, 4646464646464646h
mov     [rsp+120h+var_F8], rax
mov     rax, 4545454545454545h
mov     [rsp+120h+var_100], rax
mov     r9, 4444444444444444h
mov     r8, 4343434343434343h
mov     rdx, 4242424242424242h
mov     rcx, 4141414141414141h
call    j_MyFunction
```

It would appear that `rax` is being used as a temporary register to place the fifth and sixth parameters on the stack. Back in **WinDbg** if we examine the stack at the breakpoint using `dqs rsp` we can also see where the parameters have been placed:

```
0:000> dqs rsp
000000e8`f6f9f568  00007ff6`8ce51997 x64_calling_conventions!main+0x67 [C:\Users\John\source\repos\x64-calling-conventions\x64-calling-conventions\x64-calling-conventions.cpp @ 11]
000000e8`f6f9f570  00007ff6`8ce620f4 x64_calling_conventions!_NULL_IMPORT_DESCRIPTOR <PERF> (x64_calling_conventions+0x220f4)
000000e8`f6f9f578  00000000`00000002
000000e8`f6f9f580  00000000`00000000
000000e8`f6f9f588  00007ffe`d9682016 ucrtbased!__crt_scoped_get_last_error_reset::~__crt_scoped_get_last_error_reset+0x16 [minkernel\crts\ucrt\inc\corecrt_internal.h @ 2056]
000000e8`f6f9f590  45454545`45454545
000000e8`f6f9f598  46464646`46464646
```

The first value is the return address; the address of the instruction that will be returned to when the function exits. The next four are the shadow space, and the next two are parameters five and six respectively.

The shadow space, must be reserved by the caller and consists of 32 bytes located just between the return address and the parameters, if they exist, on the stack. The called function owns this space and can be used as temporary storage and is positioned below any stack arguments:

```
000000e8`f6f9f568  00007ff6`8ce51997 	// return address
000000e8`f6f9f570  00007ff6`8ce620f4	// ----------------+
000000e8`f6f9f578  00000000`00000002	// shadow   	   |
000000e8`f6f9f580  00000000`00000000	// space           |
000000e8`f6f9f588  00007ffe`d9682016	// ----------------+
000000e8`f6f9f590  45454545`45454545	// fifth parameter
000000e8`f6f9f598  46464646`46464646	// sixth parameter
```

If we enter `g` to continue execution the program ends and we can see the result that we placed in the `rax` register:

<img width="918" alt="image" src="https://github.com/user-attachments/assets/5dd1f00e-14f5-4f0d-90e4-9da30b41b976">

There is no trickery going on here, we are just displaying the returned value in our `C` code:

```c
// display the return value
printf("MyFunction returned 0x%p\n", ret);
```

This confirms that the value we placed in `rax` is the function return value.

## Why Should We Care

If we are going to write shellcode then we need to be sure to follow these calling conventions, particularly if we are calling Windows Win32 APIs. When we are calling Win32 APIs we must ensure we place the parameters in the correct registers, and we must ensure that we establish shadow space for the called function to use.

## Just One More Thing

When we make a call to a Win32 API using x64 assembly we must also ensure that the stack is `0x10` byte alligned. In short, this means that when the call is made the value in `rsp` must end with a `0`. If you ever find Win32 API calls crashing and you are not sure why; check that your stack is alligned. Be warned! 

## And One Last Thing

The 64-bit calling convention uses _volatile_ and _non-volatile_ registers. This means that the callee must preserve the values in _**non-volatile**_ registers, so if we take control of some code flow or we write our own functions **we** are the callee and must restore these _non-volatile_ registers before we return normal execution. I have copied this list from the [Microsoft's Register volatility and preservation guidance](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#register-volatility-and-preservation), use it wisely:

- `r12:r15` Nonvolatile, Must be preserved by callee.
- `rdi`	Nonvolatile, Must be preserved by callee.
- `rsi`	Nonvolatile, Must be preserved by callee.
- `rbx`	Nonvolatile, Must be preserved by callee.
- `rbp`	Nonvolatile, May be used as a frame pointer; must be preserved by callee.
- `rsp`	Nonvolatile, Stack pointer.

That is all, go away!

[Home](https://plackyhacker.github.io)
