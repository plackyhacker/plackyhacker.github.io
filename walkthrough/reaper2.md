# VulnLab Reaper 2 Walkthrough

## Introduction

[Reaper 2](https://www.vulnlab.com/machines) was the second lab recommended to me for my [OffSec Advanced Windows Exploitation (AWE)](https://www.offsec.com/courses/exp-401/) preperations. It was written by [xct](https://x.com/xct_de) and is part of the training and labs offered by [VulnLab](https://vunlab.com). The lab was rated **Insane** and it didn't dissapoint!

The [wiki](https://wiki.vulnlab.com/guidance/insane/reaper2) for the lab gives several clues that definitely helped me on my journey to pwning it.

In this post I'm going to do something a little different. I am not going to post any full exploit code, and I am not going to write about the way I defeated the lab. I am going to write about how I would take on the lab now I know everything I have learned. So, this isn't going to be a walthrough you can follow, copy and paste a few things and beat the lab. It will act as a guide on how you can approach the lab, and write your own exploits to get `SYSTEM` access to **Reaper 2**.

I will be showing how this can all be done without using the clues given in in the [wiki](https://wiki.vulnlab.com/guidance/insane/reaper2). Let's go!

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

### Type Confusion Bug

It turns out there is a documented [explanation and walkthrough](https://h0meb0dy-me.translate.goog/entry/Issue-1510709-Type-confusion-in-Harmony-Set-methods-leads-to-RCE?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en&_x_tr_pto=wapp) of a **type confusion** bug in this version of **D8** whilst running with the `--harmony-set-methods` argument. The bad news for us is the walkthrough is written for **Linux**.

Our challenge at this point is to convert the exploit so it will run against a **Windows Server 2022** target.

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

The second change is we need to write shellcode that will run on **Windows**.

### Enumeration

## Privilege Escalation

### Enumeration

### Custom Driver

### Kernel Base Address Disclosure Bug

### Arbitrary Code Execution Bug

### Kernel Debugging

### Exploitation
