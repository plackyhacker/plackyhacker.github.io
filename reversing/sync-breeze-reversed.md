[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/reversing/sync-breeze-reversing-2) : [Part 3](https://plackyhacker.github.io/reversing/sync-breeze-reversing-3)

# Sync Breeze Revisited Part 1

**Note:** Each time `WinDbg` is restarted the memory addresses of stack/heap buffers will change, if you are following along please be mindful of this.

At the time of writing I am studying Offensive Security Windows User Mode Exploit Development (EXP-301). I completed the Offensive Security Certified Expert (OSCE) a few years ago and really enjoyed it. However, I am finding that EXP-301 goes in to much more depth than the OSCE. That is probably because the new OSCE<sup>3</sup> is split into three areas that were covered in the single Cracking the Perimeter course of old.

I have started studying the reverse engineering section in the course and I am finding it very interesting if hard going. Firstly, `Ghidra` is not permitted on the exam, which means I have to learn how to use `IDA Free` and reverse engineering is a slow process to me anyway. Whilst the course content is good I felt I needed a bit more practice reversing Windows PE files.

A quick Google led me to this great blog page: [Vulnserver Redux 1: Reverse Engineering TRUN](https://www.purpl3f0xsecur1ty.tech/2021/05/26/trun_re.html) by Purpl3 F0x Secur1ty, I used this as a starting point and attempted to reverse engineer the PE file, using the blog when I got lost, which thankfully wasn't too often.

I decided that I would revisit the `Sync Breeze Enterprise 10.0.28` buffer overflow vulnerability introduced in the first chapter of the course, but this time I would attempt to reverse engineer it, rather than fuzz it. The public vulnerability is [here](https://www.exploit-db.com/exploits/42928).

## Goal

The goal of this exercise was for me to get better at reverse engineering using `IDA Free` and `WinDbg` and hopefully it will help anybody reading this too, and it may even help people understand stack based buffer overflow vulnerabilities at a lower level.

The goal isn't to track down any new vulnerabilites. I guess this binary has been done to death! I will try to track down the code where the known vulnerability exists.

## The Proof of Concept

I started with a similar Proof of Concept, but I reduced the size of the payload to test against the username field. The exploit will be written in `Python` because that's what all exploits are written in duh!

```python
import socket, sys

server = sys.argv[1]
port = 80
size = 100

payload = b"A" * size
content = b"username=" + payload + b"&password=A"

buffer =  b"POST /login HTTP/1.1\r\n"
buffer += b"Host: " + server.encode() + b"\r\n"
buffer += b"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:45.0) Gecko/20100101 Firefox/45.0\r\n"
buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
buffer += b"Referer: http://192.168.211.149/login\r\n"
buffer += b"Connection: close\r\n"
buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
buffer += b"Content-Length: " + str(len(content)).encode() + b"\r\n"
buffer += b"\r\n"
buffer += content

print("Sending: " + str(len(buffer)) + " bytes...")

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buffer)
    s.close()
    print("Done!")
except socket.error:
    print("Unable to connect!")
```

## Hooking the RECV function

I attached `WinDbg` to the `syncbrs.exe` process and issued the `lm` command to view the loaded modules:

```
0:007> lm
start    end        module name
...       
772f0000 77353000   WS2_32     (deferred)    
```

I found that `Sync Breeze` was using `ws2_32` for it's network operations. I configured a breakpoint on the `ws2_32!recv` function:

```
0:007> bp ws2_32!recv
```

I ran the PoC, and the breakpoint was hit. This is the starting point for reversing the username field. At this point I have no idea how long or difficult this is going to be... Eyes down for a full house!

```
Breakpoint 0 hit
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=00000448 ebx=00fceee8 ecx=011745d8 edx=0063d744 esi=0063cf5c edi=00002800
eip=773023a0 esp=0063cf20 ebp=0063d744 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
WS2_32!recv:
773023a0 8bff            mov     edi,edi
```

## Examining the Stack

If you understand calling conventions you will know that Win32 APIs use the `__stdcall` calling convention. In simple terms this means all parameters will be pushed on to the stack, in reverse order, before the function is called. When the function returns, the return value will have been moved into the `eax` register (this can be an integer, pointer to a memory address etc.)

The syntax for a call to [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) is shown below:

```c
int recv(
  [in]  SOCKET s,
  [out] char   *buf,
  [in]  int    len,
  [in]  int    flags
);
```

I examined the stack (`esp`), I wanted to see the next 5 dwords:

```
0:009> dd esp L5
0180cf20  007e2181 000003d0 0180d744 00002800
0180cf30  00000000
```

The dwords are as follows (remember this relates to the call made to `ws2_32!recv`):

- `0x007e2181` is the saved return address, when the `recv` function is complete `eip` will be loaded with this address to return to.
- `0x000003d0` is a pointer to the `SOCKET` object.
- `0x0180d744` is a pointer to the memory location where our network buffer (the one we sent using python) will be copied to.
- `0x00002800` is the length of the buffer pointed to.
- `0x00000000` is a set of flags that influences the behaviour of the function.

Once the function has completed and returned back to `0x00952181` (we do not know what this is yet), the return value will be moved in to `eax`.

I often find myself reading the Microsoft documents and examining the stack to see how it aligns to the `C` syntax. If you want to understand the function being called this is a great resource.

## Examining the Receive Buffer

Next I allowed execution of the `recv` function to complete and return back to the calling function, using the `pt` and `p` commands:

```
0:009> pt
eax=000001df ebx=00b2efb0 ecx=00000002 edx=0180cf08 esi=0180cf5c edi=00002800
eip=773024c9 esp=0180cf20 ebp=0180d744 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
WS2_32!recv+0x129:
773024c9 c21000          ret     10h
0:009> p
eax=000001df ebx=00b2efb0 ecx=00000002 edx=0180cf08 esi=0180cf5c edi=00002800
eip=00952181 esp=0180cf34 ebp=0180d744 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libpal!SCA_Base64::Destroy+0x7db1:
007e2181 85c0            test    eax,eax
```

I observed that the `eax` register contains `0x000001df`, this is the return value from `recv`. I evaluated the expression:

```
0:009> ? 1df
Evaluate expression: 479 = 000001df
```

This evaluates to `479` in decimal, which just happens to be the length of the buffer I sent in the `Python` PoC.

The Microsoft documentation states: *"If no error occurs, recv returns the number of bytes received and the buffer pointed to by the buf parameter will contain this data received."* 

It looked like my buffer was saved to the memory location successfully. I confirmed that by examining the buffer at `0x0180d744`:

```
0:009> dc 0x0180d744 L78
0180d744  54534f50 6f6c2f20 206e6967 50545448  POST /login HTTP
0180d754  312e312f 6f480a0d 203a7473 2e323931  /1.1..Host: 192.
0180d764  2e383631 39312e31 550a0d30 2d726573  168.1.190..User-
0180d774  6e656741 4d203a74 6c697a6f 352f616c  Agent: Mozilla/5
0180d784  2820302e 3b313158 6e694c20 69207875  .0 (X11; Linux i
0180d794  3b363836 3a767220 302e3534 65472029  686; rv:45.0) Ge
0180d7a4  2f6f6b63 30313032 31303130 72694620  cko/20100101 Fir
0180d7b4  786f6665 2e35342f 410a0d30 70656363  efox/45.0..Accep
0180d7c4  74203a74 2f747865 6c6d7468 7070612c  t: text/html,app
0180d7d4  6163696c 6e6f6974 7468782f 782b6c6d  lication/xhtml+x
0180d7e4  612c6c6d 696c7070 69746163 782f6e6f  ml,application/x
0180d7f4  713b6c6d 392e303d 2a2f2a2c 303d713b  ml;q=0.9,*/*;q=0
0180d804  0a0d382e 65636341 4c2d7470 75676e61  .8..Accept-Langu
0180d814  3a656761 2d6e6520 652c5355 3d713b6e  age: en-US,en;q=
0180d824  0d352e30 6665520a 72657265 7468203a  0.5..Referer: ht
0180d834  2f3a7074 3239312f 3836312e 3131322e  tp://192.168.211
0180d844  3934312e 676f6c2f 0a0d6e69 6e6e6f43  .149/login..Conn
0180d854  69746365 203a6e6f 736f6c63 430a0d65  ection: close..C
0180d864  65746e6f 542d746e 3a657079 70706120  ontent-Type: app
0180d874  6163696c 6e6f6974 772d782f 662d7777  lication/x-www-f
0180d884  2d6d726f 656c7275 646f636e 0a0d6465  orm-urlencoded..
0180d894  746e6f43 2d746e65 676e654c 203a6874  Content-Length: 
0180d8a4  0d303231 750a0d0a 6e726573 3d656d61  120....username=
0180d8b4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0180d8c4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0180d8d4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0180d8e4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0180d8f4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0180d904  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0180d914  41414141 73617026 726f7773 00413d64  AAAA&password=A.
```

I also looked where the memory had been allocated to store the buffer:

```
0:011> !address 0x0180d744

Usage:                  Stack
...
```

The buffer had been allocated in stack memory. Some readers might be thinking, here's our opportunity to overflow the stack. As far as I am aware there aren't any stack overflow vulnerabilities in `recv` so don't be tempted to overflow every variable that is written to the stack! It will be far more fruitful if we can find a buffer that has been under-allocated and over-committed.

## Aligning IDA with WinDbg

In order to start reverse engineering the PE and trying to find the vulnerability I needed to align `IDA` with `WinDbg`. Luckily the binary files that ship with `Sync Breeze` do not have any ASLR mitigations so the memory addresses remain the same (whe I was going through the alignment again later I discovered that two of the binaries did load with different base addresses, see the end of this blog post for details). This makes using dynamic and static analysis much easier.

The first step was to find out which function in the `Sync Breeze` application called `ws2_32!recv`, this is straighforward as the application returns to the saved return address before the call to `recv` (`0x007e2181`).

I looked at the loaded modules again and found that the return address is in `libpal.dll`:

```
0:011> lm
start    end        module name
...           
00790000 00864000   libpal   C (export symbols)       C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
```

I loaded the DLL into `IDA` and rebased the module using `Edit > Segments > Rebase Program...` to `0x790000`. I then went to the return address, by pressing `g` in `IDA` and entering the address (`0x007e2181`), this presented me with the instruction block:

```
.text:007E2160
.text:007E2160
.text:007E2160
.text:007E2160 sub_7E2160 proc near
.text:007E2160
.text:007E2160 arg_0= dword ptr  4
.text:007E2160 arg_4= dword ptr  8
.text:007E2160 arg_8= dword ptr  0Ch
.text:007E2160 arg_C= dword ptr  10h
.text:007E2160
.text:007E2160 mov     eax, [esp+arg_4]
.text:007E2164 mov     edx, [esp+arg_0]
.text:007E2168 push    esi
.text:007E2169 mov     esi, [esp+4+arg_8]
.text:007E216D push    0
.text:007E216F push    eax
.text:007E2170 mov     dword ptr [esi], 0
.text:007E2176 mov     eax, [ecx+8]
.text:007E2179 push    edx
.text:007E217A push    eax
.text:007E217B call    ds:WS2_32_16
.text:007E2181 test    eax, eax
.text:007E2183 jnz     short loc_7E2193
```

This shows the call to `WS2_32_16` at address `0x007E217B`: this is the call to `recv`.

In the next part I will start looking at how I can trace the instructions using dynamic and static analysis.


**A note on ASLR**

I later realised that two of the DLLs that ship with `Sync Breeze` were loaded with different base addresses upon each reaload into `WinDbg`:

```
00400000 00462000   syncbrs    (deferred)             
007d0000 008a4000   libpal     (deferred)             
009b0000 00a64000   libsync    (deferred)             
10000000 10223000   libspp     (deferred)             

00400000 00462000   syncbrs    (deferred)             
00770000 00844000   libpal     (deferred)             
00950000 00a04000   libsync    (deferred)             
10000000 10223000   libspp     (deferred)
```

Upon inspecting the loaded modules using the `narly` plugin I found none of them were compiled with ASLR mitigations:

```
0:009> !nmod
00400000 00462000 syncbrs              /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\syncbrs.exe
00770000 00844000 libpal               /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
00950000 00a04000 libsync              /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libsync.dll
10000000 10223000 libspp               /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
```

I found this very odd. I asked my fellow OSED students and was referred to [this article](https://www.mandiant.com/resources/six-facts-about-address-space-layout-randomization-on-windows) which states _"Fact 5: Windows 10 is more aggressive at applying ASLR, and even to EXEs and DLLs not marked as ASLR-compatible, and this could make ASLR stronger"._

This still confuses me, as two of the binaries didn't have ASLR applied but two of them _appear_ to have ASLR applied. This reminds me of a quote by Albert Einstein: _"God does not play dice with ASLR."_ Or something like that!

This means that when tracing `libpal` or `libsync`, every time I restarted the debugger I had to realign `IDA`.

[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/reversing/sync-breeze-reversing-2) : [Part 3](https://plackyhacker.github.io/reversing/sync-breeze-reversing-3)
