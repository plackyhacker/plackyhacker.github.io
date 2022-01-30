[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/reversing/sync-breeze-reversed)

# Sync Breeze Revisited Part 2

In the second part of my reverse engineering adventures I decided that I would trace the `Sync Breeze` instructions and try to locate the known vulnerability. I already knew from the first chapter in the OSED course that the `username` field is vulnerable, but I still thought it a good idea to reverse the application and try to find the exact instructions that make it vulnerable. The goal of this was to improve my reverse engineering skills.

I changed my approach slightly, I decided to create two different character patterns for the `username` and `password` fields. This would allow me to trace them easier in memory. I assumed at some point the application was going to parse these values and process them:

```python
username = b"A" * 100
password = b"B" * 100
content = b"username=" + username + b"&password=" + password
```

To resume where I ended on part 1, rather than step through the `recv` function I added a breakpoint to where the `recv` returns to:

```
0:009> bp libpal!SCA_Base64::Destroy+0x7db1
```

As discovered in part 1, `libpal` changes it's base address upon every restart of the debugger so it is easier to add the above breakpoint, run the PoC and grab the returned address when the breakpoint is hit, in my case it was `0x00862181`:

```
Breakpoint 0 hit
eax=000001df ebx=00b7efb0 ecx=00000002 edx=0185cf08 esi=0185cf5c edi=00002800
eip=00862181 esp=0185cf34 ebp=0185d744 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libpal!SCA_Base64::Destroy+0x7db1:
00862181 85c0            test    eax,eax
```

**WIP: Currently reverse engineering and writing at the same time!**
