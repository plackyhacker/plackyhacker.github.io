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

## Tracing TEST and CMP Instructions

When reverse engineering a binary you often have to follow the flow of the instructions to see where buffers are accessed and manipulated, and it is important to understand `test`, `cmp` and the various jump instructions.

The next two instructions following the call to `recv` were easy to follow:

```
.text:00862181 test    eax, eax
.text:00862183 jnz     short loc_862193
```

The `test` instruction carries out a bitwise AND against the two operands. In this case the two operands are both `eax`. The `test` instruction can be used to test for a zero value in a register, if `eax` is set to `0x0` then the `zf` (zero flag) will be set (to `0x1`), otherwise it will not be set. I established in part one of this article that the `eax` register contained the size of the buffer sent in the PoC, after the `test` instruction `zf` is set to `0x0` and the jump to `0x00862193` is made.

After the jump was made the next basic block contained:

```
.text:00862193
.text:00862193 loc_862193:
.text:00862193 cmp     eax, 0FFFFFFFFh
.text:00862196 jnz     short loc_8621B3
```

This is easily recognisable. As `eax` is the return value from the `recv` function it is compared to the value `0xffffffff` (`-1`), which is equivalent to the constant `SOCKET_ERROR`. I changed the name of the block `loc_862193` to `l_sockerror_check`. This seems quite trivial but it is good to get in the habit of being organised, particularly if you don't know when you will return to the blocks later. Renaming variables, blocks, functions and adding comments is really good practice.

It might seem trivial, the preceeding instructions were changed to:

```
.text:00862181 Check that the return value from ws2_32.recv is not 0x0
.text:00862181 test    eax, eax
.text:00862183 jnz     short l_sockerror_check
```

And the next block was changed to:

```
.text:00862193 Check that the return value from ws2_32.recv is not SOCKET_ERROR
.text:00862193
.text:00862193 l_sockerror_check:
.text:00862193 cmp     eax, 0FFFFFFFFh
.text:00862196 jnz     short b_cleanup_and_return
```

This next block checked the return value against `SOCKET_ERROR` using a `cmp` instruction. The `cmp` instruction is very easy to understand (thankfully). The `cmp` instruction subtracts the second operand (in this case `0FFFFFFFFh`) from the first operand (in this case `eax` - which contains the buffer length).

The instruction sets the FLAG registry, which contains a number of flags that can be used in jump instructions, in this example the `zf` (sero flag). After the `cmp` instruction `zf` was set to `0x0` and the jump to `0x008621b3` was made. This took me to the final block before the function returns:

```
.text:008621B3 This block moves the length of our buffer (eax) into the memory location pointed to by [esi],
.text:008621B3 sets the return value to 1 (eax), then returns to libssp 0x1009864c
.text:008621B3
.text:008621B3 b_cleanup_and_return:
.text:008621B3 mov     [esi], eax
.text:008621B5 mov     eax, 1
.text:008621BA pop     esi
.text:008621BB retn    10h
.text:008621BB f_calls_recv endp
```

**WIP: Currently reverse engineering and writing at the same time!**
