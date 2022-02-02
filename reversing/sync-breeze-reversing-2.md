[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/reversing/sync-breeze-reversed) : [Part 3](https://plackyhacker.github.io/reversing/sync-breeze-reversing-3)

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
.text:00862196 jnz     short l_cleanup_and_return
```

This next block checked the return value against `SOCKET_ERROR` using a `cmp` instruction. The `cmp` instruction is very easy to understand (thankfully). The `cmp` instruction subtracts the second operand (in this case `0FFFFFFFFh`) from the first operand (in this case `eax` - which contains the buffer length).

The instruction sets the FLAG registry, which contains a number of flags that can be used in jump instructions, in this example the `zf` (sero flag). After the `cmp` instruction `zf` was set to `0x0` and the jump to `0x008621b3` was made. This took me to the final block before the function returns:

```
.text:008621B3 This block moves the length of our buffer (eax) into the memory location pointed to by [esi],
.text:008621B3 sets the return value to 1 (eax), then returns to libssp 0x1009864c
.text:008621B3
.text:008621B3 l_cleanup_and_return:
.text:008621B3 mov     [esi], eax
.text:008621B5 mov     eax, 1
.text:008621BA pop     esi
.text:008621BB retn    10h
.text:008621BB f_calls_recv endp
```

I noted that our buffer length was moved into the memory location pointed to by `esi` (I wasn't sure if this was important at this stage). I used dynamic analysis in `WinDbg` to find out where the return took me:

```
0:011> p
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
eax=00000001 ebx=00b7efb0 ecx=00000002 edx=0185cf08 esi=00000000 edi=00002800
eip=1009864c esp=0185cf4c ebp=0185d744 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
libspp!SCA_HttpAgent::ReadHttpHeader+0x5c:
1009864c 85c0            test    eax,eax
```

This took me into the `libspp` binary, I loaded that in to `IDA` to continue tracing the instructions. There isn't any point me documenting all of the `cmp`/jump instructions, I have written about those which I found to be important, however I continued using the same startegy in this section. I was trying to figure out how the buffer was minipulated and at what point there may be a vulnerability.

**Note:** The optional numeric `10h` parameter to `ret` specifies the number of stack bytes to be released after the return address is popped from the stack, these are generally the parameters pushed to the stack for the call to the function.

## Psuedo Code

It isn't always necessary, but it is sometimes helpful to write psuedo-code base upon the reverse engineered assembly instructions. I am aware that `Ghidra` and `IDA Pro` can do this, but these tools are not allowed in the OSED exam and it's always good to understand what I am looking at.

The second block I encountered in the `libspp` binary following our return from the `libpal` binary finds the length of the buffer sent in the PoC. At this point I wasn't sure if this was important to finding the vulnerability but it is probably used to seperate the headers from the POST parameters.

I commented the block quite heavily, to explain what my thought process was:

```
.text:10098650 This block calls:
.text:10098650 IsHeaderReady(char const* , ulong, ulong *)
.text:10098650
.text:10098650 Our entire POST buffer is passed in to char const*.
.text:10098650 Once the function is completed, the ulong* contains the length of our buffer minus the POST parameters.
.text:10098650 (This is the http headers length)
.text:10098650
.text:10098650 mov     eax, [esp+30h+var_20] ; The length of our buffer is stored here and moved in to eax
.text:10098654 add     esi, eax        ; esi now contains the length of our buffer
.text:10098656 sub     edi, eax        ; edi started at 2800 - minus the length of our buffer, edi=00002621 (479)
.text:10098658 lea     eax, [esp+30h+var_18] ; This is a memory address that will be used to store the length of the http headers
.text:1009865C lea     ecx, [esi+1]    ; This moves our buffer length + 1 into esi
.text:1009865F push    eax             ; a pointer to a memory address to hold the length of our buffer minus the POST parameters
.text:10098660 push    ecx             ; our buffer length + 1, probably used to scan the buffer for the header  terminator '\r\n\r\n'
.text:10098661 push    ebp             ; char * - this points to the start of our entire POST buffer, including http parameters
.text:10098662 lea     ecx, [esp+3Ch+var_14]
.text:10098666 call    ?IsHeaderReady@SCA_HttpParser@@QAEHPBDKPAK@Z ; SCA_HttpParser::IsHeaderReady(char const *,ulong,ulong *)
.text:10098666
.text:10098666 After the function returns the memory pointed to by eax (pre-call at [esp+30h+var_18]) contains the length of our buffer minus the parameters.
.text:10098666
.text:1009866B test    eax, eax        ; The function returns 1 (success)
.text:1009866D jnz     short loc_100986B1 ; Not sure what the next block does yet.
```

I convertedt this to what I believed to be the psuedo-code (the purpose of this is not line-by-line accuracy but to help understand the purpose of the block in my head):

```c
bool result = SCA_HttpParser.IsHeaderReady(&postBuffer, lenOfBuffer, &headersLength);

if(result == true)
{
  // got to success block
}
else
{
  // go to fail block
}
```

Again, this can seem very trivial but for longer blocks, or multiple blocks it can help to understand the flow of the instructions and the variables being used/accessed.

## Examining the Buffer... Again

At this point I noticed that the POST buffer was located at `ebp` (which makes sense). I issued three commands in `WinDbg` to get a feel for where I was:

```
0:011> dd 01a5cf64 L1
01a5cf64  00000167
0:011> dc ebp
01a5d744  54534f50 6f6c2f20 206e6967 50545448  POST /login HTTP
01a5d754  312e312f 6f480a0d 203a7473 2e323931  /1.1..Host: 192.
01a5d764  2e383631 39312e31 550a0d30 2d726573  168.1.190..User-
01a5d774  6e656741 4d203a74 6c697a6f 352f616c  Agent: Mozilla/5
01a5d784  2820302e 3b313158 6e694c20 69207875  .0 (X11; Linux i
01a5d794  3b363836 3a767220 302e3534 65472029  686; rv:45.0) Ge
01a5d7a4  2f6f6b63 30313032 31303130 72694620  cko/20100101 Fir
01a5d7b4  786f6665 2e35342f 410a0d30 70656363  efox/45.0..Accep
0:011> dc ebp + 167
01a5d8ab  72657375 656d616e 4141413d 41414141  username=AAAAAAA
01a5d8bb  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01a5d8cb  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01a5d8db  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01a5d8eb  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01a5d8fb  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01a5d90b  41414141 41414141 41414141 61702641  AAAAAAAAAAAAA&pa
01a5d91b  6f777373 423d6472 42424242 42424242  ssword=BBBBBBBBB
```

The first command inspects the dword at `0x01a5cf64`, this is where the length of the headers is stored. The second command shows the POST buffer located at the location pointed to by `ebp`, and the third command confirms that the `SCA_HttpParser.IsHeaderReady` call is used (at least) to parse the headers for their length; I examined the buffer locate at `ebp + 167` and sure enough I found the beginning of the POST parameters.

This is what I know so far (note this is not pseudo-code, just a representation of the function calls):

```
// not sure if the paramaters are important yet
ReadHttpHeader::SCA_HttpAgent(?)
{
  // this calls the recv function, not sure if the paramaters are important yet
  f_calls_recv(?); // [don't know function name]
  {
    // this is the API that receives our POST buffer	
    ws2_32.recv(SOCKET, char*, int, int)
  }

	// [1] char* is the entire buffer (at ebp), [2] not important, [3] is the length of the POST header
  SCA_HttpParser:IsHeaderReady(char*, ulong, ulong *);

  // to be continued...
}
```

That's it for part two!

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/reversing/sync-breeze-reversed) : [Part 3](https://plackyhacker.github.io/reversing/sync-breeze-reversing-3)
