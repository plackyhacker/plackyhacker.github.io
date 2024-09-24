# Doubly-Linked Lists in the Windows Kernel

Recently I have been studying different Kernel structures and it suddenly occurred to me that there is a pattern used by Microsoft to impleemnt doubly-linked lists within their structures. I'm pretty sure this is common knowledge to a lot of people, but I thought I would put a brief post together explaining them... just in case, like me you need it.

## Why Should We Care?

If you have ever studied Kernel driver exploitation or even done a lab where a custom driver is used to get privilege escalation then you are probably familiar with token stealing shellcode. Now, you may have just copied and pasted the shellcode into your exploit but if you understand how the `System` process is enumerated then doesn't that feel a bit better?

If you didn't just copy and paste the sheelcode and you tried to understand it then you will have noticed that there is a doubly-linked list that you need to traverse until you find the `System` process. This is the `ActiveProcessLinks` field in the `_EPROCESS` structure.

## Doubly-Linked Lists

The next image will explain what a doubly-linked list looks like. It is simply a collection of `_LIST_ENTRY` structs, each containing a `Flink` (forward link), and a `Blink` (backwards link) field:

<img width="1429" alt="Screenshot 2024-09-23 at 20 20 31" src="https://github.com/user-attachments/assets/94743df7-75dd-470b-87b5-7b252ff0dcda">

The `Flink` contains a pointer to the next `_LIST_ENTRY` and the `Blink` contains a pointer to the previous `_LIST_ENTRY`. Also notice that they are circular, meaning the tail (last entry) has an `Flink` to the head (first entry) and vice-versa. All good so far.

Now the confusion (at least for me). If the doubly-linked list is inside an `_EPROCESS` structure, say the `ActiveProcessLinks` field, where is the field that points to the `_EPROCESS`?

## Doubly-Linked Lists in Structures

It turns out it isn't confusing at all, it's actually really easy to understand, I just didn't know until after observing a few of these lists it just occurde to me. **_Yeah I know!_** That's what happens when you do an IT degree instead of a computer science degree!

<img width="1333" alt="Screenshot 2024-09-23 at 20 31 53" src="https://github.com/user-attachments/assets/2095981f-9818-4d23-9ead-0e62360a230c">

The address of the `Flink` field, and of course the `Blink` field are simply offsets of the `_EPROCESS` structure! That is the address of `_LIST_ENTRY` is inside the `_EPROCESS` structure at an offset, to traverse the link, say to get the next `_EPROCESS` we dereference the `Flink` and use that address minus the offset of `ActiveProcessLinks` to get the address of the next `_EPROCESS`.

## Walking Lists in Windbg

If we break in to the kernel of a debugee we can set the process context to a `cmd.exe` instance that was started:

```
1: kd> !process 0 0 cmd.exe
PROCESS ffff82862f1240c0
    SessionId: 1  Cid: 1bf8    Peb: fe5bc63000  ParentCid: 11d4
    DirBase: 1e6040002  ObjectTable: ffffe1052fb17000  HandleCount:  70.
    Image: cmd.exe
```

Next, we can examine the `ActiveProcessLinks` field which contains the `_LIST_ENTRY` for the next and previous `_PROCESS` structures:

```
1: kd> dt _EPROCESS ffff82862f1240c0 ActiveProcessLinks
nt!_EPROCESS
   +0x448 ActiveProcessLinks : _LIST_ENTRY [ 0xffff8286`2f068508 - 0xffff8286`317dc508 ]
```

Using `0xffff82862f068508` we can follow the `Flink` and examine the next `_EPROCESS` by subtracting the `ActiveProcessLinks` field offset:

```
1: kd> dt _EPROCESS (0xffff82862f068508-0x448) UniqueProcessId, ActiveProcessLinks, ImageFileName
nt!_EPROCESS
   +0x440 UniqueProcessId     : 0x00000000`00000890 Void
   +0x448 ActiveProcessLinks  : _LIST_ENTRY [ 0xfffff800`116263a0 - 0xffff8286`2f124508 ]
   +0x5a8 ImageFileName       : [15]  "conhost.exe"
```

Continue walking the `ActiveProcessLinks` doubly-linked list and we will arrive at the `System` process:

```
1: kd> dt _EPROCESS (0xfffff800116263a0-0x448) UniqueProcessId, ActiveProcessLinks, ImageFileName
nt!_EPROCESS
   +0x440 UniqueProcessId     : (null) 
   +0x448 ActiveProcessLinks  : _LIST_ENTRY [ 0xffff8286`2c274488 - 0xffff8286`2f068508 ]
   +0x5a8 ImageFileName       : [15]  ""
1: kd> dt _EPROCESS (0xffff82862c274488-0x448) UniqueProcessId, ActiveProcessLinks, ImageFileName
nt!_EPROCESS
   +0x440 UniqueProcessId     : 0x00000000`00000004 Void
   +0x448 ActiveProcessLinks  : _LIST_ENTRY [ 0xffff8286`2c35d4c8 - 0xfffff800`116263a0 ]
   +0x5a8 ImageFileName       : [15]  "System"
```

Just for completion we can also examine the `Blink` in the `conhost.exe` process and confirm that we arrive back at the `cmd.exe` process where we started:

```
1: kd> dt _EPROCESS (0xffff8286`2f124508-0x448) UniqueProcessId, ActiveProcessLinks, ImageFileName
nt!_EPROCESS
   +0x440 UniqueProcessId     : 0x00000000`00001bf8 Void
   +0x448 ActiveProcessLinks  : _LIST_ENTRY [ 0xffff8286`2f068508 - 0xffff8286`317dc508 ]
   +0x5a8 ImageFileName       : [15]  "cmd.exe"
```

That is all, go away!

