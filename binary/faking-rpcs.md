[Home](https://plackyhacker.github.io)

# Faking Remote Procedure Calls

As I continue to prepare myself for the [Offensive Security Exploitation Expert](https://www.offsec.com/courses/exp-401/) exam I am continuing to work my way through a Microsoft Edge Type Confusion bug. I got tangled up in Remote Procedure Calls. The OffSec [syllabus](https://manage.offsec.com/app/uploads/2025/03/AWE-Syllabus-new.pdf) is publicly available on their website.

What has RPC got to do with Microsoft Edge? It is known technique for bypassing certain mitigations. [CVE-2021-26411](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26411) was the result of an exploitation of Internet Explorer found in the wild, and RPC was used to bypass Control Flow Guard (CFG).

Whenever I am trying to understand a complex topic I try to implement it in `C` so I can write my own code and debug it in WinDbg to get a better understanding of what is going on in memory and what is being passed to the associated Win32 APIs.

## Previous Research

As with many of my blog topics there has been research done by much cleverer people than me. I have attended the [Advanced Windows Exploitation](https://www.offsec.com/courses/exp-401/) course offered by Offsec and a lot of research on this topic was done by the authors. If you want to fully understand how RPC can be reverse engineered I highly recommend you attend the course.

However, others have carried out research in this area and have documented the structures:

- [A Clever but Tedious CFG Bypass](https://itm4n.github.io/ghost-in-the-ppl-part-2/#a-clever-but-tedious-cfg-bypass)
- [Exploiting Windows RPC to bypass CFG mitigation: analysis of CVE-2021-26411 in-the-wild sample](https://iamelli0t.github.io/2021/04/10/RPC-Bypass-CFG.html)

The code is my own but some of the field contents have been taken from other peoples research. I will point those out as we go along.

**Note:** I did find it helpful to map out RPC structures from other implementations (which I will not disclose as I need to be very careful about what I write withought violating any academic policies), it's a bit messy, but hopefully you get the idea:

<img alt="Screenshot 2025-01-21 at 16 24 25" src="https://github.com/user-attachments/assets/a462a047-04bb-4f04-87a1-c675f3386191" style="border: 1px solid black;" />

## RPC Stubs

RPC has been around since the 1960s. Microsoft adopted it in Windows NT 3.1 in 1993, using it for inter-process and network communication via its MSRPC implementation. RPC is a feature to allow code in one process to call a procedure in a different process. RPC also manages transportation of the call, this enables RPCs to be carried out accross networks on processes running on different hosts.

The protocol uses client and server stubs to send and receive calls:

<img alt="Screenshot 2025-01-21 at 16 24 25" src="https://github.com/user-attachments/assets/a247b36f-10d9-4d18-985f-fca8a5cd0359" style="border: 1px solid black;" />

The idea behind injecting fake RPC calls is that we can use the server runtime to get the server stub to call Win32 APIs out of context, completely bypassing the client stub and the transport layer:

<img alt="Screenshot 2025-01-21 at 16 24 25" src="https://github.com/user-attachments/assets/fd500f75-7f8d-4632-856a-72f35ba1a6cd" style="border: 1px solid black;" />

So, how can we do this. Let's try to understand how RPC calls are processed using a basic RPC implementation.

## NdrServerCall2

I decided to do some basic dynamic anlaysis on an RPC client/server call. I followed [Building a Simple RPC Client and Server: A Step-by-Step Guide](https://trainsec.net/library/windows-internals/building-a-simple-rpc-client-and-server-a-step-by-step-guide/) by Pavel Yosifovich which shows how to implement a very basic RPC server and client.

I ran the server in WinDbg and set a breakpoint on the `Add` function. I ran the client application, which calls the `Add` function using RPC. When the breakpoint was hit I looked at the call stack:

```
0:003> k L2
 # Child-SP          RetAddr               Call Site
00 000000ff`2d0feac8 00007ffa`be3c7863     Server!Add
01 000000ff`2d0fead0 00007ffa`be42b4a6     RPCRT4!Invoke+0x73
0:003> ?RPCRT4!Invoke+0x73-RPCRT4
Evaluate expression: 489571 = 00000000`00077863
```

Using Binary Ninja I discovered that the call to `Invoke` is made in the `NdrStubCall2` function:

<img alt="Screenshot 2025-01-21 at 16 24 25" src="https://github.com/user-attachments/assets/efc3e16f-c5c9-4906-86d0-e7968eecd43c" style="border: 1px solid black;" />

Working backwards I could ascertain that the `NdrServerCall2` function called `NdrStubCall2` function, this looked like a basic wrapper function:

<img alt="Screenshot 2025-01-21 at 16 24 25" src="https://github.com/user-attachments/assets/589005c5-4063-4fa1-a4b1-73c1fea6e887" style="border: 1px solid black;" />

[Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/rpcndr/nf-rpcndr-ndrservercall2) shows that `NdrServerCall2` takes a single argument, which is a `PRPC_MESSAGE` pointer. We can create our fake `RPC_MESSAGE` and call this API:

<img alt="Screenshot 2025-01-21 at 16 24 25" src="https://github.com/user-attachments/assets/8aca9900-cd7f-4160-900a-ad4bc2ea6de1" style="border: 1px solid black;" />

Next we can look at the RPC structs.

## RPC Structures

Going through various research sources, dynamic analysis in WinDbg, and pulling my hair out I came up with the following diagram:

<img alt="Screenshot 2025-01-21 at 16 24 25" src="https://github.com/user-attachments/assets/170db041-38a1-499f-b1e8-08b1a3e8f162" style="border: 1px solid black;" />

I will try to explain the important fields for each structure.

**RPC_MESSAGE**

- **Handle**: This field is a pointer to a `vptr`, which in turn points to a `vftable` for `RPCRT4!OSF_SCALL`.
- **DataRepresentation**: This field must be set to `0x10`. Microsoft states that 'Data representation of the network buffer [is] defined by the NDR specification'. This can be found [here](https://cio-wiki.org//wiki/Network_Data_Representation_(NDR)#:~:text=Data%20representation%3A%20NDR%20specifies%20a,standardized%20NDR%20format%20before%20transmission).
- **Buffer**: This is a pointer to the arguments buffer that will be passed to the Win32 API.
- **BufferLength**: A value indicating how large the arguments buffer is.
- **RpcInterfaceInfo**: A pointer to the `RPC_SERVER_INTERFACE` struct.
- **RpcFlags**: This field is set to `0x100` (`RPC_BUFFER_COMPLETE`).

**RPC_SERVER_INTERFACE**

- **Length**: This field is a value indicating the length of the struct, which is `0x60`.
- **InterpreterInfo**: A pointer to the `MIDLE_SERVER_INFO` struct.
- **Flags**: This is set to `0x4000000`.

**MIDL_SERVER_INFO**

- **pStubDesc**: A pointer to the `MIDL_STUB_DESC` struct.
- **DispatchTable**: This points to the Win32 API that we want to call.
- **ProcString**: This field points to a buffer which defines how arguments and the return value are interpreted.
- **FmtStringOffset**: This field must point to a free buffer space.

**MIDL_STUB_DESC**

- **Allocator**: A pointer to a valid allocator, such as `malloc`.
- **Deallocator**: A pointer to a valid deallocator, such as `free`.
- **pFormatTypes**: This pointer must point to a `NULL` value.
- **Version**: The RPC version being used, which is `0x50002`.

## Implementing Fake RPCs in C

I started by setting the scene. I created a large buffer where I would store my fake RPC structs, zeroed out the buffer, resolved the address of `LoadLibraryA` (this was the Win32 API I was going to call with the fake RPC), and get the base address of the RPC library to locate a `vftable` address:



```c
printf("Faking RPC Calls\n----------------\n\n");

// allocate a large buffer to fake the RPC strucs in
LPVOID buffer = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (buffer == NULL)
{
	printf("[!] Unable to allocate buffer!\n");
	return 1;
}

// zero out the buffer
memset(buffer, 0x0, 0x10000);
printf("[+] Buffer allocation: 0x%p\n", buffer);

LPVOID loadLib = &LoadLibraryA;
HMODULE rpcLib = LoadLibraryA("RPCRT4.DLL");
```

Next, I started to build the `RPC_MESSAGE` structure in the buffer:

```c
// index
DWORD index = 0;
PLONGLONG rpcStructs = (PLONGLONG)(buffer);

// RPC_MESSAGE - offset 0x00
rpcStructs[index] = (LONGLONG)buffer + 0x860; index += 1;								// 0x00 - vptr address;
rpcStructs[index] = (LONGLONG)0x10; index += 1;											// 0x08 - DataRepresentation
rpcStructs[index] = (LONGLONG)buffer + 0x800; index += 1;								// 0x10 - Arguments Buffer
rpcStructs[index] = 0x30; index += 2;													// 0x18 - BufferLength and ProcNum - both are DWORDS
rpcStructs[index] = (LONGLONG)buffer + 0x100; index += 4;								// 0x28 - RpcInterfaceInfo - ptr to RPC_SERVER_INTERFACE
rpcStructs[index] = 0x1000;																// 0x48 - RpcFlags - 0x1000 = RPC_BUFFER_COMPLETE
```

The `RPC_MESSAGE` structure points to a `RPC_SERVER_INTERFACE`:

```c
// RPC_SERVER_INTERFACE - offset 0x100
index = 0x20;
rpcStructs[index] = 0x60;	 index += 10; // was 3										// 0x00 - Length - 0x60
rpcStructs[index] = (LONGLONG)buffer + 0x200; index += 1;								// 0x50 - InterpreterInfo - ptr to MIDL_SERVER_INFO
rpcStructs[index] = 0x4000000;															// 0x58 - Flags - 0x4000000
```

And this points to a `MIDL_SERVER_INFO` structure:

```c
// MIDL_SERVER_INFO - offset 0x200
index = 0x40;
rpcStructs[index] = (LONGLONG)buffer + 0x300; index += 1;								// 0x00 - pStubDesc - ptr to MIDL_STUB_DESC
rpcStructs[index] = (LONGLONG)&loadLib; index += 1;										// 0x08 - DispatchTable - ptr to function to call
rpcStructs[index] = (LONGLONG)buffer + 0x900; index += 1;								// 0x10 - ProcString - ptr to offset +0x900
rpcStructs[index] = (LONGLONG)buffer + 0x960;											// 0x18 - FmtStringOffset
```

Within this code, there is a `DispatchTable` field which points to the `LoadLibraryA` API. There is also a `ProcString` field that points to a really complicated buffer which I will show last. This sturct also points to a `MIDL_STUB_DESC` structure:

```c
// MIDL_STUB_DESC - offset 0x300
index = 0x61;
rpcStructs[index] = (LONGLONG)&malloc; index += 1;										// 0x08 - Allocator - ptr to malloc()
rpcStructs[index] = (LONGLONG)&free; index += 6;										// 0x10 - Deallocator - ptr to free()
rpcStructs[index] = (LONGLONG)buffer + 0x9a0; index += 1;								// 0x40 - pFormatTypes - offset 0x9a0
rpcStructs[index] = (LONGLONG)0x0005000200000000;										// 0x4c - Version - 0x50002
```

The arguments for the API call are pointed to by the `RPC_MESSAGE` struct:

```c
// arguments buffer -  offset 0x800
char arg[] = "ws2_32.dll";

index = 0x100;
rpcStructs[index] = (LONGLONG)&arg; index += 1;											// argument 1
rpcStructs[index] = 0x2222222222222222; index += 1;										// argument 2
rpcStructs[index] = 0x3333333333333333; index += 1;										// argument 3
rpcStructs[index] = 0x4444444444444444; index += 1;										// argument 4
rpcStructs[index] = 0x5555555555555555; index += 1;										// argument 5
rpcStructs[index] = 0x6666666666666666; index += 1;										// argument 6
```

We can provide up to six arguments, but in this PoC only the first one is relevant. The `RPC_MESSAGE` also points to a `vptr`:

```c
// vptr - offset 0x860
index = 0x10c;
rpcStructs[index] = (LONGLONG)rpcLib + 0xe2208;	index += 1;								// 0x00 - vftable address;
rpcStructs[index] = 0x0000004089abcdef;													// stops the exception after the call
```

The two `DWORD` fields directly after the `vftable` pointer is essential to stop the application crashing following the RPC. This was discovered by OffSec and will not be discussed here.

The `ProcString` buffer is also discussed in the AWE course and will not be discussed here. Here is the code:

```c
// format (ProcString) string - offset 0x900
index = 0x120;
rpcStructs[index] = (LONGLONG)0x0000000000004832; index += 1;
rpcStructs[index] = (LONGLONG)0x0744001000600083; index += 1;
rpcStructs[index] = (LONGLONG)0x000000000000010a; index += 1;
rpcStructs[index] = (LONGLONG)0x000b000000480000; index += 1;
rpcStructs[index] = (LONGLONG)0x0048000b00080048; index += 1;
rpcStructs[index] = (LONGLONG)0x00180048000b0010; index += 1;
rpcStructs[index] = (LONGLONG)0x000b00200048000b; index += 1;
rpcStructs[index] = (LONGLONG)0x0070000b00280048; index += 1;
rpcStructs[index] = (LONGLONG)0x00001000000b0078;
```

Bringing it all together we make the `NdrServerCall2` call and display the returned result:

```c
NdrServerCall2((PRPC_MESSAGE)buffer);
printf("[+] Call completed!\n");

// in an exploit an arbitrary read would be used
printf("[+] Return value: 0x%p\n", *(LONGLONG*)rpcStructs[2]);
```

Notice that the return value is written to the `ArgumentsBuffer` field in the `RPC_MESSAGE` structure.

## Fail

When running my code I found that it failed me!

This threw me for quite a while so I decided to go into Binary Ninja and WinDbg to find out why it was crashing. Within `HeapAlloc` there was an access violation:

```
(4dc.2bdc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
ntdll!RtlAllocateHeap+0x20:
00007ffa bec508e0 817b10eeddeedd  cmp     dword ptr [rbx+10h],0DDEEDDEEh ds:00000000'®0000010=????????
```

Without going in to to much detail, by tracing the calls and registry assignments in WinDbg I identified the source of the crash was that `rcx` was `NULL` when `HeapAlloc` was called from within `AllocWrapper` in the RPC module. Using Binary Ninja we can see that `rcx` is populated from a global variable:

<img alt="Screenshot 2025-01-21 at 16 25 57" src="https://github.com/user-attachments/assets/9cfebf7b-78e6-4ec2-9709-4a6bb82a6d0a" style="border: 1px solid black;" />

When analysing this memory location in WinDbg we can clearly see that it is zeroed out:

```
0:000> dq RPCRT4+0x10cee8
00007ffa be45cee8  00000000`00000000  00000000`00000000
00007ffa be45cf08  00000000`00000000  00000000`00000000
00007ffa be45cf18  00000000`00000000  00000000`00000000
00007ffa be45cf28  00000000`00000000  00000000`00000000
00007ffa be45cf38  00000000`00000000  00000000`00000000
00007ffa be45cf48  00000000`00000000  00000000`00000000
00007ffa be45cf58  00000000`00000000  00000000`00000000
```

The prototype for `HeapAlloc` is shown below:

<img alt="Screenshot 2025-01-21 at 16 25 57" src="https://github.com/user-attachments/assets/09496e26-7458-4a71-88ad-5533aeafa18a" style="border: 1px solid black;" />

So, `rcx` should contain a pointer to the heap used for allocation. I assumed, incorrectly, that the `Allocator` field in `MIDL_STUB_DESC` ensured that this variable was populated. When I realised this was not the case I suspected that I had to ensure that RPC was initialised for the application.

## Initialising RPC

To ensure my application was initialised for RPC I used [Building a Simple RPC Client and Server: A Step-by-Step Guide](https://trainsec.net/library/windows-internals/building-a-simple-rpc-client-and-server-a-step-by-step-guide/). If you are interested then take a look at this simple tutorial. The important part is that we need to implement two functions to inform RPC which allocator and deallocator we wish to use:

```c
void* midl_user_allocate(size_t size)
{
	return malloc(size);
}

void midl_user_free(void* p)
{
	free(p);
}
```

Once I had set up RPC correctly I had no further issues.

## For the Win


Running the code again I found that the fake RPC calls the `LoadLibraryA` Win32 API and loads the `ws2_32.dll` module:

<img alt="Screenshot 2025-01-21 at 16 25 57" src="https://github.com/user-attachments/assets/f18ea6e3-308c-475b-91c7-f848d7ba64c4" style="border: 1px solid black;" />

The return value is also returned to the application properly, without any crashes:

<img alt="Screenshot 2025-01-21 at 16 25 57" src="https://github.com/user-attachments/assets/d37f636d-cdae-4b3a-84de-39cb50d6fb91" style="border: 1px solid black;" />

Phew!

## Conclusion

The purpose of this exercise was to understand how to fake RPCs and where to send them. It in no way bypasses CFG, but gives me the foundational knowledge of how I might craft fake RPC structures in an exploitation scenario. I learned a lot about RPC and it's internals. I hope this is useful to at least one other person.

We are done here!

## References

[A Clever but Tedious CFG Bypass](https://itm4n.github.io/ghost-in-the-ppl-part-2/#a-clever-but-tedious-cfg-bypass)

[Building a Simple RPC Client and Server: A Step-by-Step Guide](https://trainsec.net/library/windows-internals/building-a-simple-rpc-client-and-server-a-step-by-step-guide/)

[Demystifying Remote Procedure Calls (RPC) for Beginners: A Comprehensive Guide](https://mobterest.medium.com/demystifying-remote-procedure-calls-rpc-for-beginners-a-comprehensive-guide-7e639c92ea17)

[Exploiting Windows RPC to bypass CFG mitigation: analysis of CVE-2021-26411 in-the-wild sample](https://iamelli0t.github.io/2021/04/10/RPC-Bypass-CFG.html)

[Internet Explorer Memory Corruption Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26411)

[NdrServerCall2 function (rpcndr.h)](https://learn.microsoft.com/en-us/windows/win32/api/rpcndr/nf-rpcndr-ndrservercall2) 

[Network Data Representation (NDR)](https://cio-wiki.org//wiki/Network_Data_Representation_(NDR)#:~:text=Data%20representation%3A%20NDR%20specifies%20a,standardized%20NDR%20format%20before%20transmission)

[Home](https://plackyhacker.github.io)
