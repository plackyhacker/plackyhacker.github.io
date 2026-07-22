// PdbLocator.h
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <stdexcept>

#include <windows.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")

// declared here so the header is self-contained.
uint64_t read_qword(uint64_t address);

struct PdbId {
    uint32_t    guid1 = 0;
    uint16_t    guid2 = 0;
    uint16_t    guid3 = 0;
    uint64_t    guid4 = 0;   // last 8 GUID bytes, big-endian as the server wants them
    uint32_t    age = 0;
    std::string name;        // PDB filename from the debug record
};

// Walk the module's debug directory, find the CodeView (RSDS) record,
// and pull out the GUID/age/name that identify its PDB.
inline PdbId readCodeViewId(uint64_t nt) {
    // e_lfanew (4-byte field) -> NT headers
    uint32_t e_lfanew = (uint32_t)read_qword(nt + 0x3c);
    uint64_t ntHeaders = nt + e_lfanew;

    // Optional header debug directory entry (IMAGE_DIRECTORY_ENTRY_DEBUG = 6).
    // For PE32+ the data-directory array starts at NT + 0x88; entry 6 is at +0x30
    // within it -> 0x88 + 6*8 = 0xB8. RVA is the low 4 bytes; size the high 4.
    uint64_t dbgDirEntry = read_qword(ntHeaders + 0xb8);
    uint32_t dbgDirRva = (uint32_t)(dbgDirEntry & 0xffffffff);
    uint32_t dbgDirSize = (uint32_t)(dbgDirEntry >> 32);
    uint64_t dbgDir = nt + dbgDirRva;

    uint32_t count = dbgDirSize / 0x1c;   // sizeof(IMAGE_DEBUG_DIRECTORY) == 28

    // Find IMAGE_DEBUG_TYPE_CODEVIEW (2). Type is at +0x0c in each entry.
    uint64_t cvEntry = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t e = dbgDir + (uint64_t)i * 0x1c;
        uint32_t type = (uint32_t)read_qword(e + 0x0c);
        if (type == 2) { cvEntry = e; break; }
    }
    if (cvEntry == 0)
        throw std::runtime_error("no CodeView debug entry in module");

    // AddressOfRawData (+0x14) is the RVA of the RSDS record for an image-mapped
    // module. (Use PointerToRawData at +0x18 instead if the module is mapped flat.)
    uint32_t cvRva = (uint32_t)read_qword(cvEntry + 0x14);
    uint64_t rsds = nt + cvRva;

    // RSDS record:  "RSDS"(4) | GUID(16) | Age(4) | Name(NUL-terminated)
    uint32_t sig = (uint32_t)read_qword(rsds + 0x00);
    if (sig != 0x53445352 /* 'RSDS' little-endian */)
        throw std::runtime_error("CodeView record is not RSDS");

    PdbId id;

    // GUID: first 3 fields little-endian, last 8 bytes a raw byte array.
    uint64_t first8 = read_qword(rsds + 0x04);
    id.guid1 = (uint32_t)(first8 & 0xffffffff);
    id.guid2 = (uint16_t)((first8 >> 32) & 0xffff);
    id.guid3 = (uint16_t)((first8 >> 48) & 0xffff);

    // Those 8 bytes print in memory order on the symbol server, so read them as a
    // little-endian qword and byte-swap to get that order into a single value.
    id.guid4 = _byteswap_uint64(read_qword(rsds + 0x0c));

    id.age = (uint32_t)read_qword(rsds + 0x14);   // full 4 bytes, not masked to a byte

    // Name is a NUL-terminated string; read it byte by byte.
    std::string name;
    for (uint64_t p = rsds + 0x18; ; p++) {
        char c = (char)(read_qword(p) & 0xff);
        if (c == '\0') break;
        name.push_back(c);
        if (name.size() > 260) break;   // MAX_PATH guard against a runaway read
    }
    id.name = name.empty() ? "ntkrnlmp.pdb" : name;

    return id;
}

// Build the msdl.microsoft.com path:  <name>/<GUID><AGE>/<name>
inline std::string symbolServerUrl(const PdbId& id) {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "https://msdl.microsoft.com/download/symbols/%s/%08X%04X%04X%016llX%X/%s",
        id.name.c_str(),
        id.guid1, id.guid2, id.guid3, id.guid4, id.age,
        id.name.c_str());
    return std::string(buf);
}

// Download the PDB into a byte vector. Owns its COM init and the stream lifetime.
inline std::vector<uint8_t> downloadPdb(const std::string& url) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool ownCom = SUCCEEDED(hr);   // may already be initialised on this thread

    IStream* stream = nullptr;
    hr = URLOpenBlockingStreamA(nullptr, url.c_str(), &stream, 0, nullptr);
    if (FAILED(hr) || stream == nullptr) {
        if (ownCom) CoUninitialize();
        throw std::runtime_error("PDB download failed, hr=0x" + std::to_string((unsigned)hr));
    }

    std::vector<uint8_t> data;
    uint8_t chunk[4096];
    ULONG got = 0;
    while (SUCCEEDED(stream->Read(chunk, sizeof(chunk), &got)) && got > 0)
        data.insert(data.end(), chunk, chunk + got);

    stream->Release();
    if (ownCom) CoUninitialize();
    return data;
}
