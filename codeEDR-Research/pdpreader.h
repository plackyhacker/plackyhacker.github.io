#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <iostream>
#include <stdexcept>

// PDB reader class ----------------------------------------------------------------------------------------------------------

template <typename T>
static T readAt(const std::vector<uint8_t>& buf, size_t off) {
    T v;
    std::memcpy(&v, buf.data() + off, sizeof(T));
    return v;
}

class PdbReader {
    static constexpr uint16_t S_PUB32 = 0x110e;
    static constexpr size_t   kSectionHdrSize = 40;     // IMAGE_SECTION_HEADER

    const std::vector<uint8_t>& data;

    uint32_t blockSize = 0;
    uint32_t numStreams = 0;
    std::vector<uint8_t>  streamDirectory;
    std::vector<uint32_t> streamSizes;

    std::vector<uint8_t> syms;       // symbol record stream
    std::vector<uint8_t> sections;   // IMAGE_SECTION_HEADER array

public:
    explicit PdbReader(const std::vector<uint8_t>& pdb) : data(pdb) {
        parseSuperBlock();
        readDirectory();
        parseDbi();
    }

    // Look up a public symbol by exact, fully-decorated name.
    bool findSymbol(const char* target, uint32_t& rvaOut) const {
        size_t pos = 0;

        while (pos + 4 <= syms.size()) {
            uint16_t recordSize = readAt<uint16_t>(syms, pos);
            uint16_t recordType = readAt<uint16_t>(syms, pos + 2);

            if (recordSize == 0)
                break;                       // degenerate; would loop forever

            if (recordType == S_PUB32) {
                const char* name = (const char*)&syms[pos + 0x0e];

                if (std::strcmp(name, target) == 0) {
                    uint32_t offset = readAt<uint32_t>(syms, pos + 0x08);
                    uint16_t segment = readAt<uint16_t>(syms, pos + 0x0c);

                    uint32_t va = readAt<uint32_t>(
                        sections, (segment - 1) * kSectionHdrSize + 0x0c);

                    rvaOut = va + offset;
                    return true;
                }
            }

            pos += recordSize + 2;
        }

        return false;
    }

    // Assemble stream n from its scattered blocks.
    std::vector<uint8_t> readStream(uint32_t n) const {
        uint64_t skip = 0;
        for (uint32_t i = 0; i < n; i++)
            skip += (streamSizes[i] + blockSize - 1) / blockSize;

        uint64_t base = 4ULL + uint64_t(numStreams) * 4;
        uint64_t offset = base + skip * 4;
        uint64_t count = (streamSizes[n] + blockSize - 1) / blockSize;

        std::vector<uint32_t> blockNumbers(count);
        std::memcpy(blockNumbers.data(),
            streamDirectory.data() + offset,
            count * 4);

        std::vector<uint8_t> out(count * blockSize);
        for (uint64_t i = 0; i < count; i++)
            std::memcpy(out.data() + i * blockSize,
                data.data() + uint64_t(blockNumbers[i]) * blockSize,
                blockSize);

        out.resize(streamSizes[n]);
        return out;
    }

private:
    void parseSuperBlock() {
        static const char kMagic[32] = {
            'M','i','c','r','o','s','o','f','t',' ','C','/','C','+','+',' ',
            'M','S','F',' ','7','.','0','0','\r','\n','\x1A','D','S','\0','\0','\0'
        };

        if (data.size() < 56 || std::memcmp(data.data(), kMagic, 32) != 0)
            throw std::runtime_error("not an MSF 7.00 container");

        blockSize = readAt<uint32_t>(data, 0x20);
    }

    void readDirectory() {
        uint32_t numDirectoryBytes = readAt<uint32_t>(data, 0x2c);
        uint32_t blockMapAddr = readAt<uint32_t>(data, 0x34);
        uint64_t blockMapOffset = uint64_t(blockMapAddr) * blockSize;

        uint32_t offsetCount = (numDirectoryBytes + blockSize - 1) / blockSize;

        std::vector<uint32_t> offsets(offsetCount);
        std::memcpy(offsets.data(),
            data.data() + blockMapOffset,
            offsetCount * 4);

        streamDirectory.resize(uint64_t(offsetCount) * blockSize);
        for (uint32_t i = 0; i < offsetCount; i++)
            std::memcpy(streamDirectory.data() + size_t(i) * blockSize,
                data.data() + uint64_t(offsets[i]) * blockSize,
                blockSize);

        streamDirectory.resize(numDirectoryBytes);

        numStreams = readAt<uint32_t>(streamDirectory, 0);
        streamSizes.resize(numStreams);
        std::memcpy(streamSizes.data(),
            streamDirectory.data() + 4,
            size_t(numStreams) * 4);
    }

    void parseDbi() {
        std::vector<uint8_t> dbi = readStream(3);

        uint16_t symRecStream = readAt<uint16_t>(dbi, 0x14);

        uint32_t optDbgOffset = 0x40
            + readAt<uint32_t>(dbi, 0x18)   // ModInfoSize
            + readAt<uint32_t>(dbi, 0x1c)   // SectionContributionSize
            + readAt<uint32_t>(dbi, 0x20)   // SectionMapSize
            + readAt<uint32_t>(dbi, 0x24)   // SourceInfoSize
            + readAt<uint32_t>(dbi, 0x28)   // TypeServerMapSize
            + readAt<uint32_t>(dbi, 0x34);  // ECSubstreamSize

        uint16_t sectionHdrStream = readAt<uint16_t>(dbi, optDbgOffset + 5 * 2);

        syms = readStream(symRecStream);
        sections = readStream(sectionHdrStream);
    }
};
