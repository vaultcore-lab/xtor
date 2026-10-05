#include "backend/riscv/Decoder.hpp"

#include <iomanip>
#include <limits>
#include <ostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace XTOR_RV {
namespace {

uint32_t readWord(std::span<const uint8_t, 4> bytes) {
    uint32_t word = 0;
    for (size_t index = 0; index < bytes.size(); ++index)
        word |= static_cast<uint32_t>(bytes[index]) << (index * 8);
    return word;
}

std::string byteDirective(std::span<const uint8_t> bytes) {
    std::ostringstream assembly;
    assembly << ".byte " << std::hex << std::setfill('0');
    for (size_t index = 0; index < bytes.size(); ++index) {
        // Commas separate actual bytes; do not put one before the first.
        if (index != 0)
            assembly << ", ";
        // uint8_t may be a character type, so widen it for numeric output.
        assembly << "0x" << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }
    return assembly.str();
}

std::string wordDirective(uint32_t word) {
    std::ostringstream assembly;
    assembly << ".4byte 0x" << std::hex << std::setfill('0')
             << std::setw(8) << word;
    return assembly.str();
}

void printLine(std::ostream& out, uint64_t address,
               std::span<const uint8_t> bytes, std::string_view assembly,
               std::string_view note = {}) {
    std::ostringstream byteColumn;
    byteColumn << std::hex << std::setfill('0');
    for (size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0)
            byteColumn << ' ';
        byteColumn << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }

    std::ostringstream line;
    line << std::hex << std::setw(16) << std::setfill('0') << address << ":  "
         << std::left << std::setw(12) << std::setfill(' ') << byteColumn.str()
         << assembly;
    if (!note.empty())
        line << "  # " << note;
    out << line.str() << '\n';
}

} // namespace


void disassemble(const std::vector<uint8_t>& bytes, std::ostream& out,
                 uint64_t baseAddress) {
 
    if (!bytes.empty() &&
        bytes.size() - 1 > std::numeric_limits<uint64_t>::max() - baseAddress)
        throw std::invalid_argument("RISC-V disassembly: address range overflows");

    const std::span<const uint8_t> buffer(bytes);
    size_t offset = 0;
    while (offset < buffer.size()) {
        const uint64_t address = baseAddress + offset;
        const auto remaining = buffer.subspan(offset);

        if (remaining.size() < 4) {
            printLine(out, address, remaining, byteDirective(remaining),
                      "truncated 4-byte instruction");
            break;
        }

        const auto instructionBytes = remaining.first<4>();
        const uint32_t word = readWord(instructionBytes);
        const auto decoded = decode(word, address);
        if (decoded.has_value())
            printLine(out, address, instructionBytes,
                      decoded->instruction.toString());
        else
            printLine(out, address, instructionBytes, wordDirective(word),
                      "unknown or unsupported instruction");

        offset += 4;
    }
}

} // namespace XTOR_RV
