#include "backend/riscv/MachineInst.hpp"

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <vector>

namespace XTOR_RV {

// A branch has two useful descriptions of its destination. The assembly
// listing wants an absolute target address; re-encoding wants a signed
// displacement from the instruction's own PC. Keep both, rather than
// trying to recover an integer by parsing the printable label later.
struct DecodedInst {
    // All used registers are physical. For B/J instructions, label holds
    // the hexadecimal target calculated using the PC passed to decode().
    MachineInst instruction;

    // Signed byte distance for B/J instructions; zero for other formats.
    // Round trip: encode(decoded.instruction, decoded.displacement).
    int64_t displacement = 0;
};

std::optional<DecodedInst> decode(uint32_t word, uint64_t address = 0);

void disassemble(const std::vector<uint8_t>& bytes, std::ostream& out,
                 uint64_t baseAddress = 0);

} // namespace XTOR_RV
