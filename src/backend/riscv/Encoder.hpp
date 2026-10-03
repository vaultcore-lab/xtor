#pragma once

#include "backend/riscv/MachineInst.hpp"

#include <cstdint>
#include <vector>

namespace XTOR_RV {

//  encode
// `mi` must have physical registers in every operand its format uses, and an
// immediate already in range — both guaranteed by the factories in
// MachineInst.hpp and by register allocation having run.
//
// `displacement` is the byte offset from this instruction to its target,
// used only by B-format branches and J-format jumps. It is ignored for every
// other format. Must be even, and within the format's reach:
//
//     B-format    -4096 .. 4094
//     J-format    -1048576 .. 1048574
uint32_t encode(const MachineInst& mi, int64_t displacement = 0);

void encodeAll(const std::vector<MachineInst>& insts,
               const std::vector<int64_t>& displacements,
               std::vector<uint32_t>& out);


// J-format reaches +-1 MiB. A target farther than this needs an indirect
// jump through a register (auipc + jalr), which the relax pass must build.
constexpr bool fitsJumpOffset(int64_t off) {
    return off >= -1048576 && off <= 1048574 && (off & 1) == 0;
}

} // namespace XTOR_RV
