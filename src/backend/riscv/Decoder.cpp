#include "backend/riscv/Decoder.hpp"
#include <sstream>

namespace XTOR_RV {
namespace {

struct DecodePattern {
    uint32_t mask;
    uint32_t match;
    RvOpcode opcode;
};
constexpr uint32_t kRegisterMask = 0xFE00707F;
constexpr uint32_t kImmediateMask = 0x0000707F;
constexpr uint32_t kShift64Mask = 0xFC00707F;
constexpr uint32_t kOpcodeMask = 0x0000007F;
constexpr uint32_t kExactMask = 0xFFFFFFFF;

// Each row is one REAL operation from RvOpcode. Reserved funct3/funct7
// combinations have no row and therefore fail cleanly. Integer values
// are written in hex to make the positions comparable to emitted words.
constexpr DecodePattern kPatterns[] = {
    {kRegisterMask, 0x00000033, RvOpcode::ADD},
    {kRegisterMask, 0x40000033, RvOpcode::SUB},
    {kRegisterMask, 0x00001033, RvOpcode::SLL},
    {kRegisterMask, 0x00002033, RvOpcode::SLT},
    {kRegisterMask, 0x00003033, RvOpcode::SLTU},
    {kRegisterMask, 0x00004033, RvOpcode::XOR},
    {kRegisterMask, 0x00005033, RvOpcode::SRL},
    {kRegisterMask, 0x40005033, RvOpcode::SRA},
    {kRegisterMask, 0x00006033, RvOpcode::OR},
    {kRegisterMask, 0x00007033, RvOpcode::AND},

    {kRegisterMask, 0x0000003B, RvOpcode::ADDW},
    {kRegisterMask, 0x4000003B, RvOpcode::SUBW},
    {kRegisterMask, 0x0000103B, RvOpcode::SLLW},
    {kRegisterMask, 0x0000503B, RvOpcode::SRLW},
    {kRegisterMask, 0x4000503B, RvOpcode::SRAW},

    {kRegisterMask, 0x02000033, RvOpcode::MUL},
    {kRegisterMask, 0x02001033, RvOpcode::MULH},
    {kRegisterMask, 0x02002033, RvOpcode::MULHSU},
    {kRegisterMask, 0x02003033, RvOpcode::MULHU},
    {kRegisterMask, 0x02004033, RvOpcode::DIV},
    {kRegisterMask, 0x02005033, RvOpcode::DIVU},
    {kRegisterMask, 0x02006033, RvOpcode::REM},
    {kRegisterMask, 0x02007033, RvOpcode::REMU},
    {kRegisterMask, 0x0200003B, RvOpcode::MULW},
    {kRegisterMask, 0x0200403B, RvOpcode::DIVW},
    {kRegisterMask, 0x0200503B, RvOpcode::DIVUW},
    {kRegisterMask, 0x0200603B, RvOpcode::REMW},
    {kRegisterMask, 0x0200703B, RvOpcode::REMUW},

    {kImmediateMask, 0x00000013, RvOpcode::ADDI},
    {kImmediateMask, 0x00002013, RvOpcode::SLTI},
    {kImmediateMask, 0x00003013, RvOpcode::SLTIU},
    {kImmediateMask, 0x00004013, RvOpcode::XORI},
    {kImmediateMask, 0x00006013, RvOpcode::ORI},
    {kImmediateMask, 0x00007013, RvOpcode::ANDI},

    {kShift64Mask, 0x00001013, RvOpcode::SLLI},
    {kShift64Mask, 0x00005013, RvOpcode::SRLI},
    {kShift64Mask, 0x40005013, RvOpcode::SRAI},

    {kImmediateMask, 0x0000001B, RvOpcode::ADDIW},
    {kRegisterMask, 0x0000101B, RvOpcode::SLLIW},
    {kRegisterMask, 0x0000501B, RvOpcode::SRLIW},
    {kRegisterMask, 0x4000501B, RvOpcode::SRAIW},
    {kImmediateMask, 0x00000067, RvOpcode::JALR},

    {kImmediateMask, 0x00000003, RvOpcode::LB},
    {kImmediateMask, 0x00001003, RvOpcode::LH},
    {kImmediateMask, 0x00002003, RvOpcode::LW},
    {kImmediateMask, 0x00003003, RvOpcode::LD},
    {kImmediateMask, 0x00004003, RvOpcode::LBU},
    {kImmediateMask, 0x00005003, RvOpcode::LHU},
    {kImmediateMask, 0x00006003, RvOpcode::LWU},

    {kImmediateMask, 0x00000023, RvOpcode::SB},
    {kImmediateMask, 0x00001023, RvOpcode::SH},
    {kImmediateMask, 0x00002023, RvOpcode::SW},
    {kImmediateMask, 0x00003023, RvOpcode::SD},

    {kImmediateMask, 0x00000063, RvOpcode::BEQ},
    {kImmediateMask, 0x00001063, RvOpcode::BNE},
    {kImmediateMask, 0x00004063, RvOpcode::BLT},
    {kImmediateMask, 0x00005063, RvOpcode::BGE},
    {kImmediateMask, 0x00006063, RvOpcode::BLTU},
    {kImmediateMask, 0x00007063, RvOpcode::BGEU},

    {kOpcodeMask, 0x00000037, RvOpcode::LUI},
    {kOpcodeMask, 0x00000017, RvOpcode::AUIPC},
    {kOpcodeMask, 0x0000006F, RvOpcode::JAL},

    {kExactMask, 0x00000073, RvOpcode::ECALL},
    {kExactMask, 0x00100073, RvOpcode::EBREAK},
};

int64_t signExtend(uint32_t value, unsigned width) {
    const uint32_t signBit = uint32_t{1} << (width - 1);
    return static_cast<int64_t>(value ^ signBit) - signBit;
}

std::string targetLabel(uint64_t address, int64_t displacement) {
    const uint64_t target = address + static_cast<uint64_t>(displacement);
    std::ostringstream label;
    label << "0x" << std::hex << target;
    return label.str();
}

} // namespace

//  decode — identify the operation, then reconstruct its operands

std::optional<DecodedInst> decode(uint32_t word, uint64_t address) {
    const DecodePattern* matched = nullptr;
    for (const DecodePattern& candidate : kPatterns) {
        if ((word & candidate.mask) == candidate.match) {
            matched = &candidate;
            break;
        }
    }

    if (matched == nullptr)
        return std::nullopt;

    const MReg dest = MReg::phys((word >> 7) & 0x1F);
    const MReg source1 = MReg::phys((word >> 15) & 0x1F);
    const MReg source2 = MReg::phys((word >> 20) & 0x1F);

    DecodedInst decoded;
    MachineInst& instruction = decoded.instruction;
    instruction.op = matched->opcode;

    switch (formatOf(instruction.op)) {
        // R-format has no immediate: rd = operation(rs1, rs2).
        case RvFormat::R:
            instruction.rd = dest;
            instruction.rs1 = source1;
            instruction.rs2 = source2;
            break;

        // I-format carries rd/rs1 plus either a signed immediate or a
        // shift amount. Function bits must not leak into a shift amount.
        case RvFormat::I:
            instruction.rd = dest;
            instruction.rs1 = source1;
            switch (instruction.op) {
                case RvOpcode::SLLI:
                case RvOpcode::SRLI:
                case RvOpcode::SRAI:
                    instruction.imm = (word >> 20) & 0x3F;
                    break;
                case RvOpcode::SLLIW:
                case RvOpcode::SRLIW:
                case RvOpcode::SRAIW:
                    instruction.imm = (word >> 20) & 0x1F;
                    break;
                default:
                    instruction.imm = signExtend(word >> 20, 12);
                    break;
            }
            break;

        // Loads have I-format bits but a distinct printer form: off(rs1).
        case RvFormat::ILoad:
            instruction.rd = dest;
            instruction.rs1 = source1;
            instruction.imm = signExtend(word >> 20, 12);
            break;

        // S-format: imm[11:5] comes from bits 31:25, and imm[4:0]
        case RvFormat::S: {
            const uint32_t immediate = ((word >> 25) << 5)
                                     | ((word >> 7) & 0x1F);
            instruction.rs1 = source1;
            instruction.rs2 = source2;
            instruction.imm = signExtend(immediate, 12);
            break;
        }

        // B-format: collect each scattered group at its semantic bit
        case RvFormat::B: {
            const uint32_t immediate = ((word >> 31) << 12)       // imm[12]
                                     | (((word >> 7) & 1) << 11) // imm[11]
                                     | (((word >> 25) & 0x3F) << 5)
                                     | (((word >> 8) & 0xF) << 1);
            instruction.rs1 = source1;
            instruction.rs2 = source2;
            decoded.displacement = signExtend(immediate, 13);
            instruction.label = targetLabel(address, decoded.displacement);
            break;
        }

        // U-format prints the upper 20-bit field itself, not the value
        case RvFormat::U:
            instruction.rd = dest;
            instruction.imm = word >> 12;
            break;

        // J-format uses a different scatter: 20 | 10:1 | 11 | 19:12.
        case RvFormat::J: {
            const uint32_t immediate = ((word >> 31) << 20)
                                     | (word & 0x000FF000)
                                     | (((word >> 20) & 1) << 11)
                                     | (((word >> 21) & 0x3FF) << 1);
            instruction.rd = dest;
            decoded.displacement = signExtend(immediate, 21);
            instruction.label = targetLabel(address, decoded.displacement);
            break;
        }

        case RvFormat::None:
            break;
    }

    return decoded;
}

} // namespace XTOR_RV
