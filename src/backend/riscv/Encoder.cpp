#include "backend/riscv/Encoder.hpp"

#include <sstream>
#include <stdexcept>

namespace XTOR_RV {
namespace {

constexpr uint32_t OP        = 0b0110011;   // register arithmetic, 64-bit
constexpr uint32_t OP_32     = 0b0111011;   // register arithmetic, 32-bit (W)
constexpr uint32_t OP_IMM    = 0b0010011;   // immediate arithmetic, 64-bit
constexpr uint32_t OP_IMM_32 = 0b0011011;   // immediate arithmetic, 32-bit
constexpr uint32_t LOAD      = 0b0000011;
constexpr uint32_t STORE     = 0b0100011;
constexpr uint32_t BRANCH    = 0b1100011;
constexpr uint32_t LUI_OP    = 0b0110111;
constexpr uint32_t AUIPC_OP  = 0b0010111;
constexpr uint32_t JAL_OP    = 0b1101111;
constexpr uint32_t JALR_OP   = 0b1100111;
constexpr uint32_t SYSTEM    = 0b1110011;

struct Enc {
    uint32_t opcode;
    uint32_t funct3;
    uint32_t funct7;
};

Enc encOf(RvOpcode op) {
    switch (op) {
        case RvOpcode::ADD:    return {OP, 0b000, 0x00};
        case RvOpcode::SUB:    return {OP, 0b000, 0x20};
        case RvOpcode::SLL:    return {OP, 0b001, 0x00};
        case RvOpcode::SLT:    return {OP, 0b010, 0x00};
        case RvOpcode::SLTU:   return {OP, 0b011, 0x00};
        case RvOpcode::XOR:    return {OP, 0b100, 0x00};
        case RvOpcode::SRL:    return {OP, 0b101, 0x00};
        case RvOpcode::SRA:    return {OP, 0b101, 0x20};
        case RvOpcode::OR:     return {OP, 0b110, 0x00};
        case RvOpcode::AND:    return {OP, 0b111, 0x00};

        case RvOpcode::MUL:    return {OP, 0b000, 0x01};
        case RvOpcode::MULH:   return {OP, 0b001, 0x01};
        case RvOpcode::MULHSU: return {OP, 0b010, 0x01};
        case RvOpcode::MULHU:  return {OP, 0b011, 0x01};
        case RvOpcode::DIV:    return {OP, 0b100, 0x01};
        case RvOpcode::DIVU:   return {OP, 0b101, 0x01};
        case RvOpcode::REM:    return {OP, 0b110, 0x01};
        case RvOpcode::REMU:   return {OP, 0b111, 0x01};

        case RvOpcode::ADDW:   return {OP_32, 0b000, 0x00};
        case RvOpcode::SUBW:   return {OP_32, 0b000, 0x20};
        case RvOpcode::SLLW:   return {OP_32, 0b001, 0x00};
        case RvOpcode::SRLW:   return {OP_32, 0b101, 0x00};
        case RvOpcode::SRAW:   return {OP_32, 0b101, 0x20};
        case RvOpcode::MULW:   return {OP_32, 0b000, 0x01};
        case RvOpcode::DIVW:   return {OP_32, 0b100, 0x01};
        case RvOpcode::DIVUW:  return {OP_32, 0b101, 0x01};
        case RvOpcode::REMW:   return {OP_32, 0b110, 0x01};
        case RvOpcode::REMUW:  return {OP_32, 0b111, 0x01};

        case RvOpcode::ADDI:   return {OP_IMM, 0b000, 0};
        case RvOpcode::SLTI:   return {OP_IMM, 0b010, 0};
        case RvOpcode::SLTIU:  return {OP_IMM, 0b011, 0};
        case RvOpcode::XORI:   return {OP_IMM, 0b100, 0};
        case RvOpcode::ORI:    return {OP_IMM, 0b110, 0};
        case RvOpcode::ANDI:   return {OP_IMM, 0b111, 0};

        case RvOpcode::SLLI:   return {OP_IMM, 0b001, 0b000000};
        case RvOpcode::SRLI:   return {OP_IMM, 0b101, 0b000000};
        case RvOpcode::SRAI:   return {OP_IMM, 0b101, 0b010000};

        case RvOpcode::ADDIW:  return {OP_IMM_32, 0b000, 0};

        // The W shifts take a 5-bit amount, so the discriminator is a full
        // funct7 in imm[11:5].
        case RvOpcode::SLLIW:  return {OP_IMM_32, 0b001, 0b0000000};
        case RvOpcode::SRLIW:  return {OP_IMM_32, 0b101, 0b0000000};
        case RvOpcode::SRAIW:  return {OP_IMM_32, 0b101, 0b0100000};

        case RvOpcode::JALR:   return {JALR_OP, 0b000, 0};

        case RvOpcode::LB:     return {LOAD, 0b000, 0};
        case RvOpcode::LH:     return {LOAD, 0b001, 0};
        case RvOpcode::LW:     return {LOAD, 0b010, 0};
        case RvOpcode::LD:     return {LOAD, 0b011, 0};
        case RvOpcode::LBU:    return {LOAD, 0b100, 0};
        case RvOpcode::LHU:    return {LOAD, 0b101, 0};
        case RvOpcode::LWU:    return {LOAD, 0b110, 0};

        case RvOpcode::SB:     return {STORE, 0b000, 0};
        case RvOpcode::SH:     return {STORE, 0b001, 0};
        case RvOpcode::SW:     return {STORE, 0b010, 0};
        case RvOpcode::SD:     return {STORE, 0b011, 0};

        case RvOpcode::BEQ:    return {BRANCH, 0b000, 0};
        case RvOpcode::BNE:    return {BRANCH, 0b001, 0};
        case RvOpcode::BLT:    return {BRANCH, 0b100, 0};
        case RvOpcode::BGE:    return {BRANCH, 0b101, 0};
        case RvOpcode::BLTU:   return {BRANCH, 0b110, 0};
        case RvOpcode::BGEU:   return {BRANCH, 0b111, 0};

        case RvOpcode::LUI:    return {LUI_OP,   0, 0};
        case RvOpcode::AUIPC:  return {AUIPC_OP, 0, 0};

        case RvOpcode::JAL:    return {JAL_OP, 0, 0};

        case RvOpcode::ECALL:  return {SYSTEM, 0b000, 0};
        case RvOpcode::EBREAK: return {SYSTEM, 0b000, 0};
    }
    throw std::logic_error("encOf: unhandled RvOpcode");
}


// A register operand must be physical by now. A virtual one means register
// allocation did not run, or missed this instruction — and silently encoding
// a vreg ID as a register number would produce code that runs and is wrong.
uint32_t phys(const MReg& r, const char* which, RvOpcode op) {
    if (!r.isPhys()) {
        std::ostringstream o;
        o << "encode: " << mnemonic(op) << " operand " << which << " is "
          << (r.isVirt() ? "still virtual" : "unset")
          << " — register allocation has not run on this instruction";
        throw std::logic_error(o.str());
    }
    return r.num & 0x1F;
}

// True if the shift-immediate form uses a 5-bit amount rather than 6.
bool isWordShift(RvOpcode op) {
    return op == RvOpcode::SLLIW || op == RvOpcode::SRLIW ||
           op == RvOpcode::SRAIW;
}

bool isShiftImm(RvOpcode op) {
    return op == RvOpcode::SLLI || op == RvOpcode::SRLI ||
           op == RvOpcode::SRAI || isWordShift(op);
}

} // namespace


uint32_t encode(const MachineInst& mi, int64_t displacement) {
    const Enc e = encOf(mi.op);
    uint32_t w = e.opcode;

    switch (formatOf(mi.op)) {

        //R: funct7 | rs2 | rs1 | funct3 | rd | opcode 
        case RvFormat::R: {
            w |= phys(mi.rd,  "rd",  mi.op) << 7;
            w |= e.funct3                   << 12;
            w |= phys(mi.rs1, "rs1", mi.op) << 15;
            w |= phys(mi.rs2, "rs2", mi.op) << 20;
            w |= e.funct7                   << 25;
            break;
        }

        //I: imm[11:0] | rs1 | funct3 | rd | opcode 
        case RvFormat::I: {
            uint32_t immField;

            if (isShiftImm(mi.op)) {
                const uint32_t shamtMask = isWordShift(mi.op) ? 0x1Fu : 0x3Fu;
                const uint32_t shamtBits = isWordShift(mi.op) ? 5u : 6u;
                const uint32_t shamt =
                    static_cast<uint32_t>(mi.imm) & shamtMask;
                immField = (e.funct7 << shamtBits) | shamt;
            } else {
                immField = static_cast<uint32_t>(mi.imm) & 0xFFF;
            }

            w |= phys(mi.rd,  "rd",  mi.op) << 7;
            w |= e.funct3                   << 12;
            w |= phys(mi.rs1, "rs1", mi.op) << 15;
            w |= (immField & 0xFFF)         << 20;
            break;
        }

        //ILoad: same layout as I, different assembly spelling 
        case RvFormat::ILoad: {
            w |= phys(mi.rd,  "rd",   mi.op) << 7;
            w |= e.funct3                    << 12;
            w |= phys(mi.rs1, "base", mi.op) << 15;
            w |= (static_cast<uint32_t>(mi.imm) & 0xFFF) << 20;
            break;
        }

        // S: imm[11:5] | rs2 | rs1 | funct3 | imm[4:0] | opcode 
        // The immediate is split across two non-adjacent fields.
        case RvFormat::S: {
            const uint32_t imm = static_cast<uint32_t>(mi.imm) & 0xFFF;

            w |= (imm & 0x1F)                 << 7;    // imm[4:0]
            w |= e.funct3                     << 12;
            w |= phys(mi.rs1, "base", mi.op)  << 15;
            w |= phys(mi.rs2, "src",  mi.op)  << 20;
            w |= ((imm >> 5) & 0x7F)          << 25;   // imm[11:5]
            break;
        }

        //B: imm[12|10:5] | rs2 | rs1 | funct3 | imm[4:1|11] | opcode -
        // The worst layout in the ISA. Bit 0 is not stored — branch targets
        // are 2-byte aligned — so a 13-bit signed range lives in 12 bits.
        case RvFormat::B: {
            if (!fitsBranchOffset(displacement)) {
                std::ostringstream o;
                o << "encode: " << mnemonic(mi.op) << " displacement "
                  << displacement
                  << " is out of reach (-4096..4094, even) — the relax pass "
                     "must invert this branch around a jump";
                throw std::logic_error(o.str());
            }

            const uint32_t d = static_cast<uint32_t>(displacement);

            w |= ((d >> 11) & 0x1)  << 7;     // imm[11]
            w |= ((d >> 1)  & 0xF)  << 8;     // imm[4:1]
            w |= e.funct3           << 12;
            w |= phys(mi.rs1, "rs1", mi.op) << 15;
            w |= phys(mi.rs2, "rs2", mi.op) << 20;
            w |= ((d >> 5)  & 0x3F) << 25;    // imm[10:5]
            w |= ((d >> 12) & 0x1)  << 31;    // imm[12]
            break;
        }

        //U: imm[31:12] | rd | opcode 
        // The immediate is already the UPPER 20 bits: `lui rd, 1666` loads
        // 1666 << 12. No shifting here beyond placing the field.
        case RvFormat::U: {
            w |= phys(mi.rd, "rd", mi.op) << 7;
            w |= (static_cast<uint32_t>(mi.imm) & 0xFFFFF) << 12;
            break;
        }

        //J: imm[20|10:1|11|19:12] | rd | opcode
        case RvFormat::J: {
            if (!fitsJumpOffset(displacement)) {
                std::ostringstream o;
                o << "encode: " << mnemonic(mi.op) << " displacement "
                  << displacement
                  << " is out of reach (-1048576..1048574, even) — needs "
                     "auipc + jalr instead";
                throw std::logic_error(o.str());
            }

            const uint32_t d = static_cast<uint32_t>(displacement);

            w |= phys(mi.rd, "rd", mi.op) << 7;
            w |= ((d >> 12) & 0xFF)  << 12;   // imm[19:12]
            w |= ((d >> 11) & 0x1)   << 20;   // imm[11]
            w |= ((d >> 1)  & 0x3FF) << 21;   // imm[10:1]
            w |= ((d >> 20) & 0x1)   << 31;   // imm[20]
            break;
        }

        case RvFormat::None: {
            if (mi.op == RvOpcode::EBREAK)
                w |= 1u << 20;
            break;
        }
    }

    return w;
}

void encodeAll(const std::vector<MachineInst>& insts,
               const std::vector<int64_t>& displacements,
               std::vector<uint32_t>& out) {
    if (displacements.size() != insts.size())
        throw std::logic_error("encodeAll: one displacement per instruction "
                               "is required");

    out.reserve(out.size() + insts.size());
    for (size_t i = 0; i < insts.size(); ++i)
        out.push_back(encode(insts[i], displacements[i]));
}

} // namespace XTOR_RV
