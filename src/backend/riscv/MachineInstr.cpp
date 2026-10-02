#include "backend/riscv/MachineInst.hpp"

#include <array>
#include <ostream>
#include <sstream>
#include <stdexcept>



namespace XTOR_RV{


const char* regName(uint32_t phys) {
    static constexpr std::array<const char*, Reg::kCount> kNames = {
        "zero", "ra", "sp",  "gp",  "tp", "t0", "t1", "t2",
        "s0",   "s1", "a0",  "a1",  "a2", "a3", "a4", "a5",
        "a6",   "a7", "s2",  "s3",  "s4", "s5", "s6", "s7",
        "s8",   "s9", "s10", "s11", "t3", "t4", "t5", "t6",
    };
    return phys < kNames.size() ? kNames[phys] : "x?";
}


RvFormat formatOf(RvOpcode op) {
    switch (op) {
        case RvOpcode::ADD:    case RvOpcode::SUB:
        case RvOpcode::SLL:    case RvOpcode::SLT:   case RvOpcode::SLTU:
        case RvOpcode::XOR:    case RvOpcode::SRL:   case RvOpcode::SRA:
        case RvOpcode::OR:     case RvOpcode::AND:
        case RvOpcode::ADDW:   case RvOpcode::SUBW:
        case RvOpcode::SLLW:   case RvOpcode::SRLW:  case RvOpcode::SRAW:
        case RvOpcode::MUL:    case RvOpcode::MULH:
        case RvOpcode::MULHU:  case RvOpcode::MULHSU:
        case RvOpcode::DIV:    case RvOpcode::DIVU:
        case RvOpcode::REM:    case RvOpcode::REMU:
        case RvOpcode::MULW:   case RvOpcode::DIVW:  case RvOpcode::DIVUW:
        case RvOpcode::REMW:   case RvOpcode::REMUW:
            return RvFormat::R;

        case RvOpcode::ADDI:   case RvOpcode::SLTI:  case RvOpcode::SLTIU:
        case RvOpcode::XORI:   case RvOpcode::ORI:   case RvOpcode::ANDI:
        case RvOpcode::SLLI:   case RvOpcode::SRLI:  case RvOpcode::SRAI:
        case RvOpcode::ADDIW:  case RvOpcode::SLLIW:
        case RvOpcode::SRLIW:  case RvOpcode::SRAIW:
        case RvOpcode::JALR:
            return RvFormat::I;

        case RvOpcode::LB:  case RvOpcode::LH:  case RvOpcode::LW:
        case RvOpcode::LD:  case RvOpcode::LBU: case RvOpcode::LHU:
        case RvOpcode::LWU:
            return RvFormat::ILoad;

        case RvOpcode::SB:  case RvOpcode::SH:
        case RvOpcode::SW:  case RvOpcode::SD:
            return RvFormat::S;

        case RvOpcode::BEQ:  case RvOpcode::BNE:  case RvOpcode::BLT:
        case RvOpcode::BGE:  case RvOpcode::BLTU: case RvOpcode::BGEU:
            return RvFormat::B;

        case RvOpcode::LUI:  case RvOpcode::AUIPC:
            return RvFormat::U;

        case RvOpcode::JAL:
            return RvFormat::J;

        case RvOpcode::ECALL: case RvOpcode::EBREAK:
            return RvFormat::None;
    }
    throw std::logic_error("formatOf: unhandled RvOpcode");
}


const char* mnemonic(RvOpcode op) {
    switch (op) {
        case RvOpcode::ADD:    return "add";
        case RvOpcode::SUB:    return "sub";
        case RvOpcode::SLL:    return "sll";
        case RvOpcode::SLT:    return "slt";
        case RvOpcode::SLTU:   return "sltu";
        case RvOpcode::XOR:    return "xor";
        case RvOpcode::SRL:    return "srl";
        case RvOpcode::SRA:    return "sra";
        case RvOpcode::OR:     return "or";
        case RvOpcode::AND:    return "and";

        case RvOpcode::ADDW:   return "addw";
        case RvOpcode::SUBW:   return "subw";
        case RvOpcode::SLLW:   return "sllw";
        case RvOpcode::SRLW:   return "srlw";
        case RvOpcode::SRAW:   return "sraw";

        case RvOpcode::MUL:    return "mul";
        case RvOpcode::MULH:   return "mulh";
        case RvOpcode::MULHU:  return "mulhu";
        case RvOpcode::MULHSU: return "mulhsu";
        case RvOpcode::DIV:    return "div";
        case RvOpcode::DIVU:   return "divu";
        case RvOpcode::REM:    return "rem";
        case RvOpcode::REMU:   return "remu";
        case RvOpcode::MULW:   return "mulw";
        case RvOpcode::DIVW:   return "divw";
        case RvOpcode::DIVUW:  return "divuw";
        case RvOpcode::REMW:   return "remw";
        case RvOpcode::REMUW:  return "remuw";

        case RvOpcode::ADDI:   return "addi";
        case RvOpcode::SLTI:   return "slti";
        case RvOpcode::SLTIU:  return "sltiu";
        case RvOpcode::XORI:   return "xori";
        case RvOpcode::ORI:    return "ori";
        case RvOpcode::ANDI:   return "andi";
        case RvOpcode::SLLI:   return "slli";
        case RvOpcode::SRLI:   return "srli";
        case RvOpcode::SRAI:   return "srai";
        case RvOpcode::ADDIW:  return "addiw";
        case RvOpcode::SLLIW:  return "slliw";
        case RvOpcode::SRLIW:  return "srliw";
        case RvOpcode::SRAIW:  return "sraiw";
        case RvOpcode::JALR:   return "jalr";

        case RvOpcode::LB:     return "lb";
        case RvOpcode::LH:     return "lh";
        case RvOpcode::LW:     return "lw";
        case RvOpcode::LD:     return "ld";
        case RvOpcode::LBU:    return "lbu";
        case RvOpcode::LHU:    return "lhu";
        case RvOpcode::LWU:    return "lwu";

        case RvOpcode::SB:     return "sb";
        case RvOpcode::SH:     return "sh";
        case RvOpcode::SW:     return "sw";
        case RvOpcode::SD:     return "sd";

        case RvOpcode::BEQ:    return "beq";
        case RvOpcode::BNE:    return "bne";
        case RvOpcode::BLT:    return "blt";
        case RvOpcode::BGE:    return "bge";
        case RvOpcode::BLTU:   return "bltu";
        case RvOpcode::BGEU:   return "bgeu";

        case RvOpcode::LUI:    return "lui";
        case RvOpcode::AUIPC:  return "auipc";
        case RvOpcode::JAL:    return "jal";

        case RvOpcode::ECALL:  return "ecall";
        case RvOpcode::EBREAK: return "ebreak";
    }
    throw std::logic_error("mnemonic: unhandled RvOpcode");

}

std::string MReg::toString() const {
    switch (kind) {
        case Kind::None: return "-";
        case Kind::Phys: return regName(num);
        case Kind::Virt: return "%v" + std::to_string(num);
    }
    return "?";
}


namespace {

void requireFormat(RvOpcode op, RvFormat want, const char* who) {
    const RvFormat got = formatOf(op);
    if (got != want) {
        std::ostringstream o;
        o << who << ": " << mnemonic(op) << " is not a "
          << static_cast<int>(want) << "-format instruction";
        throw std::logic_error(o.str());
    }
}

void requireImmInRange(RvOpcode op, int64_t imm) {
    switch (op) {
        case RvOpcode::SLLI: case RvOpcode::SRLI: case RvOpcode::SRAI:
            if (imm < 0 || imm > 63)
                throw std::logic_error(std::string("mkI: ") + mnemonic(op) +
                                       " shift amount out of range 0..63");
            return;

        case RvOpcode::SLLIW: case RvOpcode::SRLIW: case RvOpcode::SRAIW:
            if (imm < 0 || imm > 31)
                throw std::logic_error(std::string("mkI: ") + mnemonic(op) +
                                       " shift amount out of range 0..31");
            return;

        default:
            if (!fitsImm12(imm))
                throw std::logic_error(std::string("mkI/mkLoad/mkStore: ") +
                    mnemonic(op) + " immediate " + std::to_string(imm) +
                    " does not fit a 12-bit signed field — legalize it first");
            return;
    }
}


void requireImm20(RvOpcode op, int64_t imm) {
    if (imm < -0x80000 || imm > 0x7FFFF)
        throw std::logic_error(std::string("mkU: ") + mnemonic(op) +
            " immediate " + std::to_string(imm) +
            " does not fit a 20-bit signed field");
}    
}

MachineInst mkR(RvOpcode op, MReg rd, MReg rs1, MReg rs2) {
    requireFormat(op, RvFormat::R, "mkR");
    MachineInst mi;
    mi.op = op; mi.rd = rd; mi.rs1 = rs1; mi.rs2 = rs2;
    return mi;
}

MachineInst mkI(RvOpcode op, MReg rd, MReg rs1, int64_t imm) {
    requireFormat(op, RvFormat::I, "mkI");
    requireImmInRange(op, imm);
    MachineInst mi;
    mi.op = op; mi.rd = rd; mi.rs1 = rs1; mi.imm = imm;
    return mi;
}

MachineInst mkLoad(RvOpcode op, MReg rd, MReg base, int64_t off) {
    requireFormat(op, RvFormat::ILoad, "mkLoad");
    requireImmInRange(op, off);
    MachineInst mi;
    mi.op = op; mi.rd = rd; mi.rs1 = base; mi.imm = off;
    return mi;
}

MachineInst mkStore(RvOpcode op, MReg src, MReg base, int64_t off) {
    requireFormat(op, RvFormat::S, "mkStore");
    requireImmInRange(op, off);
    // Note the operand order: the VALUE is rs2 and the BASE is rs1, matching
    // the encoding rather than the assembly syntax `sd rs2, off(rs1)`.
    MachineInst mi;
    mi.op = op; mi.rs1 = base; mi.rs2 = src; mi.imm = off;
    return mi;
}

MachineInst mkB(RvOpcode op, MReg rs1, MReg rs2, std::string label) {
    requireFormat(op, RvFormat::B, "mkB");
    MachineInst mi;
    mi.op = op; mi.rs1 = rs1; mi.rs2 = rs2; mi.label = std::move(label);
    return mi;
}

MachineInst mkU(RvOpcode op, MReg rd, int64_t imm) {
    requireFormat(op, RvFormat::U, "mkU");
    requireImm20(op, imm);
    MachineInst mi;
    mi.op = op; mi.rd = rd; mi.imm = imm;
    return mi;
}

MachineInst mkJ(RvOpcode op, MReg rd, std::string label) {
    requireFormat(op, RvFormat::J, "mkJ");
    MachineInst mi;
    mi.op = op; mi.rd = rd; mi.label = std::move(label);
    return mi;
}

MachineInst mkSystem(RvOpcode op) {
    requireFormat(op, RvFormat::None, "mkSystem");
    MachineInst mi;
    mi.op = op;
    return mi;
}

//Psedo-instruction helpers 

MachineInst mkMove(MReg rd, MReg rs) {
    return mkI(RvOpcode::ADDI, rd, rs, 0);
}

MachineInst mkLoadImmSmall(MReg rd, int64_t imm) {
    if (!fitsImm12(imm))
        throw std::logic_error("mkLoadImmSmall: immediate does not fit 12 bits "
                               "— use emitLoadImm");
    return mkI(RvOpcode::ADDI, rd, MReg::phys(Reg::zero), imm);
}

MachineInst mkNot(MReg rd, MReg rs) {
    return mkI(RvOpcode::XORI, rd, rs, -1);
}

MachineInst mkNeg(MReg rd, MReg rs) {
    return mkR(RvOpcode::SUB, rd, MReg::phys(Reg::zero), rs);
}

MachineInst mkSeqz(MReg rd, MReg rs) {
    // rs == 0  <=>  (unsigned)rs < 1
    return mkI(RvOpcode::SLTIU, rd, rs, 1);
}

MachineInst mkSnez(MReg rd, MReg rs) {
    // rs != 0  <=>  0 < (unsigned)rs
    return mkR(RvOpcode::SLTU, rd, MReg::phys(Reg::zero), rs);
}

MachineInst mkBeqz(MReg rs, std::string label) {
    return mkB(RvOpcode::BEQ, rs, MReg::phys(Reg::zero), std::move(label));
}

MachineInst mkBnez(MReg rs, std::string label) {
    return mkB(RvOpcode::BNE, rs, MReg::phys(Reg::zero), std::move(label));
}

MachineInst mkJump(std::string label) {
    return mkJ(RvOpcode::JAL, MReg::phys(Reg::zero), std::move(label));
}

MachineInst mkRet() {
    return mkI(RvOpcode::JALR, MReg::phys(Reg::zero),
               MReg::phys(Reg::ra), 0);
}

MachineInst mkNop() {
    return mkI(RvOpcode::ADDI, MReg::phys(Reg::zero),
               MReg::phys(Reg::zero), 0);
}

size_t emitLoadImm(std::vector<MachineInst>& out, MReg rd, int64_t imm,
                   uint64_t sourceAddr) {
    const size_t before = out.size();

    if (fitsImm12(imm)) {
        out.push_back(mkLoadImmSmall(rd, imm));
    }

    // Guarded on the ROUNDED hi, not on imm. Being inside the 32-bit range is
    // not enough: the +0x800 rounding can carry hi past 0x7FFFF, the largest
    // value a 20-bit signed field holds. imm = 0x7FFFFFFF is exactly that —
    // hi rounds to 0x80000, LUI reads it as negative, and the result lands
    // 0x100000000 away from the constant asked for. Those values fall through
    // to case 3, which handles them correctly.
    else if (imm >= INT32_MIN && imm <= INT32_MAX &&
             ((imm + 0x800) >> 12) >= -0x80000 &&
             ((imm + 0x800) >> 12) <= 0x7FFFF) {
        const int64_t hi = (imm + 0x800) >> 12;    // rounded; fits 20 bits
        const int64_t lo = imm - (hi << 12);       // lands in [-2048, 2047]

        out.push_back(mkU(RvOpcode::LUI, rd, hi));
        if (lo != 0)
            out.push_back(mkI(RvOpcode::ADDI, rd, rd, lo));
    }

    else {
        const uint64_t uv = static_cast<uint64_t>(imm);
        int64_t lo = static_cast<int64_t>(uv & 0xFFF);
        if (lo & 0x800)
            lo -= 0x1000;

        // the sign, which now lives in bit 51.
        const uint64_t shifted = (uv - static_cast<uint64_t>(lo)) >> 12;
        int64_t hi = static_cast<int64_t>(shifted);
        if (shifted & (1ull << 51))
            hi = static_cast<int64_t>(shifted | 0xFFF0000000000000ull);

        emitLoadImm(out, rd, hi, sourceAddr);
        out.push_back(mkI(RvOpcode::SLLI, rd, rd, 12));
        if (lo != 0)
            out.push_back(mkI(RvOpcode::ADDI, rd, rd, lo));
    }

    for (size_t i = before; i < out.size(); ++i)
        out[i].sourceAddr = sourceAddr;

    return out.size() - before;
}

std::string MachineInst::toString() const {
    std::ostringstream o;
    o << mnemonic(op);

    for (size_t pad = std::string(mnemonic(op)).size(); pad < 7; ++pad)
        o << ' ';

    switch (formatOf(op)) {
        case RvFormat::R:
            o << rd.toString() << ", " << rs1.toString() << ", "
              << rs2.toString();
            break;

        case RvFormat::I:
            o << rd.toString() << ", " << rs1.toString() << ", " << imm;
            break;

        case RvFormat::ILoad:
            o << rd.toString() << ", " << imm << "(" << rs1.toString() << ")";
            break;

        case RvFormat::S:
            // Assembly order is value first, then the addressed base.
            o << rs2.toString() << ", " << imm << "(" << rs1.toString() << ")";
            break;

        case RvFormat::B:
            o << rs1.toString() << ", " << rs2.toString() << ", " << label;
            break;

        case RvFormat::U:
            o << rd.toString() << ", " << imm;
            break;

        case RvFormat::J:
            o << rd.toString() << ", " << label;
            break;

        case RvFormat::None:
            break;
    }

    return o.str();
}
MachineBlock* MachineFunction::findBlock(const std::string& lbl) {
    for (MachineBlock& b : blocks)
        if (b.label == lbl)
            return &b;
    return nullptr;
}

const MachineBlock* MachineFunction::findBlock(const std::string& lbl) const {
    for (const MachineBlock& b : blocks)
        if (b.label == lbl)
            return &b;
    return nullptr;
}

uint64_t MachineFunction::byteSize() const {
    uint64_t n = 0;
    for (const MachineBlock& b : blocks)
        n += b.byteSize();
    return n;
}

void printMachineFunction(const MachineFunction& fn, std::ostream& os) {
    os << "# " << fn.name << "  (" << fn.byteSize() << " bytes)\n";

    for (const MachineBlock& b : fn.blocks) {
        os << b.label << ":\n";

        for (const MachineInst& mi : b.insts) {
            os << "    " << mi.toString();

            if (mi.sourceAddr != 0) {
                os << "    # guest 0x" << std::hex << mi.sourceAddr
                   << std::dec;
            }
            os << "\n";
        }
    }
}

}
