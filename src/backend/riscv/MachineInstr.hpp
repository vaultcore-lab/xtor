#pragma once 

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector> 


namespace XTOR_RV {

namespace Reg {
    constexpr uint32_t zero = 0;
    constexpr uint32_t ra   = 1;    // return address
    constexpr uint32_t sp   = 2;    // host stack pointer — NOT the guest's
    constexpr uint32_t gp   = 3;
    constexpr uint32_t tp   = 4;
    constexpr uint32_t t0   = 5,  t1  = 6,  t2  = 7;
    constexpr uint32_t s0   = 8,  s1  = 9;
    constexpr uint32_t a0   = 10, a1  = 11, a2  = 12, a3  = 13;
    constexpr uint32_t a4   = 14, a5  = 15, a6  = 16, a7  = 17;
    constexpr uint32_t s2   = 18, s3  = 19, s4  = 20, s5  = 21;
    constexpr uint32_t s6   = 22, s7  = 23, s8  = 24, s9  = 25;
    constexpr uint32_t s10  = 26, s11 = 27;
    constexpr uint32_t t3   = 28, t4  = 29, t5  = 30, t6  = 31;

    constexpr uint32_t kCount = 32;
}

const char *regName(uint32_t phys); 

enum class RvFormat{
    R, 
    I,
    ILoad, 
    S, 
    B, 
    U, 
    J,
    None 
};

enum class RvOpcode {
    ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND,

    ADDW, SUBW, SLLW, SRLW, SRAW,

    MUL, MULH, MULHU, MULHSU, DIV, DIVU, REM, REMU,
    MULW, DIVW, DIVUW, REMW, REMUW,

    ADDI, SLTI, SLTIU, XORI, ORI, ANDI,
    SLLI, SRLI, SRAI,              // 6-bit shamt on RV64
    ADDIW, SLLIW, SRLIW, SRAIW,    // 5-bit shamt

    JALR,                          // rd = pc+4; pc = (rs1 + imm) & ~1

    LB, LH, LW, LD, LBU, LHU, LWU,

    SB, SH, SW, SD,

    BEQ, BNE, BLT, BGE, BLTU, BGEU,

    LUI, AUIPC,

    JAL,

    ECALL, EBREAK,
};

RvFormat formatOf(RvOpcode op);

struct MReg {
    enum class Kind : uint8_t {
        None,   // operand unused by this instruction's format
        Phys,   // x0..x31
        Virt,   // an IR temporary awaiting allocation
    };

    Kind kind = Kind::None;
    uint32_t num  = 0;

    static MReg none() { return {}; }
    static MReg phys(uint32_t x) { return {Kind::Phys, x}; }
    static MReg virt(uint32_t id) { return {Kind::Virt, id}; }

    bool isNone() const { return kind == Kind::None; }
    bool isPhys() const { return kind == Kind::Phys; }
    bool isVirt() const { return kind == Kind::Virt; }

    // "sp", "t0" when physical; "%v42" when virtual; "-" when unused.
    std::string toString() const;

    bool operator==(const MReg& o) const {
        return kind == o.kind && num == o.num;
    }
};

struct MachineInst {
    RvOpcode op = RvOpcode::ADDI;

    MReg rd;     // destination; None for stores and branches
    MReg rs1;    // first source
    MReg rs2;    // second source; None for I/U/J formats

    int64_t imm = 0;

    std::string label;

    // Guest address this came from, carried through from IRInst::sourceAddr.
    // The whole chain stays traceable back to one x86 instruction, which is
    // the only practical way to debug wrong translation.
    uint64_t sourceAddr = 0;

    std::string toString() const;
};

MachineInst mkR(RvOpcode op, MReg rd, MReg rs1, MReg rs2);
MachineInst mkI(RvOpcode op, MReg rd, MReg rs1, int64_t imm);
MachineInst mkLoad(RvOpcode op, MReg rd, MReg base, int64_t off);
MachineInst mkStore(RvOpcode op, MReg src, MReg base, int64_t off);
MachineInst mkB(RvOpcode op, MReg rs1, MReg rs2, std::string label);
MachineInst mkU(RvOpcode op, MReg rd, int64_t imm);
MachineInst mkJ(RvOpcode op, MReg rd, std::string label);
MachineInst mkSystem(RvOpcode op);

// These are not opcodes — each returns the real instruction it aliases.
// Keeping them out of RvOpcode is what lets the encoder be a direct
// transcription of the ISA manual.

// mv rd, rs        ->  addi rd, rs, 0
MachineInst mkMove(MReg rd, MReg rs);

// li rd, 0         ->  addi rd, x0, 0     (and any other small constant)
MachineInst mkLoadImmSmall(MReg rd, int64_t imm);

// not rd, rs       ->  xori rd, rs, -1
MachineInst mkNot(MReg rd, MReg rs);

// neg rd, rs       ->  sub rd, x0, rs
MachineInst mkNeg(MReg rd, MReg rs);

// seqz rd, rs      ->  sltiu rd, rs, 1
MachineInst mkSeqz(MReg rd, MReg rs);

// snez rd, rs      ->  sltu rd, x0, rs
MachineInst mkSnez(MReg rd, MReg rs);

// beqz rs, label   ->  beq rs, x0, label
MachineInst mkBeqz(MReg rs, std::string label);

// bnez rs, label   ->  bne rs, x0, label
MachineInst mkBnez(MReg rs, std::string label);

// j label          ->  jal x0, label      (return address discarded)
MachineInst mkJump(std::string label);

// ret              ->  jalr x0, ra, 0
MachineInst mkRet();

// nop              ->  addi x0, x0, 0
MachineInst mkNop();

}

// A 12-bit signed immediate fits in one ADDI. Anything wider needs LUI+ADDI,
// and a full 64-bit constant needs a shift-and-or chain. So this appends to
// a list instead of returning one instruction.
//
// Returns how many instructions were appended, which the relax pass needs in
// order to compute offsets.
size_t emitLoadImm(std::vector<MachineInst>& out, MReg rd, int64_t imm,
                   uint64_t sourceAddr = 0);

// True if `imm` fits the 12-bit signed field of an I-type or S-type
// instruction, i.e. -2048 <= imm <= 2047. The selector checks this to decide
// between `addi rd, rs, imm` and materialising the constant first.
constexpr bool fitsImm12(int64_t imm) {
    return imm >= -2048 && imm <= 2047;
}

// True if `imm` fits the 13-bit signed, 2-byte-aligned displacement of a
// B-type branch: -4096..4094, even. Checked by the relax pass, not by the
// selector, because displacements are not known until layout.
constexpr bool fitsBranchOffset(int64_t off) {
    return off >= -4096 && off <= 4094 && (off & 1) == 0;
}

struct MachineBlock {
    std::string label;
    std::vector<MachineInst> insts;

    // Byte offset of this block from the start of the function. Filled in by
    // the layout step of the relax pass; meaningless before then.
    uint64_t offset = 0;

    uint64_t byteSize() const { return insts.size() * 4; }
};


struct MachineFunction {
    std::string name;                    // "tb_0x401136", same as the IRFunction
    std::vector<MachineBlock> blocks;    // blocks[0] is the entry

    // Highest virtual register ID used, so the allocator can size its
    // tables without a second walk.
    uint32_t maxVirtReg = 0;

    MachineBlock* findBlock(const std::string& label);
    const MachineBlock* findBlock(const std::string& label) const;

    uint64_t byteSize() const;
};

void printMachineFunction(const MachineFunction& fn, std::ostream& os);

} // namespace XTOR_RV
