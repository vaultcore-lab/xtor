#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <variant>
#include <memory>
#include <stdexcept>
#include <unordered_map>

namespace XTOR_IR{

class IRType;
class IRValue;
class IRInst;
class IRBasicBlock;
class IRFunction;
class IRProgram;


enum class IRTypeKind{
    Void,
    I1, I8, I16, I32, I64,
    F32, F64,
    Ptr,
};

enum class CallingConv{
    C,
    Win64,
    Fast,
    Naked,
};

enum class IcmpCond{
    EQ, NE,
    SLT, SLE, SGT, SGE, //signed
    ULT, ULE, UGT, UGE, //unsigned
};

enum class FcmpCond {
    OEQ, ONE, OLT, OLE, OGT, OGE,  // ordered (no NaN)
    UNO, ORD,                        // unordered / ordered predicate
};

enum class Opcode{
    //Register-to-register copy
    MOV,
    //Interger arithmetic
    ADD, SUB, MUL, SDIV, UDIV, SREM, UREM, NEG,
    //Bitwise / shift
    AND, OR, XOR, NOT, SHL, LSHR, ASHR,
    //Float arithmetic
    FADD, FSUB, FMUL, FDIV, FNEG,
    //Type conversion
    ZEXT, SEXT, TRUNC,
    FPEXT, FPTRUNC, FPTOSI, FPTOUI, SITOFP, UITOFP,
    INTTOPTR, PTRTOINT, BITCAST,
    //Memory
    LOAD, STORE, ALLOCA,
    //Comaparision , produces an i1
    ICMP, FCMP,
    //Branchless conditional move
    SELECT,
    //Control flow
    JMP, CJMP, RET, CALL, PHI,
    NOP,
};

// Virtual register IDs reserved for the 16 x86-64 general purpose registers.
// The lifter maps RAX..R15 onto IDs 0..15 (see gprVRegId in X86Lifter.cpp),
// so a "read of RAX" is just a reference to vreg 0 — no load is emitted.
namespace GprVReg{
    constexpr uint32_t RAX = 0,  RBX = 1,  RCX = 2,  RDX = 3;
    constexpr uint32_t RSI = 4,  RDI = 5,  RSP = 6,  RBP = 7;
    constexpr uint32_t R8  = 8,  R9  = 9,  R10 = 10, R11 = 11;
    constexpr uint32_t R12 = 12, R13 = 13, R14 = 14, R15 = 15;
}

// Virtual register IDs reserved for the x86 arithmetic flags.
//
// NOTE: with lazy flag evaluation (Flags::FlagState) the lifter no longer
// writes these on every arithmetic instruction — flags are recomputed on
// demand at the consuming Jcc/SETcc/CMOVcc. The IDs stay reserved so that a
// future eager-flags mode, or a pass that needs a stable home for a flag
// value, has one; and so temporary IDs never collide with them.
namespace FlagVReg{
    constexpr uint32_t CF = 16;
    constexpr uint32_t ZF = 17;
    constexpr uint32_t SF = 18;
    constexpr uint32_t OF = 19;
}

class IRType{

public:

    //static factories, the only way to contruct an IRType

    static IRType i1()    { return IRType(IRTypeKind::I1);   }
    static IRType i8()    { return IRType(IRTypeKind::I8);   }
    static IRType i16()   { return IRType(IRTypeKind::I16);  }
    static IRType i32()   { return IRType(IRTypeKind::I32);  }
    static IRType i64()   { return IRType(IRTypeKind::I64);  }
    static IRType f32()   { return IRType(IRTypeKind::F32);  }
    static IRType f64()   { return IRType(IRTypeKind::F64);  }
    static IRType ptr()   { return IRType(IRTypeKind::Ptr);  }
    static IRType void_() { return IRType(IRTypeKind::Void); }

    IRTypeKind kind() const {return m_kind; }


    //Return byte width fir RISC-V load/store width selction
    uint32_t byteWidth() const{
        switch (m_kind){
            case IRTypeKind::I1:
            case IRTypeKind::I8:    return 1;
            case IRTypeKind::I16:   return 2;
            case IRTypeKind::I32:
            case IRTypeKind::F32:   return 4;
            case IRTypeKind::I64:
            case IRTypeKind::F64:
            case IRTypeKind::Ptr:   return 8;
            case IRTypeKind::Void:
                throw std::logic_error("IRType::byteWidth called on void");
        }
        __builtin_unreachable();
    }

    // Bit width — what the lifter actually wants when building masks for
    // partial register writes (byteWidth() * 8).
    uint32_t bitWidth() const {
        return m_kind == IRTypeKind::I1 ? 1 : byteWidth() * 8;
    }

    bool isInteger()  const { return m_kind >= IRTypeKind::I1  && m_kind <= IRTypeKind::I64; }
    bool isFloat()    const { return m_kind == IRTypeKind::F32 || m_kind == IRTypeKind::F64; }
    bool isPointer()  const { return m_kind == IRTypeKind::Ptr;  }
    bool isVoid()     const { return m_kind == IRTypeKind::Void; }

    bool operator==(const IRType& o) const { return m_kind == o.m_kind; }
    bool operator!=(const IRType& o) const { return !(*this == o); }

    std::string toString() const;
private:

    explicit IRType(IRTypeKind kind) : m_kind(kind) {}

    IRTypeKind m_kind;
};

//IR virtual register
class VReg{
public:
    VReg(uint32_t id, std::string debugName = "")
        : m_id(id), m_debugName(std::move(debugName)) {}

    uint32_t id() const { return m_id;}
    const std::string& debugName() const { return m_debugName;}

    bool operator==(const VReg& o) const { return m_id == o.m_id; }
    bool operator!=(const VReg& o) const { return !(*this == o); }

    std::string toString() const {
        return m_debugName.empty()
            ? "%vreg" + std::to_string(m_id)
            : "%" + m_debugName + "." + std::to_string(m_id);
    }

private:
    uint32_t m_id;
    std::string m_debugName;
};

class Immediate{
public:
    Immediate(int64_t value, IRType type)
        : m_value(value), m_type(type) {}

    int64_t value() const { return m_value; }
    const IRType& type() const {return m_type; }

    std::string toString() const{
        return std::to_string(m_value);
    }
private:
    int64_t m_value;
    IRType m_type;
};

//A reference to a symbol from the ELF symbol table
//almost always Ptr(value is an address)
class GlobalRef{
public:
    GlobalRef(std::string name, IRType type)
        : m_name(std::move(name)), m_type(type) {}

    const std::string& name() const { return m_name; }
    const IRType& type() const { return m_type; }

    std::string toString() const { return "@" + m_name; }

private:
    std::string m_name;
    IRType m_type;
};

class IRValue{

public:

    static IRValue makeVReg(uint32_t id, IRType ty, std::string name = ""){
        return IRValue(VReg(id, std::move(name)), ty);
    }

    static IRValue makeImm(int64_t v, IRType ty){
        return IRValue(Immediate(v, ty), ty);
    }

    static IRValue makeGlobal(std::string name, IRType ty){
        return IRValue(GlobalRef(std::move(name), ty), ty);
    }

    const IRType& type() const { return m_type; }

    bool isVReg() const { return std::holds_alternative<VReg>(m_payload); }
    bool isImm() const { return std::holds_alternative<Immediate>(m_payload);}
    bool isGlobal() const { return std::holds_alternative<GlobalRef>(m_payload);}

    const VReg& asVReg() const { return std::get<VReg>(m_payload); }
    const Immediate& asImm() const { return std::get<Immediate>(m_payload); }
    const GlobalRef& asGlobal() const { return std::get<GlobalRef>(m_payload); }

    std::string toString() const;
private:

    using Payload = std::variant<VReg, Immediate, GlobalRef>;

    IRValue(Payload payload, IRType type)
        : m_payload(std::move(payload)), m_type(type) {}

    Payload m_payload;
    IRType m_type;
};

//Descibes alignment and volatility of a memory access.
class MemFlags{
public:
    explicit MemFlags(uint32_t alignment = 1, bool isVolatile = false)
        : m_aligment(alignment), m_isVolatile(isVolatile){
        //alignment must be power of 2
        if(alignment == 0 || (alignment & (alignment -1)) != 0)
            throw std::invalid_argument("MemFlags: alignment must be a power of two");
    }

    uint32_t alignment() const { return m_aligment; }
    bool isVolatile() const { return m_isVolatile; }

private:
    uint32_t m_aligment;
    bool m_isVolatile;
};

class IRInst{

public:

    //Factories (one per opcode family)

    //Register copy: dst = src  (no computation, just a move)
    static IRInst makeMov(VReg dst, IRType ty, IRValue src);

    //Binary integer/float arithmetic: dst = lhs op rhs
    static IRInst makeBinop(Opcode op, VReg dst, IRType ty,
                            IRValue lhs, IRValue rhs);

    //Unary: dst = op src (NEG, NOT, FNEG)
    static IRInst makeUnop(Opcode op, VReg dst, IRType ty,
                           IRValue src);

    //Integer comparision : results an i1
    static IRInst makeIcmp(IcmpCond cond, VReg dst,
                           IRValue lhs, IRValue rhs);

    //Float comparision
    static IRInst makeFcmp(FcmpCond cond, VReg dst,
                           IRValue lhs, IRValue rhs);

    //Type cast (ZEXT, SEXT, TRUNC, FPEXT... BITCAST)
    static IRInst makeCast(Opcode castOp, VReg dst,
                           IRType dstTy, IRValue src);
    //dst = *ptr
    static IRInst makeLoad(VReg dst, IRType loadTy,
                           IRValue ptr, MemFlags flags = MemFlags{});

    // *ptr = val
    static IRInst makeStore(IRValue val, IRValue ptr,
                            MemFlags flags = MemFlags{});

    //dst = alloca <bytes> - allocates on the stack frame
    static IRInst makeAlloca(VReg dst, uint64_t bytes, uint32_t alignment = 8);

    //unconditional branch
    static IRInst makeJmp(std::string targetBlock);

    //Conditional branch
    static IRInst makeCjmp(IRValue cond,
                           std::string trueBlock,
                           std::string falseBlock);

    //return (with optional value)
    static IRInst makeRet(std::optional<IRValue> retVal = std::nullopt);

    //function call
    static IRInst makeCall(std::optional<VReg> dst, IRType retTy,
                           IRValue callee,
                           std::vector<IRValue> args,
                           CallingConv cc = CallingConv::C,
                           bool tailCall = false);

    //branchless select: dst = cond ? trueVal : falseVal
    static IRInst makeSelect(VReg dst, IRType ty,
                             IRValue cond,
                             IRValue trueVal, IRValue falseVal);

    static IRInst makeNop();

    Opcode opcode() const { return m_opcode; }
    const IRType& resultType() const { return m_resultType; }
    uint64_t sourceAddr() const { return m_sourceAddr; }
    bool hasResult() const { return m_dst.has_value(); }

    //these throw std::logic_error if instruction doesn't have the field

    const VReg& dst() const;
    const std::vector<IRValue>& operands() const { return m_operands; }
    const IRValue& operand(size_t i) const;

    const IcmpCond& icmpCond()    const;   // only valid for ICMP
    const FcmpCond& fcmpCond()    const;   // only valid for FCMP
    const std::string& branchTrue()  const;   // JMP / CJMP
    const std::string& branchFalse() const;   // CJMP only

    CallingConv callConv()    const;   // CALL only
    bool        isTailCall()  const;   // CALL only

    const MemFlags&  memFlags()    const;   // LOAD / STORE / ALLOCA
    uint64_t         allocaBytes() const;   // ALLOCA only

    void setSourceAddr(uint64_t addr) { m_sourceAddr = addr; }

    std::string toString() const;

private:

    IRInst() = default;

    Opcode m_opcode = Opcode::NOP;
    IRType m_resultType = IRType::void_();
    uint64_t m_sourceAddr = 0;

    std::optional<VReg> m_dst;
    std::vector<IRValue> m_operands;

    std::optional<IcmpCond>  m_icmpCond;
    std::optional<FcmpCond> m_fcmpCond;
    std::string m_branchTrue;
    std::string m_branchFalse;
    std::optional<CallingConv> m_callConv;
    bool m_isTailCall = false;
    std::optional<MemFlags> m_memFlags;
    std::optional<uint64_t> m_allocaBytes;
};

class IRBasicBlock{
public:
    explicit IRBasicBlock(std::string name, uint64_t startAddr = 0)
        : m_name(std::move(name)), m_startAddr(startAddr) {}

    //observers
    const std::string& name() const { return m_name; }
    uint64_t startAddr() const { return m_startAddr; }
    const std::vector<std::string>& predecessors() const { return m_predecessors; }
    const std::vector<std::string>& successors() const { return m_successors; }
    const std::vector<IRInst>& instructions() const { return m_instructions; }

    // Mutable access — the lifter uses this to back-annotate the source
    // x86 virtual address onto every IR instruction it just emitted for a
    // given machine instruction (see FunctionLifter::liftBlock). Callers
    // must not push through this handle; use pushInst so the
    // "no instructions after a terminator" guard still runs.
    std::vector<IRInst>& instructions() { return m_instructions; }

    bool isTerminated() const;
    //return last instruction
    const IRInst& terminator() const;

    void pushInst(IRInst inst);
    void addPredecessor(std::string blockName);
    void addSuccessor(std::string blockName);

private:
    std::string m_name;
    uint64_t m_startAddr;
    std::vector<std::string> m_predecessors;
    std::vector<std::string> m_successors;
    std::vector<IRInst> m_instructions;
};

//IRParam
//One formal parameter of a function. Immuatable
// The parameter is simply pre-loaded into the corresponding GPR
class IRParam{
public:
    IRParam(IRType type, std::string name, uint32_t vregId)
        : m_type(type), m_name(std::move(name)), m_vregId(vregId) {}

    const IRType&      type()   const { return m_type;   }
    const std::string& name()   const { return m_name;   }
    uint32_t           vregId() const { return m_vregId; }

private:
    IRType      m_type;
    std::string m_name;
    uint32_t    m_vregId;  // the SSA vreg that holds this param at entry
};

//IRFunction
//Owns it's basic blocks and manages vreg ID allocation

class IRFunction{
public:
    IRFunction(std::string name, IRType returnType,
               CallingConv cc = CallingConv::C)
        :   m_name(std::move(name)),
            m_returnType(returnType),
            m_callingConv(cc),
            m_nextVregId(20) {} //IDs 0-19 reserved for GPRs and flags

    const std::string& name() const { return m_name; }
    const IRType& returnType() const { return m_returnType;  }
    CallingConv callingConv() const { return m_callingConv; }
    bool isExternal() const { return m_isExternal;  }
    bool isNoReturn() const { return m_isNoReturn;  }
    const std::vector<IRParam>& params() const { return m_params; }
    const std::vector<IRBasicBlock>& blocks() const { return m_blocks; }
    std::vector<IRBasicBlock>& blocks() { return m_blocks; }

    //Allocates a temporary VReg id (>=20)
    uint32_t allocVreg() { return m_nextVregId++; }

    void addParam(IRParam param) { m_params.push_back(std::move(param)); }
    void addBlock(IRBasicBlock block) { m_blocks.push_back(std::move(block)); }
    void setExternal(bool v) { m_isExternal = v; }
    void setNoReturn(bool v) { m_isNoReturn = v; }

    IRBasicBlock* findBlock(const std::string& name);
    const IRBasicBlock* findBlock(const std::string& name) const;
    const IRBasicBlock& entryBlock() const;
    IRBasicBlock& entryBlock();

private:
    std::string m_name;
    IRType m_returnType;
    CallingConv m_callingConv;
    bool m_isExternal  = false;
    bool m_isNoReturn  = false;
    std::vector<IRParam> m_params;
    std::vector<IRBasicBlock> m_blocks;
    uint32_t m_nextVregId;
};

// Global varaiblbes */
class IRGlobal {
public:
    IRGlobal(std::string name, IRType type, uint64_t address,
             bool isReadOnly, bool isZeroInit,
             std::vector<uint8_t> initialBytes = {})
        : m_name(std::move(name)), m_type(type), m_address(address),
          m_isReadOnly(isReadOnly), m_isZeroInit(isZeroInit),
          m_initialBytes(std::move(initialBytes)) {}

    const std::string& name() const { return m_name;}
    const IRType& type() const { return m_type; }
    uint64_t address() const { return m_address;}
    bool isReadOnly() const { return m_isReadOnly;}
    bool isZeroInit() const { return m_isZeroInit;  }
    const std::vector<uint8_t>& initialBytes() const { return m_initialBytes; }

private:
    std::string          m_name;
    IRType               m_type;
    uint64_t             m_address;
    bool                 m_isReadOnly;
    bool                 m_isZeroInit;
    std::vector<uint8_t> m_initialBytes;
};

class IRProgram{
public:
    IRProgram() = default;

    const std::vector<IRGlobal>& globals() const { return m_globals; }
    const std::vector<IRFunction>& functions() const { return m_functions; }
    std::vector<IRFunction>& functions() { return m_functions; }

    std::string symbolAt(uint64_t addr) const;

    void addGlobal(IRGlobal global);
    void addFunction(IRFunction fn);
    void registerSymbol(uint64_t addr, std::string name);

    IRFunction* findFunction(const std::string& name);
    const IRFunction* findFunction(const std::string& name) const;

private:
    std::vector<IRGlobal>                      m_globals;
    std::vector<IRFunction>                    m_functions;
    std::unordered_map<uint64_t, std::string>  m_addrToSymbol;
};

std::string toString(IRTypeKind k);
std::string toString(Opcode op);
std::string toString(IcmpCond c);
std::string toString(FcmpCond c);
std::string toString(CallingConv cc);

void printIRInst(const IRInst& inst, int indent = 2);
void printIRBlock(const IRBasicBlock& block);
void printIRFunction(const IRFunction& fn);
void printIRProgram(const IRProgram& program);

// Verifier — non-SSA checks only:
//   - every VReg used in an operand has an ID ≤ function's current counter
//   - OR is one of the 16 reserved GPR IDs (0-15)
//   - every block ends with exactly one terminator
//   - branch targets name blocks that exist in the same function
// Does NOT check single-definition, that is intentionally allowed.
std::vector<std::string> verifyIR(const IRProgram& program);

} // namespace XTOR_IR
