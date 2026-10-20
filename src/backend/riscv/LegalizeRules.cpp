#include "backend/riscv/Legalize.hpp"

namespace XTOR_RV {
namespace {

using namespace XTOR_IR;


// All operands in an arithmetic instruction must agree with the selected
// type. 
bool operandsMatch(const IRInst& instruction, size_t count, IRType type) {
    if (instruction.operands().size() != count)
        return false;
   
    for (const IRValue& operand : instruction.operands()) {
        if (operand.type() != type)
            return false;
    }

    return true;
}

LegalizeDecision unsupported(const std::string& reason) {
    return {LegalizeAction::Unsupported, LegalizeFallback::None, reason};
}

// Validate FP operation shapes before inspecting feature bits. In particular,
// FCMP's i1 result and FPTOSI's integer result do not describe the FP precision.
// Source operands must be examined as well as the destination type.
bool validFloatingShape(const IRInst& instruction) {
    if (!instruction.hasResult())
        return false;
   
    const IRType result = instruction.resultType();
    
    switch (instruction.opcode()) {
        case Opcode::FADD: 
        case Opcode::FSUB:
        case Opcode::FMUL: 
        case Opcode::FDIV:
            // Arithmetic uses two inputs of the same precision as its result.
            return result.isFloat() && operandsMatch(instruction, 2, result);

        case Opcode::FNEG:
            // Negation has one input and does not change its precision.
            return result.isFloat() && operandsMatch(instruction, 1, result);
        case Opcode::FCMP:
            return result == IRType::i1() &&
                   instruction.operands().size() == 2 &&
                   instruction.operand(0).type().isFloat() &&
                   operandsMatch(instruction, 2, instruction.operand(0).type());
        default:
            break;
    }


    // Every conversion requires exactly one source operand.
    if (instruction.operands().size() != 1)
        return false;
    
    const IRType source = instruction.operand(0).type();
   
    
    // F32/F64 are currently the only FP widths expressible in this IR.
    switch (instruction.opcode()) {
        case Opcode::FPEXT:
            // Extension idds specifically a widening conversion, not a copy.
            return source == IRType::f32() && result == IRType::f64();
        case Opcode::FPTRUNC:
            // Truncation runs in the opposite direction.
            return source == IRType::f64() && result == IRType::f32();
        case Opcode::FPTOSI: case Opcode::FPTOUI:
            // Signedness is in the opcode; precision is in the source type.
            return source.isFloat() && result.isInteger();
        case Opcode::SITOFP: case Opcode::UITOFP:
            // The source integer can be narrower than the native register.
            return source.isInteger() && result.isFloat();
        default:
            return false;
    }
}

// Decide whether a well-formed FP operation has the required hardware.
// D requires F, and a conversion involving F64 needs D even if its RESULT
// is an integer or F32. Checking only resultType would misclassify that case.
LegalizeDecision floatingDecision(const IRInst& instruction,
                                  const RvTarget& target) {
    
    if (!validFloatingShape(instruction))
        return unsupported("invalid floating-point operand/result types");

    bool needsDouble = instruction.resultType() == IRType::f64();
    for (const IRValue& operand : instruction.operands()) {
        needsDouble = needsDouble || operand.type() == IRType::f64();
    }

    const bool supported = needsDouble ? target.hasFloat64() : target.hasFloat32();
    if (supported) {
        return {LegalizeAction::Legal, LegalizeFallback::None, {}};
    }

    // A missing FP unit chooses a software-call lowering hook, not a NOP.
    return {LegalizeAction::LibCall, LegalizeFallback::FloatingPoint,
            std::string("requires ") + (needsDouble ? "F and D" : "F") +
                "; target is " + target.isaString()};
}

}

LegalizeDecision legalizationFor(const XTOR_IR::IRInst& instruction,
                                 const RvTarget& target) {
    // Queries report bad target descriptions rather than throwing. The
    // mutating driver performs this check once before it starts rewriting.
    if (const std::string reason = target.unsupportedReason(); !reason.empty())
        return unsupported(reason);

    // Namespace qualification is shortened only inside this function.
    using XTOR_IR::IRType;
    using XTOR_IR::Opcode;

    switch (instruction.opcode()) {
        case Opcode::MUL:
        case Opcode::SDIV: case Opcode::UDIV:
        case Opcode::SREM: case Opcode::UREM: {
            // These feature rules apply only to two-input integer operations.
            // Their signed/unsigned distinctions remain in the original opcode.
            const IRType result = instruction.resultType();
            if (!instruction.hasResult() || !result.isInteger() ||
                !operandsMatch(instruction, 2, result))
                return unsupported("multiply/divide/remainder needs matching integer operands");

            // Zmmul authorizes multiplication but NOT division or remainder.
            if (instruction.opcode() == Opcode::MUL) {
                if (target.hasMultiply())
                    return {LegalizeAction::Legal, LegalizeFallback::None, {}};
                // The actual shift/add algorithm is a separate placeholder.
                return {LegalizeAction::Expand, LegalizeFallback::Multiply,
                        "MUL requires M or Zmmul; target is " + target.isaString()};
            }

            // All four divide/remainder operations require full M.
            if (target.hasDivide())
                return {LegalizeAction::Legal, LegalizeFallback::None, {}};
            // Preserve which result the requested operation needs.
            const bool remainder = instruction.opcode() == Opcode::SREM ||
                                   instruction.opcode() == Opcode::UREM;
            // Dispatch signedness and width through the complete instruction.
            return {LegalizeAction::LibCall,
                    remainder ? LegalizeFallback::Remainder : LegalizeFallback::Divide,
                    "division/remainder requires M; target is " + target.isaString()};
        }

        case Opcode::FADD: case Opcode::FSUB: case Opcode::FMUL:
        case Opcode::FDIV: case Opcode::FNEG: case Opcode::FCMP:
        case Opcode::FPEXT: case Opcode::FPTRUNC:
        case Opcode::FPTOSI: case Opcode::FPTOUI:
        case Opcode::SITOFP: case Opcode::UITOFP:
            return floatingDecision(instruction, target);

        case Opcode::SELECT: {
            // SELECT has an i1 condition and two equally typed value arms.
            const IRType result = instruction.resultType();
            if (!instruction.hasResult() ||
                !(result.isInteger() || result.isPointer() || result.isFloat()) ||
                instruction.operands().size() != 3 ||
                instruction.operand(0).type() != IRType::i1() ||
                instruction.operand(1).type() != result ||
                instruction.operand(2).type() != result)
                return unsupported("SELECT needs an i1 condition and matching value arms");

            if (!result.isFloat() && target.hasCondMove())
                return {LegalizeAction::Legal, LegalizeFallback::None, {}};
            return {LegalizeAction::Expand, LegalizeFallback::Select,
                    result.isFloat() ? "FP SELECT has no direct Zicond lowering"
                                     : "SELECT requires Zicond or a base-ISA expansion"};
        }

        case Opcode::ALLOCA:
            return unsupported("ALLOCA has no lowering: a translation block has no frame");
        case Opcode::PHI:
            return unsupported("PHI is unexpected: the lifter does not emit SSA");

        case Opcode::MOV:
        case Opcode::ADD: case Opcode::SUB: case Opcode::NEG:
        case Opcode::AND: case Opcode::OR: case Opcode::XOR: case Opcode::NOT:
        case Opcode::SHL: case Opcode::LSHR: case Opcode::ASHR:
        case Opcode::ZEXT: case Opcode::SEXT: case Opcode::TRUNC:
        case Opcode::INTTOPTR: case Opcode::PTRTOINT: case Opcode::BITCAST:
        case Opcode::LOAD: case Opcode::STORE:
        case Opcode::ICMP:
        case Opcode::JMP: case Opcode::CJMP: case Opcode::RET:
        case Opcode::CALL: case Opcode::NOP:
            return {LegalizeAction::Legal, LegalizeFallback::None, {}};
    }

    return unsupported("no RISC-V legality rule for this opcode");
}

}
