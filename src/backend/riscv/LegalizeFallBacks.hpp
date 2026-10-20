#pragma once

#include "backend/riscv/RvTarget.hpp"
#include "ir/IR.hpp"

#include <string>
#include <vector>


namespace XTOR_RV {

struct LegalizeExpansion {
    bool implemented = false;
    std::vector<XTOR_IR::IRInst> instructions;
    std::string problem;
}; 

// MUL without M/Zmmul: eventually emit a width-correct base-ISA sequence.
LegalizeExpansion expandMultiply(const XTOR_IR::IRInst& instruction,
                                 XTOR_IR::IRFunction& function,
                                 const RvTarget& target);

// SDIV/UDIV without M: eventually construct the appropriate helper CALL.
LegalizeExpansion lowerDivisionToHelper(const XTOR_IR::IRInst& instruction,
                                        XTOR_IR::IRFunction& function,
                                        const RvTarget& target);

// SREM/UREM without M: signedness and result width must survive lowering.
LegalizeExpansion lowerRemainderToHelper(const XTOR_IR::IRInst& instruction,
                                         XTOR_IR::IRFunction& function,
                                         const RvTarget& target);

// FP arithmetic, comparisons, and conversions without the required F/D:
// eventually use software helpers that preserve the operation's FP semantics.
LegalizeExpansion lowerFloatingPointToHelper(const XTOR_IR::IRInst& instruction,
                                             XTOR_IR::IRFunction& function,
                                             const RvTarget& target);

// SELECT without a suitable Zicond integer path, including FP-valued SELECT:
// eventually construct a bit-preserving, straight-line selection sequence.
LegalizeExpansion expandSelect(const XTOR_IR::IRInst& instruction,
                               XTOR_IR::IRFunction& function,
                               const RvTarget& target);    
}



