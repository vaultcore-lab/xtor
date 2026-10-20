#pragma once

#include "backend/riscv/RvTarget.hpp"
#include "ir/IR.hpp"

#include <cstddef>
#include <iosfwd>
#include <string>
#include <vector>

namespace XTOR_RV {

enum class LegalizeAction {
    Legal,        // supported target-level operation or base-ISA recipe
    Expand,       // replace with simpler operations during translation
    LibCall,      // replace with an IR call to a future runtime helper
    Unsupported,  // malformed or not covered by any lowering contract
};


// Identify the exact named hook independently of the overall action.
// This lets diagnostics/tests inspect the policy without executing a hook.
enum class LegalizeFallback {
    None,
    Multiply,
    Divide,
    Remainder,
    FloatingPoint,
    Select,
};


struct LegalizeDecision {
    LegalizeAction action = LegalizeAction::Unsupported;
    LegalizeFallback fallback = LegalizeFallback::None;
    std::string reason;
};

LegalizeDecision legalizationFor(const XTOR_IR::IRInst& instruction,
                                 const RvTarget& target);

struct LegalizeResult {
    bool ok = true;

    size_t castsCSEd      = 0;   // duplicate conversions replaced by the first
    size_t deadRemoved    = 0;   // conversions whose result nothing reads
    size_t instsBefore    = 0;
    size_t instsAfter     = 0;
    size_t fallbacksCalled = 0; // actual hook invocations, including failures
    size_t rewritesApplied = 0; // original instructions successfully replaced

    // Entries include the failing instruction and its original guest address.
    // A failure in generated IR inherits that address from its parent.
    std::vector<std::string> problems;

    void describe(std::ostream& os) const;
};

LegalizeResult legalize(XTOR_IR::IRFunction& fn, const RvTarget& target);

} 
