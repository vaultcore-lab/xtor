#include "backend/riscv/LegalizeFallbacks.hpp"

namespace XTOR_RV {
namespace {

LegalizeExpansion notImplemented(const char* handlerName) {
    LegalizeExpansion expansion;
    expansion.problem = std::string(handlerName) + " is not implemented";
    return expansion;
}

} // namespace

// expandMultiply — invoked only when neither M nor Zmmul provides MUL.
LegalizeExpansion expandMultiply(const XTOR_IR::IRInst&,
                                 XTOR_IR::IRFunction&,
                                 const RvTarget&) {
    return notImplemented("expandMultiply");
}

// lowerDivisionToHelper — invoked for SDIV or UDIV when M is absent.
LegalizeExpansion lowerDivisionToHelper(const XTOR_IR::IRInst&,
                                        XTOR_IR::IRFunction&,
                                        const RvTarget&) {
    return notImplemented("lowerDivisionToHelper");
}

// lowerRemainderToHelper — the corresponding SREM/UREM runtime-call hook.
LegalizeExpansion lowerRemainderToHelper(const XTOR_IR::IRInst&,
                                         XTOR_IR::IRFunction&,
                                         const RvTarget&) {
    return notImplemented("lowerRemainderToHelper");
}

// lowerFloatingPointToHelper — selected using both source and result types.
// FCMP returns i1 and FP-to-integer conversion returns an integer, so looking
// only at the result would lose the precision of the floating-point input.
LegalizeExpansion lowerFloatingPointToHelper(const XTOR_IR::IRInst&,
                                             XTOR_IR::IRFunction&,
                                             const RvTarget&) {
    return notImplemented("lowerFloatingPointToHelper");
}

// expandSelect — selected when a native integer conditional recipe is absent.
LegalizeExpansion expandSelect(const XTOR_IR::IRInst&,
                               XTOR_IR::IRFunction&,
                               const RvTarget&) {
    return notImplemented("expandSelect");
}

} // namespace XTOR_RV
