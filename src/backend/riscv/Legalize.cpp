#include "backend/riscv/Legalize.hpp"
#include "backend/riscv/LegalizeFallbacks.hpp"

#include <iterator>
#include <map>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace XTOR_RV {

using namespace XTOR_IR;

namespace {

constexpr size_t kMaxExpansionDepth = 32;
constexpr size_t kMaxExpansionInstructions = 4096;

bool isConversion(Opcode op) {
    return op == Opcode::ZEXT || op == Opcode::SEXT || op == Opcode::TRUNC;
}

void reportProblem(const IRInst& instruction, const std::string& reason,
                   LegalizeResult& result) {
    std::ostringstream diagnostic;
    diagnostic << "0x" << std::hex << instruction.sourceAddr() << std::dec << ": ";
    if (instruction.hasResult())
        diagnostic << instruction.dst().toString() << " = ";
    // The opcode/type still identify the failing family and precision.
    diagnostic << XTOR_IR::toString(instruction.opcode()) << ' '
               << instruction.resultType().toString() << " (";
    // Iterate the real operand vector; even zero operands are safe to report.
    for (size_t index = 0; index < instruction.operands().size(); ++index) {
        if (index != 0)
            diagnostic << ", ";
        const IRValue& operand = instruction.operands()[index];
        diagnostic << operand.type().toString() << ' ' << operand.toString();
    }
    diagnostic << ") — " << reason;
    result.problems.push_back(diagnostic.str());
    result.ok = false;
}

LegalizeExpansion invokeFallback(LegalizeFallback fallback,
                                  const IRInst& instruction,
                                  IRFunction& function,
                                  const RvTarget& target) {
    switch (fallback) {
        case LegalizeFallback::Multiply:
            return expandMultiply(instruction, function, target);
        case LegalizeFallback::Divide:
            return lowerDivisionToHelper(instruction, function, target);
        case LegalizeFallback::Remainder:
            return lowerRemainderToHelper(instruction, function, target);
        case LegalizeFallback::FloatingPoint:
            return lowerFloatingPointToHelper(instruction, function, target);
        case LegalizeFallback::Select:
            return expandSelect(instruction, function, target);
        case LegalizeFallback::None:
            break;
    }

    // Fail closed if a future rule forgets to connect its implementation.
    LegalizeExpansion expansion;
    expansion.problem = "no fallback handler is registered for this decision";
    return expansion;
}

bool appendLegalized(const IRInst& instruction, IRFunction& function,
                     const RvTarget& target, LegalizeResult& result,
                     std::vector<IRInst>& output, size_t depth,
                     size_t& visited, bool& rewritten) {
    // Count all visited instructions, including legal leaves of wide trees.
    if (visited >= kMaxExpansionInstructions) {
        reportProblem(instruction, "fallback instruction budget exceeded", result);
        return false;
    }
    // Increment only after the bound check; this counter cannot overflow.
    ++visited;

    // Apply the SAME target policy to original and newly emitted operations.
    const LegalizeDecision decision = legalizationFor(instruction, target);
    if (decision.action == LegalizeAction::Legal) {
        // No hook needed: preserve the instruction and its existing metadata.
        output.push_back(instruction);
        return true;
    }
    if (decision.action == LegalizeAction::Unsupported) {
        // Unsupported is distinct from a valid operation needing expansion.
        reportProblem(instruction, decision.reason, result);
        return false;
    }

    // A handler that returns the same unsupported operation would otherwise
    // recurse forever. Legal leaves are allowed after 32 expansion levels.
    if (depth >= kMaxExpansionDepth) {
        reportProblem(instruction, "fallback recursion limit exceeded", result);
        return false;
    }

    // Count real invocations even if the placeholder or a nested rewrite fails.
    ++result.fallbacksCalled;
    LegalizeExpansion expansion =
        invokeFallback(decision.fallback, instruction, function, target);
    if (!expansion.implemented) {
        // Combine the CPU requirement with the exact missing handler name.
        const std::string detail = expansion.problem.empty()
            ? "fallback handler did not implement this operation" : expansion.problem;
        reportProblem(instruction, decision.reason + "; " + detail, result);
        return false;
    }

    // A successful value-producing rewrite cannot be an empty deletion.
    if (expansion.instructions.empty()) {
        reportProblem(instruction, "fallback returned an empty replacement", result);
        return false;
    }
    // Reject an already oversized list before recursively walking any of it.
    if (expansion.instructions.size() > kMaxExpansionInstructions - visited) {
        reportProblem(instruction, "fallback instruction budget exceeded", result);
        return false;
    }

    bool definesResult = !instruction.hasResult();
    for (const IRInst& replacement : expansion.instructions) {
        // This contract supports a linear sequence, not a CFG transformation.
        const Opcode opcode = replacement.opcode();
        if (opcode == Opcode::JMP || opcode == Opcode::CJMP || opcode == Opcode::RET ||
            (opcode == Opcode::CALL && replacement.isTailCall())) {
            reportProblem(instruction, "fallback cannot change control flow", result);
            return false;
        }
        if (instruction.hasResult() && replacement.hasResult() &&
            replacement.dst() == instruction.dst()) {
            if (replacement.resultType() != instruction.resultType()) {
                reportProblem(instruction, "fallback changed the destination type", result);
                return false;
            }
            definesResult = true;
        }
    }
    if (!definesResult) {
        reportProblem(instruction, "fallback did not define the original destination", result);
        return false;
    }

    std::vector<IRInst> legalized;
    for (IRInst& replacement : expansion.instructions) {
        // Do not mistake an absent source mapping for a new guest address.
        if (replacement.sourceAddr() == 0)
            replacement.setSourceAddr(instruction.sourceAddr());
        // A generated multiply can itself need expansion on an M-less target.
        if (!appendLegalized(replacement, function, target, result, legalized,
                             depth + 1, visited, rewritten))
            return false;
    }

    // Commit in original instruction order, without copying the prepared IR.
    output.insert(output.end(), std::make_move_iterator(legalized.begin()),
                  std::make_move_iterator(legalized.end()));
    // The caller counts rewritten ORIGINAL operations, not intermediate nodes.
    rewritten = true;
    return true;
}

//
// The lifter computes the same conversion repeatedly. `xor ebp, ebp` lifts to
// two identical truncs of %rbp before the xor, and patterns like it account
// for 101,037 instructions across the measured corpus.
//
// The trap: this IR is NOT SSA. Virtual registers 0..19 are the guest's
// registers and flags, and the lifter rewrites them freely —
//
//     %rsp.6 = mov i64 %vreg26
//     %rsp.6 = mov i64 %vreg28
//
// so "the same conversion of the same vreg" is only the same VALUE while
// that vreg has not been written in between. A cache that ignores this
// replaces the second `trunc %rsp` with a stale earlier result, and produces
// code that runs and is wrong.
//
// So every cached entry is keyed on its source vreg, and writing a vreg
// invalidates every entry that reads it. The invalidation is the correctness
// argument; the caching is just the speed.
struct CastKey {
    Opcode   op;
    uint32_t srcVreg;
    uint32_t srcTy;     // IRTypeKind as an integer, for comparability
    uint32_t dstTy;

    bool operator<(const CastKey& o) const {
        if (op      != o.op)      return op      < o.op;
        if (srcVreg != o.srcVreg) return srcVreg < o.srcVreg;
        if (srcTy   != o.srcTy)   return srcTy   < o.srcTy;
        return dstTy < o.dstTy;
    }
};

} // namespace

LegalizeResult legalize(IRFunction& fn, const RvTarget& target) {

    if (const std::string why = target.unsupportedReason(); !why.empty())
        throw std::runtime_error("legalize: " + why);

    LegalizeResult res;

    for (IRBasicBlock& block : fn.blocks()) {
        // Count the original stream before any instruction can expand.
        res.instsBefore += block.instructions().size();
        // Do not modify the vector being traversed; build its replacement.
        std::vector<IRInst> output;
        output.reserve(block.instructions().size());
        for (const IRInst& instruction : block.instructions()) {
            // Each original instruction gets its own budget and transaction.
            size_t visited = 0;
            bool rewritten = false;
            std::vector<IRInst> replacement;
            if (appendLegalized(instruction, fn, target, res, replacement,
                                0, visited, rewritten)) {
                // All nested operations passed; now the replacement is usable.
                output.insert(output.end(), std::make_move_iterator(replacement.begin()),
                              std::make_move_iterator(replacement.end()));
                // A Legal instruction copied unchanged is not an expansion.
                if (rewritten)
                    ++res.rewritesApplied;
            } else {
                output.push_back(instruction);
            }
        }
        block.instructions() = std::move(output);
    }

    // Block-local on purpose. Carrying the cache across blocks would need to
    // know which predecessors can reach this one and what they wrote, which
    // is dataflow this pass does not do. A translation block is at most 64
    // instructions, so almost all of the redundancy is local anyway.
    for (IRBasicBlock& b : fn.blocks()) {

        std::map<CastKey, uint32_t> available;   // key -> vreg holding it
        std::unordered_map<uint32_t, uint32_t> replace;  // old vreg -> new

        // Which cached entries read a given vreg, so a write can drop them.
        std::unordered_map<uint32_t, std::vector<CastKey>> readers;

        std::vector<IRInst> out;
        out.reserve(b.instructions().size());

        for (const IRInst& in : b.instructions()) {

            IRInst inst = in;

            // Rewrite operands that earlier CSE redirected. Done first, so a
            // chain of conversions collapses in one walk.
            if (!replace.empty()) {
                for (IRValue& v : inst.operands()) {
                    if (!v.isVReg()) continue;
                    auto it = replace.find(v.asVReg().id());
                    if (it == replace.end()) continue;
                    v = IRValue::makeVReg(it->second, v.type(),
                                          v.asVReg().debugName());
                }
            }

            // A write to any vreg kills every cached conversion reading it.
            if (inst.hasResult()) {
                const uint32_t d = inst.dst().id();

                if (auto it = readers.find(d); it != readers.end()) {
                    for (const CastKey& k : it->second)
                        available.erase(k);
                    readers.erase(it);
                }

                replace.erase(d);
            }

            if (isConversion(inst.opcode()) && inst.hasResult() &&
                inst.operands().size() == 1 && inst.operand(0).isVReg()) {

                const CastKey key{
                    inst.opcode(),
                    inst.operand(0).asVReg().id(),
                    static_cast<uint32_t>(inst.operand(0).type().kind()),
                    static_cast<uint32_t>(inst.resultType().kind()),
                };

                if (auto it = available.find(key); it != available.end()) {
                    replace[inst.dst().id()] = it->second;
                    ++res.castsCSEd;
                    continue;
                }

                available.emplace(key, inst.dst().id());
                readers[key.srcVreg].push_back(key);
            }

            out.push_back(std::move(inst));
        }

        b.instructions() = std::move(out);
    }

    for (const IRBasicBlock& b : fn.blocks())
        res.instsAfter += b.instructions().size();

    return res;
}

void LegalizeResult::describe(std::ostream& os) const {
    os << "legalize: " << instsBefore << " -> " << instsAfter
       << " instructions";

    if (instsBefore > 0) {
        const bool grew = instsAfter > instsBefore;
        const size_t difference = grew ? instsAfter - instsBefore : instsBefore - instsAfter;
        const double pct =
            100.0 * static_cast<double>(difference) /
            static_cast<double>(instsBefore);
        os << (grew ? "  (+" : "  (-") << static_cast<int>(pct + 0.5) << "%)";
    }
    os << "\n"
       << "  duplicate conversions removed : " << castsCSEd << "\n"
       << "  fallback hooks called         : " << fallbacksCalled << "\n"
       << "  original operations rewritten : " << rewritesApplied << "\n";

    if (!problems.empty()) {
        os << "  operations with no lowering   : " << problems.size() << "\n";
        for (const std::string& p : problems)
            os << "      " << p << "\n";
    }
}

} // namespace XTOR_RV
