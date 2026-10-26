#pragma once

#include "backend/x86/X86Lifter.hpp"   
#include "runtime/Loader.hpp"
#include "runtime/TranslationBlock.hpp" 

#include <cstdint>
#include <iosfwd>
#include <string>
#include <unordered_map>
#include <vector>


namespace Runtime {

//  the result of asking guest memory for bytes to decode
struct CodeFetch {
    // Non-empty on success. A zero-length successful fetch cannot occur:
    // fetchCode reports "nothing startable here" as a failure instead, so
    // that a caller never sees an empty-but-valid buffer and lifts an empty
    // block out of it forever.
    std::vector<uint8_t> bytes;

    // Empty on success; otherwise "unmapped", "not executable", or the
    // message from a failed read.
    //
    // Worth keeping rather than collapsing to a bool: a guest jumping into
    // a data page and a guest jumping into nothing at all are different
    // bugs, and this string ends up in the block report where the
    // difference is visible.
    std::string why;

    bool ok() const { return why.empty(); }
};

class Translator{
public: 

    explicit Translator(const GuestProcess& process, 
                        XTOR_IR::IRProgram symbols = {}); 

    CodeFetch fetchCode(uint64_t guestVA) const; 

    const XTOR_IR::TranslationBlock& translate(uint64_t guestVA); 

    //true if guestVA has already been cached 
    bool isCached(uint64_t guestVA) const; 

    // Every block translated so far, in address order (the map itself is
    // unordered; the dispatcher does not care, reports do).
    std::vector<const XTOR_IR::TranslationBlock*> blocksByAddress() const;

    size_t cachedCount() const { return m_cache.size(); }

    // Translate outward from `startVA` following only the edges whose
    // targets are knowable without running anything. Per EDGE, not per
    // block: a `call rax` contributes no callee but does contribute a
    // return address, and that edge is followed.
    //
    // This stands in for the dispatcher loop and terminates for the same
    // reason a real one does not: the worklist runs dry when every frontier
    // block ends indirectly. Returns the number of blocks translated by
    // this call (cache hits are not counted twice).
    //
    // maxBlocks bounds the walk. Guest code is a graph, not a tree, and
    // while the cache prevents re-translating a block it does not prevent a
    // pathological binary from having more reachable blocks than anyone
    // wants to wait for.
    size_t translateReachableBlocks(uint64_t startVA, size maxBlocks = 4096);
    
    void printTranslationInfo(std::ostream& os) const;
    
    const std::vector<uint64_t>& unresolvedExits() const {
        return m_unresolved;
    }

private:
     // The longest possible x86-64 instruction. The straddle allowance.
    static constexpr size_t kMaxInstrBytes = 15;

    const GuestProcess& m_process;
    XTOR_IR::IRProgram  m_symbols;
    XTOR_IR::TBLimits m_limits;

    std::unordered_map<uint64_t, XTOR_IR::TranslationBlock> m_cache;
    std::vector<uint64_t> m_unresolved;
}; 

}
