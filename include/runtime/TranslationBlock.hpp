#pragma once

#include "ir/IR.hpp"

#include <cstdint>
#include <string>

namespace XTOR_IR {

enum class ExitKind {
    Fallthrough,
    DirectJump,
    Conditional,
    DirectCall,
    IndirectJump,
    IndirectCall,
    Return,
    Syscall,

    Unsupported,
};

const char* toString(ExitKind kind);

bool isStaticallyKnown(ExitKind kind); 

struct TranslationBlock {
    explicit TranslationBlock(uint64_t start = 0) : guestStart(start) {}

    // A stable address-derived name for IR and machine-code diagnostics.
    std::string name() const;

    uint64_t guestStart = 0;

    uint64_t guestEnd = 0;

    uint32_t byteLength = 0;   
    uint32_t instrCount = 0;   

    ExitKind exit = ExitKind::Unsupported;

    bool hasTaken       = false;  // is `taken` meaningful?
    uint64_t taken          = 0;      // branch target / call target
    bool hasFallthrough = false;  // is `fallthrough` meaningful?
    uint64_t fallthrough    = 0;      // not-taken path / return address

    // Set when the exit reason is worth explaining in a report — an
    // unsupported mnemonic, a decode failure, a budget cut-off.
    std::string note;

    const std::vector<IRBasicBlock>& blocks() const { return m_blocks; }
    std::vector<IRBasicBlock>& blocks() { return m_blocks; }
    void addBlock(IRBasicBlock block);
    IRBasicBlock* findBlock(const std::string& label);
    const IRBasicBlock* findBlock(const std::string& label) const;
    IRBasicBlock& entryBlock();
    const IRBasicBlock& entryBlock() const;

    uint32_t allocVreg();

    // Reserve IDs already present in hand-built or rewritten IR before a pass
    // allocates more. addBlock calls this automatically; passes using mutable
    // instruction vectors call it once before requesting new temporaries.
    void reserveVregs();
    uint64_t execCount = 0;

private:
    std::vector<IRBasicBlock> m_blocks;
    // A wider cursor detects exhaustion instead of wrapping back into v0.
    uint64_t m_nextVregId = 20;
}; 

struct TBLimits {
    uint32_t maxInstructions = 64;

    // A hard byte ceiling as well, because 64 x86 instructions can be
    // anywhere from 64 bytes to nearly a kilobyte.
    uint32_t maxBytes = 512;

    // Stop at a guest page boundary.
    //
    // correctness rule. A TB is invalidated when
    // the guest writes to the bytes it was translated from, and
    // invalidation is tracked per page. A block spanning two pages would
    // have to be registered with both, and the second page may not even be
    // mapped yet (translating across the edge would fault on bytes the
    // guest never intended to execute).
    bool stopAtPageBoundary = true;

    uint64_t pageSize = 4096;
};
}
