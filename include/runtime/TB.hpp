#pragma once

#include "ir/IR.hpp"

#include <cstdint>
#include <string>


namespace XTOR_IR{

enum class ExitKind{
    Fallthrough, 
    DirectJump, 
    Conditional, 
    DirectCall, 
    IndirectJump, 
    Return, 
    Syscall, 
    Unsupported, 
}; 

const char *toString(ExitKind kind); 

struct TranslationBlock{
    uint64_t guestStart = 0; 
    uint64_t guestEnd = 0; 

    uint32_t bytelength = 0; 
    uint64_t instrCOunt = 0; 

    ExitKind exit = ExitKind::Unsupported; 

    bool isTaken = false; 
    uint64_t taken = 0; 
    bool hasFallthrough = false; 
    uint64_t fallthrough = 0; 

    std::string note; 

    IRFunction ir{"tb_unlifter", IRType::i64(), CallingConv::C}; 

    uint64_t execCount = 0; 
};

struct TBLimits{
    uint32_t maxInstructions = 64; 
    uint32_t maxBytes = 512; 
    bool stopAtPageBoundary = true; 
    uint64_t pageSize = 4096; 
}; 


}
