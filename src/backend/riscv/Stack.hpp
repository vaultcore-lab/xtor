#pragma once

#include "backend/riscv/MachineInst.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace XTOR_RV {

inline constexpr uint64_t kStackAlignment = 16;

[[nodiscard]] constexpr bool stackNeedsAlignment(uint64_t sp) noexcept {
    return (sp & (kStackAlignment - 1)) != 0;
}

[[nodiscard]] constexpr uint64_t alignStackPointer(uint64_t sp) noexcept {
    return sp & ~(kStackAlignment - 1);
}

    default:
        
        break;
}

}
