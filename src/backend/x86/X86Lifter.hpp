#pragma once

#include "ir/IRProgram.hpp"
#include "ELFLoader.hpp"
#include "runtime/TranslationBlock.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace XTOR_IR {

IRProgram liftX86ToIR(const ElfLoad::ElfLoadResult& elf);

TranslationBlock liftTranslationBlock(uint64_t guestVA,
                                      const uint8_t* bytes,
                                      size_t length,
                                      const IRProgram& symbols,
                                      const TBLimits& limits = {});

} // namespace XTOR_IR

