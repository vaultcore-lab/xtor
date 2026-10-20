#pragma once

#include <cstdint>
#include <string>

namespace XTOR_RV {

enum class RvExt : uint32_t {
    None = 0,

    // M — integer multiply and divide. mul, mulh, div, divu, rem, remu and
    // the W forms. Without it, multiplication may still use Zmmul, while
    // division/remainder need their software-helper lowering hooks.
    M = 1u << 0,

    // A — atomics (lr/sc, amoadd and friends). Needed once the guest's
    // `lock`-prefixed instructions are modelled; nothing uses it yet.
    A = 1u << 1,

    // F, D — single and double precision floating point. The x86 lifter
    // models no SSE or x87 today, so no float opcode ever reaches the
    // backend from that lifter. The legalizer nevertheless accepts typed FP
    // IR from other callers and chooses hardware versus soft-float hooks.
    F = 1u << 2,
    D = 1u << 3,

    // C — compressed, 16-bit encodings. Purely a size optimisation, and one
    // this backend does NOT emit: the encoder produces 32-bit forms only,
    // and a code cache cares about translation speed rather than density.
    // Listed because a target may still have it, and a future peephole could
    // use it.
    C = 1u << 4,

    // Zba — address generation. sh1add, sh2add, sh3add fold a shift into an
    // add. Directly relevant: the IR holds 85,700 inttoptr operations, most
    // of them scaled-index address arithmetic from x86 addressing modes.
    Zba = 1u << 5,

    // Zbb — basic bit manipulation. The ones that matter here are sext.b,
    // sext.h and zext.h, which collapse the two-instruction shift pair the
    // legalizer otherwise needs for every narrow extension. Also andn, orn,
    // ctz, cpop.
    Zbb = 1u << 6,

    // Zbs — single-bit instructions: bset, bclr, binv, bext. x86 bt/bts/btr
    // map onto these directly once they are lifted.
    Zbs = 1u << 7,

    // Zicond — integer conditional operations, czero.eqz and czero.nez.
    // The branchless lowering for SELECT.
    Zicond = 1u << 8,

    // Zmmul — the multiply-only subset of M. Keep a distinct bit so a chip
    // with a multiplier but no divider does not accidentally get DIV/REM.
    // M implies this capability even when this bit is not separately set.
    Zmmul = 1u << 9,
};

constexpr uint32_t operator|(RvExt a, RvExt b) {
    return static_cast<uint32_t>(a) | static_cast<uint32_t>(b);
}
constexpr uint32_t operator|(uint32_t a, RvExt b) {
    return a | static_cast<uint32_t>(b);
}

struct RvTarget{

      // Register width in bits. This backend supports 64 only: the guest is
    // x86-64, its registers and pointers are 64-bit, and lowering them onto
    // a 32-bit host would mean splitting every value into a register pair.
    // Stored rather than assumed so the check has something to test.
    uint32_t xlen = 64;

    uint32_t extensions = 0;

    //-- queries ----------------------------------------------------------

    constexpr bool is64() const { return xlen == 64; }

    constexpr bool has(RvExt e) const {
        return (extensions & static_cast<uint32_t>(e)) != 0;
    }

    // True only if every extension in the mask is present.
    constexpr bool hasAll(uint32_t mask) const {
        return (extensions & mask) == mask;
    }

    constexpr bool hasMulDiv()      const { return has(RvExt::M); }
    constexpr bool hasMultiply()    const { return has(RvExt::M) || has(RvExt::Zmmul); }
    constexpr bool hasDivide()      const { return has(RvExt::M); }
    // D depends on F. Check both here even before target validation runs.
    constexpr bool hasFloat32()     const { return has(RvExt::F); }
    constexpr bool hasFloat64()     const { return hasAll(RvExt::F | RvExt::D); }
    constexpr bool hasFastExtend()  const { return has(RvExt::Zbb); }
    constexpr bool hasCondMove()    const { return has(RvExt::Zicond); }
    constexpr bool hasShiftAdd()    const { return has(RvExt::Zba); }

    constexpr uint32_t pointerBytes() const { return xlen / 8; }
    constexpr uint32_t nativeBits() const { return xlen; }
    constexpr bool hasWordOps() const { return xlen == 64; }

    
    // rv64gc — the default, and what a Linux riscv64 userland is built for.
    // G is shorthand for IMAFD plus Zicsr and Zifencei.
    static constexpr RvTarget rv64gc() {
        return RvTarget{64, RvExt::M | RvExt::A | RvExt::F | RvExt::D |
                            RvExt::C};
    }

    // rv64i — base integer only. Useful for exercising the missing-feature
    // dispatch paths. Until expansion bodies are supplied, operations that
    // reach those hooks fail explicitly instead of silently remaining legal.
    static constexpr RvTarget rv64i() {
        return RvTarget{64, 0};
    }

    // A modern application core: rv64gc plus the bit-manipulation and
    // conditional-move extensions the backend can exploit.
    static constexpr RvTarget rv64gc_b() {
        return RvTarget{64, RvExt::M | RvExt::A | RvExt::F | RvExt::D |
                            RvExt::C | RvExt::Zba | RvExt::Zbb |
                            RvExt::Zbs | RvExt::Zicond};
    }

    // The ISA string, e.g. "rv64imafdc_zba_zbb". Printed in diagnostics so a
    // miscompile can be tied to the configuration that produced it.
    std::string isaString() const {
        std::string s = "rv" + std::to_string(xlen) + "i";
        if (has(RvExt::M)) s += "m";
        if (has(RvExt::A)) s += "a";
        if (has(RvExt::F)) s += "f";
        if (has(RvExt::D)) s += "d";
        if (has(RvExt::C)) s += "c";
        if (has(RvExt::Zba))    s += "_zba";
        if (has(RvExt::Zbb))    s += "_zbb";
        if (has(RvExt::Zbs))    s += "_zbs";
        if (has(RvExt::Zicond)) s += "_zicond";
        // Do not redundantly print Zmmul when M already implies it.
        if (has(RvExt::Zmmul) && !has(RvExt::M)) s += "_zmmul";
        return s;
    }

    // Why this target cannot be used, or an empty string if it can.
    //
    // Returned rather than thrown so the caller decides whether an
    // unsupported configuration is fatal. The backend requires 64-bit.
    // Missing M is a per-operation fallback decision, not an invalid chip.
    // This descriptor is supplied by the caller; it does not probe the CPU.
    std::string unsupportedReason() const {
        if (xlen != 64)
            return "XTOR's RISC-V backend requires a 64-bit target (xlen=" +
                   std::to_string(xlen) + " given); the x86-64 guest's "
                   "registers and pointers are 64-bit and lowering them onto "
                   "a 32-bit host would mean splitting every value into a "
                   "register pair";
        // A contradictory feature mask must not authorize double-precision
        // instructions on a target missing their single-precision base.
        if (has(RvExt::D) && !has(RvExt::F))
            return "the D extension requires F in the target feature mask";
        return {};
    }
};

}
