
#include "X86Lifter.hpp"
#include "FlagState.hpp"

#include <Zydis/Zydis.h>
#include <elfio/elfio.hpp>

#include <algorithm>
#include <cassert>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace XTOR_IR{

namespace {
//Describes one ELF symbol of interest (function or global object)
struct SymbolInfo{
    std::string name; 
    uint64_t address; 
    uint64_t size; 
    unsigned char type; 
    unsigned char binding; 
}; 

struct DecodedInstr{
    uint64_t va; 
    uint8_t length;
    ZydisDecodedInstruction zydis; 
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]
}; 

#if defined(ZYDIS_VERSION) && (ZYDIS_VERSION >= 0x0004000000000000ULL)
  #define XTOR_ZYDIS_V4 1
#else
  #define XTOR_ZYDIS_V4 0
#endif


//x86-64 registers are aliased. we model all registers 
//through thier 64-bit canonical form 
static ZydisRegister canonicalReg(ZydisRegister reg) {
    switch (reg) {
        // Legacy A/B/C/D registers each have a low byte, a high byte
        // (AH etc., bits 15:8), a 16-bit, a 32-bit and a 64-bit name.
        case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AH:
        case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_RAX:
            return ZYDIS_REGISTER_RAX;

        case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BH:
        case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_EBX:
        case ZYDIS_REGISTER_RBX:
            return ZYDIS_REGISTER_RBX;

        case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CH:
        case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_ECX:
        case ZYDIS_REGISTER_RCX:
            return ZYDIS_REGISTER_RCX;

        case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DH:
        case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_EDX:
        case ZYDIS_REGISTER_RDX:
            return ZYDIS_REGISTER_RDX;

        // SI/DI/SP/BP gained byte-sized names (SIL, DIL, SPL, BPL) only
        // in 64-bit mode, and only when a REX prefix is present.
        case ZYDIS_REGISTER_SIL: case ZYDIS_REGISTER_SI:
        case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_RSI:
            return ZYDIS_REGISTER_RSI;

        case ZYDIS_REGISTER_DIL: case ZYDIS_REGISTER_DI:
        case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_RDI:
            return ZYDIS_REGISTER_RDI;

        case ZYDIS_REGISTER_SPL: case ZYDIS_REGISTER_SP:
        case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_RSP:
            return ZYDIS_REGISTER_RSP;

        case ZYDIS_REGISTER_BPL: case ZYDIS_REGISTER_BP:
        case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_RBP:
            return ZYDIS_REGISTER_RBP;

        // R8..R15 are uniform: B = byte, W = word, D = dword, bare = qword.
        case ZYDIS_REGISTER_R8B:  case ZYDIS_REGISTER_R8W:
        case ZYDIS_REGISTER_R8D:  case ZYDIS_REGISTER_R8:
            return ZYDIS_REGISTER_R8;

        case ZYDIS_REGISTER_R9B:  case ZYDIS_REGISTER_R9W:
        case ZYDIS_REGISTER_R9D:  case ZYDIS_REGISTER_R9:
            return ZYDIS_REGISTER_R9;

        case ZYDIS_REGISTER_R10B: case ZYDIS_REGISTER_R10W:
        case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10:
            return ZYDIS_REGISTER_R10;

        case ZYDIS_REGISTER_R11B: case ZYDIS_REGISTER_R11W:
        case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11:
            return ZYDIS_REGISTER_R11;

        case ZYDIS_REGISTER_R12B: case ZYDIS_REGISTER_R12W:
        case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12:
            return ZYDIS_REGISTER_R12;

        case ZYDIS_REGISTER_R13B: case ZYDIS_REGISTER_R13W:
        case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13:
            return ZYDIS_REGISTER_R13;

        case ZYDIS_REGISTER_R14B: case ZYDIS_REGISTER_R14W:
        case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14:
            return ZYDIS_REGISTER_R14;

        case ZYDIS_REGISTER_R15B: case ZYDIS_REGISTER_R15W:
        case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15:
            return ZYDIS_REGISTER_R15;

        default: return reg; // XMM / segment / control regs — pass through
    }
}

// Returns the IRType corresponding to the register's access width.
static IRType typeOfReg(ZydisRegister reg) {

    // 8-bit registers
    switch (reg) {
        case ZYDIS_REGISTER_AL:  case ZYDIS_REGISTER_AH:
        case ZYDIS_REGISTER_BL:  case ZYDIS_REGISTER_BH:
        case ZYDIS_REGISTER_CL:  case ZYDIS_REGISTER_CH:
        case ZYDIS_REGISTER_DL:  case ZYDIS_REGISTER_DH:
        case ZYDIS_REGISTER_SIL: case ZYDIS_REGISTER_DIL:
        case ZYDIS_REGISTER_SPL: case ZYDIS_REGISTER_BPL:
        case ZYDIS_REGISTER_R8B: case ZYDIS_REGISTER_R9B:
        case ZYDIS_REGISTER_R10B: case ZYDIS_REGISTER_R11B:
        case ZYDIS_REGISTER_R12B: case ZYDIS_REGISTER_R13B:
        case ZYDIS_REGISTER_R14B: case ZYDIS_REGISTER_R15B:
            return IRType::i8();

        // 16-bit registers
        case ZYDIS_REGISTER_AX:  case ZYDIS_REGISTER_BX:
        case ZYDIS_REGISTER_CX:  case ZYDIS_REGISTER_DX:
        case ZYDIS_REGISTER_SI:  case ZYDIS_REGISTER_DI:
        case ZYDIS_REGISTER_SP:  case ZYDIS_REGISTER_BP:
        case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R9W:
        case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R11W:
        case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R13W:
        case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R15W:
            return IRType::i16();

        // 32-bit registers
        case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_EBX:
        case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_EDX:
        case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_EDI:
        case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_EBP:
        case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R9D:
        case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R11D:
        case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R13D:
        case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R15D:
            return IRType::i32();

        default:
            // All 64-bit GPRs, XMM (modelled as i64 in this pass), etc.
            return IRType::i64();
    }
}

static uint32_t gprVRegId(ZydisRegister canonReg) {
    switch (canonReg) {
        case ZYDIS_REGISTER_RAX: return 0;
        case ZYDIS_REGISTER_RBX: return 1;
        case ZYDIS_REGISTER_RCX: return 2;
        case ZYDIS_REGISTER_RDX: return 3;
        case ZYDIS_REGISTER_RSI: return 4;
        case ZYDIS_REGISTER_RDI: return 5;
        case ZYDIS_REGISTER_RSP: return 6;
        case ZYDIS_REGISTER_RBP: return 7;
        case ZYDIS_REGISTER_R8:  return 8;
        case ZYDIS_REGISTER_R9:  return 9;
        case ZYDIS_REGISTER_R10: return 10;
        case ZYDIS_REGISTER_R11: return 11;
        case ZYDIS_REGISTER_R12: return 12;
        case ZYDIS_REGISTER_R13: return 13;
        case ZYDIS_REGISTER_R14: return 14;
        case ZYDIS_REGISTER_R15: return 15;
        default:
            return UINT32_MAX;   // untracked (XMM, segment, etc.)
    }
}

// isHighByteReg — true for AH/BH/CH/DH, the four registers that alias
// bits 15:8 rather than 7:0 of their parent.
static bool isHighByteReg(ZydisRegister reg) {
    return reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH ||
           reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH;
}

static IRType typeFromEncodedSize(uint16_t sizeInBits) {
    switch (sizeInBits) {
        case 8:  
            return IRType::i8();
        case 16: 
            return IRType::i16();
        case 32: 
            return IRType::i32();
        default: 
            return IRType::i64();   // 64 and anything unexpected
    }
}

static std::string regName(ZydisRegister reg){
    const char *s = ZydisRegisterGetString(reg); 
    return s ? std::string(s) : "reg"; 
}

static IRType destWidth(const ZydisDecodedOperand& dst,
                        const ZydisDecodedOperand& src) {

    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
        return typeOfReg(dst.reg.value);
    if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
        return typeOfReg(src.reg.value);
    return typeFromEncodedSize(dst.size);
}


static IRType operandWidth(const ZydisDecodedOperand& op) {
    return (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
             ? typeOfReg(op.reg.value)
             : typeFromEncodedSize(op.size);
}

// condRequestFor — map any conditional mnemonic (Jcc, SETcc, CMOVcc) to
// a FlagRequest
static std::optional<Flags::FlagRequest> condRequestFor(ZydisMnemonic m) {
    switch (m) {

        // SETcc - store the condition as a 0/1 byte.
        case ZYDIS_MNEMONIC_SETZ:   return Flags::FlagRequest::ZF;
        case ZYDIS_MNEMONIC_SETNZ:  return Flags::FlagRequest::NOT_ZF;
        case ZYDIS_MNEMONIC_SETS:   return Flags::FlagRequest::SF;
        case ZYDIS_MNEMONIC_SETNS:  return Flags::FlagRequest::NOT_SF;
        case ZYDIS_MNEMONIC_SETO:   return Flags::FlagRequest::OF;
        case ZYDIS_MNEMONIC_SETNO:  return Flags::FlagRequest::NOT_OF;
        case ZYDIS_MNEMONIC_SETB:   return Flags::FlagRequest::CF;
        case ZYDIS_MNEMONIC_SETNB:  return Flags::FlagRequest::NOT_CF;
        case ZYDIS_MNEMONIC_SETBE:  return Flags::FlagRequest::CF_OR_ZF;
        case ZYDIS_MNEMONIC_SETNBE: return Flags::FlagRequest::NOT_CF_AND_NOT_ZF;
        case ZYDIS_MNEMONIC_SETL:   return Flags::FlagRequest::SF_XOR_OF;
        case ZYDIS_MNEMONIC_SETNL:  return Flags::FlagRequest::NOT_SF_XOR_OF;
        case ZYDIS_MNEMONIC_SETLE:  return Flags::FlagRequest::ZF_OR_SF_XOR_OF;
        case ZYDIS_MNEMONIC_SETNLE: return Flags::FlagRequest::NOT_ZF_AND_NOT_SF_XOR_OF;

        // CMOVcc - conditional register move, lifted to a branchless SELECT.
        case ZYDIS_MNEMONIC_CMOVZ:   return Flags::FlagRequest::ZF;
        case ZYDIS_MNEMONIC_CMOVNZ:  return Flags::FlagRequest::NOT_ZF;
        case ZYDIS_MNEMONIC_CMOVS:   return Flags::FlagRequest::SF;
        case ZYDIS_MNEMONIC_CMOVNS:  return Flags::FlagRequest::NOT_SF;
        case ZYDIS_MNEMONIC_CMOVO:   return Flags::FlagRequest::OF;
        case ZYDIS_MNEMONIC_CMOVNO:  return Flags::FlagRequest::NOT_OF;
        case ZYDIS_MNEMONIC_CMOVB:   return Flags::FlagRequest::CF;
        case ZYDIS_MNEMONIC_CMOVNB:  return Flags::FlagRequest::NOT_CF;
        case ZYDIS_MNEMONIC_CMOVBE:  return Flags::FlagRequest::CF_OR_ZF;
        case ZYDIS_MNEMONIC_CMOVNBE: return Flags::FlagRequest::NOT_CF_AND_NOT_ZF;
        case ZYDIS_MNEMONIC_CMOVL:   return Flags::FlagRequest::SF_XOR_OF;
        case ZYDIS_MNEMONIC_CMOVNL:  return Flags::FlagRequest::NOT_SF_XOR_OF;
        case ZYDIS_MNEMONIC_CMOVLE:  return Flags::FlagRequest::ZF_OR_SF_XOR_OF;
        case ZYDIS_MNEMONIC_CMOVNLE: return Flags::FlagRequest::NOT_ZF_AND_NOT_SF_XOR_OF;

        // Everything else: try the jump table, which returns nullopt for
        // non-conditional mnemonics.
        default: return Flags::flagRequestForJcc(m);
    }
}

//  Iterates .symtab (and .dynsym as fallback) using ELFIO
static std::vector<SymbolInfo> readSymbols(const ELFIO::elfio& reader) {
    std::vector<SymbolInfo> result;

    for (const auto& sec : reader.sections) {
        if (sec->get_type() != ELFIO::SHT_SYMTAB &&
            sec->get_type() != ELFIO::SHT_DYNSYM)
            continue;

        ELFIO::symbol_section_accessor symtab(reader, sec.get());
        ELFIO::Elf_Xword count = symtab.get_symbols_num();

        for (ELFIO::Elf_Xword i = 0; i < count; ++i) {
            std::string   name;
            ELFIO::Elf64_Addr value   = 0;  
            ELFIO::Elf_Xword  size    = 0;
            unsigned char     bind    = 0;  // STB_LOCAL / GLOBAL 
            unsigned char     type    = 0;  // STT_OBJECT / STT_FUNC
            ELFIO::Elf_Half   shndx   = 0;  
            unsigned char     other   = 0;  

            symtab.get_symbol(i, name, value, size, bind, type, shndx, other);

            if (shndx == ELFIO::SHN_UNDEF || name.empty()) continue;

            if (type != ELFIO::STT_FUNC && type != ELFIO::STT_OBJECT) continue;

            result.push_back({name, value, size, type, bind});
        }
    }

    // Sort by address so we can quickly find the next symbol boundary when
    // a function's size field is zero
    std::sort(result.begin(), result.end(),
              [](const SymbolInfo& a, const SymbolInfo& b) {
                  return a.address < b.address;
              });
    return result;
}

static bool isTBTerminator(ZydisMnemonic m) {
    switch (m) {
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_JB:   case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JL:   case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNB:  case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JNL:  case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JNO:  case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JNS:  case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JO:   case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JS:   case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_JCXZ: case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JRCXZ:
        case ZYDIS_MNEMONIC_LOOP: case ZYDIS_MNEMONIC_LOOPE:
        case ZYDIS_MNEMONIC_LOOPNE:
        case ZYDIS_MNEMONIC_CALL:
        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_HLT:
        case ZYDIS_MNEMONIC_UD2:
            return true;
        default:
            return false;
    }
}

// TBDecode — the raw result of decoding one translation block's worth of
// bytes. Separated from classification so the decoder stays a pure
// "bytes in, instructions out" step.
struct TBDecode {
    std::vector<DecodedInstr> instrs;

    // The last instruction in `instrs` is a control transfer. When false,
    // the block was cut by a budget and control simply continues at the
    // next address.
    bool endedOnTerminator = false;

    // Zydis rejected the bytes at `failVA`. The block contains everything
    // decoded up to that point (possibly nothing).
    bool decodeFailed = false;
    uint64_t failVA       = 0;

    // Decoding stopped because the buffer ran out part-way through an
    // instruction. Distinct from decodeFailed: this means the CALLER
    // clipped the range (at a page edge, say), not that the guest code is
    // malformed.
    bool truncated = false;
}; 




class X86Disassmbler{
public: 
    X86Disassmbler(){

#if XTOR_ZYDIS_V4 
        ZydisDecoderInit(&m_decoder,
                         ZYDIS_MACHINE_MODE_LONG_64, 
                         ZYDIS_STACK_WIDTH_64);
#else
        ZydisDecoderInit(&m_decoder, 
                         ZYDIS_MACHINE_MODE_LONG_64, 
                         ZYDIS_ADDRESS_WIDTH_64); 
#endif 
    }


    std::vector<DecodedInstr> disassemble(const uint8_t* data, 
                                          size_t len, 
                                          uint64_t baseVA) const{
        std::vector<DecodedInstr> instrs; 
        size_t offset = 0; 
        
        //Decode one instruction at a time 
        while(offset < len){
            DecodedInstr di{}; 
            di.va = baseVA + offset;

            ZyanStatus status;
#if XTOR_ZYDIS_V4
            status = ZydisDecoderDecoderBuffer(&m_decoder,
                                               data + offset, 
                                               len - offset, 
                                               &di.Zydis
                                               di.operands);
#else 
            status = ZydisDecoderDecoderBuffer(&m_decoder, 
                                               data + offset, 
                                               len - offset, 
                                               &di.zydis);

            if (ZYAN_SUCCESS(status)) {
                for (uint8_t i = 0; i < ZYDIS_MAX_OPERAND_COUNT; ++i)
                    di.operands[i] = di.zydis.operands[i];
            }
#endif

            if(!ZYAN_SUCCESS(status)){
                di.length = 1; 
                di.zydis.mnemonic = ZYDIS_MNEMONIC_NOP; 
                di.zydis.length = 1; 
                di.zydis.operand_count_visible =0; 
                instr.push_back(di). 
                offset += 1;
                continue; 
            }

            di.length = static_cast<uint8_t>(di.zydis.length); 
            instrs.push_back(di); 
            offset + = di.length; 
        }
        return instrs; 
    }

    //dissasmble on translation block 
    //len : how many bytes exist in this buffer
    //blockBytes : how many bytes of the buffer belong to this block 
    TBDecode disassembleTB(const uint8_t *data, 
                           size_t len, 
                           uint64_t baseVA, 
                           uint32_t maxInstructions, 
                           size_t blockBytes) const{

        TBDecode out; 
        size_t offset = 0; 

        while (offset < blockBytes && out.instrs.size() < maxInstructions){
            DecodedInstr di{}; 
            di.va = baseVA + offset; 

            ZyanStatus status;
#if XTOR_ZYDIS_V4
            status = ZydisDecoderDecodeFull(&m_decoder,
                                            data + offset,
                                            len - offset,
                                            &di.zydis,
                                            di.operands);
#else
            status = ZydisDecoderDecodeBuffer(&m_decoder,
                                              data + offset,
                                              len - offset,
                                              &di.zydis);
            if (ZYAN_SUCCESS(status)) {
                for (uint8_t i = 0; i < ZYDIS_MAX_OPERAND_COUNT; ++i)
                    di.operands[i] = di.zydis.operands[i];
            }

#endif  
            
            if(!ZYAN_SUCCESS(status)){
                out.failVA = di.va; 
                if(len - offset < 15) 
                    out.truncated = true; 
                else 
                    out.decodeFailed = true; 
                brea; 
            }

            di.length = static_cast<uint8_t>(di.zydis.length); 
            out.instrs.push_back(di). 
            offset += di.length; 

            if(isTBTerminator(di.zydis.mnemonic)){
                out.endedOnTerminator = true; 
                break; 
            }
        }

        return out; 

    }

private:
    ZydisDecoder m_decoder; 

}; 



//CFG builder 
//build basic blocks from a flat instrucion stream 
class CFGBuilder{

public: 

    std::map<uint64_t, std::vector<DecodedInstr>>

    buildCFG(const std::vector<DecodedInstr>& instrs) const{
        
        if(instrs.empty())
            return {}; 

        std::set<uint64_t> leaders; 
        leaders.insert(instrs.front().va); 

        for(size_t i = 0; i < instrs.size(); ++i){
            const auto& di = instrs[i]; 

            if(!isNotControlFlow(di)) 
                continue; 

            if(i + 1 < instrs.size())
                leaders.insert(instrs[i + 1].va); 

            uint64_t target = directTarget(di); 
            if(target != 0)
                leaders.insert(target); 
        }

        std::map<uint64_t, std::vector<DecodedInstr>> blocks;
        uint64_t current = instrs.front().va; 
        blocks[current]; 

        if(const auto& di : instrs){
            if(leaders.count(di.va) != 0 && di.va != current){
                current = di.va;
            }
            blocks[current].push_back(di); 
        }
        return blocks; 
    }

private:
    // Returns true if this instruction ends a straight-line sequence
    // and may transfer control to a different address.
    static bool isControlFlow(const DecodedInstr& di) {
        switch (di.zydis.mnemonic) {
            case ZYDIS_MNEMONIC_JMP:
            case ZYDIS_MNEMONIC_CALL:
            case ZYDIS_MNEMONIC_RET:  case ZYDIS_MNEMONIC_RETF:
            // All conditional jumps (Jcc family)
            case ZYDIS_MNEMONIC_JB:   case ZYDIS_MNEMONIC_JBE:
            case ZYDIS_MNEMONIC_JL:   case ZYDIS_MNEMONIC_JLE:
            case ZYDIS_MNEMONIC_JNB:  case ZYDIS_MNEMONIC_JNBE:
            case ZYDIS_MNEMONIC_JNL:  case ZYDIS_MNEMONIC_JNLE:
            case ZYDIS_MNEMONIC_JNO:  case ZYDIS_MNEMONIC_JNP:
            case ZYDIS_MNEMONIC_JNS:  case ZYDIS_MNEMONIC_JNZ:
            case ZYDIS_MNEMONIC_JO:   case ZYDIS_MNEMONIC_JP:
            case ZYDIS_MNEMONIC_JS:   case ZYDIS_MNEMONIC_JZ:
            case ZYDIS_MNEMONIC_LOOP: case ZYDIS_MNEMONIC_LOOPE:
            case ZYDIS_MNEMONIC_LOOPNE:
                return true;
            default:
                return false;
        }
    }

    //Returns the direct brnach target virtual address (PC-relative immediate).
    //or 0 if the target is indirect  
    static uint64_t directTarget(const DecodedInstr& di){
        for(uint8_t i = 0; < di.zydis.operand_count_visible; ++){
            const auto& op = di.zydis.operands[i]; 
            if(op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative){
                return di.va + di.length + static_cast<uint64_t>(static_cast<int64>(op.imm.value.s)); 
            }
        }
        return 0; 
    }
};

// directBranchTarget — absolute VA of a PC-relative branch/call operand, or
// nullopt when the transfer is indirect.
static std::optional<uint64_t> directBranchTarget(const DecodedInstr& di) {
    for (uint8_t k = 0; k < di.zydis.operand_count_visible; ++k) {
        const auto& op = di.operands[k];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
            return di.va + di.length +
                   static_cast<uint64_t>(static_cast<int64_t>(op.imm.value.s));
        }
    }
    return std::nullopt;
}

// isModelledJcc — conditional jumps the flag machinery can actually
// evaluate. JP/JNP are absent because parity is not modelled, and the
// counter-based branches (JRCXZ, LOOP) are absent because they are not
// lifted at all.
static bool isModelledJcc(ZydisMnemonic m) {
    switch (m) {
        case ZYDIS_MNEMONIC_JZ:   case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JS:   case ZYDIS_MNEMONIC_JNS:
        case ZYDIS_MNEMONIC_JO:   case ZYDIS_MNEMONIC_JNO:
        case ZYDIS_MNEMONIC_JB:   case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JBE:  case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JL:   case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JLE:  case ZYDIS_MNEMONIC_JNLE:
            return true;
        default:
            return false;
    }
}

enum class TailMode{
    Branch, 
    Appended, 
    Manual, 
}; 

struct TBPlan{
    ExitKind kind = ExitKind::Unsupported ]; 
    TailMode tail = TailMode::Appended; 
    std::optional<uint64_t> taken; 
    std::optional<uint64_t> fallthrough; 
    std::string note; 
}; 

// classifyTBExit — read the decoded block and decide how it leaves.
// `endVA` is one past the last decoded byte: the fallthrough address, and
// the address a `call` will eventually return to.
static TBPlan classifyTBExit(const TBDecode& dec, uint64_t endVA) {
    TBPlan plan;

    if (dec.instrs.empty()) {
        plan.kind = ExitKind::Unsupported;
        plan.tail = TailMode::Appended;
        plan.fallthrough = endVA;
        plan.note = dec.decodeFailed
            ? "no decodable instruction at block start"
            : "no bytes available at block start";
        return plan;
    }

    //Cut short, no control transfer reached 
    if (!dec.endedOnTerminator) {
        plan.tail = TailMode::Appended;
        plan.fallthrough = endVA;

        if (dec.decodeFailed) {
            plan.kind = ExitKind::Unsupported;
            plan.note = "undecodable byte";
        } else {
            plan.kind = ExitKind::Fallthrough;
            if (dec.truncated)
                plan.note = "clipped by the supplied byte window";
        }
        return plan;
    }

    //A real control transfer
    const DecodedInstr& last   = dec.instrs.back();
    std::optional<uint64_t> tgt = directBranchTarget(last);

    switch (last.zydis.mnemonic) {

        case ZYDIS_MNEMONIC_JMP:
            if (tgt.has_value()) {
                // `jmp rel32`. One successor, known now. liftInstr emits
                // the branch into the exit stub for us.
                plan.kind = ExitKind::DirectJump;
                plan.tail = TailMode::Branch;
                plan.taken = tgt;
            } else {
                // `jmp rax`, `jmp [rax*8+tbl]` — switch dispatch or tail
                // call. The successor is a runtime value, so the block
                // computes it and returns it to the dispatcher.
                plan.kind = ExitKind::IndirectJump;
                plan.tail = TailMode::Manual;
            }
            return plan;

        case ZYDIS_MNEMONIC_CALL:
            // Either way the return address is endVA and the block pushes
            // it onto the guest stack before exiting.
            plan.tail = TailMode::Manual;
            plan.fallthrough = endVA;
            if (tgt.has_value()) {
                plan.kind  = ExitKind::DirectCall;
                plan.taken = tgt;
            } else {
                plan.kind = ExitKind::IndirectCall;
            }
            return plan;

        case ZYDIS_MNEMONIC_RET:
            // The successor is whatever is on top of the guest stack. This
            // is the single clearest reason a DBT cannot be replaced by
            // ahead-of-time translation.
            plan.kind = ExitKind::Return;
            plan.tail = TailMode::Manual;
            return plan;

        case ZYDIS_MNEMONIC_SYSCALL:
            plan.kind = ExitKind::Syscall;
            plan.tail = TailMode::Appended;
            plan.fallthrough = endVA;
            return plan;

        default:
            break;
    }

    if (isModelledJcc(last.zydis.mnemonic) && tgt.has_value()) {
        // Two successors, both known now. x86-64 has no indirect Jcc, so
        // the target is always a relative immediate.
        plan.kind = ExitKind::Conditional;
        plan.tail = TailMode::Branch;
        plan.taken = tgt;
        plan.fallthrough = endVA;
        return plan;
    }

    // JP/JNP (parity is not modelled), JRCXZ/LOOP (not lifted), INT, INT3,
    // HLT, UD2.
    //
    // These get a well-formed block ending in `ret endVA` so the IR stays
    // valid and printable, but the exit kind stays Unsupported so the
    // dispatcher refuses to follow the edge. Emitting valid-looking IR with
    // a confident-looking successor would be the worse outcome: a dropped
    // taken-edge on a JP shows up much later as execution in the wrong
    // place, with nothing pointing back to here.
    plan.kind        = ExitKind::Unsupported;
    plan.tail        = TailMode::Appended;
    plan.fallthrough = endVA;
    plan.note        = std::string("unmodelled control transfer: ")
                     + (ZydisMnemonicGetString(last.zydis.mnemonic)
                            ? ZydisMnemonicGetString(last.zydis.mnemonic)
                            : "?");
    return plan;
}


//Translates one x86-64 function (as a CFG of DecodedInstr)
class FunctionLifter{
public:

    FunctionLifter(const std::string name& name, 
                   uint64_t baseVA, 
                   CallingConv cc)
        : m_fn(name, retType, cc), m_baseVA(baseVA) {}

    IRFunction lift(const std::map<uint64_t, std::vector<DecodedInstr>>& cfgBlocks) {

        if (cfgBlocks.empty())
            return std::move(m_fn);

        m_fn.blocks().reserve(cfgBlocks.size());

        for (const auto& [va, _] : cfgBlocks)
            m_blockNames[va] = makeLabel(va);

        for (const auto& [va, _] : cfgBlocks)
            m_fn.addBlock(IRBasicBlock(makeLabel(va), va));

        //  lift instructions
        size_t blockIdx = 0;
        for (const auto& [va, instrs] : cfgBlocks) {
            liftBlock(va, instrs, blockIdx);

            IRBasicBlock& block = m_fn.blocks()[blockIdx];
            if (!block.isTerminated()) {
                if (blockIdx + 1 < m_fn.blocks().size()) {
                    // Fall through to the physically next block.
                    block.pushInst(
                        IRInst::makeJmp(m_fn.blocks()[blockIdx + 1].name()));
                } else {
                    block.pushInst(IRInst::makeRet(
                        IRValue::makeVReg(GprVReg::RAX, IRType::i64(), "rax")));
                }
            }
            ++blockIdx;
        }

        wireEdges();

        return std::move(m_fn);
    }

    IRFunction liftTB(uint64_t startVA, 
                     const std::vector<DecodedInstr>& instrs, 
                     const TBPlan& plan, 
                     uint64_t endVA) {

        std::vector<uint64_t> exitVAs;
        if (plan.tail == TailMode::Branch) {
            if (plan.taken.has_value())
                exitVAs.push_back(*plan.taken);
            if (plan.fallthrough.has_value() &&
                (!plan.taken.has_value() || *plan.fallthrough != *plan.taken))
                exitVAs.push_back(*plan.fallthrough);
        }

        for (uint64_t va : exitVAs)
            m_blockNames[va] = exitLabel(va);

        // create the blocks
        // Reserve first: liftBlock holds an IRBasicBlock& into this vector,
        // and a reallocating push_back would dangle it.
        m_fn.blocks().reserve(1 + exitVAs.size());
        m_fn.addBlock(IRBasicBlock(tbLabel(startVA), startVA));
        for (uint64_t va : exitVAs)
            m_fn.addBlock(IRBasicBlock(m_blockNames[va], va));

         //lift the body
        // TailMode::Manual withholds the final instruction from liftInstr; see
        // TailMode for why its function-oriented CALL/RET lifting is wrong
        // here.
        std::vector<DecodedInstr> trimmed;
        const std::vector<DecodedInstr>* body = &instrs;
        if (plan.tail == TailMode::Manual && !instrs.empty()) {
            trimmed.assign(instrs.begin(), instrs.end() - 1);
            body = &trimmed;
        }
        liftBlock(startVA, *body, 0);

        // close the body 
        IRBasicBlock& bodyBlock = m_fn.blocks()[0];
        if (!bodyBlock.isTerminated()) {
            if (plan.tail == TailMode::Manual && !instrs.empty())
                emitManualTail(instrs.back(), plan, bodyBlock, endVA);
            else
                emitExit(bodyBlock,
                         IRValue::makeImm(static_cast<int64_t>(endVA),
                                          IRType::i64()),
                         endVA);
        }

        // fill the exit stubs 
        // Each stub is one instruction: return the guest address it stands
        // for. Constant-valued, so a backend can chain straight through it.
        for (size_t i = 0; i < exitVAs.size(); ++i) {
            IRBasicBlock& stub = m_fn.blocks()[i + 1];
            emitExit(stub,
                     IRValue::makeImm(static_cast<int64_t>(exitVAs[i]),
                                      IRType::i64()),
                     exitVAs[i]);
        }

        //  edges 
        // Body stub links, so the printed IR and any later pass can see
        // the shape. There are no incoming edges from outside: a TB has
        // exactly one entry, by construction.
        wireEdges();

        return std::move(m_fn);
    }


private:
    IRFunction m_fn; 
    uint64_t m_baseVA; 

    const IRProgram* m_program; 

    //maps basic block leader VA -> IR block label string
    std::unordered_map<uint64_t, std::string> m_blockNames; 

    Flags::FlagState m_flagState; 

    static std::string makeLabel(uint64_t va){
        std::string ss; 
        ss << "bb_0x" << std::hex << va; 
        return ss.str(); 
    }

    //alocate temporary VReg (ID > 16)
    uint32_t newTemp() {
        return m_fn.allocVreg(); 
    }

     static std::string tbLabel(uint64_t va) {
        std::ostringstream ss;
        ss << "tb_0x" << std::hex << va;
        return ss.str();
    }

    static std::string exitLabel(uint64_t va) {
        std::ostringstream ss;
        ss << "exit_0x" << std::hex << va;
        return ss.str();
    }

    void emitExit(IRBasicBlock& block, IRValue next, uint64_t srcVA) {
        IRInst ret = IRInst::makeRet(std::move(next));
        ret.setSourceAddr(srcVA);
        block.pushInst(std::move(ret));
    }


 // emitManualTail — lift the terminators whose DBT meaning differs from
    // their function-level meaning: CALL, RET and indirect JMP.
    //
    // liftInstr models these for a static, function-scoped world (a call
    // becomes an IR CALL to the callee; a ret returns RAX). In a DBT both
    // are wrong, because there is no callee IRFunction to call and no
    // caller to return to — there is only the guest stack and the next
    // guest PC.
    void emitManualTail(const DecodedInstr& di,
                        const TBPlan& plan,
                        IRBasicBlock& block,
                        uint64_t endVA) {

        const ZydisDecodedOperand* ops = di.operands;
        const size_t before = block.instructions().size();

        switch (plan.kind) {

            //call rel32 / call r/m64 
            case ExitKind::DirectCall:
            case ExitKind::IndirectCall: {
                // ORDER MATTERS, and it is the opposite of the intuitive
                // one. x86 evaluates the call's operand BEFORE pushing the
                // return address, so `call [rsp]` transfers control to the
                // value that was on top of the stack on entry, not to the
                // return address that is about to be written there.
                // Computing the target first is what makes that correct.
                IRValue target =
                    plan.taken.has_value()
                        ? IRValue::makeImm(static_cast<int64_t>(*plan.taken),
                                           IRType::i64())
                        : readOperand(di, ops[0], block, IRType::i64());

                // Now the architectural side effect: push the return
                // address. This is a real store to real guest memory
                // through rsp — the guest can and does read it back
                // (return-address rewriting, stack unwinding, `ret` itself).
                pushStack(IRValue::makeImm(static_cast<int64_t>(endVA),
                                           IRType::i64()),
                          block);

                // A call clobbers flags as far as we can know.
                m_flagState.invalidate();

                emitExit(block, std::move(target), di.va);
                break;
            }

            //ret / ret imm16 
            case ExitKind::Return: {
                // The return address comes off the guest stack, exactly as
                // the hardware would take it. No shortcut is available: the
                // value may have been written by a call this translator
                // never saw, or deliberately altered by the guest.
                IRValue retAddr = popStack(block);

                // `ret imm16` additionally releases imm16 bytes of
                // arguments (stdcall-style callees, and some hand-written
                // assembly). Rare in x86-64 SysV but cheap to honour, and
                // silently ignoring it would desynchronise rsp.
                if (di.zydis.operand_count_visible > 0 &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    const int64_t extra =
                        static_cast<int64_t>(ops[0].imm.value.u);
                    if (extra != 0) {
                        uint32_t spId = newTemp();
                        block.pushInst(IRInst::makeBinop(
                            Opcode::ADD, VReg(spId, "rsp_ret"), IRType::i64(),
                            IRValue::makeVReg(GprVReg::RSP, IRType::i64(), "rsp"),
                            IRValue::makeImm(extra, IRType::i64())));
                        block.pushInst(IRInst::makeMov(
                            VReg(GprVReg::RSP, "rsp"), IRType::i64(),
                            IRValue::makeVReg(spId, IRType::i64())));
                    }
                }

                emitExit(block, std::move(retAddr), di.va);
                break;
            }

            //jmp r/m64 
            case ExitKind::IndirectJump: {
                // A switch-table dispatch, a tail call, or a PLT thunk.
                // Nothing is pushed and nothing is popped: read the target
                // and leave.
                IRValue target = readOperand(di, ops[0], block, IRType::i64());
                emitExit(block, std::move(target), di.va);
                break;
            }

            default:
                // classifyTBExit only ever selects Manual for the three
                // kinds above. Anything else reaching here is a bug, so
                // fall back to the safe, well-formed thing rather than
                // leaving the block unterminated.
                emitExit(block,
                         IRValue::makeImm(static_cast<int64_t>(endVA),
                                          IRType::i64()),
                         di.va);
                break;
        }

        // Back-annotate everything just emitted with the terminator's own
        // address, matching what liftBlock does for the body.
        for (size_t k = before; k < block.instructions().size(); ++k)
            block.instructions()[k].setSourceAddr(di.va);
    }

    //computes and stores CF, ZF, SF, OF in their reserved VRegs 
    //after an arithmetic instruction 
    //result - IRValue produced by the arithmetic 
    //lhs - left operand of the arithmetic, needed to computee CF
    //ty - the IRType the arithmetic ran at (i8,i16,i32)
    //isSub - true for SUB/CMP (changes how CF is computed))
    //block - the basic block to push flag- computing IR instruction into 

    void emitFlagsForArith(IRValue result, IRValue lhs, IRType ty, 
                           bool isSub, IRBasicBlock& block){

        //ZF = 1 if the result is exactly zero, 0 otherwise
        //emit compare instruction
        {
            uint32_t cmpId = newTemp(); 
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::EQ 
                Vreg(cmpId, "zf_cmp"), 
                result, 
                IRValue::makeImm(0, ty)));

            //Mov the i1 result into the stable ZF VReg 
            block.pushInst(IRInst::makeMov(
                VReg(FlagVreg::ZF, "zf"), 
                IRType::i1(), 
                IRValue::makeVReg(cmpId, IRType::i1()))); 
        }

        //SF: sign flag 
        //SF = 1 if the result's most significant bit is 1 
        //in two's compliment arithmetic, the MSB being 1 means 
        //the value is negative when interpreted as a signed integer 
        {
            uint32_t cmpId = newTemp(); 
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SLT, 
                VReg(cmpId, "sf_cmp"), 
                result, 
                IRValue::makeImm(0, ty))); 

            block.pushInst(IRInst::makeMov(
                VReg(FlagVreg::SF, "sf"), 
                IRType::i1(), 
                IRValue::makeVReg(cmpId, IRType::i1()))); 
        }

        //CF: carry flag 
        ///for ADD. CF = 1 if unsigned overflow occured 
        ///for SUB: CF = 1 if unsigned borrow occured 
        {
            uint32_t cmpId = newTemp(); 
            block.pushInst(IRInst::makeIcmp(
                isSub ? IcmpCond::UGT : IcmpCond::ULT, 
                VReg(cmpId, "cf_cmp"), 
                result, 
                lhs)); 

            block.pushInst(IRInst::makeMov(
                VReg(FlagVreg::CF, "cf"), 
                IRType::i1(), 
                IRValue::makeVReg(cmpId, IRType::i1()))); 
        }

        //Overflow flag 
        
        {
            // lhs_nn = (lhs >=signed 0)  i.e. lhs was non-negative
            uint32_t lhsNnId = newTemp();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SGE,
                VReg(lhsNnId, "lhs_nn"),
                lhs,
                IRValue::makeImm(0, ty)));

            // lhs_neg = (lhs <signed 0)
            uint32_t lhsNegId = newTemp();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SLT,
                VReg(lhsNegId, "lhs_neg"),
                lhs,
                IRValue::makeImm(0, ty)));

            // result_lt_lhs = (result <signed lhs)
            // For ADD with positive lhs: if result < lhs, the addition
            // pushed us past the max positive value and we wrapped.
            uint32_t rLtLId = newTemp();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SLT,
                VReg(rLtLId, "r_lt_l"),
                result,
                lhs));

            // result_gt_lhs = (result >signed lhs)
            // For SUB / ADD with negative lhs: if result > lhs, the addition
            // of a negative pushed us past the min negative value and we wrapped.
            uint32_t rGtLId = newTemp();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SGT,
                VReg(rGtLId, "r_gt_l"),
                result,
                lhs));

            // pos_overflow = lhs_nn AND result_lt_lhs
            // (positive lhs, result went negative — wrapped upward)
            uint32_t posOvId = newTemp();
            block.pushInst(IRInst::makeBinop(
                Opcode::AND,
                VReg(posOvId, "pos_ov"),
                IRType::i1(),
                IRValue::makeVReg(lhsNnId, IRType::i1()),
                IRValue::makeVReg(rLtLId,  IRType::i1())));

            // neg_overflow = lhs_neg AND result_gt_lhs
            // (negative lhs, result went positive — wrapped downward)
            uint32_t negOvId = newTemp();
            block.pushInst(IRInst::makeBinop(
                Opcode::AND,
                VReg(negOvId, "neg_ov"),
                IRType::i1(),
                IRValue::makeVReg(lhsNegId, IRType::i1()),
                IRValue::makeVReg(rGtLId,   IRType::i1())));

            // OF = pos_overflow OR neg_overflow
            uint32_t ofId = newTemp();
            block.pushInst(IRInst::makeBinop(
                Opcode::OR,
                VReg(ofId, "of_cmp"),
                IRType::i1(),
                IRValue::makeVReg(posOvId, IRType::i1()),
                IRValue::makeVReg(negOvId, IRType::i1())));

            block.pushInst(IRInst::makeMov(
                VReg(FlagVReg::OF, "of"),
                IRType::i1(),
                IRValue::makeVReg(ofId, IRType::i1())));
        }
    }
    //Returns an IRValue referencing the GPR's fixed Vreg directly
    IRValue readReg(ZydisRegister reg, IRBasicBlock block){
        
        ZydisRegister canon = canonicalReg(reg); 
        uint32_t id = gprVRegId(canon);
        IRType ty = typeOfReg(reg); 

        if(id == UINT32_MAX)
            return IRValue::makeImm(0, IRType::i64()); 

        IRValue full = IRValue::makeVReg(id, IRType::i64(), regName(canon)); 

        if(ty == IRType::i64())
            return full; 

        //sub-regsiter: emit TRUNC to narrow the value 
        uint32_t truncID = newTemp(); 
        block.pushInst(IRInst::makeCast(
            Opcode::TRUNC, VReg(truncID, "sub_" + regName(reg)), ty, full));
        return IRValue::makeVReg(truncID, ty); 
    } 

    //Register write 
    //emits a mov into a GPR's fixed Vreg 
    //handles the threee partial-write semantics 
    //64-bit: %rax = mov i64 val 
    //32-bit: %rax, zext i32 val to i64
    //8/16-bit:% - 

    void writeReg(ZydisRegister reg, IRValue val, IRBasicBlock block){
        ZydisRegister canon = canonicalReg(reg); 
        uint32_t id = gprVRegId(canon); 
        IRType ty = typeOfReg(reg); 

        if(id == UINT32_MAX)
            return; 

        VReg gprVReg(id, regName(canon)); 
        IRValue toStore = val; 

        if(ty == IRType::i64()){
            //full 64-bit write 
            block.pushInst(IRInst::makeMov(gprVReg, IRType::i64(), val)); 

        }else if (ty == IRType::i32()){
            // 32-bit write zero-extends into 64 bits (x86-64 architectural rule).
            // %t_z = zext i32 val to i64
            // %rax = mov i64 %t_z
            uint32_t zId = newTemp(); 
            block.pushInst(IRInst::makeCast(
                Opcode::ZEXT, VReg(zId, "zext32"), IRType::i64(), val)); 
            block.pushInst(IRInst::makeMov(
                gprVReg, IRType::i64(),
                IRValue::makeVReg(zId, IRType::64())); 
        }else{
            // 8/16-bit partial write: read-modify-write to preserve upper bits.
            // Read the current full register value.
            IRValue cur = IRValue::makeVReg(id, IRType::i64(), regName(canon));

            // Mask out the bits we are about to overwrite.
            uint64_t width = static_cast<uint64_t>(ty.byteWidth()) * 8;
            uint64_t mask  = ~((UINT64_C(1) << width) - 1);

            uint32_t maskedId = newTemp();
            block.pushInst(IRInst::makeBinop(
                Opcode::AND, VReg(maskedId, "masked"), IRType::i64(),
                cur,
                IRValue::makeImm(static_cast<int64_t>(mask), IRType::i64())));

            // Zero-extend the new value to 64 bits.
            uint32_t zId = newTemp();
            block.pushInst(IRInst::makeCast(
                Opcode::ZEXT, VReg(zId, "zext_partial"), IRType::i64(), val));

            // Merge and write back into the GPR VReg.
            block.pushInst(IRInst::makeBinop(
                Opcode::OR, gprVReg, IRType::i64(),
                IRValue::makeVReg(maskedId, IRType::i64()),
                IRValue::makeVReg(zId, IRType::i64())));
        }
    }

    //X86 Address computation 

    IRValue computeAddr(const ZydisDecodedOperand& memOp, IRBasicBlock& block){

        IRValue addr = IRValue::makeImm(0, IRType::i64()); 
        bool hasAddr = false; 

        //base register 
        if(memOp.mem.base != ZYDIS_REGISTER_NONE && 
           memOp.mem.base != ZYDIS_REGISTER_RIP){

            //get IRValue to VReg ID 
            addr = readReg(memOp.mem.base, block); 
            hasAddr = true; 

        }else if (memOp.mem.base == ZYDIS_REGISTER_RIP){
            addr = IRValue::makeImm(memOp.mem.disp.value, IRValue::i64()); 
            hasAddr = true; 
        }

        //index * scale 

        if(memOp.mem.index != ZYDIS_REGISTER_NONE){
            IRValue idx = readReg(memOp.mem.index, block); 

            if(memOp.mem.scale > 1){
                uint32_t sId = newTemp(); 
                block.pushInst(IRInst::makeBinop(
                    Opcode::MUL, VReg(sId, "idx_scaled"), IRType::i64(), 
                    idx, IRValue::makeImm(memOp.mem.scale, IRValue::i64())));
                idx = IRValue::makeVReg(sId, IRType::i64()); 
            }

            //base + scaled index 
            uint32_t aId = newTemp(); 
            block.pushInst(IRInst::makeBinop(
                Opcode::ADD, VReg(aId, "addr_idx"), IRType::i64(), 
                hasAddr ? addr : IRValue::makeImm(0, IRType::i64()), idx)); 
            addr = IRValue::makeVReg(aId, IRType::i64()); 
            hasAddr = true 
        }

        //displacement 
        if(memOp.mem.disp.has_displacement && memOp.mem.disp.value != 0){
            uint32_t dId = newTemp(); 
            block.pushInst(IRInst::makeBinop(
                Opcode::ADD, VReg(dId, "addr_disp"), IRType::i64(),
                hasAddr ? addr : IRType::makeImm(0, IRType::i64()), 
                IRValue::makeImm(memOp.mem.disp.value, IRType::i64()))); 
            addr = IRValue::makeVReg(dId, IRType::i64()); 
            hasAddr = true; 
        }

        //cast integer address to pointer 
        uint32_t pId = newTemp(); 
        block.pushInst(IRInst::makeCast(
            Opcode::INTTOPTR, VReg(pId, "mem_ptr"), IRType::ptr(), 
            hasAddr ? addr : IRValue::makeImm(0, IRType::i64()))); 

        return IRValue::makeVReg(pId, IRType::ptr()); 
    }

    /*read any source operand and return a typed IRValue
     * typHint is used for immediates  */ 
    IRValue readOperand(const ZydisDecodedOperand& op,
                        IRBasicBlock& block, 
                        IRType TypeHint = IRType::i64(){

        switch(op.type){

            case ZYDIS_OPERAND_TYPE_REGISTER:
                return readReg(op.reg.value, block);

            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                return IRValue::makeImm(op.imm.is_signed 
                                        ? op.imm.value.s
                                        : static_cast<int64>(op.imm.value.u.),
                                        TypeHint); 
            
            /*x86's  CISC encoding let's add, eax, [rabx+8] express cpmputeaddr,
             * then add as a single instrucion, 
             * RISC-V and the IR has no such fused instrucion. the lifter has to explicrly unfuse it*/ 
            case ZYDIS_OPERAND_TYPE_MEMORY: {

                IRValue ptr = computeAddr(op, block); 
                uint32_t lId = newTemp(); 
                block.pushInst(IRInst::makeLoad(VReg(lId, "mem_load"), 
                                                TypeHint, ptr, MemFlags(1))); 
                return IRValue::makeVReg(lId, hint);
            }
            default:
                return IRValue::makeImm(0, IRType::i64()); 
        }
    }

    void writeOperand(const ZydisDecodedOperand& op, 
                      IRValue val , 
                      IRBasicBlock& block){

        switch(op.type){

            case ZYDIS_OPERAND_TYPE_REGISTER:
                writeReg(op.reg.value, val, block); 
                break; 

            case ZYDIS_OPERAND_TYPE_MEMORY: {
                IRValue ptr = computeAddr(op, block); 
                block.pushInst(IRInst::makeStore(val, ptr, MemFlags(1))); 
                break; 
            } 

            default: break; 
        }
    }



    //Maps the zydis mnemonic of a conditional jump to the 
    //corresponding IcmpCond that should be emmited 

    static std::optional<IcmpCond> jccCond(ZydisMnemonic m) {
        switch (m) {
            case ZYDIS_MNEMONIC_JZ:   return IcmpCond::EQ;   // JE  — equal / zero
            case ZYDIS_MNEMONIC_JNZ:  return IcmpCond::NE;   // JNE — not equal
            case ZYDIS_MNEMONIC_JL:   return IcmpCond::SLT;  // signed 
            case ZYDIS_MNEMONIC_JLE:  return IcmpCond::SLE;  // signed <=
            case ZYDIS_MNEMONIC_JNL:  return IcmpCond::SGE;  // signed >=
            case ZYDIS_MNEMONIC_JNLE: return IcmpCond::SGT;  // signed >
            case ZYDIS_MNEMONIC_JB:   return IcmpCond::ULT;  // unsigned < (below)
            case ZYDIS_MNEMONIC_JBE:  return IcmpCond::ULE;  // unsigned <=
            case ZYDIS_MNEMONIC_JNB:  return IcmpCond::UGE;  // unsigned >=
            case ZYDIS_MNEMONIC_JNBE: return IcmpCond::UGT;  // unsigned > (above)
            // JS/JNS test the sign flag. Map to "< 0" / ">= 0" as a best
            // approximation — exact semantics would need a full flags model.
            case ZYDIS_MNEMONIC_JS:   return IcmpCond::SLT;
            case ZYDIS_MNEMONIC_JNS:  return IcmpCond::SGE;
            default:                  return std::nullopt;
        }
    }

    void liftBlock(uint64_t leaderVA, 
                   const std::vector<DecodedInstr>& instrs, 
                   size_t blockIdx,  
                   const IRProgram program){

        IRBasicBlock& blocks = m_fn.blocks()[blockIdx]; 

        for(const auto& di : instrs){

        }
    }


    //  INSTRUCTION LIFTING
    //
    //  The main dispatch table. Each case handles one mnemonic
    //  (or mnemonic family) and emits the corresponding IR.
    //  Unrecognised instructions become NOPs tagged with their
    //  source VA so they're easy to find and implement later.

    void liftInstr(const DecodedInstr& di, IRBasicBlock& block) {

        const ZydisDecodedInstruction& z   = di.zydis;
        const ZydisDecodedOperand*     ops = di.operands;

        switch (z.mnemonic) {

            // no-ops 
            // No data-flow meaning, but they must not reach `default`,
            // which would invalidate flag state for no reason.
            case ZYDIS_MNEMONIC_NOP:
            case ZYDIS_MNEMONIC_ENDBR64:
            case ZYDIS_MNEMONIC_INT3:      
                emitNOP(di, block);
                break;

            // data movement 
            case ZYDIS_MNEMONIC_MOV:       
                emitMOV(di, block);      
                break;
            case ZYDIS_MNEMONIC_MOVZX:     
                emitMOVZX(di, block);    
                break;
            case ZYDIS_MNEMONIC_MOVSX:
            case ZYDIS_MNEMONIC_MOVSXD:    
                emitMOVSX(di, block);    
                break;
            case ZYDIS_MNEMONIC_LEA:       
                emitLEA(di, block);      
                break;
            case ZYDIS_MNEMONIC_XCHG:      
                emitXCHG(di, block);     
                break;
            case ZYDIS_MNEMONIC_CWDE:
            case ZYDIS_MNEMONIC_CDQE:      
                emitCWDE(di, block);     
                break;
            case ZYDIS_MNEMONIC_CDQ:
            case ZYDIS_MNEMONIC_CQO:       
                emitCDQ(di, block);      
                break;

            //arithmetic
            case ZYDIS_MNEMONIC_ADD:       
                emitADD(di, block);      
                break;
            case ZYDIS_MNEMONIC_SUB:       
                emitSUB(di, block);      
                break;
            case ZYDIS_MNEMONIC_ADC:       
                emitADC(di, block);      
                break;
            case ZYDIS_MNEMONIC_SBB:       
                emitSBB(di, block);      
                break;
            case ZYDIS_MNEMONIC_INC:       
                emitINC(di, block);      
                break;
            case ZYDIS_MNEMONIC_DEC:       
                emitDEC(di, block);      
                break;
            case ZYDIS_MNEMONIC_IMUL:      
                emitIMUL(di, block);     
                break;
            case ZYDIS_MNEMONIC_MUL:       
                emitMUL(di, block);      
                break;
            case ZYDIS_MNEMONIC_IDIV:
            case ZYDIS_MNEMONIC_DIV:       
                emitDIV(di, block);      
                break;

            // logic and shifts 
            case ZYDIS_MNEMONIC_AND:       
                emitAND(di, block);      
                break;
            case ZYDIS_MNEMONIC_OR:       
                emitOR(di, block);       
                break;
            case ZYDIS_MNEMONIC_XOR:       
                emitXOR(di, block);      
                break;
            case ZYDIS_MNEMONIC_NOT:       
                emitNOT(di, block);      
                break;
            case ZYDIS_MNEMONIC_NEG:       
                emitNEG(di, block);      
                break;
            case ZYDIS_MNEMONIC_SHL:       
                emitSHL(di, block);      
                break;
            case ZYDIS_MNEMONIC_SHR:       
                emitSHR(di, block);      
                break;
            case ZYDIS_MNEMONIC_SAR:       
                emitSAR(di, block);      
                break;

            // compare: flags only, result discarded 
            case ZYDIS_MNEMONIC_CMP:       
                emitCMP(di, block);      
                break;
            case ZYDIS_MNEMONIC_TEST:      
                emitTEST(di, block);     
                break;

            // conditions
            // Jcc steers control flow; SETcc and CMOVcc consume the same
            // condition machinery to produce a value instead.
            case ZYDIS_MNEMONIC_JZ:
            case ZYDIS_MNEMONIC_JNZ:
            case ZYDIS_MNEMONIC_JS:
            case ZYDIS_MNEMONIC_JNS:
            case ZYDIS_MNEMONIC_JO:
            case ZYDIS_MNEMONIC_JNO:
            case ZYDIS_MNEMONIC_JB:
            case ZYDIS_MNEMONIC_JNB:
            case ZYDIS_MNEMONIC_JBE:
            case ZYDIS_MNEMONIC_JNBE:
            case ZYDIS_MNEMONIC_JL:
            case ZYDIS_MNEMONIC_JNL:
            case ZYDIS_MNEMONIC_JLE:
            case ZYDIS_MNEMONIC_JNLE:      
                emitJcc(di, block);      
                break;
            case ZYDIS_MNEMONIC_SETZ:
            case ZYDIS_MNEMONIC_SETNZ:
            case ZYDIS_MNEMONIC_SETS:
            case ZYDIS_MNEMONIC_SETNS:
            case ZYDIS_MNEMONIC_SETO:
            case ZYDIS_MNEMONIC_SETNO:
            case ZYDIS_MNEMONIC_SETB:
            case ZYDIS_MNEMONIC_SETNB:
            case ZYDIS_MNEMONIC_SETBE:
            case ZYDIS_MNEMONIC_SETNBE:
            case ZYDIS_MNEMONIC_SETL:
            case ZYDIS_MNEMONIC_SETNL:
            case ZYDIS_MNEMONIC_SETLE:
            case ZYDIS_MNEMONIC_SETNLE:    
                emitSETcc(di, block);    
                break;
            case ZYDIS_MNEMONIC_CMOVZ:
            case ZYDIS_MNEMONIC_CMOVNZ:
            case ZYDIS_MNEMONIC_CMOVS:
            case ZYDIS_MNEMONIC_CMOVNS:
            case ZYDIS_MNEMONIC_CMOVO:
            case ZYDIS_MNEMONIC_CMOVNO:
            case ZYDIS_MNEMONIC_CMOVB:
            case ZYDIS_MNEMONIC_CMOVNB:
            case ZYDIS_MNEMONIC_CMOVBE:
            case ZYDIS_MNEMONIC_CMOVNBE:
            case ZYDIS_MNEMONIC_CMOVL:
            case ZYDIS_MNEMONIC_CMOVNL:
            case ZYDIS_MNEMONIC_CMOVLE:
            case ZYDIS_MNEMONIC_CMOVNLE:   
                emitCMOVcc(di, block);   
                break;

            // control transfer 
            case ZYDIS_MNEMONIC_JMP:       
                emitJMP(di, block);      
                break;
            case ZYDIS_MNEMONIC_CALL:      
                emitCALL(di, block);     
                break;
            case ZYDIS_MNEMONIC_RET:       
                emitRET(di, block);      
                break;
            case ZYDIS_MNEMONIC_SYSCALL:   
                emitSYSCALL(di, block);  
                break;

            //stack
            case ZYDIS_MNEMONIC_PUSH:      
                emitPUSH(di, block);     
                break;
            case ZYDIS_MNEMONIC_POP:       
                emitPOP(di, block);      
                break;
            case ZYDIS_MNEMONIC_LEAVE:     
                emitLEAVE(di, block);    
                break;

            ///TODO everything not yet implemented 
            // SSE/AVX, string ops (MOVS/STOS/SCAS), bit manipulation
            // (BSF/BSR/POPCNT), atomics, x87 — all land here.
            //
            // A source-tagged NOP is deliberately better than throwing:
            // the function still lifts, the printed IR shows exactly which
            // address was skipped, and grepping the output for `nop  ; 0x`
            // gives a work list. Flag state is invalidated because an
            // unmodelled instruction may well have written flags.
            default: {
                IRInst nop = IRInst::makeNop();
                nop.setSourceAddr(di.va);
                block.pushInst(std::move(nop));
                m_flagState.invalidate();
                break;
            }
        }

    }
}
