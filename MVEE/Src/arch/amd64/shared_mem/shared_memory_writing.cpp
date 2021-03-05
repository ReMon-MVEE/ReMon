//
// Created by jonas on 15.04.20.
//


#include <stdint.h>
#include <sys/user.h>
#include <MVEE.h>
#include <MVEE_interaction.h>
#include <MVEE_monitor.h>
#include <arch/amd64/shared_mem/shared_mem_reg_access.h>
#include <sys/mman.h>
#include "shared_memory_emulation.h"


// =====================================================================================================================
//      byte emulators
// =====================================================================================================================

int         instruction_intent_emulation::block_write               BYTE_EMULATOR_ARGUMENTS
{
    // return that there has been an illegal access attempt
    return -1;
}

/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x00)


/* Valid in first round */
BYTE_WRITE_IMPL(0x01)
{
    // add r/m(16, 32, 64), r(16, 32, 64)
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // lock forced here
        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            auto* typed_source = (uint64_t*)source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint64_t, "lock add QWORD PTR [%[dst]], %[src];")
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_source = (uint16_t*)source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint16_t, "lock add WORD PTR [%[dst]], %[src];")
        }
        // 32-bit
        else
        {
            auto* typed_source = (uint32_t*)source;

            NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint32_t, "lock add DWORD PTR [%[dst]], %[src];")
        }

        // no need to do any write backs here, only general purpose registers changed
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x02)


/* Valid in first round */
// BYTE_WRITE_IMPL(0x03)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x04)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x05)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x06)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x07)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x08)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x09)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x0a)


/* Valid in first round */
// BYTE_WRITE_IMPL(0x0b)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x0c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x0d)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x0e)


/* Not implemented - blocked in first round */
// BYTE_WRITE_IMPL(0x0f)


/* Valid in second round */
// BYTE_WRITE_IMPL(0x10)


/* Valid in second round */
BYTE_WRITE_IMPL(0x11)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // only allow no prefix version for now
        if (PREFIXES_GRP_ONE_PRESENT(instruction) || PREFIXES_GRP_THREE_PRESENT(instruction))
            return -1;

        // movups xmm/m128, xmm
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(16)
        LOAD_REG_CODE(source, xmm_lookup)

        // perform operation
        XMM_TO_SHARED_WRITE(
                __asm__
                (
                        ".intel_syntax noprefix;"
                        "movups xmm0, XMMWORD PTR [rdx];"
                        "movups XMMWORD PTR [rax], xmm0;"
                        ".att_syntax;"
                        :
                        : [dst] "a" (destination), [src] "d" (source)
                        : "xmm0", "cc"
                )
        )

        // no write back needed
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x12)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x13)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x14)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x15)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x16)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x17)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x18)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x19)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x1a)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x1b)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x1c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x1d)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x1e)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x1f)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x20)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x21)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x22)


/* Valid in first round */
// BYTE_WRITE_IMPL(0x23)

/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x24)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x25)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x26)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x27)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x28)


/* Valid in second round */
BYTE_WRITE_IMPL(0x29)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // sub Ev, Gv
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        int access_size = GET_INSTRUCTION_ACCESS_SIZE;
        LOAD_RM_CODE_NO_DEFINE(access_size)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit
        if (access_size == 8)
        {
            auto* typed_source = (uint64_t*) source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint64_t, "lock sub QWORD PTR [%[dst]], %[src];")
        }
        // 16-bit
        else if (access_size == 2)
        {
            auto* typed_source = (uint16_t*) source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint16_t, "lock sub WORD PTR [%[dst]], %[src];")
        }
        // 32-bit
        else
        {
            auto* typed_source = (uint32_t*) source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint32_t, "lock sub DWORD PTR [%[dst]], %[src];")
        }

        // save content of flags register to repliaction buffer
        // registers will be written back on resume.
        RETURN_ADVANCE
    }
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // size and register type is the same, regardless of prefix
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(16)
        LOAD_REG_CODE(source, xmm_lookup)

        // movapd xmm/m128, xmm
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            XMM_TO_SHARED_WRITE(
                    __asm__(
                            ".intel_syntax noprefix;"
                            "movups xmm0, XMMWORD PTR [rdx];"
                            "movapd XMMWORD PTR [rax], xmm0;"
                            ".att_syntax"
                            :
                            : [dst] "a" (destination), [src] "d" (source)
                            : "xmm0"
                    )
            )
        }
        // movaps xmm/m128, xmm
        else
        {
            XMM_TO_SHARED_WRITE(
                    __asm__(
                            ".intel_syntax noprefix;"
                            "movups xmm0, XMMWORD PTR [rdx];"
                            "movaps XMMWORD PTR [rax], xmm0;"
                            ".att_syntax"
                            :
                            : [dst] "a" (destination), [src] "d" (source)
                            : "xmm0"
                    )
            )
        }

        // source is register, no write back needed
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Valid in second round */
// BYTE_WRITE_IMPL(0x2a)


/* Valid in first and second round */
BYTE_WRITE_IMPL(0x2b)
{
    // movntps m128, xmm
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(16)
        LOAD_REG_CODE(source, xmm_lookup)

        XMM_TO_SHARED_WRITE(
                __asm__
                (
                        ".intel_syntax noprefix;"
                        "movdqu xmm0, XMMWORD PTR [rdx];"
                        "movntps XMMWORD PTR [rax], xmm0;"
                        ".att_syntax;"
                        :
                        : "a" (destination), "d" (source)
                        : "xmm0"
                )
        )

        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x2c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x2d)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x2e)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x2f)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x30)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x31)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x32)


/* Valid in first round */
// BYTE_WRITE_IMPL(0x33)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x34)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x35)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x36)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x37)


/* Valid in first round */
BYTE_WRITE_IMPL(0x38)
{
    // cmp Eb, Gb
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(1)
        LOAD_REG_CODE(source, general_purpose_lookup)
        auto* typed_source = (uint8_t*) source;
        NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint8_t, "cmp BYTE PTR [%[dst]], %[src];")

        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}

/* Valid in first round */
BYTE_WRITE_IMPL(0x39)
{
    // cmp Ev, Gv
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            LOAD_RM_CODE_NO_DEFINE(8)
            auto typed_source = (uint64_t*) source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint64_t, "cmp QWORD PTR [%[dst]], %[src];")
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            LOAD_RM_CODE_NO_DEFINE(2)
            auto typed_source = (uint16_t*) source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint16_t, "cmp WORD PTR [%[dst]], %[src];")
        }
        // 32-bit
        else
        {
            LOAD_RM_CODE_NO_DEFINE(4)
            auto typed_source = (uint32_t*) source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint32_t, "cmp DWORD PTR [%[dst]], %[src];")
        }

        // registers will be written back anyway
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x3a)


/* Valid in first round */
// BYTE_WRITE_IMPL(0x3b)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x3c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x3d)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x3e)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x3f)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x40)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x41)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x42)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x43)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x44)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x45)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x46)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x47)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x48)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x49)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x4a)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x4b)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x4c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x4d)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x4e)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x4f)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x50)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x51)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x52)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x53)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x54)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x55)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x56)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x57)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x58)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x59)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x5a)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x5b)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x5c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x5d)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x5e)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x5f)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x60)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x61)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x62)


/* Valid in first round */
// BYTE_WRITE_IMPL(0x63)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x64)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x65)


/* Prefix, blocked */
// BYTE_WRITE_IMPL(0x66)


/* Prefix, blocked */
// BYTE_WRITE_IMPL(0x67)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x68)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x69)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x6a)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x6b)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x6c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x6d)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x6e)


/* Valid in second round */
// BYTE_WRITE_IMPL(0x6f)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x70)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x71)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x72)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x73)


/* Valid in fist round */
// BYTE_WRITE_IMPL(0x74)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x75)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x76)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x77)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x78)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x79)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x7a)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x7b)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x7c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x7d)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x7e)


/* Valid in second round */
BYTE_WRITE_IMPL(0x7f)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // movdqu xmm/m128, xmm if f3 prefix is present
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE)
        {
            DEFINE_FPREGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE_NO_DEFINE(16)
            LOAD_REG_CODE(source, xmm_lookup)

            XMM_TO_SHARED_WRITE(
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "movdqu xmm0, XMMWORD PTR [rdx];"
                            "movdqu XMMWORD PTR [rax], xmm0;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source)
                            : "xmm0"
                    )
            )
        }
        // movdqa xmm/m128, xmm if f3 prefix is not present
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            DEFINE_FPREGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE_NO_DEFINE(16)
            LOAD_REG_CODE(source, xmm_lookup)

            XMM_TO_SHARED_WRITE(
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "movdqu xmm0, XMMWORD PTR [rdx];"
                            "movdqa XMMWORD PTR [rax], xmm0;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source)
                            : "xmm0"
                    )
            )
        }
        // movq m64, mm
        else
        {
            DEFINE_FPREGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE_NO_DEFINE(8)
            LOAD_REG_CODE(source, mm_lookup)
            auto* typed_source = (uint64_t*) source;

            NORMAL_TO_SHARED_WRITE(uint64_t,
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "movq mm0, QWORD PTR [rdx];"
                            "movq QWORD PTR [rax], mm0;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (typed_destination), [src] "d" (typed_source)
                            : "mm0"
                    )
            )
        }

        // no write back needed here
        RETURN_ADVANCE
    }

    // illegal access otherwise
    return -1;
}


/* Valid in first round */
BYTE_WRITE_IMPL(0x80)
{
    // Immediate Grp 1 Eb, Ib
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(1)
        LOAD_IMM(source)

        // replay no spoofing needed
        auto* typed_source = (uint8_t*)source;

        // ModR/M reg field used as opcode extension
        switch (GET_REG_CODE(modrm))
        {
            case 0b000u: // ADD - not yet implemented
                return -1;
            case 0b001u: // OR  - not yet implemented
            {
                // perform operation, note that the flags register is also changed here
                NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint8_t, "lock or BYTE PTR [%[dst]], %[src];")

                break;
            }
            case 0b010u: // ADC - not yet implemented
            case 0b011u: // SBB - not yet implemented
                return -1;
            case 0b100u: // AND - and r/m8, imm8
            {
                // perform operation, note that the flags register is also changed here
                NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint8_t, "lock and BYTE PTR [%[dst]], %[src];")
                break;
            }
            case 0b101u: // SUB - not yet implemented
            case 0b110u: // XOR - not yet implemented
            case 0b111u: // CMP - CMP r/m8, imm8
            {
                // perform operation, note that the flags register is also changed here
                NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint8_t, "cmp BYTE PTR [%[dst]], %[src];")
                break;
            }
            default:
                return -1;
        }

        // registers will be written back with rip
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_WRITE_IMPL(0x81)
{
    // immediate grp 1 Ev, Iz
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_IMM(source)

        switch (GET_REG_CODE(modrm))
        {
            case 0b000u: // ADD - not yet implemented
            case 0b001u: // OR  - not yet implemented
            case 0b010u: // ADC - not yet implemented
            case 0b011u: // SBB - not yet implemented
                return -1;
            case 0b100u: // AND - and r/m(16,32,64), imm(16,32,32)
            {
                // perform operation, note that the flags register is also changed here
                // and r/m64, imm32
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    uint64_t source_extended = (int64_t)*(int32_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint64_t, "lock and QWORD PTR [%[dst]], %[src];")
                }
                // and r/m16, imm16
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    auto* typed_source = (uint16_t*)source;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint16_t, "lock and WORD PTR [%[dst]], %[src];")
                }
                // and r/m32, imm32
                else
                {
                    auto* typed_source = (uint32_t*)source;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint32_t, "lock and DWORD PTR [%[dst]], %[src];")
                }

                break;
            }
            case 0b101u: // SUB - not yet implemented
            case 0b110u: // XOR - not yet implemented
                return -1;
            case 0b111u: // CMP - CMP r/m, imm
            {
                // cmp r/m64, imm32
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    uint64_t source_extended = (int64_t)*(int32_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint64_t, "cmp QWORD PTR [%[dst]], %[src];")
                }
                // cmp r/m16, imm16
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    auto* typed_source = (uint16_t*)source;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint16_t, "cmp WORD PTR [%[dst]], %[src];")
                }
                // cmp r/m32, imm32
                else
                {
                    auto* typed_source = (uint32_t*)source;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint32_t,"cmp DWORD PTR [%[dst]], %[src];")
                }

                break;
            }

            default:
                return -1;
        }

        // general purpose registers will be written back by default
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x82)


/* Valid in first round */
BYTE_WRITE_IMPL(0x83)
{
    // grp 1 r/m(16,32,64), imm8
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_IMM(source)

        switch (GET_REG_CODE((unsigned ) instruction[instruction.effective_opcode_index + 1]))
        {
            case 0b000u: // ADD - add r/m(16,32,64), imm8
            {
                // perform operation, note that the flags register is also changed here
                // add r/m64, imm8
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    uint64_t source_extended = (int64_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint64_t, "lock add QWORD PTR [%[dst]], %[src];")
                }
                // add r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t source_extended = (int16_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint16_t, "lock add WORD PTR [%[dst]], %[src];")
                }
                // add r/m32, imm8
                else
                {
                    uint32_t source_extended = (int32_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint32_t, "lock add DWORD PTR [%[dst]], %[src];")
                }

                break;
            }
            case 0b001u: // OR  - not yet implemented
            {
                // perform operation, note that the flags register is also changed here
                // or r/m64, imm8
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    uint64_t source_extended = (int64_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint64_t, "lock or QWORD PTR [%[dst]], %[src];")
                }
                // or r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t source_extended = (int16_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint16_t, "lock or WORD PTR [%[dst]], %[src];")
                }
                // or r/m32, imm8
                else
                {
                    uint32_t source_extended = (int32_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint32_t, "lock or DWORD PTR [%[dst]], %[src];")
                }

                break;
            }
            case 0b010u: // ADC - not yet implemented
            case 0b011u: // SBB - not yet implemented
            case 0b100u: // AND - not yet implemented
                return -1;
            case 0b101u: // SUB - not yet implemented
            {
                // perform operation, note that the flags register is also changed here
                // sub r/m64, imm8
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    uint64_t source_extended = (int64_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint64_t, "lock sub QWORD PTR [%[dst]], %[src];")
                }
                // sub r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t source_extended = (int16_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint16_t, "lock sub WORD PTR [%[dst]], %[src];")
                }
                // sub r/m32, imm8
                else
                {
                    uint32_t source_extended = (int32_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_WRITE(uint32_t, "lock sub DWORD PTR [%[dst]], %[src];")
                }

                break;
            }
            case 0b110u: // XOR - not yet implemented
                return -1;
            case 0b111u: // CMP - cmp r/m(16,32,64), imm8
            {
                // perform operation, note that the flags register is also changed here
                // cmp r/m64, imm8
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    uint64_t source_extended = (int64_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint64_t, "cmp QWORD PTR [%[dst]], %[src];")
                }
                // cmp r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t source_extended = (int16_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint16_t, "cmp WORD PTR [%[dst]], %[src];")
                }
                // cmp r/m32, imm8
                else
                {
                    uint32_t source_extended = (int32_t)*(int8_t*)source;
                    auto* typed_source = &source_extended;
                    NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint32_t, "cmp DWORD PTR [%[dst]], %[src];")
                }

                break;
            }
            default:
                return -1;
        }

        // general purpose registers will be written back by default
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x84)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x85)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x86)


/* Valid in first round */
#define EXCHANGE_TO_SHARED_WRITE(__cast)                                                                               \
LOAD_RM_CODE_NO_DEFINE(sizeof(__cast))                                                                                 \
auto* typed_source = (__cast*)source;                                                                                  \
__cast* typed_destination;                                                                                             \
                                                                                                                       \
void* buffer = nullptr;                                                                                                \
unsigned long long size;                                                                                               \
int result = relevant_monitor.buffer.obtain_last_buffer(variant->variant_num, (void**) &buffer, size);                 \
if (result < 0)                                                                                                        \
    return result;                                                                                                     \
if (size != 3 * sizeof(__cast))                                                                                        \
    return -1;                                                                                                         \
                                                                                                                       \
if (!variant->variant_num)                                                                                             \
{                                                                                                                      \
    typed_destination = (__cast*)((unsigned long long) mapping_info->monitor_base + offset);                           \
    __cast orig_source = *typed_source;                                                                                \
    __atomic_exchange(typed_destination, typed_source, typed_source, __ATOMIC_ACQ_REL);                                \
    *(__cast*)buffer = *typed_source;                                                                                  \
    __atomic_exchange((__cast*)(mapping_info->variant_shadows[0].monitor_base + offset), &orig_source, &orig_source,   \
            __ATOMIC_ACQ_REL);                                                                                         \
    *((__cast*)buffer + 2) = orig_source;                                                                              \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    typed_destination = (__cast*)(mapping_info->variant_shadows[variant->variant_num].monitor_base + offset);          \
    __atomic_exchange(typed_destination, typed_source, typed_source, __ATOMIC_ACQ_REL);                                \
    if (*((__cast*)buffer + 2) != *(__cast*)buffer)                                                                    \
        *typed_source = *(__cast*)buffer;                                                                              \
}

BYTE_WRITE_IMPL(0x87)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            EXCHANGE_TO_SHARED_WRITE(uint64_t)
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            EXCHANGE_TO_SHARED_WRITE(uint16_t)
        }
        // 32-bit
        else
        {
            EXCHANGE_TO_SHARED_WRITE(uint32_t)
        }

        // no need to write back registers here
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_WRITE_IMPL(0x88)
{
    // mov r/m8, r8
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(1)
        LOAD_REG_CODE_BYTE(source, general_purpose_lookup)

        // special case that uses higher order lower byte, for example ah
        if (!PREFIXES_REX_PRESENT(instruction) && GET_REG_CODE((unsigned) modrm) & 0b100u)
            source = (void*) ((unsigned long long) source + 1);

        auto* typed_source = (uint8_t*)source;

        // execute operation
        NORMAL_TO_SHARED_WRITE(uint8_t , *typed_destination = *typed_source);

        // we don't have to write anything back here, destination shouldn't be able to be a register
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_WRITE_IMPL(0x89)
{
    // move Ev, Gv
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit implementation
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            auto* typed_source = (uint64_t*)source;
            NORMAL_TO_SHARED_WRITE(uint64_t, *typed_destination = *typed_source)
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_source = (uint16_t*)source;
            NORMAL_TO_SHARED_WRITE(uint16_t, *typed_destination = *typed_source)
        }
        // default 32-bit
        else
        {
            auto* typed_source = (uint32_t*)source;
            NORMAL_TO_SHARED_WRITE(uint32_t, *typed_destination = *typed_source)
        }

        // no need to write back any registers
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
// BYTE_WRITE_IMPL(0x8a)


/* Valid in first round */
// BYTE_WRITE_IMPL(0x8b)


/* Not implemented - blocked in first round */
// BYTE_WRITE_IMPL(0x8c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x8d)


/* Not implemented - blocked in first round */
// BYTE_WRITE_IMPL(0x8e)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x8f)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x90)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x91)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x92)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x93)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x94)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x95)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x96)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x97)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x98)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x99)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x9a)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x9b)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x9c)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x9d)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x9e)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0x9f)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xa0)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xa1)


/* Valid in second round */
// BYTE_WRITE_IMPL(0xa2)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xa3)


/* Not implemented - blocked */
BYTE_WRITE_IMPL(0xa4)
{
    // movsb
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // gonna be using general purpose registers
        MOVS_STRUCT
        GET_LAST_BUFFER_RAW(temp_t)

        if (!buffer->dst_info)
        {
            warnf(" > writing to non-existing shared memory destination\n");
            return -1;
        }

        if (!variant->variant_num)
            memcpy(buffer->dst_info->monitor_base + buffer->offset, buffer->buffer, buffer->size);
        memcpy(buffer->dst_info->variant_shadows[variant->variant_num].monitor_base + buffer->offset,
               buffer->buffer, buffer->size);

        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xa5)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xa6)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xa7)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xa8)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xa9)


#define STOS_WRITE(__cast, __core)                                                                                     \
STOS_STRUCT(__cast)                                                                                                    \
GET_LAST_BUFFER_RAW(temp_t)                                                                                            \
OBTAIN_SHARED_MAPPING_INFO(buffer->count * sizeof(__cast))                                                             \
if (!variant->variant_num)                                                                                             \
{                                                                                                                      \
    __asm__                                                                                                            \
    (                                                                                                                  \
            ".intel_syntax noprefix;"                                                                                  \
            __core                                                                                                     \
            ".att_syntax;"                                                                                             \
            :                                                                                                          \
            : "a" (*(__cast*) source), "c" (buffer->count),                                                            \
                "D" (mapping_info->monitor_base + offset)                                                              \
            : "memory"                                                                                                 \
    );                                                                                                                 \
}                                                                                                                      \
__asm__                                                                                                                \
(                                                                                                                      \
        ".intel_syntax noprefix;"                                                                                      \
        __core                                                                                                         \
        ".att_syntax;"                                                                                                 \
        :                                                                                                              \
        : "a" (*(__cast*) source), "c" (buffer->count),                                                                \
            "D" (mapping_info->variant_shadows[variant->variant_num].monitor_base + offset)                            \
        : "memory"                                                                                                     \
);                                                                                                                     \
                                                                                                                       \
if (buffer->flags & (0b1u << 10u))                                                                                     \
    regs_struct->rdi -= buffer->count * sizeof(__cast);                                                                \
else                                                                                                                   \
    regs_struct->rdi += buffer->count * sizeof(__cast);

/* Valid in first round */
BYTE_WRITE_IMPL(0xaa)
{
    // we're in need of rax as source
    DEFINE_REGS_STRUCT
    void* source = shared_mem_register_access::ACCESS_GENERAL_NAME(rax)(regs_struct);
    STOS_WRITE(uint8_t, )
    RETURN_ADVANCE
}


/* Valid in first round */
BYTE_WRITE_IMPL(0xab)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && (PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE ||
                PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE))
            return -1;

        // we're in need of rax as source
        DEFINE_REGS_STRUCT
        void* source = shared_mem_register_access::ACCESS_GENERAL_NAME(rax)(regs_struct);

        // stos m64
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            STOS_WRITE(uint64_t, "rep stosq;")
        }
        // stos m16
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            STOS_WRITE(uint16_t, "rep stosw;")
        }
        // stos m32
        else
        {
            STOS_WRITE(uint32_t, "rep stosd;")
        }

        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xac)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xad)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xae)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xaf)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xb0)


#define CMPXCHG_WRITE(__cast, __core)                                                                                  \
LOAD_RM_CODE_NO_DEFINE(sizeof(__cast))                                                                                 \
CMPXCHG_STRUCT(__cast)                                                                                                 \
GET_LAST_BUFFER_RAW(temp_t)                                                                                            \
                                                                                                                       \
__cast* typed_destination;                                                                                             \
auto* typed_source = (__cast*)source;                                                                                  \
                                                                                                                       \
if (!variant->variant_num)                                                                                             \
{                                                                                                                      \
    typed_destination = (__cast*)(mapping_info->monitor_base + offset);                                                \
    __asm__                                                                                                            \
    (                                                                                                                  \
            ".intel_syntax noprefix;"                                                                                  \
            "push %[flags];"                                                                                           \
            "popf;"                                                                                                    \
            __core                                                                                                     \
            "pushf;"                                                                                                   \
            "pop %[flags];"                                                                                            \
            ".att_syntax;"                                                                                             \
            : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination), "+a" (regs_struct->rax)                   \
            : [dst] "r" (typed_destination), [src] "r" (*typed_source)                                                 \
            : "cc"                                                                                                     \
    );                                                                                                                 \
    buffer->replaced_rax = regs_struct->rax;                                                                           \
    buffer->flags        = regs_struct->eflags;                                                                        \
                                                                                                                       \
    if (buffer->replaced_rax == buffer->original_rax)                                                                  \
        buffer->leader_rax = buffer->original_rax;                                                                     \
    else                                                                                                               \
        buffer->leader_rax = *typed_source;                                                                            \
    __atomic_exchange((__cast*)(mapping_info->variant_shadows[variant->variant_num].monitor_base + offset),            \
            &buffer->leader_rax, &buffer->leader_rax, __ATOMIC_ACQ_REL);                                               \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    typed_destination = (__cast*)(mapping_info->variant_shadows[variant->variant_num].monitor_base + offset);          \
    if (buffer->replaced_rax == buffer->original_rax)                                                                  \
        *typed_destination = *typed_source;                                                                            \
    else if (buffer->leader_rax == buffer->replaced_rax)                                                               \
        regs_struct->rax = *typed_destination;                                                                         \
    else                                                                                                               \
        regs_struct->rax = buffer->replaced_rax;                                                                       \
    regs_struct->eflags = buffer->flags;                                                                               \
}
/* Valid in second round */
BYTE_WRITE_IMPL(0xb1)
{
    // cmpxchg Ev, Gv
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // affects flags as well
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            CMPXCHG_WRITE(uint64_t, "lock cmpxchg QWORD PTR [%[dst]], %[src];")
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            CMPXCHG_WRITE(uint16_t, "lock cmpxchg WORD PTR [%[dst]], %[src];")
        }
        // 32-bit
        else
        {
            CMPXCHG_WRITE(uint32_t, "lock cmpxchg DWORD PTR [%[dst]], %[src];")
        }

        // general purpose registers are written back with rip by default
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xb2)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xb3)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xb4)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xb5)


/* Valid in second round */
// BYTE_WRITE_IMPL(0xb6)


/* Valid in second round */
// BYTE_WRITE_IMPL(0xb7)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xb8)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xb9)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xba)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xbb)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xbc)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xbd)


/* Valid in second round */
// BYTE_WRITE_IMPL(0xbe)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xbf)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xc0)


#define XADD_WRITE(__cast, __core)                                                                                     \
XADD_STRUCT(__cast)                                                                                                    \
GET_LAST_BUFFER_RAW(temp_t)                                                                                            \
__cast* typed_destination;                                                                                             \
auto* typed_source = (__cast*)source;                                                                                  \
                                                                                                                       \
if (!variant->variant_num)                                                                                              \
{                                                                                                                      \
    buffer->leader_destination = *typed_source;                                                                        \
    __atomic_exchange((__cast*)(mapping_info->variant_shadows[variant->variant_num].monitor_base + offset),            \
            &buffer->leader_destination, &buffer->leader_destination, __ATOMIC_ACQ_REL);                               \
    typed_destination = (__cast*)(mapping_info->monitor_base + offset);                                                \
    __asm__                                                                                                            \
    (                                                                                                                  \
            ".intel_syntax noprefix;"                                                                                  \
            "push %[flags];"                                                                                           \
            "popf;"                                                                                                    \
            __core                                                                                                     \
            "pushf;"                                                                                                   \
            "pop %[flags];"                                                                                            \
            ".att_syntax;"                                                                                             \
            : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination), [src] "+r" (*typed_source)                \
            : [dst] "r" (typed_destination)                                                                            \
            : "cc"                                                                                                     \
    );                                                                                                                 \
    buffer->flags                = regs_struct->eflags;                                                                \
    buffer->original_destination = *typed_source;                                                                      \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    __atomic_exchange((__cast*)(mapping_info->variant_shadows[variant->variant_num].monitor_base + offset),            \
            typed_source, typed_source, __ATOMIC_ACQ_REL);                                                             \
    regs_struct->eflags = buffer->flags;                                                                               \
    if (buffer->original_destination != buffer->leader_destination)                                                    \
        *typed_source = buffer->original_destination;                                                                  \
}
/* Valid in second round */
BYTE_WRITE_IMPL(0xc1)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // xadd Ev, Gv
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            XADD_WRITE(uint64_t , "lock xadd QWORD PTR [%[dst]], %[src];")
        }
        // 16-bit size
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            XADD_WRITE(uint16_t , "lock xadd WORD PTR [%[dst]], %[src];")
        }
        // 32-bit size
        else
        {
            XADD_WRITE(uint32_t , "lock xadd DWORD PTR [%[dst]], %[src];")
        }

        // registers will be written back in a bit
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xc2)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xc3)


/* valid in first round */
// BYTE_WRITE_IMPL(0xc4)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xc5)


/* Valid in first round */
BYTE_WRITE_IMPL(0xc6)
{
    // mov r/m8, imm8
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_MODRM
        LOAD_IMM(source)
        LOAD_RM_CODE_NO_DEFINE(1)

        // perform operation
        auto* typed_source = (uint8_t*)source;
        IMM_TO_SHARED_WRITE(uint8_t, *typed_destination = *typed_source);

        // no write back needed
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_WRITE_IMPL(0xc7)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)
        // small test
        if (GET_REG_CODE((unsigned) modrm) != 0b000u)
            return -1;
        LOAD_IMM(source)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            uint64_t source_converted = *(int32_t*)source;
            uint64_t* typed_source = &source_converted;
            IMM_TO_SHARED_WRITE(uint64_t, *typed_destination = *typed_source)
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_source = (uint16_t*)source;
            IMM_TO_SHARED_WRITE(uint16_t, *typed_destination = *typed_source);
        }
        // 32-bit
        else
        {
            auto* typed_source = (uint32_t*)source;
            IMM_TO_SHARED_WRITE(uint32_t, *typed_destination = *typed_source);
        }

        // no register write back needed
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xc8)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xc9)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xca)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xcb)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xcc)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xcd)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xce)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xcf)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd0)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd1)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd2)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd3)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd4)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd5)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd6)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd7)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd8)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xd9)


/* Valid in second round */
// BYTE_WRITE_IMPL(0xda)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xdb)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xdc)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xdd)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xde)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xdf)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xe0)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xe1)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xe2)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xe3)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xe4)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xe5)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xe6)


/* Valid in second round */
BYTE_WRITE_IMPL(0xe7)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        DEFINE_MODRM

        // movntdq m128, xmm
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            DEFINE_FPREGS_STRUCT
            LOAD_RM_CODE_NO_DEFINE(16)
            LOAD_REG_CODE(source, xmm_lookup)

            XMM_TO_SHARED_WRITE(
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "movdqu xmm0, XMMWORD PTR [rdx];"
                            "movntdq XMMWORD PTR [rax], xmm0;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source)
                            : "xmm0", "memory"
                    )
            )
        }
        // illegal access
        else if (PREFIXES_GRP_ONE_PRESENT(instruction) && (PREFIXES_GRP_TWO(instruction) == REPZ_PREFIX_CODE ||
                PREFIXES_GRP_TWO(instruction) == REPNZ_PREFIX_CODE))
            return -1;
        // movntq m64, mm
        else
        {
            DEFINE_FPREGS_STRUCT
            LOAD_RM_CODE_NO_DEFINE(8)
            LOAD_REG_CODE(source, mm_lookup)
            auto typed_source = (uint64_t*) source;

            NORMAL_TO_SHARED_WRITE(uint64_t,
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "movq  mm0, QWORD PTR [rdx];"
                            "movntq QWORD PTR [rax], mm0;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (typed_destination), [src] "d" (typed_source)
                            : "mm0", "memory"
                    )
            )
        }

        // no registers need to be written back
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xe8)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xe9)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xea)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xeb)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xec)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xed)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xee)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xef)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xf0)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xf1)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xf2)


/* Implemented - allowed in round 1 */
// BYTE_WRITE_IMPL(0xf3)

/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xf4)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xf5)


/* Valid in first round */
BYTE_WRITE_IMPL(0xf6)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_B(instruction))
        {
            DEFINE_REGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE_NO_DEFINE(1)

            // ModR/M reg field used as opcode extension
            switch (GET_REG_CODE(modrm))
            {
                case 0b000u: // TEST - test r/m8, imm8
                case 0b001u: // TEST - test r/m8, imm8
                    {
                        LOAD_IMM(source)
                        auto* typed_source = (uint8_t*)source;
                        NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_WRITE(uint8_t,
                                "test BYTE PTR [%[dst]], %[src];");
                        break;
                    }
                case 0b010u: // NOT - not yet implemented
                case 0b011u: // NEG - not yet implemented
                case 0b100u: // MUL - not yet implemented
                case 0b101u: // IMUL - not yet implemented
                case 0b110u: // DIV - not yet implemented
                case 0b111u: // IDIV - not yet implemented
                default:
                    return -1;
            }

            RETURN_ADVANCE
        }
        // illegal otherwise
        return -1;
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xf7)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xf8)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xf9)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xfa)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xfb)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xfc)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xfd)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xfe)


/* Not implemented - blocked */
// BYTE_WRITE_IMPL(0xff)
