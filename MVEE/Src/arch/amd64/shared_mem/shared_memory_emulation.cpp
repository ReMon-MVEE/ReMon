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

int         instruction_intent_emulation::block_emulator            BYTE_EMULATOR_ARGUMENTS
{
    // return that there has been an illegal access attempt
    return -1;
}

/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x00)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x01)
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
            NORMAL_TO_SHARED_EMULATE(uint64_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in add m64, reg64\n"))
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_source = (uint16_t*)source;
            NORMAL_TO_SHARED_EMULATE(uint16_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in add m16, reg16\n")
            )
        }
        // 32-bit
        else
        {
            auto* typed_source = (uint32_t*)source;
            NORMAL_TO_SHARED_EMULATE(uint32_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in add m32, reg32\n"))
        }

        // do NOT advance the buffer here
        RETURN_WRITE(0x01)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x02)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x03)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // add Gv, Ev
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            uint64_t* typed_destination = (uint64_t*)destination;
            NORMAL_FROM_SHARED(uint64_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "add QWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            uint16_t* typed_destination = (uint16_t*)destination;
            NORMAL_FROM_SHARED(uint16_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "add WORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 32-bit
        else
        {
            uint32_t* typed_destination = (uint32_t*)destination;
            NORMAL_FROM_SHARED(uint32_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "add DWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );

            *(typed_destination + 1) = 0;
        }

        // registers will be written back anyway
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x04)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x05)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x06)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x07)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x08)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x09)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x0a)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x0b)
{
    // or Gv, Ev
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            auto* typed_destination = (uint64_t*) destination;
            LOAD_RM_CODE_NO_DEFINE(sizeof(uint64_t))
            NORMAL_FROM_SHARED(uint64_t)

            __asm__(
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "or %[dst], QWORD PTR [%[src]];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), [dst] "+r" (*typed_destination), "+m" (*typed_source)
                    : [src] "r" (typed_source)
                    : "cc"
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_ONE_PRESENT(instruction))
        {
            auto* typed_destination = (uint16_t*) destination;
            LOAD_RM_CODE_NO_DEFINE(sizeof(uint16_t))
            NORMAL_FROM_SHARED(uint16_t)

            __asm__(
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "or %[dst], WORD PTR [%[src]];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), [dst] "+r" (*typed_destination), "+m" (*typed_source)
                    : [src] "r" (typed_source)
                    : "cc"
            );
        }
        // 32-bit
        else
        {
            auto* typed_destination = (uint32_t*) destination;
            LOAD_RM_CODE_NO_DEFINE(sizeof(uint32_t))
            NORMAL_FROM_SHARED(uint32_t)

            __asm__(
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "or %[dst], DWORD PTR [%[src]];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), [dst] "+r" (*typed_destination), "+m" (*typed_source)
                    : [src] "r" (typed_source)
                    : "cc"
            );
        }

        // registers will be written back anyway
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x0c)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x0d)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x0e)


/* Not implemented - blocked in first round */
// BYTE_EMULATOR_IMPL(0x0f)

/* Valid in second round */
BYTE_EMULATOR_IMPL(0x10)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
            return -1;

        // movups xmm, xmm/m128
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, xmm_lookup)


        // perform operation
        if (PREFIXES_GRP_ONE_PRESENT(instruction))
        {
            // we don't support this yet, one step at a time
            if (PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE)
                return -1;

            LOAD_RM_CODE_NO_DEFINE(8)
            NORMAL_FROM_SHARED(uint64_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movdqu xmm0, XMMWORD PTR [%[dst]];"
                    "movsd xmm0, QWORD PTR[%[src]];"
                    "movdqu XMMWORD PTR [%[dst]], xmm0;"
                    ".att_syntax;"
                    :
                    : [dst] "r" (destination), [src] "r" (typed_source)
                    : "xmm0"
            );
        }
        else
        {
            LOAD_RM_CODE_NO_DEFINE(16)
            XMM_FROM_SHARED
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movups xmm0, XMMWORD PTR [rdx];"
                    "movups XMMWORD PTR [rax], xmm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "xmm0"
            );
        }

        // writeback required
        if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
        {
            RETURN_ADVANCE
        }
    }

    // illegal otherwise
    return -1;
}


/* Valid in second round */
BYTE_EMULATOR_IMPL(0x11)
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
        XMM_TO_SHARED_EMULATE(WRITE_DIVERGENCE_XMM_PTR_CHECK(buffer, source,
                " > write divergence in movups m128, xmm\n"))

        // no write back needed
        RETURN_WRITE(0x11)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x12)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x13)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x14)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x15)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x16)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x17)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x18)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x19)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x1a)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x1b)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x1c)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x1d)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x1e)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x1f)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x20)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x21)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x22)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x23)
{
    // and Gv, Ev
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            auto* typed_destination = (uint64_t*)destination;
            LOAD_RM_CODE_NO_DEFINE(sizeof(uint64_t))
            NORMAL_FROM_SHARED(uint64_t)

            asm
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "and %[dst], QWORD PTR[%[src]];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), [dst] "+r" (*typed_destination)
                    : [src] "r" (typed_source)
                    : "cc"
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_ONE_PRESENT(instruction))
        {
            auto* typed_destination = (uint16_t*)destination;
            LOAD_RM_CODE_NO_DEFINE(sizeof(uint16_t))
            NORMAL_FROM_SHARED(uint16_t)

            asm
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "and %[dst], WORD PTR[%[src]];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), [dst] "+r" (*typed_destination)
                    : [src] "r" (typed_source)
                    : "cc"
            );
        }
        // 32-bit
        else
        {
            auto* typed_destination = (uint32_t*)destination;
            LOAD_RM_CODE_NO_DEFINE(sizeof(uint32_t))
            NORMAL_FROM_SHARED(uint32_t)

            asm
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "and %[dst], DWORD PTR[%[src]];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), [dst] "+r" (*typed_destination)
                    : [src] "r" (typed_source)
                    : "cc"
            );
        }

        // registers will be written back by default
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}

/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x24)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x25)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x26)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x27)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x28)


/* Valid in second round */
BYTE_EMULATOR_IMPL(0x29)
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
            uint64_t* typed_source = (uint64_t*) source;
            NORMAL_TO_SHARED_EMULATE(uint64_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in sub m64, reg64\n"))
        }
        // 16-bit
        else if (access_size == 2)
        {
            uint16_t* typed_source = (uint16_t*) source;
            NORMAL_TO_SHARED_EMULATE(uint16_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in sub m16, reg16\n"))
        }
        // 32-bit
        else
        {
            uint32_t* typed_source = (uint32_t*) source;
            NORMAL_TO_SHARED_EMULATE(uint32_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in sub m32, reg32\n"))
        }

        // do NOT advance buffer here
        RETURN_WRITE(0x29)
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
            XMM_TO_SHARED_EMULATE(WRITE_DIVERGENCE_XMM_EQUAL(buffer, source,
                    " > write divergence in movapd m128, xmm\n")
            )
        }
        // movaps xmm/m128, xmm
        else
        {
            XMM_TO_SHARED_EMULATE(WRITE_DIVERGENCE_XMM_EQUAL(__buffer, __source,
                    " > write divergence in movaps m128, xmm\n")
            )
        }

        // do NOT advance buffer here
        RETURN_WRITE(0x29)
    }

    // illegal otherwise
    return -1;
}


/* Valid in second round */
BYTE_EMULATOR_IMPL(0x2a)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // cvtsi2sd xmm, r32/m32
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE)
        {
            DEFINE_FPREGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE_NO_DEFINE(4)
            LOAD_REG_CODE(destination, xmm_lookup)

            NORMAL_FROM_SHARED(uint32_t)
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movdqu xmm1, XMMWORD PTR [%[dst]];"
                    "cvtsi2sd xmm1, DWORD PTR [%[src]];"
                    "movdqu XMMWORD PTR [%[dst]], xmm1;"
                    ".att_syntax;"
                    :
                    : [dst] "r" (destination), [src] "r" (typed_source)
                    : "xmm1"
            );

            // write back fpregs
            if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
            {
                RETURN_ADVANCE
            }
        }
    }

    // illegal otherwise
    return -1;
}


/* Valid in first and second round */
BYTE_EMULATOR_IMPL(0x2b)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // sub Gv, Ev
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            uint64_t* typed_destination = (uint64_t*)destination;
            NORMAL_FROM_SHARED(uint64_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "sub QWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            uint16_t* typed_destination = (uint16_t*)destination;
            NORMAL_FROM_SHARED(uint16_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "sub WORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 32-bit
        else
        {
            uint32_t* typed_destination = (uint32_t*)destination;
            NORMAL_FROM_SHARED(uint32_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "sub DWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );

            *(typed_destination + 1) = 0;
        }

        // registers will be written back anyway
        RETURN_ADVANCE
    }

    // movntps m128, xmm
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(16)
        LOAD_REG_CODE(source, xmm_lookup)

        XMM_TO_SHARED_EMULATE(WRITE_DIVERGENCE_XMM_EQUAL(__buffer, __source,
                " > write divergence in movntps m128, xmm\n"))

        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x2c)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x2d)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x2e)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x2f)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x30)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x31)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x32)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x33)
{
    // xor Gv, Ev
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            uint64_t* typed_destination = (uint64_t*)destination;
            NORMAL_FROM_SHARED(uint64_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "xor QWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            uint16_t* typed_destination = (uint16_t*)destination;
            NORMAL_FROM_SHARED(uint16_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "xor WORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 32-bit
        else
        {
            uint32_t* typed_destination = (uint32_t*)destination;
            NORMAL_FROM_SHARED(uint32_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "xor DWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }

        // registers will be written back anyway
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x34)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x35)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x36)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x37)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x38)
{
    // cmp Eb, Gb
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(1)
        LOAD_REG_CODE(source, general_purpose_lookup)
        auto* typed_source = (uint8_t*) source;
        NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_EMULATE(uint8_t,
                WRITE_DIVERGENCE_ERROR(" > write divergence in cmp m8, reg8\n"))


        // do NOT advance buffer here
        RETURN_WRITE(0x38)
    }

    // illegal otherwise
    return -1;
}

/* Valid in first round */
BYTE_EMULATOR_IMPL(0x39)
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
            NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_EMULATE(uint64_t,
                    WRITE_DIVERGENCE_PTR_CHECK(((uint64_t*)((unsigned long long*) buffer + 1)),
                            typed_source,
                            " > write divergence in cmp m64, reg64\n"))
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            LOAD_RM_CODE_NO_DEFINE(2)
            auto typed_source = (uint16_t*) source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_EMULATE(uint16_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in cmp m16, reg16\n"))
        }
        // 32-bit
        else
        {
            LOAD_RM_CODE_NO_DEFINE(4)
            auto typed_source = (uint32_t*) source;
            NORMAL_TO_SHARED_REPLICATE_FLAGS_MASTER_EMULATE(uint32_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in cmp m32, reg32\n"))
        }

        // do NOT advance buffer here
        RETURN_WRITE(0x39)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x3a)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x3b)
{
    // cmp Gv, Ev
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            LOAD_RM_CODE_NO_DEFINE(8)
            auto* typed_destination = (uint64_t*)destination;
            NORMAL_FROM_SHARED(uint64_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "cmp QWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags)
                    : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            LOAD_RM_CODE_NO_DEFINE(2)
            auto* typed_destination = (uint16_t*)destination;
            NORMAL_FROM_SHARED(uint16_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "cmp WORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags)
                    : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 32-bit
        else
        {
            LOAD_RM_CODE_NO_DEFINE(4)
            auto* typed_destination = (uint32_t*)destination;
            NORMAL_FROM_SHARED(uint32_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "cmp DWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags)
                    : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }

        // registers will be written back anyway
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x3c)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x3d)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x3e)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x3f)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x40)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x41)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x42)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x43)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x44)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x45)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x46)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x47)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x48)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x49)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x4a)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x4b)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x4c)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x4d)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x4e)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x4f)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x50)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x51)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x52)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x53)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x54)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x55)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x56)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x57)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x58)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x59)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x5a)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x5b)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x5c)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x5d)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x5e)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x5f)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x60)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x61)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x62)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x63)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)

        // movsxd r64, r/m32
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            int64_t* typed_destination = (int64_t*)destination;
            NORMAL_FROM_SHARED(uint32_t)
            *typed_destination = *typed_source;
        }
        // movsxd r32, r/m32 | movsxd r16, r/m16
        else
        {
            // these aren't behaving well
            return -1;
        }

        // general purpose regs will be written back by default
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x64)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x65)


/* Prefix, blocked */
// BYTE_EMULATOR_IMPL(0x66)


/* Prefix, blocked */
// BYTE_EMULATOR_IMPL(0x67)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x68)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x69)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x6a)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x6b)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x6c)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x6d)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x6e)


/* Valid in second round */
BYTE_EMULATOR_IMPL(0x6f)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM

        // movdqu xmm, xmm/m128 if f3 prefix is present
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE)
        {
            LOAD_REG_CODE(destination, xmm_lookup)
            LOAD_RM_CODE_NO_DEFINE(16)
            XMM_FROM_SHARED

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movdqu xmm0, XMMWORD PTR [rdx];"
                    "movdqu XMMWORD PTR [rax], xmm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "xmm0"
            );
        }
        // movdqa xmm, xmm/m128 if f3 prefix is not present
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            LOAD_REG_CODE(destination, xmm_lookup)
            LOAD_RM_CODE_NO_DEFINE(16)
            XMM_FROM_SHARED

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movdqu xmm0, XMMWORD PTR [rdx];"
                    "movdqu XMMWORD PTR [rax], xmm0;" // todo this should be `movdqa`, but that causes segfaults
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "xmm0"
            );
        }
        // mova mm, m64
        else
        {
            LOAD_REG_CODE(destination, mm_lookup)
            LOAD_RM_CODE_NO_DEFINE(8)
            NORMAL_FROM_SHARED(uint64_t)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movq mm0, QWORD PTR [rdx];"
                    "movq QWORD PTR [rax], mm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (typed_source)
                    : "mm0"
            );
        }

        // write back regs, always needed here
        if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
        {
            RETURN_ADVANCE
        }
    }

    // invalid otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x70)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x71)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x72)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x73)


/* Valid in fist round */
BYTE_EMULATOR_IMPL(0x74)
{
    // valid in first round
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // define regs struct
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM

        // pcmpeqb xmm, xmm/m128
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            LOAD_RM_CODE_NO_DEFINE(16)
            LOAD_REG_CODE(destination, xmm_lookup)

            XMM_FROM_SHARED

            // perform operation
            __asm(
                    ".intel_syntax noprefix;"
                    "movdqu xmm1, XMMWORD PTR [rax];"
                    "movdqu xmm0, XMMWORD PTR [rdx];"
                    "pcmpeqb xmm1, xmm0;"
                    "movdqu XMMWORD PTR [rax], xmm1;"
                    ".att_syntax"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "xmm1", "xmm0"
            );
        }
        // pcmpeqb mm, mm/m64
        else
        {
            LOAD_RM_CODE_NO_DEFINE(8)
            LOAD_REG_CODE(destination, mm_lookup)

            NORMAL_FROM_SHARED(uint64_t)

            // perform operation
            __asm(
                    ".intel_syntax noprefix;"
                    "movq mm1, QWORD PTR [rax];"
                    "pcmpeqb mm1, QWORD PTR [rdx];"
                    "movq QWORD PTR [rax], mm1;"
                    ".att_syntax"
                    :
                    : [dst] "a" (destination), [src] "d" (typed_source)
                    : "mm1"
            );
        }

        // we always write to a register, so we have to write it back
        if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
        {
            RETURN_ADVANCE
        }
    }
    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x75)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x76)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x77)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x78)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x79)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x7a)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x7b)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x7c)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x7d)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x7e)


/* Valid in second round */
BYTE_EMULATOR_IMPL(0x7f)
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

            XMM_TO_SHARED_EMULATE(WRITE_DIVERGENCE_XMM_EQUAL(__buffer, __source,
                    " > write divergence in movdqu m128, xmm\n"))
        }
        // movdqa xmm/m128, xmm if f3 prefix is not present
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            DEFINE_FPREGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE_NO_DEFINE(16)
            LOAD_REG_CODE(source, xmm_lookup)

            XMM_TO_SHARED_EMULATE(WRITE_DIVERGENCE_XMM_EQUAL(__buffer, __source,
                    " > write divergence in movdqa m128, xmm\n"))
        }
        // movq m64, mm
        else
        {
            DEFINE_FPREGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE_NO_DEFINE(8)
            LOAD_REG_CODE(source, mm_lookup)
            auto* typed_source = (uint64_t*) source;

            NORMAL_TO_SHARED_EMULATE(uint64_t, WRITE_DIVERGENCE_ERROR(" > write divergence in movq m64, mm\n"))
        }

        // do NOT advance the buffer here
        RETURN_WRITE(0x7f)
    }

    // illegal access otherwise
    return -1;
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x80)
{
    // Immediate Grp 1 Eb, Ib
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(1)

        // ModR/M reg field used as opcode extension
        switch (GET_REG_CODE(modrm))
        {
            case 0b000u: // ADD - not yet implemented
                return -1;
            case 0b001u: // OR  - not yet implemented
            {
                IMM_TO_SHARED_REPLICATE_FLAGS_EMULATE
                break;
            }
            case 0b010u: // ADC - not yet implemented
            case 0b011u: // SBB - not yet implemented
                return -1;
            case 0b100u: // AND - and r/m8, imm8
            {
                IMM_TO_SHARED_REPLICATE_FLAGS_EMULATE
                break;
            }
            case 0b101u: // SUB - not yet implemented
            case 0b110u: // XOR - not yet implemented
                return -1;
            case 0b111u: // CMP - CMP r/m8, imm8
            {
                // perform operation, note that the flags register is also changed here
                IMM_TO_SHARED_REPLICATE_FLAGS_MASTER_EMULATE
                break;
            }

            default:
                return -1;
        }

        // do NOT advance buffer here
        RETURN_WRITE(0x80)
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x81)
{
    // immediate grp 1 Ev, Iz
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)

        switch (GET_REG_CODE(modrm))
        {
            case 0b000u: // ADD - not yet implemented
            case 0b001u: // OR  - not yet implemented
            case 0b010u: // ADC - not yet implemented
            case 0b011u: // SBB - not yet implemented
                return -1;
            case 0b100u: // AND - and r/m(16,32,64), imm(16,32,32)
            {
                IMM_TO_SHARED_REPLICATE_FLAGS_EMULATE
                break;
            }
            case 0b101u: // SUB - not yet implemented
            case 0b110u: // XOR - not yet implemented
                return -1;
            case 0b111u: // CMP - CMP r/m, imm
            {
                IMM_TO_SHARED_REPLICATE_FLAGS_MASTER_EMULATE
                break;
            }

            default:
                return -1;
        }

        RETURN_WRITE(0x81)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x82)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x83)
{
    // grp 1 r/m(16,32,64), imm8
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)

        switch (GET_REG_CODE((unsigned ) instruction[instruction.effective_opcode_index + 1]))
        {
            case 0b000u: // ADD - add r/m(16,32,64), imm8
            {
                IMM_TO_SHARED_REPLICATE_FLAGS_EMULATE
                break;
            }
            case 0b001u: // OR  - not yet implemented
            {
                IMM_TO_SHARED_REPLICATE_FLAGS_EMULATE
                break;
            }
            case 0b010u: // ADC - not yet implemented
                return -1;
            case 0b011u: // SBB - not yet implemented
                return -1;
            case 0b100u: // AND - not yet implemented
                return -1;
            case 0b101u: // SUB - not yet implemented
            {
                IMM_TO_SHARED_REPLICATE_FLAGS_EMULATE
                break;
            }
            case 0b110u: // XOR - not yet implemented
                return -1;
            case 0b111u: // CMP - cmp r/m(16,32,64), imm8
            {
                IMM_TO_SHARED_REPLICATE_FLAGS_MASTER_EMULATE
                break;
            }
            default:
                return -1;
        }

        RETURN_WRITE(0x83)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x84)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x85)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x86)


/* Valid in first round */
#define EXCHANGE_TO_SHARED(__cast, __divergence)                                                                       \
LOAD_RM_CODE_NO_DEFINE(sizeof(__cast))                                                                                 \
auto* typed_source = (__cast*)source;                                                                                  \
auto* typed_destination = (__cast*)((unsigned long long) mapping_info->monitor_base + offset);                         \
                                                                                                                       \
if (!variant->variant_num)                                                                                             \
{                                                                                                                      \
    unsigned long long requested_size = 3 * sizeof(__cast);                                                            \
    void* buffer = nullptr;                                                                                            \
    int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, typed_destination, instruction, &buffer,  \
            requested_size);                                                                                           \
    if (result < 0)                                                                                                    \
        return result;                                                                                                 \
    *((__cast*)buffer + 1) = *typed_source;                                                                            \
    __cast orig_source = *typed_source;                                                                                \
    __atomic_exchange(typed_destination, typed_source, typed_source, __ATOMIC_ACQ_REL);                                \
    *(__cast*)buffer = *typed_source;                                                                                  \
    if (mapping_info->variant_shadows[0].monitor_base)/* Only access shadow memory if it exists */                     \
    {                                                                                                                  \
        __atomic_exchange((__cast*)(mapping_info->variant_shadows[0].monitor_base + offset), &orig_source,             \
                &orig_source, __ATOMIC_ACQ_REL);                                                                       \
        *((__cast*)buffer + 2) = orig_source;                                                                          \
    }                                                                                                                  \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    void* buffer = nullptr;                                                                                            \
    unsigned long long size = 0;                                                                                       \
    int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, typed_destination, instruction, &buffer,  \
            size);                                                                                                     \
    if (result < 0)                                                                                                    \
        return result;                                                                                                 \
                                                                                                                       \
    if (*((__cast*)buffer + 1) != *typed_source)                                                                       \
    {                                                                                                                  \
        __divergence                                                                                                   \
    }                                                                                                                  \
    if (mapping_info->variant_shadows[variant->variant_num].monitor_base)/* Only access shadow memory if it exists */  \
    {                                                                                                                  \
        typed_destination = (__cast*)(mapping_info->variant_shadows[variant->variant_num].monitor_base + offset);      \
        __atomic_exchange(typed_destination, typed_source, typed_source, __ATOMIC_ACQ_REL);                            \
        if (*((__cast*)buffer + 2) != *(__cast*)buffer)                                                                \
            *typed_source = *(__cast*)buffer;                                                                          \
    }                                                                                                                  \
    else                                                                                                               \
        *typed_source = *(__cast*)buffer;                                                                              \
}


BYTE_EMULATOR_IMPL(0x87)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            EXCHANGE_TO_SHARED(uint64_t, WRITE_DIVERGENCE_PTR_CHECK(((uint64_t *)buffer + 1),
                                                                    typed_source,
                                                                    " > diverging write in 0x87 - source\n"))
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            EXCHANGE_TO_SHARED(uint16_t, WRITE_DIVERGENCE_ERROR(
                    " > diverging write in 0x87 - source\n"))
        }
        // 32-bit
        else
        {
            EXCHANGE_TO_SHARED(uint32_t, WRITE_DIVERGENCE_ERROR(
                    " > diverging write in 0x87 - source\n"))
        }

        // no need to write back registers here
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x88)
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

        uint8_t* typed_source = (uint8_t*)source;

        // execute operation
        NORMAL_TO_SHARED_EMULATE(uint8_t,
                                 WRITE_DIVERGENCE_ERROR(" > write divergence in mov m8, reg8\n"));

        // do NOT advance buffer here
        RETURN_WRITE(0x88)
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x89)
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
            NORMAL_TO_SHARED_EMULATE(uint64_t,
                    WRITE_DIVERGENCE_PTR_CHECK(buffer, typed_source,
                                               " > pointer check failed in mov m64, reg64\n"))
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_source = (uint16_t*)source;
            NORMAL_TO_SHARED_EMULATE(uint16_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in mov m16, reg16\n"))
        }
        // default 32-bit
        else
        {
            auto* typed_source = (uint32_t*)source;
            NORMAL_TO_SHARED_EMULATE(uint32_t,
                                     WRITE_DIVERGENCE_ERROR(" > write divergence in mov m32, reg32\n"))
        }

        // do NOT advance buffer here
        RETURN_WRITE(0x89)
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x8a)
{
    // move r8, r/m8
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE_BYTE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(1)

        // use higher order byte of lowest word exception
        if (!PREFIXES_REX_PRESENT(instruction) && GET_REG_CODE((unsigned) modrm) & 0b100u)
            destination = (void*) ((unsigned long long) destination + 1);

        uint8_t* typed_destination = (uint8_t*)destination;
        NORMAL_FROM_SHARED(uint8_t)

        // execute operation
        *typed_destination = *typed_source;

        // registers will be written back with rip
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x8b)
{
    // move Gv, Ev
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)

        // 64-bit version
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            auto* typed_destination = (uint64_t*)destination;
            NORMAL_FROM_SHARED(uint64_t)
            *typed_destination = *typed_source;
        }
        // 16-bit version
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_destination = (uint16_t*)destination;
            NORMAL_FROM_SHARED(uint16_t)
            *typed_destination = *typed_source;
        }
        // 32-bit version
        else
        {
            auto* typed_destination = (uint64_t*)destination;
            NORMAL_FROM_SHARED(uint32_t)
            *typed_destination = *typed_source;
        }

        // registers will be written back with rip
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked in first round */
BYTE_EMULATOR_IMPL(0x8c)
{
    warnf("0x8c not actually implemented right now\n");
    // ignoring for now
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x8d)


/* Not implemented - blocked in first round */
BYTE_EMULATOR_IMPL(0x8e)
{
    warnf("0x8e not actually implemented right now\n");
    // ignoring for now
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x8f)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x90)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x91)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x92)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x93)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x94)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x95)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x96)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x97)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x98)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x99)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x9a)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x9b)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x9c)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x9d)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x9e)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x9f)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xa0)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xa1)


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xa2)
{
    // cpuid
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // this should be valid here
        user_regs_struct* regs = &variant->regs;

        uint32_t eax_input = regs->rax & REG_SIZE_32;
        uint32_t ecx_input = regs->rcx & REG_SIZE_32;

        // execute instruction
        __asm__
        (
                ".intel_syntax noprefix;"
                "cpuid;"
                ".att_syntax;"
                : "+a" (regs->rax), "=d" (regs->rdx), "+c" (regs->rcx), "=b" (regs->rbx)
                :
                :
        );

        // check eax content
        if (eax_input == 0x01)
            regs->rcx &= FEATURE_ECX_BLOCKS;
        else if (eax_input == 0x07 && ecx_input == 0)
        {
            regs->rdx &= EXTENDED_FEATURE_EDX_BLOCKS;
            regs->rcx &= EXTENDED_FEATURE_ECX_BLOCKS;
            regs->rbx &= EXTENDED_FEATURE_EBX_BLOCKS;
        }

        // return ok
        return 0;
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xa3)


/* Not implemented - blocked */
BYTE_EMULATOR_IMPL(0xa4)
{
    // movsb
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // gonna be using general purpose registers
        DEFINE_REGS_STRUCT

        unsigned long long src = regs_struct->rsi;
        unsigned long long dst = regs_struct->rdi;
        unsigned long long src_offset;
        unsigned long long dst_offset;
        shared_monitor_map_info* src_info = nullptr;
        shared_monitor_map_info* dst_info = nullptr;
        unsigned long long size = PREFIXES_GRP_ONE_PRESENT(instruction) &&
                (PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE ||
                 PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE) ? regs_struct->rcx : 1;

        // source is shared memory
        if (IS_TAGGED_ADDRESS(src))
        {
            // source to monitor pointer
            src = decode_address_tag(src, variant);
            OBTAIN_SHARED_MAPPING_INFO_NO_DEF(src, src_info, src_offset, size)
            src = (unsigned long long) src_info->monitor_base + src_offset;
        }
        // destination is shared memory
        if (IS_TAGGED_ADDRESS(dst))
        {
            dst = decode_address_tag(dst, variant);
            OBTAIN_SHARED_MAPPING_INFO_NO_DEF(dst, dst_info, dst_offset, size)
            dst = (unsigned long long) dst_info->monitor_base + dst_offset;
        }
        // we would expect one of the two to be known shared memory
        if (!dst_info && !src_info)
            return -1;

        // replay and spoofing
        MOVS_STRUCT
        GET_BUFFER_RAW((void*) (src_info ? src : dst), sizeof(temp_t) + size)
        auto typed_buffer = (temp_t*)buffer;
        typed_buffer->buffer = (void*)((unsigned long long)buffer + sizeof(temp_t));

        // imitate
        if (!variant->variant_num)
        {
            typed_buffer->size     = size;
            typed_buffer->offset   = dst_offset;
            typed_buffer->src_info = src_info;
            typed_buffer->dst_info = dst_info;
            if (dst_info && src_info)
                typed_buffer->dst = dst;


            if (src_info)
                memcpy(typed_buffer->buffer, (void*)src, size);
            else
            {
                if (!interaction::read_memory(variant->variantpid, (void*) src, (long long)size, typed_buffer->buffer))
                {
                    warnf("could not read data from source check, %llu bytes at %p\n", size, (void*) src);
                    return -1;
                }
            }

            if (dst_info)
            {
                RETURN_WRITE(0xa4)
            }
            else
            {
                if (!interaction::read_memory(variant->variantpid, (void*) dst, (long long)size, typed_buffer->buffer))
                {
                    warnf("could not write data to destination, %llu bytes at %p\n", size, (void*) dst);
                    return -1;
                }
                regs_struct->rcx = 0;
                RETURN_ADVANCE
            }
        }
        else
        {
            if (dst_info && src_info && dst != typed_buffer->dst)
            {
                warnf("second address mismatch\n");
                return -1;
            }
            if (typed_buffer->size != size)
            {
                warnf(" > size mismatches for 0xa4");
                return -1;
            }

            if (!src_info)
            {
                void* src_check = malloc(size);
                if (!src_check)
                {
                    warnf("could not allocate buffer for source check\n");
                    return -1;
                }
                if (!interaction::read_memory(variant->variantpid, (void*) src, (long long)size, src_check))
                {
                    warnf("could not read data from source check, %llu bytes at %p\n", size, (void*) src);
                    return -1;
                }
                if (memcmp(src_check, typed_buffer->buffer, size) != 0)
                {
                    warnf(" > variant %d attempting to write diverging data, %llu bytes using movsb %p %p\n",
                          variant->variant_num, size, (void*)dst, (void*)src);
                    return -1;
                }
                free(src_check);
            }

            if (!dst_info)
            {
                if (!interaction::write_memory(variant->variantpid, (void*) dst, (long long) size,
                        typed_buffer->buffer))
                {
                    warnf("could not write data to variant\n");
                    return -1;
                }

                regs_struct->rcx = 0;
                RETURN_ADVANCE
            }
            else
            {
                RETURN_WRITE(0xa4)
            }
        }
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xa5)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xa6)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xa7)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xa8)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xa9)


#define STOS_EMULATE(__cast)                                                                                           \
OBTAIN_SHARED_MAPPING_INFO(count)                                                                                      \
void* destination = (void*) ((unsigned long long) mapping_info->monitor_base + offset);                                \
void* source = shared_mem_register_access::ACCESS_GENERAL_NAME(rax)(regs_struct);                                      \
                                                                                                                       \
STOS_STRUCT(__cast)                                                                                                    \
GET_BUFFER_RAW(destination, sizeof(temp_t))                                                                            \
auto typed_buffer = (temp_t*)buffer;                                                                                   \
if (!variant->variant_num)                                                                                             \
{                                                                                                                      \
    typed_buffer->source = *(__cast*) source;                                                                          \
    typed_buffer->count = count;                                                                                       \
    typed_buffer->flags = regs_struct->eflags;                                                                         \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    if (typed_buffer->source != *(__cast*) source)                                                                     \
    {                                                                                                                  \
        warnf(" > stos(%lu) with diverging source | %llx != %llx\n", sizeof(__cast),                                   \
                (unsigned long long) typed_buffer->source, (unsigned long long) *(__cast*) source);                    \
        return -1;                                                                                                     \
    }                                                                                                                  \
    else if (typed_buffer->count != count)                                                                             \
    {                                                                                                                  \
        warnf(" > stos(%lu) with diverging count | %llx != %llx\n", sizeof(__cast),                                    \
                typed_buffer->count, (unsigned long long) count);                                                      \
        return -1;                                                                                                     \
    }                                                                                                                  \
    else if ((typed_buffer->flags & (0b1u << 10u)) != (regs_struct->eflags & (0b1u << 10u)))                           \
    {                                                                                                                  \
        warnf(" > stos(%lu) with diverging ZF\n", sizeof(__cast));                                                     \
        return -1;                                                                                                     \
    }                                                                                                                  \
}

/* Valid in first round */
BYTE_EMULATOR_IMPL(0xaa)
{
    // we're in need of rax as source
    DEFINE_REGS_STRUCT

    unsigned long long count = 1;
    if (PREFIXES_GRP_ONE_PRESENT(instruction) && (PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE ||
                                                  PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE))
        count = regs_struct->rcx;
    STOS_EMULATE(uint8_t)
    RETURN_WRITE(0xaa)
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0xab)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // we're in need of rax as source
        DEFINE_REGS_STRUCT

        unsigned long long count = 1;
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && (PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE ||
                PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE))
            count = regs_struct->rcx;

        // stos m64
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            STOS_EMULATE(uint64_t)
        }
        // stos m16
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            STOS_EMULATE(uint16_t)
        }
        // stos m32
        else
        {
            STOS_EMULATE(uint32_t)
        }

        RETURN_WRITE(0xab)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xac)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xad)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xae)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xaf)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xb0)


#define CMPXCHG_EMULATE(__cast)                                                                                        \
CMPXCHG_STRUCT(__cast)                                                                                                 \
GET_BUFFER_RAW(destination, sizeof(temp_t))                                                                            \
auto typed_buffer = (temp_t*)buffer;                                                                                   \
if (!variant->variant_num)                                                                                             \
{                                                                                                                      \
    typed_buffer->original_rax = (__cast)variant->regs.rax;                                                            \
    typed_buffer->source       = *(__cast*)source;                                                                     \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    if (typed_buffer->source != *(__cast*) source)                                                                     \
    {                                                                                                                  \
        warnf(" > mismatching source for 0xb1 (%lu) | %llx != %llx", sizeof(__cast),                                   \
                (unsigned long long)typed_buffer->source, (unsigned long long)*(__cast*)source);                       \
            return -1;                                                                                                 \
    }                                                                                                                  \
    if (typed_buffer->original_rax != (__cast)regs_struct->rax)                                                        \
    {                                                                                                                  \
        warnf(" > mismatching rax for 0xb1 (%lu) | %llx != %llx", sizeof(__cast),                                      \
                (unsigned long long)typed_buffer->original_rax, (unsigned long long)(__cast)regs_struct->rax);         \
            return -1;                                                                                                 \
    }                                                                                                                  \
}
/* Valid in second round */
BYTE_EMULATOR_IMPL(0xb1)
{
    // cmpxchg Ev, Gv
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // affects flags as well
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            CMPXCHG_EMULATE(uint64_t)
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            CMPXCHG_EMULATE(uint16_t)
        }
        // 32-bit
        else
        {
            CMPXCHG_EMULATE(uint32_t)
        }

        RETURN_WRITE(0xb1)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xb2)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xb3)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xb4)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xb5)


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xb6)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // movzx Gv, Eb
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(sizeof(uint8_t))

        NORMAL_FROM_SHARED(uint8_t)

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            auto* typed_destination = (uint64_t*)destination;
            *typed_destination = *typed_source;
        }
        // 16-bit size
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_destination = (uint16_t*)destination;
            *typed_destination = *typed_source;
        }
        // 32-bit size
        else
        {
            auto* typed_destination = (uint64_t*)destination;
            *typed_destination = *typed_source;
        }

        // registers will be written back with rip
        RETURN_ADVANCE
    }

    // illegal operation otherwise
    return -1;
}


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xb7)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // movzx Gv, Ew
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)

        NORMAL_FROM_SHARED(uint16_t)

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            auto* typed_destination = (uint64_t*)destination;
            *typed_destination = *typed_source;
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_destination = (uint16_t*)destination;
            *typed_destination = *typed_source;
        }
        // 32-bit size
        else
        {
            auto* typed_destination = (uint64_t*)destination;
            *typed_destination = *typed_source;
        }

        // registers will be written back with rip
        RETURN_ADVANCE
    }

    // illegal operation otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xb8)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xb9)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xba)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xbb)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xbc)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xbd)


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xbe)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // movsx Gv, Eb
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(sizeof(uint8_t))

        // always byte
        NORMAL_FROM_SHARED(int8_t)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            auto* typed_destination = (int64_t*)destination;
            *typed_destination = (uint64_t)*typed_source;
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_destination = (int16_t*)destination;
            *typed_destination = (uint16_t)*typed_source;
        }
        // 32-bit
        else
        {
            auto* typed_destination = (int32_t*)destination;
            *typed_destination = (uint32_t)*typed_source;
            *(typed_destination + 1) = 0x00;
        }

        // registers written back by default
        RETURN_ADVANCE
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xbf)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc0)


#define XADD_EMULATE(__cast)                                                                                           \
XADD_STRUCT(__cast)                                                                                                    \
GET_BUFFER_RAW(destination, sizeof(temp_t))                                                                            \
auto* typed_buffer = (temp_t*)buffer;                                                                                  \
                                                                                                                       \
if (!variant->variant_num)                                                                                             \
    typed_buffer->original_source = *(__cast*)source;                                                                  \
else                                                                                                                   \
{                                                                                                                      \
    if (*(__cast*)source != typed_buffer->original_source)                                                             \
    {                                                                                                                  \
        warnf(" > mismatching source in 0xc1 (%lu) | %llx != %llx\n", sizeof(__cast),                                  \
                (unsigned long long)typed_buffer->original_source, (unsigned long long)*(__cast*)source);              \
    }                                                                                                                  \
}
/* Valid in second round */
BYTE_EMULATOR_IMPL(0xc1)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // xadd Ev, Gv
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            XADD_EMULATE(uint64_t)
        }
        // 16-bit size
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            XADD_EMULATE(uint16_t)
        }
        // 32-bit size
        else
        {
            XADD_EMULATE(uint32_t)
        }

        RETURN_WRITE(0xc1)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc2)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc3)


/* valid in first round */
// BYTE_EMULATOR_IMPL(0xc4)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc5)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0xc6)
{
    // mov r/m8, imm8
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_MODRM
        LOAD_IMM(source)
        LOAD_RM_CODE_NO_DEFINE(1)

        // perform operation
        auto* typed_source = (uint8_t*)source;
        NORMAL_TO_SHARED_EMULATE(uint8_t,
                WRITE_DIVERGENCE_ERROR(" > write divergence in mov m8, imm8\n"));

        // do NOT advance buffer here
        RETURN_WRITE(0xc6)
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0xc7)
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
            NORMAL_TO_SHARED_EMULATE(uint64_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in mov m64, imm32\n"))
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_source = (uint16_t*)source;
            NORMAL_TO_SHARED_EMULATE(uint16_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in mov m32, imm23\n"));
        }
        // 32-bit
        else
        {
            auto* typed_source = (uint32_t*)source;
            NORMAL_TO_SHARED_EMULATE(uint32_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in mov m32, imm23\n"));
        }

        // do NOT advance buffer here
        RETURN_WRITE(0xc7)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc8)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc9)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xca)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xcb)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xcc)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xcd)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xce)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xcf)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd0)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd1)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd2)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd3)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd4)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd5)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd6)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd7)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd8)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xd9)


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xda)
{
    // valid in second round
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // we're gonna be using fpregs
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM

        // pminub xmm, xmm/m128
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            LOAD_RM_CODE_NO_DEFINE(16)
            LOAD_REG_CODE(destination, xmm_lookup)

            XMM_FROM_SHARED

            // execute operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movdqu xmm0, XMMWORD PTR [rax];"
                    "movdqu xmm1, XMMWORD PTR [rdx];"
                    "pminub xmm0, xmm1;"
                    "movdqu XMMWORD PTR [rax], xmm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "xmm0", "xmm1"
            );
        }
        // pminub mm, mm/m64
        else
        {
            LOAD_RM_CODE_NO_DEFINE(8)
            LOAD_REG_CODE(destination, mm_lookup)
            NORMAL_FROM_SHARED(uint64_t)

            // execute operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movq mm0, QWORD PTR [rax];"
                    "pminub mm0, QWORD PTR [rdx];"
                    "movq QWORD PTR [rax], mm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (typed_source)
                    : "mm0"
            );
        }


        // we have to write the registers back
        if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
        {
            RETURN_ADVANCE
        }
    }

    // illegal access
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xdb)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xdc)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xdd)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xde)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xdf)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe0)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe1)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe2)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe3)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe4)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe5)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe6)


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xe7)
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

            XMM_TO_SHARED_EMULATE(WRITE_DIVERGENCE_XMM_EQUAL(__buffer, __source,
                    " > write divergence in movntdq m128, xmm\n"))
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

            NORMAL_TO_SHARED_EMULATE(uint64_t,
                    WRITE_DIVERGENCE_ERROR(" > write divergence in movntq m64, mm\n"))
        }

        // do NOT advance the buffer here
        RETURN_WRITE(0xe7)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe8)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe9)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xea)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xeb)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xec)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xed)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xee)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xef)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xf0)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xf1)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xf2)


/* Implemented - allowed in round 1 */
// BYTE_EMULATOR_IMPL(0xf3)

/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xf4)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xf5)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0xf6)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_B(instruction))
        {
            DEFINE_MODRM
            LOAD_RM_CODE_NO_DEFINE(1)

            // ModR/M reg field used as opcode extension
            switch (GET_REG_CODE(modrm))
            {
                case 0b000u: // TEST - test r/m8, imm8
                case 0b001u: // TEST - test r/m8, imm8
                {
                    IMM_TO_SHARED_REPLICATE_FLAGS_MASTER_EMULATE;
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

            RETURN_WRITE(0xf6)
        }
        // illegal otherwise
        return -1;
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xf7)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xf8)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xf9)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xfa)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xfb)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xfc)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xfd)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xfe)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xff)
