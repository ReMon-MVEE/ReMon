//
// Created by jonas on 15.04.20.
//


#include <sys/user.h>
#include <MVEE.h>
#include <MVEE_interaction.h>
#include <MVEE_monitor.h>
#include <arch/amd64/shared_mem/shared_mem_reg_access.h>
#include "instruction_intent_emulation.h"


// =====================================================================================================================
//      macros
// =====================================================================================================================
#define LOAD_SRC_AND_DST(DEFINE_REGS, lookup, DST_LOADER_MACRO, SRC_LOADER_MACRO)                                      \
    DEFINE_REGS                                                                                                        \
                                                                                                                       \
    __uint8_t modrm = instruction[instruction.effective_opcode_index + 1];                                             \
                                                                                                                       \
    void* source;                                                                                                      \
    SRC_LOADER_MACRO(source, lookup);                                                                                  \
                                                                                                                       \
    void* destination;                                                                                                 \
    DST_LOADER_MACRO(destination, lookup)


#define DEFINE_REGS_STRUCT                                                                                             \
    user_regs_struct* regs_struct = &variant->regs;                                                                    \
    relevant_monitor.call_check_regs(variant->variant_num);


#define DEFINE_FPREGS_STRUCT                                                                                           \
    user_fpregs_struct* regs_struct = &variant->fpregs;                                                                \
    relevant_monitor.call_check_fpregs(variant->variant_num);


#define LOAD_RM_CODE(pointer, lookup)                                                                                  \
/* register if mod bits equal 0b11 */                                                                                  \
if (GET_MOD_CODE((unsigned) modrm) == 0b11u)                                                                           \
    /* For shared memory emulation, this shouldn't happen */                                                           \
    return -1;                                                                                                         \
/* memory reference otherwise, so determine the monitor relevant pointer */                                            \
if (instruction.determine_monitor_pointer(relevant_monitor, variant, instruction.effective_address, &pointer) < 0)     \
    return -1;

#define LOAD_REG_CODE(pointer, lookup)                                                                                 \
__uint8_t reg_rex_extra = PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_R(instruction) ?                     \
        0b1000u : 0;                                                                                                   \
pointer = shared_mem_register_access::lookup[reg_rex_extra | GET_REG_CODE((unsigned) modrm)](regs_struct);

#define LOAD_REG_CODE_BYTE(pointer, lookup)                                                                            \
__uint8_t reg_code = GET_REG_CODE((unsigned) modrm);                                                                   \
if (PREFIXES_REX_PRESENT(instruction))                                                                                 \
{                                                                                                                      \
    if (PREFIXES_REX_FIELD_R(instruction))                                                                             \
        reg_code |= 0b1000u;                                                                                           \
}                                                                                                                      \
else                                                                                                                   \
    reg_code &= ~0b100u;                                                                                               \
pointer = shared_mem_register_access::lookup[reg_code](regs_struct);

#define LOAD_IMM(pointer, ignore)                                                                                      \
if (!instruction.immediate_operand_index)                                                                              \
    return -1;                                                                                                         \
pointer = &instruction.instruction[instruction.immediate_operand_index];


#define CHECK_FROM_SHARED_MEMORY(size)                                                                                 \
int result;                                                                                                            \
if ((result = relevant_monitor.replay_buffer.access_data(variant->variant_num, &instruction,                           \
        (__uint8_t**) &source, size, source)) != 0)                                                                    \
    return result;

#define CHECK_TO_SHARED_MEMORY(size)                                                                                   \
void* intermediate = source;                                                                                           \
auto result = relevant_monitor.replay_buffer.access_data(variant->variant_num, &instruction,                           \
        (__uint8_t**) &intermediate, size, destination);                                                               \
if (result != 0)                                                                                                       \
    return result;                                                                                                     \
if (variant->variant_num != 0)                                                                                         \
{                                                                                                                      \
    for (int i = 0; i < size; i++)                                                                                     \
        if (((__uint8_t*) intermediate)[i] != ((__uint8_t*) source)[i])                                                \
            return -1;                                                                                                 \
    return 0;                                                                                                          \
}


#define EMULATE_TO_SHARED_MEMORY(size)                                                                                 \
__uint8_t intermediate[size];                                                                                          \
auto result = relevant_monitor.replay_buffer.access_data(variant->variant_num, &instruction,                           \
        (__uint8_t**) &destination, size, destination);                                                                \
if (result != 0)                                                                                                       \
    return result;                                                                                                     \
for (int i = 0; i < size; i++)                                                                                         \
    intermediate[i] = ((__uint8_t*) destination)[i];



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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x01)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x02)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x03)


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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x0b)


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
        if (PREFIXES_GRP_ONE_PRESENT(instruction) || PREFIXES_GRP_THREE_PRESENT(instruction))
            return -1;

        // movups xmm, xmm/m128
        LOAD_SRC_AND_DST(DEFINE_FPREGS_STRUCT, xmm_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        CHECK_FROM_SHARED_MEMORY(16)

        // perform operation
        __asm
        (
                ".intel_syntax noprefix;"
                "movups xmm0, XMMWORD PTR [rdx];"
                "movups XMMWORD PTR [rax], xmm0;"
                ".att_syntax;"
                :
                : [dst] "a" (destination), [src] "d" (source)
                : "xmm0"
        );

        // writeback required
        if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
            return 0;
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
        LOAD_SRC_AND_DST(DEFINE_FPREGS_STRUCT, xmm_lookup, LOAD_RM_CODE, LOAD_REG_CODE)

        CHECK_TO_SHARED_MEMORY(16)

        // perform operation
        __asm
        (
                ".intel_syntax noprefix;"
                "movups xmm0, XMMWORD PTR [rdx];"
                "movups XMMWORD PTR [rax], xmm0;"
                ".att_syntax;"
                :
                : [dst] "a" (destination), [src] "d" (source)
                : "xmm0"
        );

        // no writeback needed
        return 0;
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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x23)


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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x29)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x2a)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x2b)


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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x33)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x34)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x35)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x36)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x37)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x38)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x39)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x3a)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x3b)


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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x63)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x64)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x65)


/* Not implemented - blocked in first round */
// BYTE_EMULATOR_IMPL(0x66)


/* Not implemented - blocked in first round */
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
    if (EXTRA_INFO_ROUND_CODE(instruction))
    {
        LOAD_SRC_AND_DST(DEFINE_FPREGS_STRUCT, xmm_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        // movdqu xmm, xmm/m128 if f3 prefix is present
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE)
        {
            CHECK_FROM_SHARED_MEMORY(16)

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
        // movdqa xmm, xmm/m128 if f3 prefix is present
        // implemented as movdqu because it's not behaving
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            CHECK_FROM_SHARED_MEMORY(16)

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

        // write back regs, always needed here
        if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
            return 0;
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

        // pointers to the source and destination location
        void* source;
        void* destination;

        // define regs struct
        DEFINE_FPREGS_STRUCT

        // temporary modrm copy
        __uint8_t modrm = instruction[instruction.effective_opcode_index + 1];

        // pcmpeqb xmm, xmm/m128
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            // source rm
            LOAD_RM_CODE(source, ignored_anyway)
            // destination reg
            LOAD_REG_CODE(destination, xmm_lookup)

            CHECK_FROM_SHARED_MEMORY(16)
            __uint8_t temp[16];
            for (int byte = 0; byte < 16; byte++)
                temp[byte] = ((__uint8_t*) source)[byte];

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
            // source rm
            LOAD_RM_CODE(source, ignored_anyway)
            // destination reg
            LOAD_REG_CODE(destination, mm_lookup)

            CHECK_FROM_SHARED_MEMORY(8)


            // perform operation
            __asm(
                    ".intel_syntax noprefix;"
                    "movq mm1, QWORD PTR [rax];"
                    "pcmpeqb mm1, QWORD PTR [rdx];"
                    "movq QWORD PTR [rax], mm1;"
                    ".att_syntax"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "mm1"
            );
        }


        // we always write to a register, so we have to write it back
        if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
            return 0;

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
// BYTE_EMULATOR_IMPL(0x7f)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x80)
{
    // Immediate Grp 1 Eb, Ib
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // temporary ModR/M copy
        __uint8_t modrm = instruction[instruction.effective_opcode_index + 1];

        // uses general purpose registers
        DEFINE_REGS_STRUCT

        // ModR/M reg field used as opcode extension
        switch (GET_REG_CODE(modrm))
        {
            case 0b000u: // ADD - not yet implemented
            case 0b001u: // OR  - not yet implemented
            case 0b010u: // ADC - not yet implemented
            case 0b011u: // SBB - not yet implemented
            case 0b100u: // AND - not yet implemented
            case 0b101u: // SUB - not yet implemented
            case 0b110u: // XOR - not yet implemented
                return -1;
            case 0b111u: // CMP - CMP r/m8, imm8
            {
                // source is immediate operand
                void* source = (void*) &instruction.instruction[instruction.immediate_operand_index];

                // destination operand is decided by modrm
                void* destination;
                LOAD_RM_CODE(destination, general_purpose_lookup)

                // current flags
                void* flags = &(regs_struct->eflags);

                EMULATE_TO_SHARED_MEMORY(1)

                // perform operation, note that the flags register is also changed here
                __asm
                (
                        ".intel_syntax noprefix;"
                        "pushfq;"
                        "push QWORD PTR [rcx];"
                        "popfq;"
                        "mov r15b, BYTE PTR [rdx];"
                        "cmp BYTE PTR [rax], r15b;"
                        "pushfq;"
                        "pop QWORD PTR [rcx];"
                        "popfq;"
                        ".att_syntax;"
                        :
                        : [dst] "a" (intermediate), [src] "d" (source), [flags] "c" (flags)
                        : "r15"
                );

                break;
            }

            default:
                return -1;
        }


        // registers will be written back with rip
        return 0;
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x81)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x82)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x83)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x84)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x85)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x86)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x87)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x88)
{
    // mov r/m8, r8
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_REG_CODE_BYTE)

        // special case that uses higher order lower byte, for example ah
        if (!PREFIXES_REX_PRESENT(instruction) && GET_REG_CODE((unsigned) modrm) & 0b100u)
            source = (void*) ((unsigned long long) source + 1);

        CHECK_TO_SHARED_MEMORY(1)

        // execute operation
        __asm
        (
                ".intel_syntax noprefix;"
                "mov dl, BYTE PTR [rdx];"
                "mov BYTE PTR [rax], dl;"
                ".att_syntax;"
                :
                : [dst] "a" (destination), [src] "d" (source)
                :
        );

        // we don't have to write anything back here, destination shouldn't be able to be a register
        return 0;
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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_REG_CODE)

        // 64-bit implementation
        if (PREFIXES_REX_FIELD_W(instruction))
        {
            CHECK_TO_SHARED_MEMORY(8)

            __asm
            (
            ".intel_syntax noprefix;"
            "mov rdx, QWORD PTR [rdx];"
            "mov QWORD PTR [rax], rdx;"
            ".att_syntax;"
            :
            : [dst] "a" (destination), [src] "d" (source)
            :
            );
        }
        // default 32-bit
        else
        {
            CHECK_TO_SHARED_MEMORY(4)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov edx, DWORD PTR [rdx];"
                    "mov DWORD PTR [rax], edx;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    :
            );
        }

        warnf("reached by %d\n\n", variant->variant_num);

        // no need to write back any registers
        return 0;
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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE_BYTE, LOAD_RM_CODE)

        // use higher order byte of lowest word exception
        if (!PREFIXES_REX_PRESENT(instruction) && GET_REG_CODE((unsigned) modrm) & 0b100u)
            destination = (void*) ((unsigned long long) destination + 1);

        CHECK_FROM_SHARED_MEMORY(1)

        __asm
        (
                ".intel_syntax noprefix;"
                "mov dl, BYTE PTR [rdx];"
                "mov BYTE PTR [rax], dl;"
                ".att_syntax;"
                :
                : [dst] "a" (destination), [src] "d" (source)
                :
        );

        // registers will be written back with rip
        return 0;
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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        // 64-bit version
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            CHECK_FROM_SHARED_MEMORY(8)

            __asm
            (
            ".intel_syntax noprefix;"
            "mov rdx, QWORD PTR [rdx];"
            "mov QWORD PTR [rax], rdx;"
            ".att_syntax;"
            :
            : [dst] "a" (destination), [src] "d" (source)
            :
            );
        }
        // 32-bit version
        else
        {
            CHECK_FROM_SHARED_MEMORY(4)

            __asm
            (
            ".intel_syntax noprefix;"
            "mov edx, DWORD PTR [rdx];"
            "mov DWORD PTR [rax], edx;"
            ".att_syntax;"
            :
            : [dst] "a" (destination), [src] "d" (source)
            :
            );
        }

        // registers will be written back with rip
        return 0;
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked in first round */
BYTE_EMULATOR_IMPL(0x8c)
{
    // ignoring for now
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x8d)


/* Not implemented - blocked in first round */
BYTE_EMULATOR_IMPL(0x8e)
{
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

        __uint32_t eax_input = regs->rax & REG_SIZE_32;
        __uint32_t ecx_input = regs->rcx & REG_SIZE_32;

        // execute instruction
        __asm
        (
                ".intel_syntax noprefix;"
                "cpuid;"
                ".att_syntax;"
                : "+a" (regs->rax), "+d" (regs->rdx), "+c" (regs->rcx), "+b" (regs->rbx)
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
// BYTE_EMULATOR_IMPL(0xa4)


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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xaa)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xab)


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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xb1)


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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        CHECK_FROM_SHARED_MEMORY(1)

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movzx r15, BYTE PTR [rdx];"
                    "mov QWORD PTR [rax], r15;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "r15"
            );
        }
        // 32-bit size
        else
        {
            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movzx r15d, BYTE PTR [rdx];"
                    "mov DWORD PTR [rax], r15d;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "r15"
            );
        }

        // registers will be written back with rip
            return 0;
    }

    // illegal operation otherwise
    return -1;
}


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xb7)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // movzx Gv, Eq
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        CHECK_FROM_SHARED_MEMORY(2)

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movzx r15, WORD PTR [rdx];"
                    "mov QWORD PTR [rax], r15;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "r15"
            );
        }
            // 32-bit size
        else
        {
            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movzx r15d, WORD PTR [rdx];"
                    "mov DWORD PTR [rax], r15d;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "r15"
            );
        }

        // registers will be written back with rip
        return 0;
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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xbe)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xbf)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc0)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc1)


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
        // local temporary modrm byte copy
        __uint8_t modrm = instruction.instruction[instruction.effective_opcode_index + 1];

        // define source
        void* source;
        LOAD_IMM(source, ignored_anyway)

        // define destination
        void* destination;
        LOAD_RM_CODE(destination, ignored_anyway)

        CHECK_TO_SHARED_MEMORY(1)

        // perform operation
        __asm
        (
                ".intel_syntax noprefix;"
                "mov dl, BYTE PTR [rdx];"
                "mov BYTE PTR [rax], dl;"
                ".att_syntax;"
                :
                : [dst] "a" (destination), [src] "d" (source)
                :
        );

        // no writeback needed
        return 0;
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc7)


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

        // save local copy for modrm
        __uint8_t modrm = instruction.instruction[instruction.effective_opcode_index + 1];


        // pminub xmm, xmm/m128
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            // load source from rm
            void* source;
            LOAD_RM_CODE(source, xmm_lookup)

            // load destination from reg
            void* destination;
            LOAD_RM_CODE(destination, xmm_lookup)

            CHECK_FROM_SHARED_MEMORY(16)

            // execute operation
            __asm
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
            // load source from rm
            void* source;
            LOAD_RM_CODE(source, mm_lookup)

            // load destination from reg
            void* destination;
            LOAD_RM_CODE(destination, mm_lookup)

            CHECK_FROM_SHARED_MEMORY(8)

            // execute operation
            __asm
            (
                    ".intel_syntax noprefix;"
                    "movq mm0, QWORD PTR [rax];"
                    "pminub mm0, QWORD PTR [rdx];"
                    "movq QWORD PTR [rax], mm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "mm0"
            );
        }


        // we have to write the registers back
        if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
            return 0;
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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xe7)


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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xf6)


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