//
// Created by jonas on 15.04.20.
//


#include <sys/user.h>
#include <MVEE.h>
#include <MVEE_interaction.h>
#include <MVEE_monitor.h>
#include <arch/amd64/shared_mem/shared_mem_reg_access.h>
#include <sys/mman.h>
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
    return UNKNOWN_MEMORY_TERMINATION;


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


#define COMPARE_BUFFERS(first, second, size)                                                                           \
for (int i = 0; i < size; i++)                                                                                         \
    if (((__uint8_t*) first)[i] != ((__uint8_t*) second)[i])                                                           \
        return -1;


#define COPY_BUFFER(first, second, size)                                                                               \
for (int i = 0; i < size; i++)                                                                                         \
    ((__uint8_t*) first)[i] = ((__uint8_t*) second)[i];                                                                \


#define REPLAY_BUFFER_ADVANCE                                                                                          \
if (relevant_monitor.buffer.advance(variant->variant_num) != 0)                                                 \
    return -1;


#define GET_BUFFER_RAW(monitor_pointer, size)                                                                          \
void* buffer;                                                                                                          \
int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer, instruction,          \
        &buffer, size);                                                                                                \
if (result < 0)                                                                                                        \
    return result;


#define GET_NULL_BUFFER(monitor_pointer)                                                                               \
int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer, instruction,                 \
        nullptr, 0);                                                                                                   \
if (result < 0)                                                                                                        \
    return result;                                                                                                     \
else if (result != REPLAY_BUFFER_RETURN_FIRST)                                                                         \
{                                                                                                                      \
    REPLAY_BUFFER_ADVANCE                                                                                              \
    return 0;                                                                                                          \
}


#define GET_BUFFER_CHECK_OR_FILL(monitor_pointer, to_check, size)                                                      \
void* buffer;                                                                                                          \
int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer, instruction, &buffer, size); \
if (result < 0)                                                                                                        \
    return result;                                                                                                     \
if (result == REPLAY_BUFFER_RETURN_FIRST)                                                                              \
{                                                                                                                      \
    COPY_BUFFER(buffer, to_check, size)                                                                                \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    COMPARE_BUFFERS(buffer, to_check, size)                                                                            \
    REPLAY_BUFFER_ADVANCE                                                                                              \
    return 0;                                                                                                          \
}


#define GET_BUFFER_REPLACE(monitor_pointer, size)                                                                      \
void* buffer;                                                                                                          \
int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer, instruction, &buffer, size); \
if (result < 0)                                                                                                        \
    return result;                                                                                                     \
if (result == REPLAY_BUFFER_RETURN_FIRST)                                                                              \
{                                                                                                                      \
    COPY_BUFFER(buffer, monitor_pointer, size)                                                                         \
}                                                                                                                      \
monitor_pointer = buffer;


#define GET_BUFFER_IMITATE_RESULT(monitor_pointer, destination_buffer, size)                                           \
void* buffer;                                                                                                          \
int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer, instruction, &buffer, size); \
if (result < 0)                                                                                                        \
    return result;                                                                                                     \
if (result != REPLAY_BUFFER_RETURN_FIRST)                                                                              \
{                                                                                                                      \
    COPY_BUFFER(destination_buffer, buffer, size)                                                                      \
    REPLAY_BUFFER_ADVANCE                                                                                              \
    return 0;                                                                                                          \
}                                                                                                                      \
monitor_pointer = buffer;


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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_REG_CODE)

        unsigned long long mask = (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction)) ?
                0xffffffffffffffff : (PREFIXES_GRP_THREE_PRESENT(instruction) ? 0xffff : 0xffffffff);

        GET_BUFFER_RAW(destination, 2 * sizeof(unsigned long long))
        auto buffer_src   = (unsigned long long*) buffer;
        auto buffer_flags = ((unsigned long long*) buffer) + 1;
        if (result != REPLAY_BUFFER_RETURN_FIRST)
        {
            if ((*(unsigned long long*) source & mask) != (*buffer_src & mask))
                return -1;

            regs_struct->eflags = *buffer_flags;
            REPLAY_BUFFER_ADVANCE
            return 0;
        }

        *buffer_src = *(unsigned long long*) source & mask;

        // lock forced here
        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "pushf;"
                    "push QWORD PTR [rcx];"
                    "popf;"
                    "mov rdx, QWORD PTR [rdx];"
                    "lock add QWORD PTR [rax], rdx;"
                    "pushf;"
                    "pop QWORD PTR [rcx];"
                    "popf;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source), "c" (&regs_struct->eflags)
                    :
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "pushf;"
                    "push QWORD PTR [rcx];"
                    "popf;"
                    "mov dx, WORD PTR [rdx];"
                    "lock add WORD PTR [rax], dx;"
                    "pushf;"
                    "pop QWORD PTR [rcx];"
                    "popf;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source), "c" (&regs_struct->eflags)
                    :
            );
        }
        // 32-bit
        else
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "pushf;"
                    "push QWORD PTR [rcx];"
                    "popf;"
                    "mov edx, DWORD PTR [rdx];"
                    "lock add DWORD PTR [rax], edx;"
                    "pushf;"
                    "pop QWORD PTR [rcx];"
                    "popf;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source), "c" (&regs_struct->eflags)
                    :
            );
        }

        *buffer_flags = regs_struct->eflags;

        // no need to do any write backs here, only general purpose registers changed
        REPLAY_BUFFER_ADVANCE
        return 0;
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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_REPLACE(source, 8)
            __asm
            (
                    ".intel_syntax noprefix;"
                    "pushf;"
                    "push QWORD PTR [rcx];"
                    "popf;"
                    "mov rdx, QWORD PTR [rdx];"
                    "add QWORD PTR [rax], rdx;"
                    "pushf;"
                    "pop QWORD PTR [rcx];"
                    "popf;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source), "c" (&regs_struct->eflags)
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_REPLACE(source, 2)
            __asm
            (
                    ".intel_syntax noprefix;"
                    "pushf;"
                    "push QWORD PTR [rcx];"
                    "popf;"
                    "mov dx, WORD PTR [rdx];"
                    "add WORD PTR [rax], dx;"
                    "pushf;"
                    "pop QWORD PTR [rcx];"
                    "popf;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source), "c" (&regs_struct->eflags)
            );
        }
        // 32-bit
        else
        {
            GET_BUFFER_REPLACE(source, 4)
            __asm
            (
                    ".intel_syntax noprefix;"
                    "pushf;"
                    "push QWORD PTR [rcx];"
                    "popf;"
                    "mov r15, QWORD PTR [rax];"
                    "add r15d, DWORD PTR [rdx];"
                    "mov QWORD PTR [rax], r15;"
                    "pushf;"
                    "pop QWORD PTR [rcx];"
                    "popf;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source), "c" (&regs_struct->eflags)
            );
        }

        // registers will be written back anyway
        REPLAY_BUFFER_ADVANCE
        return 0;
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

        GET_BUFFER_REPLACE(source, 16)

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
        {
            REPLAY_BUFFER_ADVANCE
            return 0;
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
        LOAD_SRC_AND_DST(DEFINE_FPREGS_STRUCT, xmm_lookup, LOAD_RM_CODE, LOAD_REG_CODE)

        GET_BUFFER_CHECK_OR_FILL(destination, source, 16)

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


        // no write back needed
        REPLAY_BUFFER_ADVANCE
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


/* Valid in second round */
BYTE_EMULATOR_IMPL(0x29)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // size and register type is the same, regardless of prefix
        LOAD_SRC_AND_DST(DEFINE_FPREGS_STRUCT, xmm_lookup, LOAD_RM_CODE, LOAD_REG_CODE)

        GET_BUFFER_CHECK_OR_FILL(destination, source, 16)

        // movapd xmm/m128, xmm
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "movups xmm0, XMMWORD PTR [rdx];"
                    "movapd XMMWORD PTR [rax], xmm0;"
                    ".att_syntax"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "xmm0"
            );
        }
        // movaps xmm/m128, xmm
        else
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "movups xmm0, XMMWORD PTR [rdx];"
                    "movaps XMMWORD PTR [rax], xmm0;"
                    ".att_syntax"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "xmm0"
            );
        }

        // source is register, no write back needed
        REPLAY_BUFFER_ADVANCE
        return 0;
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0x2a)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x2b)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // sub Gv, Ev
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)


        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_REPLACE(source, 8)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov rdx, QWORD PTR [rdx];"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "sub QWORD PTR [rax], rdx;"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source), "c" (&regs_struct->eflags)
                    :
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_REPLACE(source, 2)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov dx, WORD PTR [rdx];"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "sub WORD PTR [rax], dx;"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source), "c" (&regs_struct->eflags)
                    :
            );
        }
        // 32-bit
        else
        {
            GET_BUFFER_REPLACE(source, 4)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov r8, QWORD PTR [rax];"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "sub r8d, DWORD PTR [rdx];"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    "mov QWORD PTR [rax], r8;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source), "c" (&regs_struct->eflags)
                    : "r8"
            );
        }

        // registers will be written back anyway
        REPLAY_BUFFER_ADVANCE
        return 0;
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


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x3b)
{
    // cmp Gv, Ev
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_REPLACE(source, 8)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov rdx, QWORD PTR [rdx];"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "cmp QWORD PTR [rax], rdx;"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source), "c" (&regs_struct->eflags)
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_REPLACE(source, 2)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov dx, WORD PTR [rdx];"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "cmp WORD PTR [rax], dx;"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source), "c" (&regs_struct->eflags)
            );
        }
        // 32-bit
        else
        {
            GET_BUFFER_REPLACE(source, 4)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov r15, QWORD PTR [rax];"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "cmp r15d, DWORD PTR [rdx];"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    "mov QWORD PTR [rax], r15;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source), "c" (&regs_struct->eflags)
                    : "r15"
            );
        }

        // registers will be written back anyway
        REPLAY_BUFFER_ADVANCE
        return 0;
    }

    // illegal otherwise
    return 1;
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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        // movsxd r64, r/m32
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_REPLACE(source, 8)
            __asm
            (
                    ".intel_syntax noprefix;"
                    "movsxd rdx, DWORD PTR[rdx];"
                    "mov QWORD PTR[rax], rdx;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    :
            );
        }
        // movsxd r32, r/m32 | movsxd r16, r/m16
        else
        {
            // these aren't behaving well
            return -1;
        }

        // general purpose regs will be written back by default
        REPLAY_BUFFER_ADVANCE
        return 0;
    }

    // illegal otherwise
    return -1;
}


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
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        LOAD_SRC_AND_DST(DEFINE_FPREGS_STRUCT, xmm_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        // movdqu xmm, xmm/m128 if f3 prefix is present
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE)
        {
            GET_BUFFER_REPLACE(source, 16)

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
            GET_BUFFER_REPLACE(source, 16)

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
        else
            return -1;


        // write back regs, always needed here
        if (interaction::write_all_fpregs(*instruction.variant_pid, regs_struct))
        {
            REPLAY_BUFFER_ADVANCE
            return 0;
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

            GET_BUFFER_REPLACE(source, 16)

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

            GET_BUFFER_REPLACE(source, 8)

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
        {
            REPLAY_BUFFER_ADVANCE
            return 0;
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
// BYTE_EMULATOR_IMPL(0x7f)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x80)
{
    // Immediate Grp 1 Eb, Ib
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_IMM)

        GET_BUFFER_IMITATE_RESULT(destination, &(regs_struct->eflags), 8)

        // ModR/M reg field used as opcode extension
        switch (GET_REG_CODE(modrm))
        {
            case 0b000u: // ADD - not yet implemented
            case 0b001u: // OR  - not yet implemented
            case 0b010u: // ADC - not yet implemented
            case 0b011u: // SBB - not yet implemented
                return -1;
            case 0b100u: // AND - and r/m8, imm8
            {
                // perform operation, note that the flags register is also changed here
                __asm
                (
                        ".intel_syntax noprefix;"
                        "pushfq;"
                        "push QWORD PTR [rcx];"
                        "popfq;"
                        "mov r15b, BYTE PTR [rdx];"
                        "and BYTE PTR [rax], r15b;"
                        "pushfq;"
                        "pop QWORD PTR [rcx];"
                        "popfq;"
                        ".att_syntax;"
                        :
                        : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                        : "r15"
                );

                break;
            }
            case 0b101u: // SUB - not yet implemented
            case 0b110u: // XOR - not yet implemented
                return -1;
            case 0b111u: // CMP - CMP r/m8, imm8
            {
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
                        : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                        : "r15"
                );

                break;
            }

            default:
                return -1;
        }

        COPY_BUFFER(buffer, &(regs_struct->eflags), 8)

        // registers will be written back with rip
        REPLAY_BUFFER_ADVANCE
        return 0;
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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_REG_CODE)

        GET_BUFFER_IMITATE_RESULT(destination, &(regs_struct->eflags), 8)

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
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "xor r15, r15;"
                            "mov r15d, DWORD PTR [rdx];"
                            "and QWORD PTR [rax], r15;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            : "r15"
                    );
                }
                // and r/m16, imm16
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "mov dx, WORD PTR [rdx];"
                            "and WORD PTR [rax], dx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            :
                    );
                }
                // and r/m32, imm32
                else
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "mov edx, DWORD PTR [rdx];"
                            "and DWORD PTR [rax], edx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            :
                    );
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
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "movsxd rdx, DWORD PTR [rdx];"
                            "cmp QWORD PTR [rax], rdx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            :
                    );
                }
                // cmp r/m16, imm16
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "mov dx, WORD PTR [rdx];"
                            "cmp WORD PTR [rax], dx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            :
                    );
                }
                // cmp r/m32, imm32
                else
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "mov edx, DWORD PTR [rdx];"
                            "cmp DWORD PTR [rax], edx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            :
                    );
                }

                break;
            }

            default:
                return -1;
        }

        COPY_BUFFER(buffer, &(regs_struct->eflags), 8)

        // general purpose registers will be written back by default
        REPLAY_BUFFER_ADVANCE
        return 0;
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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_IMM)

        GET_BUFFER_RAW(destination, sizeof(unsigned long long))
        if (result != REPLAY_BUFFER_RETURN_FIRST)
        {
            regs_struct->eflags = *(unsigned long long*) buffer;
            REPLAY_BUFFER_ADVANCE
            return 0;
        }

        switch (GET_REG_CODE((unsigned ) instruction[instruction.effective_opcode_index + 1]))
        {
            case 0b000u: // ADD - add r/m(16,32,64), imm8
            {
                // perform operation, note that the flags register is also changed here
                // add r/m64, imm8
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "movsx rdx, BYTE PTR [rdx];"
                            "add QWORD PTR [rax], rdx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a"(destination), [src] "d"(source), [flags] "c"(&(regs_struct->eflags))
                            :
                    );
                }
                // add r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "movsx dx, BYTE PTR [rdx];"
                            "add WORD PTR [rax], dx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            :
                    );
                }
                // add r/m32, imm8
                else
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "movsx edx, BYTE PTR [rdx];"
                            "add DWORD PTR [rax], edx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            :
                    );
                }

                break;
            }
            case 0b001u: // OR  - not yet implemented
            {
                // perform operation, note that the flags register is also changed here
                // or r/m64, imm8
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "movsx rdx, BYTE PTR [rdx];"
                            "or QWORD PTR [rax], rdx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a"(destination), [src] "d"(source), [flags] "c"(&(regs_struct->eflags))
                            :
                    );
                }
                    // or r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    __asm
                    (
                    ".intel_syntax noprefix;"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "movsx dx, BYTE PTR [rdx];"
                    "or WORD PTR [rax], dx;"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                    :
                    );
                }
                    // add r/m32, imm8
                else
                {
                    __asm
                    (
                    ".intel_syntax noprefix;"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "movsx edx, BYTE PTR [rdx];"
                    "or DWORD PTR [rax], edx;"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                    :
                    );
                }

                break;
            }
            case 0b010u: // ADC - not yet implemented
            case 0b011u: // SBB - not yet implemented
            case 0b100u: // AND - not yet implemented
            case 0b101u: // SUB - not yet implemented
            {
                // perform operation, note that the flags register is also changed here
                // or r/m64, imm8
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    __asm
                    (
                    ".intel_syntax noprefix;"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "movsx rdx, BYTE PTR [rdx];"
                    "sub QWORD PTR [rax], rdx;"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    ".att_syntax;"
                    :
                    : [dst] "a"(destination), [src] "d"(source), [flags] "c"(&(regs_struct->eflags))
                    :
                    );
                }
                    // or r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    __asm
                    (
                    ".intel_syntax noprefix;"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "movsx dx, BYTE PTR [rdx];"
                    "sub WORD PTR [rax], dx;"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                    :
                    );
                }
                    // add r/m32, imm8
                else
                {
                    __asm
                    (
                    ".intel_syntax noprefix;"
                    "pushfq;"
                    "push QWORD PTR [rcx];"
                    "popfq;"
                    "movsx edx, BYTE PTR [rdx];"
                    "sub DWORD PTR [rax], edx;"
                    "pushfq;"
                    "pop QWORD PTR [rcx];"
                    "popfq;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                    :
                    );
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
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "movsx rdx, BYTE PTR [rdx];"
                            "cmp QWORD PTR [rax], rdx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a"(destination), [src] "d"(source), [flags] "c"(&(regs_struct->eflags))
                            :
                    );
                }
                // cmp r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "movsx dx, BYTE PTR [rdx];"
                            "cmp WORD PTR [rax], dx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            :
                    );
                }
                // cmp r/m32, imm8
                else
                {
                    __asm
                    (
                            ".intel_syntax noprefix;"
                            "pushfq;"
                            "push QWORD PTR [rcx];"
                            "popfq;"
                            "movsx edx, BYTE PTR [rdx];"
                            "cmp DWORD PTR [rax], edx;"
                            "pushfq;"
                            "pop QWORD PTR [rcx];"
                            "popfq;"
                            ".att_syntax;"
                            :
                            : [dst] "a" (destination), [src] "d" (source), [flags] "c" (&(regs_struct->eflags))
                            :
                    );
                }

                break;
            }
            default:
                return -1;
        }

        *(unsigned long long*) buffer = regs_struct->eflags;

        // general purpose registers will be written back by default
        REPLAY_BUFFER_ADVANCE
        return 0;
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


/* Not implemented - blocked */
BYTE_EMULATOR_IMPL(0x87)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_REG_CODE)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_RAW(destination, 2 * sizeof(__uint64_t))
            auto orig_src = (__uint64_t*) buffer;
            auto repl_src = ((__uint64_t*) buffer) + 1;

            if (result != REPLAY_BUFFER_RETURN_FIRST)
            {
                if (*orig_src != *(__uint64_t*) source)
                    return -1;

                *(__uint64_t*) source = *repl_src;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }

            *orig_src = *(__uint64_t*) source;
            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov r15, QWORD PTR [rdx];"
                    "lock xchg QWORD PTR [rax], r15;"
                    "mov QWORD PTR [rdx], r15;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    : "r15"
            );
            *repl_src = *(__uint64_t*) source;
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_RAW(destination, 2 * sizeof(__uint16_t))
            auto orig_src = (__uint16_t*) buffer;
            auto repl_src = ((__uint16_t*) buffer) + 1;

            if (result != REPLAY_BUFFER_RETURN_FIRST)
            {
                if (*orig_src != *(__uint16_t*) source)
                    return -1;

                *(__uint16_t*) source = *repl_src;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }

            *orig_src = *(__uint16_t*) source;
            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov r15w, WORD PTR [rdx];"
                    "lock xchg WORD PTR [rax], r15w;"
                    "mov WORD PTR [rdx], r15w;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    : "r15"
            );
            *repl_src = *(__uint16_t*) source;
        }
        // 32-bit
        else
        {
            GET_BUFFER_RAW(destination, 2 * sizeof(__uint32_t))
            auto orig_src = (__uint32_t*) buffer;
            auto repl_src = ((__uint32_t*) buffer) + 1;

            if (result != REPLAY_BUFFER_RETURN_FIRST)
            {
                if (*orig_src != *(__uint32_t*) source)
                    return -1;

                *(__uint32_t*) source = *repl_src;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }

            *orig_src = *(__uint32_t*) source;
            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov r15d, DWORD PTR [rdx];"
                    "lock xchg DWORD PTR [rax], r15d;"
                    "mov DWORD PTR [rdx], r15d;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    : "r15"
            );
            *repl_src = *(__uint32_t*) source;
        }

        // no need to write back registers here
        REPLAY_BUFFER_ADVANCE
        return 0;
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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_REG_CODE_BYTE)

        // special case that uses higher order lower byte, for example ah
        if (!PREFIXES_REX_PRESENT(instruction) && GET_REG_CODE((unsigned) modrm) & 0b100u)
            source = (void*) ((unsigned long long) source + 1);

        GET_BUFFER_CHECK_OR_FILL(destination, source, 1)

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
        REPLAY_BUFFER_ADVANCE
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
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_CHECK_OR_FILL(destination, source, 8)
            /*
            void* buffer;
            int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, destination, instruction,
                    &buffer, sizeof (unsigned long long) + sizeof(int));
            auto content         = (unsigned long long*) buffer;
            auto leading_variant = (int*) ((unsigned long long*) buffer + 1);
            if (result < 0)
                return result;
            if (result == REPLAY_BUFFER_RETURN_FIRST)
            {
                *content         = *(unsigned long long*) source;
                *leading_variant = variant->variant_num;
            }
            else if (*(unsigned long long*) buffer == *(unsigned long long*) source)
            {
                REPLAY_BUFFER_ADVANCE
                return 0;
            }
            else if (relevant_monitor.same_address(*leading_variant, *content, variant->variant_num,
                    *(unsigned long long*) source))
            {
                warnf("same memory region detected\n\n");
                REPLAY_BUFFER_ADVANCE
                return 0;
            }
            else
            {
                warnf("sources don't match\n\n");
                return -1;
            }
            */

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
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_CHECK_OR_FILL(destination, source, 2)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov dx, WORD PTR [rdx];"
                    "mov WORD PTR [rax], dx;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    :
            );
        }
        // default 32-bit
        else
        {
            GET_BUFFER_CHECK_OR_FILL(destination, source, 4)

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

        // no need to write back any registers
        REPLAY_BUFFER_ADVANCE
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

        GET_BUFFER_REPLACE(source, 1)

        __asm
        (
                ".intel_syntax noprefix;"
                "mov dl, BYTE PTR [rdx];"
                "mov BYTE PTR [rax], dl;"
                ".att_syntax;"
                :
                : [dst] "a" (destination), [src] "d" (buffer)
                :
        );

        // registers will be written back with rip
        REPLAY_BUFFER_ADVANCE
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
            GET_BUFFER_REPLACE(source, 8)

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
        // 16-bit version
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_REPLACE(source, 2)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov dx, WORD PTR [rdx];"
                    "mov WORD PTR [rax], dx;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    :
            );
        }
        // 32-bit version
        else
        {
            GET_BUFFER_REPLACE(source, 4)

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov edx, DWORD PTR [rdx];"
                    "mov QWORD PTR [rax], rdx;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    :
            );
        }

        // registers will be written back with rip
        REPLAY_BUFFER_ADVANCE
        return 0;
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
BYTE_EMULATOR_IMPL(0xa4)
{
    // movsb
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // gonna be using general purpose registers
        DEFINE_REGS_STRUCT

        void* source;
        void* destination;
        bool src_spoof = false;
        bool dst_spoof = false;
        unsigned long long size = PREFIXES_GRP_ONE_PRESENT(instruction) &&
                (PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE ||
                 PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE) ? regs_struct->rcx : 1;

        // source is known to be shared memory
        if ((void*) (regs_struct->rsi & ~SHARED_MEMORY_ADDRESS_TAG) == instruction.effective_address)
        {
            // source to monitor pointer
            if (instruction_intent::determine_monitor_pointer(relevant_monitor, variant,
                    instruction.effective_address, &source, size) < 0)
                return -1;

            // check if destination is shared memory, or regular variant memory
            int result = instruction_intent::determine_monitor_pointer(relevant_monitor, variant,
                    (void*) ((regs_struct->rdi & SHARED_MEMORY_ADDRESS_TAG) == SHARED_MEMORY_ADDRESS_TAG ?
                            regs_struct->rdi & ~SHARED_MEMORY_ADDRESS_TAG : regs_struct->rdi), &destination, size);
            if (result == NO_REGION_INFO)
            {
                destination = (void*) regs_struct->rdi;
                dst_spoof = true;
            }
            else if (result < 0)
                return -1;
        }
        // destination is known shared memory
        else if ((void*) (regs_struct->rdi & ~SHARED_MEMORY_ADDRESS_TAG) == instruction.effective_address)
        {
            // destination to monitor pointer
            if (instruction_intent::determine_monitor_pointer(relevant_monitor, variant,
                    instruction.effective_address, &destination, size) < 0)
                return -1;

            // check if source is shared memory, or regular variant memory
            int result = instruction_intent::determine_monitor_pointer(relevant_monitor, variant,
                    (void*) ((regs_struct->rsi & SHARED_MEMORY_ADDRESS_TAG) == SHARED_MEMORY_ADDRESS_TAG ?
                            regs_struct->rsi & ~SHARED_MEMORY_ADDRESS_TAG : regs_struct->rsi), &source, size);
            if (result == NO_REGION_INFO)
            {
                source = (void*) regs_struct->rsi;
                src_spoof = true;
            }
            else if (result < 0)
                return -1;
        }
        // we would expect one of the two to be known shared memory
        else
            return -1;


        // replay and spoofing
        GET_BUFFER_RAW((src_spoof ? destination : source),
                       ((!src_spoof && !dst_spoof) ? sizeof(void*) : (dst_spoof ? size : 0)) +
                       (sizeof(unsigned long long) * 2))
        auto rcx_result = (unsigned long long*) buffer;
        auto efalgs_result = (unsigned long long*) ((unsigned long long) buffer + sizeof(unsigned long long));
        void** actual_buffer = src_spoof ? nullptr :
                (void**) ((unsigned long long) buffer + (sizeof(unsigned long long) * 2));

        // imitate
        if (result != REPLAY_BUFFER_RETURN_FIRST)
        {
            if (!dst_spoof && !src_spoof && destination != *actual_buffer)
            {
                warnf("second address mismatch\n");
                return -1;
            }
            else if (dst_spoof && !interaction::write_memory(variant->variantpid, destination, (long long) size,
                    actual_buffer))
            {
                warnf("could not write data to variant\n");
                return -1;
            }

            *rcx_result    = regs_struct->rcx;
            *efalgs_result = regs_struct->eflags;

            REPLAY_BUFFER_ADVANCE
            return 0;
        }


        // spoof
        void* spoof = src_spoof ? malloc(size) : actual_buffer;
        if (src_spoof)
        {
            if (!spoof)
            {
                warnf("problem setting up spoof buffer\n");
                return -1;
            }

            if (!interaction::read_memory(variant->variantpid, source, (signed long long) size, spoof))
            {
                warnf("could not read source to spoof\n");
                return -1;
            }
        }


        // different option for repeating
        if (PREFIXES_GRP_ONE_PRESENT(instruction) &&
            (PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE ||
             PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE))
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "pushf;"
                    "push QWORD PTR [rbx];"
                    "popf;"
                    "mov r8, rcx;"
                    "mov rcx, QWORD PTR [r8];"
                    "mov rsi, rdx;"
                    "mov rdi, rax;"
                    "rep movsb;"
                    "mov QWORD PTR [r8], rcx;"
                    "pushf;"
                    "pop QWORD PTR [rbx];"
                    "popf;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (dst_spoof ? spoof : destination), [src] "d" (src_spoof ? spoof : source),
                            [count] "c" (&regs_struct->rcx), [flags] "b" (&regs_struct->eflags)
                    : "r8"
            );

            if (dst_spoof && !interaction::write_memory(variant->variantpid, destination, (long) size, spoof))
            {
                warnf("movsb could not write back destination\n");
                return -1;
            }
            if (src_spoof)
                free(spoof);

            *rcx_result    = regs_struct->rcx;
            *efalgs_result = regs_struct->eflags;
            if (!src_spoof && !dst_spoof)
                *actual_buffer = destination;

            REPLAY_BUFFER_ADVANCE
            return 0;
        }
        // non repeating
        else
        {
            return -1;
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


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xaa)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0xab)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // we're in need of rax as source
        DEFINE_REGS_STRUCT

        void* monitor_pointer;
        if (instruction_intent::determine_monitor_pointer(relevant_monitor, variant, instruction.effective_address,
                                                          &monitor_pointer) != 0)
            return -1;
        void* source = shared_mem_register_access::ACCESS_GENERAL_NAME(rax)(regs_struct);

        // stos m64
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_RAW(monitor_pointer, 8)
            if (result == REPLAY_BUFFER_RETURN_FIRST)
                *(__uint64_t*) buffer = *(__uint64_t*) source;
            else if (*(__uint64_t*) buffer == *(__uint64_t*) source)
            {
                if (regs_struct->eflags & (0b1u << 10u))
                    regs_struct->rdi -= 8;
                else
                    regs_struct->rdi += 8;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }
            else
                return -1;

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov rdi, rdx;"
                    "stosq;"
                    ".att_syntax;"
                    :
                    : "a" (*(__uint64_t*) source), "d" (monitor_pointer)
            );

            if (regs_struct->eflags & (0b1u << 10u))
                regs_struct->rdi -= 8;
            else
                regs_struct->rdi += 8;
        }
        // stos m16
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_RAW(monitor_pointer, 2)
            if (result == REPLAY_BUFFER_RETURN_FIRST)
                *(__uint16_t*) buffer = *(__uint16_t*) source;
            else if (*(__uint16_t*) buffer == *(__uint16_t*) source)
            {
                if (regs_struct->eflags & (0b1u << 10u))
                    regs_struct->rdi -= 2;
                else
                    regs_struct->rdi += 2;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }
            else
                return -1;

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov rdi, rdx;"
                    "stosw;"
                    ".att_syntax;"
                    :
                    : "a" (*(__uint16_t*) source), "d" (monitor_pointer)
            );

            if (regs_struct->eflags & (0b1u << 10u))
                regs_struct->rdi -= 2;
            else
                regs_struct->rdi += 2;
        }
        // stos m32
        else
        {
            GET_BUFFER_RAW(monitor_pointer, 2)
            if (result == REPLAY_BUFFER_RETURN_FIRST)
                *(__uint32_t*) buffer = *(__uint32_t*) source;
            else if (*(__uint32_t*) buffer == *(__uint32_t*) source)
            {
                if (regs_struct->eflags & (0b1u << 10u))
                    regs_struct->rdi -= 2;
                else
                    regs_struct->rdi += 2;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }
            else
                return -1;

            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov rdi, rdx;"
                    "stosd;"
                    ".att_syntax;"
                    :
                    : "a" (*(__uint32_t*) source), "d" (monitor_pointer)
            );

            if (regs_struct->eflags & (0b1u << 10u))
                regs_struct->rdi -= 2;
            else
                regs_struct->rdi += 2;
        }

        REPLAY_BUFFER_ADVANCE
        return 0;
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


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xb1)
{
    // cmpxchg Ev, Gv
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // affects flags as well
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_REG_CODE)

        // we're saving the source to compare later, the result to imitate it later, and the eflags to imitate as well
        GET_BUFFER_RAW(destination, (sizeof(unsigned long long) * 4))
        auto buffer_source   = (unsigned long long*) buffer;
        auto buffer_orig_rax = (unsigned long long*) buffer + 1;
        auto buffer_rax      = (unsigned long long*) buffer + 2;
        auto buffer_eflags   = (unsigned long long*) buffer + 3;

        if (result == REPLAY_BUFFER_RETURN_FIRST)
        {
            *buffer_orig_rax = variant->regs.rax;
            *buffer_source = *(unsigned long long*) source;
        }
        else if (result != REPLAY_BUFFER_RETURN_FIRST)
        {
            if (*buffer_source != *(unsigned long long*) source && regs_struct->rax != *buffer_orig_rax)
                return -1;
            unsigned long long mask = (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction)) ?
                    0xffffffffffffffff : (PREFIXES_GRP_THREE_PRESENT(instruction) ? 0xffff : 0xffffffff);
            regs_struct->rax &= ~mask;
            regs_struct->rax |= mask & *buffer_rax;
            regs_struct->eflags = *buffer_eflags;

            REPLAY_BUFFER_ADVANCE
            return 0;
        }


        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            // todo - always executed with LOCK for now, might not be the best
            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov rcx, QWORD PTR [rcx];"
                    "mov rax, QWORD PTR [rsi];"
                    "pushfq;"
                    "push QWORD PTR [rbx];"
                    "popfq;"
                    "lock cmpxchg QWORD PTR [rdx], rcx;"
                    "pushfq;"
                    "pop QWORD PTR [rbx];"
                    "popfq;"
                    "mov QWORD PTR [rsi], rax;"
                    ".att_syntax;"
                    :
                    : [dst] "d" (destination), [src] "c" (source),
                        [flags] "b" (&regs_struct->eflags), "S" (&regs_struct->rax)
                    :
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov cx, WORD PTR [rcx];"
                    "mov ax, WORD PTR [rsi];"
                    "pushfq;"
                    "push QWORD PTR [rbx];"
                    "popfq;"
                    "lock cmpxchg WORD PTR [rdx], cx;"
                    "pushfq;"
                    "pop QWORD PTR [rbx];"
                    "popfq;"
                    "mov WORD PTR [rsi], ax;"
                    ".att_syntax;"
                    :
                    : [dst] "d" (destination), [src] "c" (source),
                            [flags] "b" (&regs_struct->eflags), "S" (&regs_struct->rax)
                    :
            );
        }
        // 32-bit
        else
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov ecx, DWORD PTR [rcx];"
                    "mov eax, DWORD PTR [rsi];"
                    "pushfq;"
                    "push QWORD PTR [rbx];"
                    "popfq;"
                    "lock cmpxchg DWORD PTR [rdx], ecx;"
                    "pushfq;"
                    "pop QWORD PTR [rbx];"
                    "popfq;"
                    "mov DWORD PTR [rsi], eax;"
                    ".att_syntax;"
                    :
                    : [dst] "d" (destination), [src] "c" (source),
                        [flags] "b" (&regs_struct->eflags), "S" (&regs_struct->rax)
                    :
            );
        }

        *buffer_rax = regs_struct->rax;
        *buffer_eflags = regs_struct->eflags;

        // general purpose registers are written back with rip by default
        REPLAY_BUFFER_ADVANCE
        return 0;
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
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        GET_BUFFER_REPLACE(source, 1)

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
        // 16-bit size
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movzx r15, BYTE PTR [rdx];"
                    "mov WORD PTR [rax], r15w;"
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
                    "mov QWORD PTR [rax], r15;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "r15"
            );
        }

        // registers will be written back with rip
        REPLAY_BUFFER_ADVANCE
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
        // movzx Gv, Ew
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        GET_BUFFER_REPLACE(source, 2)

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
        // 16-bit size
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movzx r15d, WORD PTR [rdx];"
                    "mov WORD PTR [rax], r15w;"
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
                    "mov QWORD PTR [rax], r15;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "r15"
            );
        }

        // registers will be written back with rip
        REPLAY_BUFFER_ADVANCE
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


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xbe)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // movsx Gv, Eb
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_REG_CODE, LOAD_RM_CODE)

        // always byte
        GET_BUFFER_REPLACE(source, 2)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "movsx r15, BYTE PTR [rdx];"
                    "mov QWORD PTR [rax], r15;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    : "r15"
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "movsx r15w, BYTE PTR [rdx];"
                    "mov WORD PTR [rax], r15w;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    : "r15"
            );
        }
        // 32-bit
        else
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "movsx r15d, BYTE PTR [rdx];"
                    "mov QWORD PTR [rax], r15;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    : "r15"
            );
        }

        // registers written back by default
        REPLAY_BUFFER_ADVANCE
        return 0;
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xbf)


/* Not implemented - blocked */
// BYTE_EMULATOR_IMPL(0xc0)


/* Valid in second round */
BYTE_EMULATOR_IMPL(0xc1)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // xadd Ev, Gv
        LOAD_SRC_AND_DST(DEFINE_REGS_STRUCT, general_purpose_lookup, LOAD_RM_CODE, LOAD_REG_CODE)

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_RAW(destination, (sizeof(__uint64_t) * 2))
            auto source_original  = (__uint64_t*) buffer;
            auto source_overwrite = ((__uint64_t*) buffer) + 1;

            if (result != REPLAY_BUFFER_RETURN_FIRST)
            {
                if (*((__uint64_t*) source) != *source_original)
                    return -1;
                *((__uint64_t*) source) = *source_overwrite;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }

            *source_original = *((__uint64_t*) source);

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "mov r15, QWORD PTR [rdx];"
                    "xadd QWORD PTR [rax], r15;"
                    "mov QWORD PTR [rdx], r15;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "r15"
            );

            *source_overwrite = *((__uint64_t*) source);
        }
        // 16-bit size
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_RAW(destination, (sizeof(__uint16_t) * 2))
            auto source_original  = (__uint16_t*) buffer;
            auto source_overwrite = ((__uint16_t*) buffer) + 1;

            if (result != REPLAY_BUFFER_RETURN_FIRST)
            {
                if (*((__uint16_t*) source) != *source_original)
                    return -1;
                *((__uint16_t*) source) = *source_overwrite;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }

            *source_original = *((__uint16_t*) source);

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "mov r15w, WORD PTR [rdx];"
                    "xadd WORD PTR [rax], r15w;"
                    "mov WORD PTR [rdx], r15w;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "r15"
            );

            *source_overwrite = *((__uint16_t*) source);
        }
        // 32-bit size
        else
        {
            GET_BUFFER_RAW(destination, (sizeof(__uint32_t) * 2))
            auto source_original  = (__uint32_t*) buffer;
            auto source_overwrite = ((__uint32_t*) buffer) + 1;

            if (result != REPLAY_BUFFER_RETURN_FIRST)
            {
                if (*((__uint32_t*) source) != *source_original)
                    return -1;
                *((__uint32_t*) source) = *source_overwrite;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }

            *source_original = *((__uint32_t*) source);

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "mov r15d, DWORD PTR [rdx];"
                    "xadd DWORD PTR [rax], r15d;"
                    "mov DWORD PTR [rdx], r15d;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "r15"
            );

            *source_overwrite = *((__uint32_t*) source);
        }

        // registers will be written back in a bit
        REPLAY_BUFFER_ADVANCE
        return 0;
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
        // local temporary modrm byte copy
        __uint8_t modrm = instruction.instruction[instruction.effective_opcode_index + 1];

        // define source
        void* source;
        LOAD_IMM(source, ignored_anyway)

        // define destination
        void* destination;
        LOAD_RM_CODE(destination, ignored_anyway)

        GET_BUFFER_RAW(destination, 1)

        if (result != REPLAY_BUFFER_RETURN_FIRST)
        {
            // nothing to do here, it's fine if the buffer obtaining passes
            REPLAY_BUFFER_ADVANCE
            return 0;
        }

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
        REPLAY_BUFFER_ADVANCE
        return 0;
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0xc7)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // small test
        __uint8_t modrm = instruction[instruction.effective_opcode_index + 1];
        if (GET_REG_CODE((unsigned) modrm) != 0b000u)
            return -1;

        void* destination;
        LOAD_RM_CODE(destination, ignore)

        void* source;
        LOAD_IMM(source, ignore)

        GET_NULL_BUFFER(destination)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "movsxd r15, DWORD PTR [rdx];"
                    "mov QWORD PTR [rax], r15;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    : "r15"
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov r15w, WORD PTR [rdx];"
                    "mov WORD PTR [rax], r15w;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    : "r15"
            );
        }
        // 32-bit
        else
        {
            __asm
            (
                    ".intel_syntax noprefix;"
                    "mov r15d, DWORD PTR [rdx];"
                    "mov DWORD PTR [rax], r15d;"
                    ".att_syntax;"
                    :
                    : "a" (destination), "d" (source)
                    : "r15"
            );
        }

        // no register writeback needed
        REPLAY_BUFFER_ADVANCE
        return 0;
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

            GET_BUFFER_REPLACE(source, 16)

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

            GET_BUFFER_REPLACE(source, 8)

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
        {
            REPLAY_BUFFER_ADVANCE
            return 0;
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