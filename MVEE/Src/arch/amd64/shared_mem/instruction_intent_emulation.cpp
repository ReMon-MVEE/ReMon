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
#include "instruction_intent_emulation.h"


// =====================================================================================================================
//      macros
// =====================================================================================================================
#define DEFINE_REGS_STRUCT                                                                                             \
    user_regs_struct* regs_struct = &variant->regs;                                                                    \
    relevant_monitor.call_check_regs(variant->variant_num);


#define DEFINE_FPREGS_STRUCT                                                                                           \
    user_fpregs_struct* regs_struct = &variant->fpregs;                                                                \
    relevant_monitor.call_check_fpregs(variant->variant_num);


#define DEFINE_MODRM                                                                                                   \
uint8_t modrm = instruction[instruction.effective_opcode_index + 1];


#define LOAD_RM_CODE(__src_or_dst, __size)                                                                             \
LOAD_RM_CODE_NO_DEFINE(__size)                                                                                         \
void* __src_or_dst = (void*) ((unsigned long long) mapping_info->monitor_base + offset);                               \


#define LOAD_RM_CODE_NO_DEFINE(__size)                                                                                 \
/* register if mod bits equal 0b11 */                                                                                  \
if (GET_MOD_CODE((unsigned) modrm) == 0b11u)                                                                           \
    /* For shared memory emulation, this shouldn't happen */                                                           \
    return -1;                                                                                                         \
/* memory reference otherwise, so determine the monitor relevant pointer */                                            \
OBTAIN_SHARED_MAPPING_INFO(__size)                                                                                     \


#define OBTAIN_SHARED_MAPPING_INFO(__size)                                                                             \
shared_monitor_map_info* mapping_info;                                                                                 \
unsigned long long offset;                                                                                             \
if (!(mapping_info = relevant_monitor.set_mmap_table->get_shared_info(                                                 \
        (unsigned long long) instruction.effective_address)))                                                          \
    return UNKNOWN_MEMORY_TERMINATION;                                                                                 \
if ((offset = shm_handling::shared_memory_determine_offset(mapping_info,                                               \
        (unsigned long long) instruction.effective_address, __size)) == (unsigned long long) -1)                       \
    return -1;


#define OBTAIN_SHARED_MAPPING_INFO_NO_DEF(__variant_address, __mapping_info, __offset, __size)                         \
if (!(__mapping_info = relevant_monitor.set_mmap_table->get_shared_info(__variant_address)))                           \
    return UNKNOWN_MEMORY_TERMINATION;                                                                                 \
if ((__offset = shm_handling::shared_memory_determine_offset(__mapping_info, __variant_address, __size))               \
        == (unsigned long long) -1)                                                                                    \
    return -1;


#define LOAD_REG_CODE(__src_or_dst, lookup)                                                                            \
uint8_t reg_rex_extra = PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_R(instruction) ?                       \
        0b1000u : 0;                                                                                                   \
void* __src_or_dst = shared_mem_register_access::lookup[reg_rex_extra | GET_REG_CODE((unsigned) modrm)](regs_struct);


#define LOAD_REG_CODE_BYTE(__src_or_dst, lookup)                                                                       \
uint8_t reg_code = GET_REG_CODE((unsigned) modrm);                                                                     \
if (PREFIXES_REX_PRESENT(instruction))                                                                                 \
{                                                                                                                      \
    if (PREFIXES_REX_FIELD_R(instruction))                                                                             \
        reg_code |= 0b1000u;                                                                                           \
}                                                                                                                      \
else                                                                                                                   \
    reg_code &= ~0b100u;                                                                                               \
void* __src_or_dst = shared_mem_register_access::lookup[reg_code](regs_struct);

#define LOAD_IMM(__src_or_dst)                                                                                         \
if (!instruction.immediate_operand_index)                                                                              \
    return -1;                                                                                                         \
void* __src_or_dst = &instruction.instruction[instruction.immediate_operand_index];


#define GET_INSTRUCTION_ACCESS_SIZE                                                                                    \
((PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction)) ?                                            \
        8 : (PREFIXES_GRP_THREE_PRESENT(instruction) ? 2 : 4))


#define REPLAY_BUFFER_ADVANCE                                                                                          \
if (relevant_monitor.buffer.advance(variant->variant_num) != 0)                                                        \
    return -1;


#define GET_BUFFER_RAW(monitor_pointer, size)                                                                          \
void* buffer;                                                                                                          \
int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer, instruction,                 \
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
    memcpy(buffer, to_check, size);                                                                                    \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    if (memcmp(buffer, to_check, size))                                                                                \
        return -1;                                                                                                     \
    REPLAY_BUFFER_ADVANCE                                                                                              \
    return 0;                                                                                                          \
}


#define GET_BUFFER_CHECK_OR_FILL_WITH_FLAGS(monitor_pointer, to_check, size)                                           \
void* buffer;                                                                                                          \
int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer, instruction, &buffer,        \
    size + sizeof(unsigned long long));                                                                                \
if (result < 0)                                                                                                        \
    return result;                                                                                                     \
if (result == REPLAY_BUFFER_RETURN_FIRST)                                                                              \
{                                                                                                                      \
    memcpy(buffer, to_check, size);                                                                                    \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    if (memcmp(buffer, to_check, size))                                                                                \
        return -1;                                                                                                     \
    regs_struct->eflags = *(unsigned long*) ((unsigned long) buffer + size);                                           \
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
    memcpy(buffer, monitor_pointer, size);                                                                             \
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


#define GET_BUFFER_IMITATE_FLAGS(__monitor_pointer)                                                                    \
void* buffer;                                                                                                          \
int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, __monitor_pointer, instruction, &buffer, 8);  \
if (result < 0)                                                                                                        \
    return result;                                                                                                     \
if (result != REPLAY_BUFFER_RETURN_FIRST)                                                                              \
{                                                                                                                      \
    regs_struct->eflags = *(unsigned long long*) buffer;                                                               \
    REPLAY_BUFFER_ADVANCE                                                                                              \
    return 0;                                                                                                          \
}



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
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

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
            uint64_t* typed_destination = (uint64_t*)destination;
            uint64_t* typed_source = (uint64_t*)source;
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "lock add QWORD PTR [%[dst]], %[src];"
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
            uint16_t* typed_source = (uint16_t*)source;
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "lock add WORD PTR [%[dst]], %[src];"
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
            uint32_t* typed_source = (uint32_t*)source;
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "lock add DWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE(source, GET_INSTRUCTION_ACCESS_SIZE)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_REPLACE(source, 8)
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
            GET_BUFFER_REPLACE(source, 2)
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
            GET_BUFFER_REPLACE(source, 4)
            uint32_t* typed_destination = (uint32_t*)destination;
            NORMAL_FROM_SHARED(uint32_t)
            *(typed_destination + 1) = 0;
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
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, xmm_lookup)
        LOAD_RM_CODE(source, 16)

        GET_BUFFER_REPLACE(source, 16)

        // perform operation
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
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(16)
        LOAD_REG_CODE(source, xmm_lookup)

        // perform operation
        XMM_TO_SHARED(
                __asm__
                (
                ".intel_syntax noprefix;"
                "movups xmm0, XMMWORD PTR [rdx];"
                "movups XMMWORD PTR [rax], xmm0;"
                ".att_syntax;"
                :
                : [dst] "a" (destination), [src] "d" (source)
                : "xmm0"
        ))

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
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // sub Ev, Gv
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        int access_size = GET_INSTRUCTION_ACCESS_SIZE;
        LOAD_RM_CODE(destination, access_size)
        LOAD_REG_CODE(source, general_purpose_lookup)
        GET_BUFFER_CHECK_OR_FILL_WITH_FLAGS(destination, source, access_size)

        // 64-bit
        if (access_size == 8)
        {
            uint64_t* typed_destination = (uint64_t*) destination;
            uint64_t* typed_source = (uint64_t*) source;
            // warnf(" > sub m64, r64 | 0x%lx - 0x%lx\n",
            //       (unsigned long) *typed_destination, (unsigned long) *typed_source);
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
        else if (access_size == 2)
        {
            uint16_t* typed_destination = (uint16_t*) destination;
            uint16_t* typed_source = (uint16_t*) source;
            // warnf(" > sub m16, r16 | 0x%lx - 0x%lx\n",
            //       ((unsigned long) *typed_destination)&0xffffu, ((unsigned long) *typed_source)&0xffffu);
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
            uint32_t* typed_destination = (uint32_t*) destination;
            uint32_t* typed_source = (uint32_t*) source;
            // warnf(" > sub m32, r32 | 0x%lx - 0x%lx\n",
            //       ((unsigned long) *typed_destination)&0xffffffffu, ((unsigned long) *typed_source)&0xffffffffu);
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
        }

        // save content of flags register to repliaction buffer
        *(unsigned long*) ((unsigned long) buffer + access_size) = regs_struct->eflags;
        // registers will be written back on resume.
        REPLAY_BUFFER_ADVANCE
        return 0;
    }
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // size and register type is the same, regardless of prefix
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, 16)
        LOAD_REG_CODE(source, xmm_lookup)

        GET_BUFFER_CHECK_OR_FILL(destination, source, 16)

        // movapd xmm/m128, xmm
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            __asm__
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
            __asm__
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE(source, GET_INSTRUCTION_ACCESS_SIZE)


        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_REPLACE(source, 8)
            uint64_t* typed_destination = (uint64_t*)destination;
            uint64_t* typed_source = (uint64_t*)source;

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
            GET_BUFFER_REPLACE(source, 2)
            uint16_t* typed_destination = (uint16_t*)destination;
            uint16_t* typed_source = (uint16_t*)source;

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
            GET_BUFFER_REPLACE(source, 4)
            uint32_t* typed_destination = (uint32_t*)destination;
            uint32_t* typed_source = (uint32_t*)source;
            *(typed_destination + 1) = 0;

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
        }

        // registers will be written back anyway
        REPLAY_BUFFER_ADVANCE
        return 0;
    }

    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, 16)
        LOAD_REG_CODE(source, xmm_lookup)

        GET_BUFFER_CHECK_OR_FILL(destination, source, 16)

        __asm__
        (
                ".intel_syntax noprefix;"
                "movdqu xmm0, XMMWORD PTR [rdx];"
                "movntps XMMWORD PTR [rax], xmm0;"
                ".att_syntax;"
                :
                : "a" (destination), "d" (source)
                : "xmm0"
        );

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

/* Valid in first round */
BYTE_EMULATOR_IMPL(0x39)
{
    // cmp Ev, Gv
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_REPLACE(destination, 8)
            uint64_t* typed_destination = (uint64_t*)destination;
            uint64_t* typed_source = (uint64_t*)source;

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
            GET_BUFFER_REPLACE(destination, 2)
            uint16_t* typed_destination = (uint16_t*)destination;
            uint16_t* typed_source = (uint16_t*)source;

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
            GET_BUFFER_REPLACE(destination, 4)
            uint32_t* typed_destination = (uint32_t*)destination;
            uint32_t* typed_source = (uint32_t*)source;

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
        REPLAY_BUFFER_ADVANCE
        return 0;
    }

    // illegal otherwise
    return 1;
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
        LOAD_RM_CODE(source, GET_INSTRUCTION_ACCESS_SIZE)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_REPLACE(source, 8)
            uint64_t* typed_destination = (uint64_t*)destination;
            uint64_t* typed_source = (uint64_t*)source;

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
            GET_BUFFER_REPLACE(source, 2)
            uint16_t* typed_destination = (uint16_t*)destination;
            uint16_t* typed_source = (uint16_t*)source;

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
            GET_BUFFER_REPLACE(source, 4)
            uint32_t* typed_destination = (uint32_t*)destination;
            uint32_t* typed_source = (uint32_t*)source;

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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE(source, GET_INSTRUCTION_ACCESS_SIZE)

        // movsxd r64, r/m32
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_REPLACE(source, 4)
            int64_t* typed_destination = (int64_t*)destination;
            int32_t* typed_source = (int32_t*)source;
            *typed_destination = *typed_source;
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
            LOAD_RM_CODE(source, 16)
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
        // movdqa xmm, xmm/m128 if f3 prefix is not present
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            LOAD_REG_CODE(destination, xmm_lookup)
            LOAD_RM_CODE(source, 16)
            GET_BUFFER_REPLACE(source, 16)

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movdqu xmm0, XMMWORD PTR [rdx];"
                    "movdqa XMMWORD PTR [rax], xmm0;"
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
            LOAD_RM_CODE(source, 8)
            GET_BUFFER_REPLACE(source, 8);

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movq mm0, QWORD PTR [rdx];"
                    "movq QWORD PTR [rax], mm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "mm0"
            );
        }

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
        // define regs struct
        DEFINE_FPREGS_STRUCT
        DEFINE_MODRM

        // pcmpeqb xmm, xmm/m128
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            // source rm
            LOAD_RM_CODE(source, 16)
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
            LOAD_RM_CODE(source, 8)
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
BYTE_EMULATOR_IMPL(0x7f)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // movdqu xmm/m128, xmm if f3 prefix is present
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE)
        {
            DEFINE_FPREGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE(destination, 16)
            LOAD_REG_CODE(source, xmm_lookup)
            GET_BUFFER_CHECK_OR_FILL(destination, source, 16)

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
        // movdqa xmm/m128, xmm if f3 prefix is not present
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            DEFINE_FPREGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE(destination, 16)
            LOAD_REG_CODE(source, xmm_lookup)
            GET_BUFFER_CHECK_OR_FILL(destination, source, 16)

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movdqu xmm0, XMMWORD PTR [rdx];"
                    "movdqa XMMWORD PTR [rax], xmm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "xmm0"
            );
        }
        // movq m64, mm
        else
        {
            DEFINE_FPREGS_STRUCT
            DEFINE_MODRM
            LOAD_RM_CODE(destination, 8)
            LOAD_REG_CODE(source, mm_lookup)
            GET_BUFFER_CHECK_OR_FILL(destination, source, 8)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movq mm0, QWORD PTR [rdx];"
                    "movq QWORD PTR [rax], mm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "mm0"
            );
        }


        // no write back needed here
        REPLAY_BUFFER_ADVANCE
        return 0;
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, 1)
        LOAD_IMM(source)

        // replay no spoofing needed
        GET_BUFFER_IMITATE_FLAGS(destination)

        uint8_t* typed_destination = (uint8_t*)destination;
        uint8_t* typed_source = (uint8_t*)source;

        // ModR/M reg field used as opcode extension
        switch (GET_REG_CODE(modrm))
        {
            case 0b000u: // ADD - not yet implemented
                return -1;
            case 0b001u: // OR  - not yet implemented
            {
                // perform operation, note that the flags register is also changed here
                __asm__
                (
                        ".intel_syntax noprefix;"
                        "push %[flags];"
                        "popf;"
                        "or BYTE PTR [%[dst]], %[src];"
                        "pushf;"
                        "pop %[flags];"
                        ".att_syntax;"
                        : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                        : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                        : "cc"
                );

                break;
            }
            case 0b010u: // ADC - not yet implemented
            case 0b011u: // SBB - not yet implemented
                return -1;
            case 0b100u: // AND - and r/m8, imm8
            {
                // perform operation, note that the flags register is also changed here
                __asm__
                (
                        ".intel_syntax noprefix;"
                        "push %[flags];"
                        "popf;"
                        "and BYTE PTR [%[dst]], %[src];"
                        "pushf;"
                        "pop %[flags];"
                        ".att_syntax;"
                        : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                        : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                        : "cc"
                );

                break;
            }
            case 0b101u: // SUB - not yet implemented
            case 0b110u: // XOR - not yet implemented
                return -1;
            case 0b111u: // CMP - CMP r/m8, imm8
            {
                // perform operation, note that the flags register is also changed here
                __asm__
                (
                        ".intel_syntax noprefix;"
                        "push %[flags];"
                        "popf;"
                        "cmp BYTE PTR [%[dst]], %[src];"
                        "pushf;"
                        "pop %[flags];"
                        ".att_syntax;"
                        : [flags] "+r" (regs_struct->eflags)
                        : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" (*typed_source)
                        : "cc"
                );

                break;
            }

            default:
                return -1;
        }

        *(unsigned long long*) buffer = regs_struct->eflags;

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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_IMM(source)

        // replay no spoofing needed
        GET_BUFFER_IMITATE_FLAGS(destination)

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
                    uint64_t* typed_destination = (uint64_t*)destination;
                    int32_t* typed_source = (int32_t*)source;
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "push %[flags];"
                            "popf;"
                            "and QWORD PTR [%[dst]], %[src];"
                            "pushf;"
                            "pop %[flags];"
                            ".att_syntax;"
                            : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                            : [dst] "r" (typed_destination), [src] "r" ((int64_t)*typed_source)
                            : "cc"
                    );
                }
                // and r/m16, imm16
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t* typed_destination = (uint16_t*)destination;
                    uint16_t* typed_source = (uint16_t*)source;
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "push %[flags];"
                            "popf;"
                            "and WORD PTR [%[dst]], %[src];"
                            "pushf;"
                            "pop %[flags];"
                            ".att_syntax;"
                            : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                            : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                            : "cc"
                    );
                }
                // and r/m32, imm32
                else
                {
                    uint32_t* typed_destination = (uint32_t*)destination;
                    uint32_t* typed_source = (uint32_t*)source;
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "push %[flags];"
                            "popf;"
                            "and DWORD PTR [%[dst]], %[src];"
                            "pushf;"
                            "pop %[flags];"
                            ".att_syntax;"
                            : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                            : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                            : "cc"
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
                    uint64_t* typed_destination = (uint64_t*)destination;
                    int32_t* typed_source = (int32_t*)source;
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
                            : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" ((int64_t)*typed_source)
                            : "cc"
                    );
                }
                // cmp r/m16, imm16
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t* typed_destination = (uint16_t*)destination;
                    uint16_t* typed_source = (uint16_t*)source;
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
                // cmp r/m32, imm32
                else
                {
                    uint32_t* typed_destination = (uint32_t*)destination;
                    uint32_t* typed_source = (uint32_t*)source;
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
// BYTE_EMULATOR_IMPL(0x82)


/* Valid in first round */
BYTE_EMULATOR_IMPL(0x83)
{
    // grp 1 r/m(16,32,64), imm8
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_IMM(source)

        GET_BUFFER_IMITATE_FLAGS(destination)

        switch (GET_REG_CODE((unsigned ) instruction[instruction.effective_opcode_index + 1]))
        {
            case 0b000u: // ADD - add r/m(16,32,64), imm8
            {
                // perform operation, note that the flags register is also changed here
                // add r/m64, imm8
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    uint64_t* typed_destination = (uint64_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
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
                            : [dst] "r" (typed_destination), [src] "r" ((int64_t)*typed_source)
                            : "cc"
                    );
                }
                // add r/m16, imm8monitor_pointer
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t* typed_destination = (uint16_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
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
                            : [dst] "r" (typed_destination), [src] "r" ((int16_t)*typed_source)
                            : "cc"
                    );
                }
                // add r/m32, imm8
                else
                {
                    uint32_t* typed_destination = (uint32_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
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
                            : [dst] "r" (typed_destination), [src] "r" ((int32_t)*typed_source)
                            : "cc"
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
                    uint64_t* typed_destination = (uint64_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "push %[flags];"
                            "popf;"
                            "or QWORD PTR [%[dst]], %[src];"
                            "pushf;"
                            "pop %[flags];"
                            ".att_syntax;"
                            : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                            : [dst] "r" (typed_destination), [src] "r" ((int64_t)*typed_source)
                            : "cc"
                    );
                }
                    // or r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t* typed_destination = (uint16_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "push %[flags];"
                            "popf;"
                            "or WORD PTR [%[dst]], %[src];"
                            "pushf;"
                            "pop %[flags];"
                            ".att_syntax;"
                            : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                            : [dst] "r" (typed_destination), [src] "r" ((int16_t)*typed_source)
                            : "cc"
                    );
                }
                    // or r/m32, imm8
                else
                {
                    uint32_t* typed_destination = (uint32_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
                    __asm__
                    (
                            ".intel_syntax noprefix;"
                            "push %[flags];"
                            "popf;"
                            "or DWORD PTR [%[dst]], %[src];"
                            "pushf;"
                            "pop %[flags];"
                            ".att_syntax;"
                            : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination)
                            : [dst] "r" (typed_destination), [src] "r" ((int32_t)*typed_source)
                            : "cc"
                    );
                }

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
                // perform operation, note that the flags register is also changed here
                // sub r/m64, imm8
                if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
                {
                    uint64_t* typed_destination = (uint64_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
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
                            : [dst] "r" (typed_destination), [src] "r" ((int64_t)*typed_source)
                            : "cc"
                    );
                }
                    // sub r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t* typed_destination = (uint16_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
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
                            : [dst] "r" (typed_destination), [src] "r" ((int16_t)*typed_source)
                            : "cc"
                    );
                }
                    // sub r/m32, imm8
                else
                {
                    uint32_t* typed_destination = (uint32_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
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
                            : [dst] "r" (typed_destination), [src] "r" ((int32_t)*typed_source)
                            : "cc"
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
                    uint64_t* typed_destination = (uint64_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
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
                            : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" ((int64_t)*typed_source)
                            : "cc"
                    );
                }
                // cmp r/m16, imm8
                else if (PREFIXES_GRP_THREE_PRESENT(instruction))
                {
                    uint16_t* typed_destination = (uint16_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
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
                            : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" ((int16_t)*typed_source)
                            : "cc"
                    );
                }
                // cmp r/m32, imm8
                else
                {
                    uint32_t* typed_destination = (uint32_t*)destination;
                    int8_t* typed_source = (int8_t*)source;
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
                            : [dst] "r" (typed_destination), "m" (*typed_destination), [src] "r" ((int32_t)*typed_source)
                            : "cc"
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


/* Valid in first round */
#define EXCHANGE_TO_SHARED(__cast, __operation)                                                                        \
auto* typed_source = (__cast*)source;                                                                                  \
auto* typed_destination = (__cast*)destination;                                                                        \
                                                                                                                       \
if (!variant->variant_num)                                                                                             \
{                                                                                                                      \
    unsigned long long requested_size = 0;                                                                             \
    if (*typed_destination != *(__cast*)(mapping_info->variant_shadows[0].monitor_base + offset))                 \
        requested_size = sizeof(__cast);                                                                               \
    void* buffer = nullptr;                                                                                            \
    int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, destination, instruction, &buffer,        \
            requested_size);                                                                                           \
    if (result < 0)                                                                                                    \
        return result;                                                                                                 \
    __cast orig_source = *typed_source;                                                                                \
    __operation;                                                                                                       \
    *(__cast*)(mapping_info->variant_shadows[0].monitor_base + offset) = orig_source;                                  \
    if (buffer)                                                                                                        \
        *(__cast*)buffer = *typed_source;                                                                              \
}                                                                                                                      \
else                                                                                                                   \
{                                                                                                                      \
    void* buffer = nullptr;                                                                                            \
    int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, destination, instruction, &buffer, 0);    \
    if (result < 0)                                                                                                    \
        return result;                                                                                                 \
                                                                                                                       \
    typed_destination = (__cast*)(mapping_info->variant_shadows[variant->variant_num].monitor_base + offset);          \
    if (buffer)                                                                                                        \
        *typed_destination = *(__cast*)buffer;                                                                         \
                                                                                                                       \
    __operation;                                                                                                       \
}


BYTE_EMULATOR_IMPL(0x87)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            EXCHANGE_TO_SHARED(uint64_t,
                    __atomic_exchange(typed_destination, typed_source, typed_source, __ATOMIC_ACQ_REL)
            )
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            EXCHANGE_TO_SHARED(uint16_t,
                    __atomic_exchange(typed_destination, typed_source, typed_source, __ATOMIC_ACQ_REL)
            )
        }
        // 32-bit
        else
        {
            EXCHANGE_TO_SHARED(uint32_t,
                    __atomic_exchange(typed_destination, typed_source, typed_source, __ATOMIC_ACQ_REL)
            )
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, 1)
        LOAD_REG_CODE_BYTE(source, general_purpose_lookup)

        // special case that uses higher order lower byte, for example ah
        if (!PREFIXES_REX_PRESENT(instruction) && GET_REG_CODE((unsigned) modrm) & 0b100u)
            source = (void*) ((unsigned long long) source + 1);

        GET_BUFFER_CHECK_OR_FILL(destination, source, 1)
        uint8_t* typed_destination = (uint8_t*)destination;
        uint8_t* typed_source = (uint8_t*)source;

        // execute operation
        *typed_destination = *typed_source;

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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit implementation
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            auto* typed_source = (uint64_t*)source;
            NORMAL_TO_SHARED(
                    uint64_t,
                    *typed_destination = *typed_source
            )
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            auto* typed_source = (uint16_t*)source;
            NORMAL_TO_SHARED(
                    uint16_t,
                    *typed_destination = *typed_source
            )
        }
        // default 32-bit
        else
        {
            auto* typed_source = (uint32_t*)source;
            NORMAL_TO_SHARED(
                    uint32_t,
                    *typed_destination = *typed_source
            )
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE_BYTE(destination, general_purpose_lookup)
        LOAD_RM_CODE(source, 1)

        // use higher order byte of lowest word exception
        if (!PREFIXES_REX_PRESENT(instruction) && GET_REG_CODE((unsigned) modrm) & 0b100u)
            destination = (void*) ((unsigned long long) destination + 1);

        GET_BUFFER_REPLACE(source, 1)
        uint8_t* typed_destination = (uint8_t*)destination;
        uint8_t* typed_source = (uint8_t*)source;

        // execute operation
        *typed_destination = *typed_source;

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
        shared_monitor_map_info* src_info;
        shared_monitor_map_info* dst_info;
        bool src_spoof = false;
        bool dst_spoof = false;
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

            // check if destination is shared memory, or regular variant memory
            if (IS_TAGGED_ADDRESS(dst))
            {
                dst = decode_address_tag(dst, variant);
                OBTAIN_SHARED_MAPPING_INFO_NO_DEF(dst, dst_info, dst_offset, size)
                dst = (unsigned long long) dst_info->monitor_base + dst_offset;
            }
            else
                dst_spoof = true;
        }
        // destination is shared memory
        else if (IS_TAGGED_ADDRESS(dst))
        {
            dst = decode_address_tag(dst, variant);
            OBTAIN_SHARED_MAPPING_INFO_NO_DEF(dst, dst_info, dst_offset, size)
            dst = (unsigned long long) dst_info->monitor_base + dst_offset;

            src_spoof = true;
        }
        // we would expect one of the two to be known shared memory
        else
            return -1;


        // replay and spoofing
        GET_BUFFER_RAW((void*) (src_spoof ? dst : src),
                       ((!src_spoof && !dst_spoof) ? sizeof(void*) : (dst_spoof ? size : 0)) +
                       (sizeof(unsigned long long) * 2))
        auto rcx_result = (unsigned long long*) buffer;
        auto efalgs_result = (unsigned long long*) buffer + 1;
        void** actual_buffer = src_spoof ? nullptr : (void**) ((unsigned long long*) buffer + 2);

        // imitate
        if (result != REPLAY_BUFFER_RETURN_FIRST)
        {
            if (!dst_spoof && !src_spoof && (void*) dst != *actual_buffer)
            {
                warnf("second address mismatch\n");
                return -1;
            }
            else if (dst_spoof && !interaction::write_memory(variant->variantpid, (void*) dst, (long long) size,
                    actual_buffer))
            {
                warnf("could not write data to variant\n");
                return -1;
            }

            regs_struct->rcx    = *rcx_result;
            regs_struct->eflags = *efalgs_result;

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

            if (!interaction::read_memory(variant->variantpid, (void*) src, (long long) size, spoof))
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
            void* asm_dst = dst_spoof ? spoof : (void*) dst;
            void* asm_src = src_spoof ? spoof : (void*) src;
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "rep movsb;"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [count] "+c" (regs_struct->rcx), [flags] "+g" (regs_struct->eflags), "+D" (asm_dst),
                            "+S" (asm_src)
                    : "m" (asm_src), "m" (asm_dst)
                    : "cc", "memory"
            );

            if (dst_spoof && !interaction::write_memory(variant->variantpid, (void*) dst, (long) size, spoof))
            {
                warnf("movsb could not write back destination\n");
                return -1;
            }
            if (src_spoof)
                free(spoof);

            *rcx_result    = regs_struct->rcx;
            *efalgs_result = regs_struct->eflags;
            if (!src_spoof && !dst_spoof)
                *actual_buffer = (void*) dst;

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


/* Valid in first round */
BYTE_EMULATOR_IMPL(0xaa)
{
    // we're in need of rax as source
    DEFINE_REGS_STRUCT

    unsigned long long count = 1;
    if (PREFIXES_GRP_ONE_PRESENT(instruction) && (PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE ||
                                                  PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE))
        count = regs_struct->rcx;

    OBTAIN_SHARED_MAPPING_INFO(count)
    void* destination = (void*) ((unsigned long long) mapping_info->monitor_base + offset);
    void* source = shared_mem_register_access::ACCESS_GENERAL_NAME(rax)(regs_struct);

    GET_BUFFER_RAW(destination, 1 + sizeof(unsigned long long))
    if (result == REPLAY_BUFFER_RETURN_FIRST)
    {
        *(uint8_t *) buffer = *(uint8_t *) source;
        *(unsigned long long*) ((uint8_t *) buffer + 1) = count;
    }
    else if (*(uint8_t*) buffer == *(uint8_t*) source)
    {
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && (PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE ||
                PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE)
                && *(unsigned long long*) ((uint8_t *) buffer + 1) != count)
            return -1;

        if (regs_struct->eflags & (0b1u << 10u))
            regs_struct->rdi -= count;
        else
            regs_struct->rdi += count;

        REPLAY_BUFFER_ADVANCE
        return 0;
    }
    else
        return -1;

    __asm__
    (
            ".intel_syntax noprefix;"
            "rep stosb;"
            ".att_syntax;"
            : "+D" (destination)
            : "a" (*(uint8_t*) source), "c" (count), "m" (destination)
            : "memory"
    );

    if (regs_struct->eflags & (0b1u << 10u))
        regs_struct->rdi -= count;
    else
        regs_struct->rdi += count;

    REPLAY_BUFFER_ADVANCE
    return 0;
}


/* Valid in first round */
BYTE_EMULATOR_IMPL(0xab)
{
    if (EXTRA_INFO_ROUND_CODE(instruction) == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        if (PREFIXES_GRP_ONE_PRESENT(instruction) && (PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE ||
                PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE))
            return -1;

        // we're in need of rax as source
        DEFINE_REGS_STRUCT

        OBTAIN_SHARED_MAPPING_INFO(GET_INSTRUCTION_ACCESS_SIZE)
        void* destination = (void*) ((unsigned long long) mapping_info->monitor_base + offset);
        void* source = shared_mem_register_access::ACCESS_GENERAL_NAME(rax)(regs_struct);

        // stos m64
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_RAW(destination, 8)
            if (result == REPLAY_BUFFER_RETURN_FIRST)
                *(uint64_t*) buffer = *(uint64_t*) source;
            else if (*(uint64_t*) buffer == *(uint64_t*) source)
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

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "stosq;"
                    ".att_syntax;"
                    : "+D" (destination)
                    : "a" (*(uint64_t*) source), "m" (destination)
                    : "memory"
            );

            if (regs_struct->eflags & (0b1u << 10u))
                regs_struct->rdi -= 8;
            else
                regs_struct->rdi += 8;
        }
        // stos m16
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_RAW(destination, 2)
            if (result == REPLAY_BUFFER_RETURN_FIRST)
                *(uint16_t*) buffer = *(uint16_t*) source;
            else if (*(uint16_t*) buffer == *(uint16_t*) source)
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

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "stosw;"
                    ".att_syntax;"
                    : "+D" (destination)
                    : "a" (*(uint16_t*) source), "m" (destination)
                    : "memory"
            );

            if (regs_struct->eflags & (0b1u << 10u))
                regs_struct->rdi -= 2;
            else
                regs_struct->rdi += 2;
        }
        // stos m32
        else
        {
            GET_BUFFER_RAW(destination, 4)
            if (result == REPLAY_BUFFER_RETURN_FIRST)
                *(uint32_t*) buffer = *(uint32_t*) source;
            else if (*(uint32_t*) buffer == *(uint32_t*) source)
            {
                if (regs_struct->eflags & (0b1u << 10u))
                    regs_struct->rdi -= 4;
                else
                    regs_struct->rdi += 4;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }
            else
                return -1;

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "stosd;"
                    ".att_syntax;"
                    : "+D" (destination)
                    : "a" (*(uint32_t*) source), "m" (destination)
                    : "memory"
            );

            if (regs_struct->eflags & (0b1u << 10u))
                regs_struct->rdi -= 4;
            else
                regs_struct->rdi += 4;
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

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
            uint64_t* typed_destination = (uint64_t*)destination;
            uint64_t* typed_source = (uint64_t*)source;

            // todo - always executed with LOCK for now, might not be the best
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "lock cmpxchg QWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination), "+a" (regs_struct->rax)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            uint16_t* typed_destination = (uint16_t*)destination;
            uint16_t* typed_source = (uint16_t*)source;

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "lock cmpxchg WORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination), "+a" (regs_struct->rax)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
            );
        }
        // 32-bit
        else
        {
            uint32_t* typed_destination = (uint32_t*)destination;
            uint32_t* typed_source = (uint32_t*)source;

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "lock cmpxchg DWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination), "+a" (regs_struct->rax)
                    : [dst] "r" (typed_destination), [src] "r" (*typed_source)
                    : "cc"
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE_NO_DEFINE(GET_INSTRUCTION_ACCESS_SIZE)

        NORMAL_FROM_SHARED(uint8_t)

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            uint64_t* typed_destination = (uint64_t*)destination;
            *typed_destination = *typed_source;
        }
        // 16-bit size
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            uint16_t* typed_destination = (uint16_t*)destination;
            *typed_destination = *typed_source;
        }
        // 32-bit size
        else
        {
            uint64_t* typed_destination = (uint64_t*)destination;
            *typed_destination = *typed_source;
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE(source, GET_INSTRUCTION_ACCESS_SIZE)

        GET_BUFFER_REPLACE(source, 2)
        uint16_t* typed_source = (uint16_t*)source;

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            uint64_t* typed_destination = (uint64_t*)destination;
            *typed_destination = *typed_source;
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            uint16_t* typed_destination = (uint16_t*)destination;
            *typed_destination = *typed_source;
        }
        // 32-bit size
        else
        {
            uint64_t* typed_destination = (uint64_t*)destination;
            *typed_destination = *typed_source;
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_REG_CODE(destination, general_purpose_lookup)
        LOAD_RM_CODE(source, GET_INSTRUCTION_ACCESS_SIZE)

        // always byte
        GET_BUFFER_REPLACE(source, 1)
        int8_t* typed_source = (int8_t*)source;

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            int64_t* typed_destination = (int64_t*)destination;
            *typed_destination = *typed_source;
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            int16_t* typed_destination = (int16_t*)destination;
            *typed_destination = *typed_source;
        }
        // 32-bit
        else
        {
            uint32_t* typed_destination = (uint32_t*)destination;
            *typed_destination = (int32_t)*typed_source;
            *(typed_destination + 1) = 0x00;
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
        DEFINE_REGS_STRUCT
        DEFINE_MODRM
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        LOAD_REG_CODE(source, general_purpose_lookup)

        // 64-bit size
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            GET_BUFFER_RAW(destination, (sizeof(uint64_t) * 2))
            auto source_original  = (uint64_t*) buffer;
            auto source_overwrite = ((uint64_t*) buffer) + 1;
            uint64_t* typed_destination = (uint64_t*)destination;
            uint64_t* typed_source = (uint64_t*)source;

            if (result != REPLAY_BUFFER_RETURN_FIRST)
            {
                if (*typed_source != *source_original)
                    return -1;
                *typed_source = *source_overwrite;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }

            *source_original = *typed_source;

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "xadd QWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination), [src] "+r" (*typed_source)
                    : [dst] "r" (typed_destination)
                    : "cc"
            );

            *source_overwrite = *typed_source;
        }
        // 16-bit size
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            GET_BUFFER_RAW(destination, (sizeof(uint16_t) * 2))
            auto source_original  = (uint16_t*) buffer;
            auto source_overwrite = ((uint16_t*) buffer) + 1;
            uint16_t* typed_destination = (uint16_t*)destination;
            uint16_t* typed_source = (uint16_t*)source;

            if (result != REPLAY_BUFFER_RETURN_FIRST)
            {
                if (*typed_source != *source_original)
                    return -1;
                *typed_source = *source_overwrite;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }

            *source_original = *typed_source;

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "xadd WORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination), [src] "+r" (*typed_source)
                    : [dst] "r" (typed_destination)
                    : "cc"
            );

            *source_overwrite = *typed_source;
        }
        // 32-bit size
        else
        {
            GET_BUFFER_RAW(destination, (sizeof(uint32_t) * 2))
            auto source_original  = (uint32_t*) buffer;
            auto source_overwrite = ((uint32_t*) buffer) + 1;
            uint32_t* typed_destination = (uint32_t*)destination;
            uint32_t* typed_source = (uint32_t*)source;

            *(typed_source + 1) = 0;

            if (result != REPLAY_BUFFER_RETURN_FIRST)
            {
                if (*typed_source != *source_original)
                    return -1;
                *typed_source = *source_overwrite;

                REPLAY_BUFFER_ADVANCE
                return 0;
            }

            *source_original = *typed_source;

            // perform operation
            __asm__
            (
                    ".intel_syntax noprefix;"
                    "push %[flags];"
                    "popf;"
                    "xadd DWORD PTR [%[dst]], %[src];"
                    "pushf;"
                    "pop %[flags];"
                    ".att_syntax;"
                    : [flags] "+r" (regs_struct->eflags), "+m" (*typed_destination), [src] "+r" (*typed_source)
                    : [dst] "r" (typed_destination)
                    : "cc"
            );

            *source_overwrite = *typed_source;
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
        DEFINE_MODRM
        LOAD_IMM(source)
        LOAD_RM_CODE(destination, 1)

        GET_BUFFER_RAW(destination, 1)

        if (result != REPLAY_BUFFER_RETURN_FIRST)
        {
            // nothing to do here, it's fine if the buffer obtaining passes
            REPLAY_BUFFER_ADVANCE
            return 0;
        }

        // perform operation
        uint8_t* typed_destination = (uint8_t*)destination;
        uint8_t* typed_source = (uint8_t*)source;
        *typed_destination = *typed_source;

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
        DEFINE_MODRM
        LOAD_RM_CODE(destination, GET_INSTRUCTION_ACCESS_SIZE)
        // small test
        if (GET_REG_CODE((unsigned) modrm) != 0b000u)
            return -1;
        LOAD_IMM(source)

        GET_NULL_BUFFER(destination)

        // 64-bit
        if (PREFIXES_REX_PRESENT(instruction) && PREFIXES_REX_FIELD_W(instruction))
        {
            int64_t* typed_destination = (int64_t*)destination;
            int32_t* typed_source = (int32_t*)source;
            *typed_destination = *typed_source;
        }
        // 16-bit
        else if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            uint16_t* typed_destination = (uint16_t*)destination;
            uint16_t* typed_source = (uint16_t*)source;
            *typed_destination = *typed_source;
        }
        // 32-bit
        else
        {
            uint32_t* typed_destination = (uint32_t*)destination;
            uint32_t* typed_source = (uint32_t*)source;
            *typed_destination = *typed_source;
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
        DEFINE_MODRM

        // pminub xmm, xmm/m128
        if (PREFIXES_GRP_THREE_PRESENT(instruction))
        {
            LOAD_RM_CODE(source, 16)
            LOAD_REG_CODE(destination, xmm_lookup)

            GET_BUFFER_REPLACE(source, 16)

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
            LOAD_RM_CODE(source, 8)
            LOAD_REG_CODE(destination, mm_lookup)

            GET_BUFFER_REPLACE(source, 8)

            // execute operation
            __asm__
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
            LOAD_RM_CODE(destination, 16)
            LOAD_REG_CODE(source, xmm_lookup)
            GET_BUFFER_CHECK_OR_FILL(destination, source, 16)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movdqu xmm0, XMMWORD PTR [rdx];"
                    "movntdq XMMWORD PTR [rax], xmm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "xmm0", "memory"
            );
        }
        // illegal access
        else if (PREFIXES_GRP_ONE_PRESENT(instruction) && (PREFIXES_GRP_TWO(instruction) == REPZ_PREFIX_CODE ||
                PREFIXES_GRP_TWO(instruction) == REPNZ_PREFIX_CODE))
            return -1;
        // movntq m64, mm
        else
        {
            DEFINE_FPREGS_STRUCT
            LOAD_RM_CODE(destination, 8)
            LOAD_REG_CODE(source, mm_lookup)
            GET_BUFFER_CHECK_OR_FILL(destination, source, 8)

            __asm__
            (
                    ".intel_syntax noprefix;"
                    "movq  mm0, QWORD PTR [rdx];"
                    "movntq QWORD PTR [rax], mm0;"
                    ".att_syntax;"
                    :
                    : [dst] "a" (destination), [src] "d" (source)
                    : "mm0", "memory"
            );
        }

        // no registers need to be written back
        REPLAY_BUFFER_ADVANCE
        return 0;
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
