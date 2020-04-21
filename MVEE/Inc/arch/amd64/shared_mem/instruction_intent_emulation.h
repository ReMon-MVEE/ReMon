//
// Created by jonas on 13/03/2020.
//

#ifndef REMON_INSTRUCTION_INTENT_EMULATION_H
#define REMON_INSTRUCTION_INTENT_EMULATION_H

#include <sys/prctl.h>

// =====================================================================================================================
//      forward definitions
// =====================================================================================================================
class instruction_intent;
class monitor;
class variantstate;


// =====================================================================================================================
//      constants
// =====================================================================================================================

// Decoding levels -----------------------------------------------------------------------------------------------------
#include "shared_mem_handling.h"

#define INSTRUCTION_DECODING_FIRST_LEVEL    0x01u
#define INSTRUCTION_DECODING_SECOND_LEVEL   0x02u
#define INSTRUCTION_DECODING_THIRD_LEVEL    0x04u
#define INSTRUCTION_DECODING_FOURTH_LEVEL   0x08u
// ---------------------------------------------------------------------------------------------------------------------


// Return codes for decoding -------------------------------------------------------------------------------------------
#define ACCESS_OK_CONTINUE                  0x00u

// Termination events
#define ACCESS_OK_TERMINATION                0
#define ILLEGAL_ACCESS_TERMINATION          -1
// ---------------------------------------------------------------------------------------------------------------------


// =====================================================================================================================
//      macros
// =====================================================================================================================

// ModR/M decoding -----------------------------------------------------------------------------------------------------
/* Filters out three bit rm code from ModR/M byte. */
#define GET_RM_CODE(modrm)                  ((modrm >> 0x00u) & 0x07u)
/* Filters out three bit reg code from ModR/M byte. */
#define GET_REG_CODE(modrm)                 ((modrm >> 0x03u) & 0x07u)
/* Filters out two bit mod code from ModR/M byte */
#define GET_MOD_CODE(modrm)                 ((modrm >> 0x06u) & 0x03u)
// ---------------------------------------------------------------------------------------------------------------------


// SIB decoding --------------------------------------------------------------------------------------------------------
/* Filters out base register for SIB addressing. */
#define GET_BASE(sib)                       ((sib >> 0x00u) & 0x07u)
/* Filters out index register for SIB addressing. */
#define GET_INDEX(sib)                      ((sib >> 0x03u) & 0x07u)
/* Filters out scale for SIB addressing. */
#define GET_SCALE(sib)                      ((sib >> 0x06u) & 0x03u)
// ---------------------------------------------------------------------------------------------------------------------


// opcode extension extraction -----------------------------------------------------------------------------------------
/* Masks out and returns only bits 5, 4, and 3, shifted all the wat to the left */
#define OPCODE_EXTENSION(byte)              ((byte & 0b00111000u) >> 0x03u)
// ---------------------------------------------------------------------------------------------------------------------


// Extra options for address decoding ----------------------------------------------------------------------------------
/* This instrution contains a ModR/M byte, and by extension potentially a SIB and offset. */
#define REST_CHECK_MODRM                    (0x01u << 0x01u)
// ---------------------------------------------------------------------------------------------------------------------

#define LOAD_NEXT_INSTRUCTION_BYTE(next_level)                                                                         \
    if (instruction++ < MAX_INSTRUCTION_SIZE)                                                                          \
    {                                                                                                                  \
        /* increase size */                                                                                            \
        instruction.size++;                                                                                              \
        /* advance instruction size to match */                                                                        \
        return instruction_intent_emulation::lookup_table[instruction.current_byte()].loader(instruction, next_level); \
    }                                                                                                                  \
    return ILLEGAL_ACCESS_TERMINATION;

#define LOAD_REST_OF_INSTRUCTION(options, immediate_size)                                                              \
    if (instruction++ < MAX_INSTRUCTION_SIZE)                                                                          \
    {                                                                                                                  \
        /* increase size */                                                                                            \
        instruction.size++;                                                                                              \
        /* advance instruction size to match */                                                                        \
        return instruction_intent_emulation::rest_check(instruction, options, immediate_size);                         \
    }                                                                                                                  \
    return ILLEGAL_ACCESS_TERMINATION;

// =====================================================================================================================
//      function definitions
// =====================================================================================================================
#define BYTE_LOADER_ARGUMENTS                           (instruction_intent& instruction, unsigned int round)
#define BYTE_LOADER_NAME(byte)              load_##byte##_byte
#define BYTE_LOADER_DEFINITION(byte)                                                                                   \
static int  BYTE_LOADER_NAME(byte)                      BYTE_LOADER_ARGUMENTS;
#define BYTE_LOADER_IMPL(byte)                                                                                         \
int         instruction_intent_emulation::BYTE_LOADER_NAME(byte)                                                       \
                                                        BYTE_LOADER_ARGUMENTS

#define BYTE_EMULATOR_ARGUMENTS                         (instruction_intent& instruction, monitor& relevant_monitor,   \
                                                         variantstate* variant)
#define BYTE_EMULATOR_NAME(byte)            emulate_##byte##_byte
#define BYTE_EMULATOR_DEFINITION(byte)                                                                                 \
static int  BYTE_EMULATOR_NAME(byte)                    BYTE_EMULATOR_ARGUMENTS;
#define BYTE_EMULATOR_IMPL(byte)                                                                                       \
int         instruction_intent_emulation::BYTE_EMULATOR_NAME(byte)                                                     \
                                                        BYTE_EMULATOR_ARGUMENTS

// =====================================================================================================================
//      struct definition
// =====================================================================================================================
struct emulation_lookup
{
    int (*loader) BYTE_LOADER_ARGUMENTS;
    int (*emulator) BYTE_EMULATOR_ARGUMENTS;
};


// =====================================================================================================================
//      class definition
// =====================================================================================================================

class instruction_intent_emulation
{
private:
public:


    // -----------------------------------------------------------------------------------------------------------------
    //      other functions
    // -----------------------------------------------------------------------------------------------------------------

/* ## Bytes that can't be loaded ##
 *
 * First round
 *   0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x0e |      |
 *   0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a | 0x1b | 0x1c | 0x1d | 0x1e | 0x1f |
 *   0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2a | 0x2b | 0x2c | 0x2d | 0x2e | 0x2f |
 *   0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3a | 0x3b | 0x3c | 0x3d | 0x3e | 0x3f |
 *        |      |      |      |      |      |      |      |      |      |      |      |      |      |      |      |
 *   0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0x57 | 0x58 | 0x59 | 0x5a | 0x5b | 0x5c | 0x5d | 0x5e | 0x5f |
 *   0x60 | 0x61 | 0x62 | 0x63 | 0x64 | 0x65 |      |      | 0x68 | 0x69 | 0x6a | 0x6b | 0x6c | 0x6d | 0x6e | 0x6f |
 *   0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7a | 0x7b | 0x7c | 0x7d | 0x7e | 0x7f |
 *        | 0x81 | 0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 |      |      |      |      |      | 0x8d |      | 0x8f |
 *   0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97 | 0x98 | 0x99 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f |
 *   0xa0 | 0xa1 | 0xa2 | 0xa3 | 0xa4 | 0xa5 | 0xa6 | 0xa7 | 0xa8 | 0xa9 | 0xaa | 0xab | 0xac | 0xad | 0xae | 0xaf |
 *   0xb0 | 0xb1 | 0xb2 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbc | 0xbd | 0xbe | 0xbf |
 *   0xc0 | 0xc1 | 0xc2 | 0xc3 |      |      |      | 0xc7 | 0xc8 | 0xc9 | 0xca | 0xcb | 0xcc | 0xcd | 0xce | 0xcf |
 *   0xd0 | 0xd1 | 0xd2 | 0xd3 | 0xd4 | 0xd5 | 0xd6 | 0xd7 | 0xd8 | 0xd9 | 0xda | 0xdb | 0xdc | 0xdd | 0xde | 0xdf |
 *   0xe0 | 0xe1 | 0xe2 | 0xe3 | 0xe4 | 0xe5 | 0xe6 | 0xe7 | 0xe8 | 0xe9 | 0xea | 0xeb | 0xec | 0xed | 0xee | 0xef |
 *   0xf0 | 0xf1 | 0xf2 |      | 0xf4 | 0xf5 | 0xf6 | 0xf7 | 0xf8 | 0xf9 | 0xfa | 0xfb | 0xfc | 0xfd | 0xfe | 0xff |
 *
 * Second round disallowed bytes:
 *   0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x0e | 0x0f |
 *        |      | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a | 0x1b | 0x1c | 0x1d | 0x1e | 0x1f |
 *   0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2a | 0x2b | 0x2c | 0x2d | 0x2e | 0x2f |
 *   0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3a | 0x3b | 0x3c | 0x3d | 0x3e | 0x3f |
 *   0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 | 0x49 | 0x4a | 0x4b | 0x4c | 0x4d | 0x4e | 0x4f |
 *   0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0x57 | 0x58 | 0x59 | 0x5a | 0x5b | 0x5c | 0x5d | 0x5e | 0x5f |
 *   0x60 | 0x61 | 0x62 | 0x63 | 0x64 | 0x65 | 0x66 | 0x67 | 0x68 | 0x69 | 0x6a | 0x6b | 0x6c | 0x6d | 0x6e |      |
 *   0x70 | 0x71 | 0x72 | 0x73 |      | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7a | 0x7b | 0x7c | 0x7d | 0x7e |      |
 *   0x80 | 0x81 | 0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8a | 0x8b | 0x8c | 0x8d | 0x8e | 0x8f |
 *   0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97 | 0x98 | 0x99 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f |
 *   0xa0 | 0xa1 |      | 0xa3 | 0xa4 | 0xa5 | 0xa6 | 0xa7 | 0xa8 | 0xa9 | 0xaa | 0xab | 0xac | 0xad | 0xae | 0xaf |
 *   0xb0 | 0xb1 | 0xb2 | 0xb3 | 0xb4 | 0xb5 |      |      | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbc | 0xbd | 0xbe | 0xbf |
 *   0xc0 | 0xc1 | 0xc2 | 0xc3 | 0xc4 | 0xc5 | 0xc6 | 0xc7 | 0xc8 | 0xc9 | 0xca | 0xcb | 0xcc | 0xcd | 0xce | 0xcf |
 *   0xd0 | 0xd1 | 0xd2 | 0xd3 | 0xd4 | 0xd5 | 0xd6 | 0xd7 | 0xd8 | 0xd9 |      | 0xdb | 0xdc | 0xdd | 0xde | 0xdf |
 *   0xe0 | 0xe1 | 0xe2 | 0xe3 | 0xe4 | 0xe5 | 0xe6 | 0xe7 | 0xe8 | 0xe9 | 0xea | 0xeb | 0xec | 0xed | 0xee | 0xef |
 *   0xf0 | 0xf1 | 0xf2 | 0xf3 | 0xf4 | 0xf5 | 0xf6 | 0xf7 | 0xf8 | 0xf9 | 0xfa | 0xfb | 0xfc | 0xfd | 0xfe | 0xff |
 *
 * Third round
 *   0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x0e | 0x0f |
 *   0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a | 0x1b | 0x1c | 0x1d | 0x1e | 0x1f |
 *   0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2a | 0x2b | 0x2c | 0x2d | 0x2e | 0x2f |
 *   0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3a | 0x3b | 0x3c | 0x3d | 0x3e | 0x3f |
 *   0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 | 0x49 | 0x4a | 0x4b | 0x4c | 0x4d | 0x4e | 0x4f |
 *   0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0x57 | 0x58 | 0x59 | 0x5a | 0x5b | 0x5c | 0x5d | 0x5e | 0x5f |
 *   0x60 | 0x61 | 0x62 | 0x63 | 0x64 | 0x65 | 0x66 | 0x67 | 0x68 | 0x69 | 0x6a | 0x6b | 0x6c | 0x6d | 0x6e | 0x6f |
 *   0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7a | 0x7b | 0x7c | 0x7d | 0x7e | 0x7f |
 *   0x80 | 0x81 | 0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8a | 0x8b | 0x8c | 0x8d | 0x8e | 0x8f |
 *   0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97 | 0x98 | 0x99 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f |
 *   0xa0 | 0xa1 | 0xa2 | 0xa3 | 0xa4 | 0xa5 | 0xa6 | 0xa7 | 0xa8 | 0xa9 | 0xaa | 0xab | 0xac | 0xad | 0xae | 0xaf |
 *   0xb0 | 0xb1 | 0xb2 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbc | 0xbd | 0xbe | 0xbf |
 *   0xc0 | 0xc1 | 0xc2 | 0xc3 | 0xc4 | 0xc5 | 0xc6 | 0xc7 | 0xc8 | 0xc9 | 0xca | 0xcb | 0xcc | 0xcd | 0xce | 0xcf |
 *   0xd0 | 0xd1 | 0xd2 | 0xd3 | 0xd4 | 0xd5 | 0xd6 | 0xd7 | 0xd8 | 0xd9 | 0xda | 0xdb | 0xdc | 0xdd | 0xde | 0xdf |
 *   0xe0 | 0xe1 | 0xe2 | 0xe3 | 0xe4 | 0xe5 | 0xe6 | 0xe7 | 0xe8 | 0xe9 | 0xea | 0xeb | 0xec | 0xed | 0xee | 0xef |
 *   0xf0 | 0xf1 | 0xf2 | 0xf3 | 0xf4 | 0xf5 | 0xf6 | 0xf7 | 0xf8 | 0xf9 | 0xfa | 0xfb | 0xfc | 0xfd | 0xfe | 0xff |
 */
    static int      block_loader                               BYTE_LOADER_ARGUMENTS;

/* ## Bytes that can't be emulated bytes ##
 *
 * First round
 *   0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x0e | 0x0f |
 *   0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a | 0x1b | 0x1c | 0x1d | 0x1e | 0x1f |
 *   0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2a | 0x2b | 0x2c | 0x2d | 0x2e | 0x2f |
 *   0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3a | 0x3b | 0x3c | 0x3d | 0x3e | 0x3f |
 *   0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 | 0x49 | 0x4a | 0x4b | 0x4c | 0x4d | 0x4e | 0x4f |
 *   0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0x57 | 0x58 | 0x59 | 0x5a | 0x5b | 0x5c | 0x5d | 0x5e | 0x5f |
 *   0x60 | 0x61 | 0x62 | 0x63 | 0x64 | 0x65 | 0x66 | 0x67 | 0x68 | 0x69 | 0x6a | 0x6b | 0x6c | 0x6d | 0x6e | 0x6f |
 *   0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7a | 0x7b | 0x7c | 0x7d | 0x7e | 0x7f |
 *        | 0x81 | 0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 |      |      |      |      |      | 0x8d |      | 0x8f |
 *   0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97 | 0x98 | 0x99 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f |
 *   0xa0 | 0xa1 | 0xa2 | 0xa3 | 0xa4 | 0xa5 | 0xa6 | 0xa7 | 0xa8 | 0xa9 | 0xaa | 0xab | 0xac | 0xad | 0xae | 0xaf |
 *   0xb0 | 0xb1 | 0xb2 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbc | 0xbd | 0xbe | 0xbf |
 *   0xc0 | 0xc1 | 0xc2 | 0xc3 | 0xc4 | 0xc5 |      | 0xc7 | 0xc8 | 0xc9 | 0xca | 0xcb | 0xcc | 0xcd | 0xce | 0xcf |
 *   0xd0 | 0xd1 | 0xd2 | 0xd3 | 0xd4 | 0xd5 | 0xd6 | 0xd7 | 0xd8 | 0xd9 | 0xda | 0xdb | 0xdc | 0xdd | 0xde | 0xdf |
 *   0xe0 | 0xe1 | 0xe2 | 0xe3 | 0xe4 | 0xe5 | 0xe6 | 0xe7 | 0xe8 | 0xe9 | 0xea | 0xeb | 0xec | 0xed | 0xee | 0xef |
 *   0xf0 | 0xf1 | 0xf2 | 0xf3 | 0xf4 | 0xf5 | 0xf6 | 0xf7 | 0xf8 | 0xf9 | 0xfa | 0xfb | 0xfc | 0xfd | 0xfe | 0xff |
 *
 * Second round disallowed bytes:
 *   0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x0e | 0x0f |
 *        |      | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a | 0x1b | 0x1c | 0x1d | 0x1e | 0x1f |
 *   0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2a | 0x2b | 0x2c | 0x2d | 0x2e | 0x2f |
 *   0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3a | 0x3b | 0x3c | 0x3d | 0x3e | 0x3f |
 *   0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 | 0x49 | 0x4a | 0x4b | 0x4c | 0x4d | 0x4e | 0x4f |
 *   0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0x57 | 0x58 | 0x59 | 0x5a | 0x5b | 0x5c | 0x5d | 0x5e | 0x5f |
 *   0x60 | 0x61 | 0x62 | 0x63 | 0x64 | 0x65 | 0x66 | 0x67 | 0x68 | 0x69 | 0x6a | 0x6b | 0x6c | 0x6d | 0x6e |      |
 *   0x70 | 0x71 | 0x72 | 0x73 |      | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7a | 0x7b | 0x7c | 0x7d | 0x7e | 0x7f |
 *   0x80 | 0x81 | 0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8a | 0x8b | 0x8c | 0x8d | 0x8e | 0x8f |
 *   0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97 | 0x98 | 0x99 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f |
 *   0xa0 | 0xa1 |      | 0xa3 | 0xa4 | 0xa5 | 0xa6 | 0xa7 | 0xa8 | 0xa9 | 0xaa | 0xab | 0xac | 0xad | 0xae | 0xaf |
 *   0xb0 | 0xb1 | 0xb2 | 0xb3 | 0xb4 | 0xb5 |      |      | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbc | 0xbd | 0xbe | 0xbf |
 *   0xc0 | 0xc1 | 0xc2 | 0xc3 | 0xc4 | 0xc5 | 0xc6 | 0xc7 | 0xc8 | 0xc9 | 0xca | 0xcb | 0xcc | 0xcd | 0xce | 0xcf |
 *   0xd0 | 0xd1 | 0xd2 | 0xd3 | 0xd4 | 0xd5 | 0xd6 | 0xd7 | 0xd8 | 0xd9 |      | 0xdb | 0xdc | 0xdd | 0xde | 0xdf |
 *   0xe0 | 0xe1 | 0xe2 | 0xe3 | 0xe4 | 0xe5 | 0xe6 | 0xe7 | 0xe8 | 0xe9 | 0xea | 0xeb | 0xec | 0xed | 0xee | 0xef |
 *   0xf0 | 0xf1 | 0xf2 | 0xf3 | 0xf4 | 0xf5 | 0xf6 | 0xf7 | 0xf8 | 0xf9 | 0xfa | 0xfb | 0xfc | 0xfd | 0xfe | 0xff |
 *
 * Third round
 *   0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x0e | 0x0f |
 *   0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a | 0x1b | 0x1c | 0x1d | 0x1e | 0x1f |
 *   0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2a | 0x2b | 0x2c | 0x2d | 0x2e | 0x2f |
 *   0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3a | 0x3b | 0x3c | 0x3d | 0x3e | 0x3f |
 *   0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 | 0x49 | 0x4a | 0x4b | 0x4c | 0x4d | 0x4e | 0x4f |
 *   0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0x57 | 0x58 | 0x59 | 0x5a | 0x5b | 0x5c | 0x5d | 0x5e | 0x5f |
 *   0x60 | 0x61 | 0x62 | 0x63 | 0x64 | 0x65 | 0x66 | 0x67 | 0x68 | 0x69 | 0x6a | 0x6b | 0x6c | 0x6d | 0x6e | 0x6f |
 *   0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7a | 0x7b | 0x7c | 0x7d | 0x7e | 0x7f |
 *   0x80 | 0x81 | 0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8a | 0x8b | 0x8c | 0x8d | 0x8e | 0x8f |
 *   0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97 | 0x98 | 0x99 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f |
 *   0xa0 | 0xa1 | 0xa2 | 0xa3 | 0xa4 | 0xa5 | 0xa6 | 0xa7 | 0xa8 | 0xa9 | 0xaa | 0xab | 0xac | 0xad | 0xae | 0xaf |
 *   0xb0 | 0xb1 | 0xb2 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbc | 0xbd | 0xbe | 0xbf |
 *   0xc0 | 0xc1 | 0xc2 | 0xc3 | 0xc4 | 0xc5 | 0xc6 | 0xc7 | 0xc8 | 0xc9 | 0xca | 0xcb | 0xcc | 0xcd | 0xce | 0xcf |
 *   0xd0 | 0xd1 | 0xd2 | 0xd3 | 0xd4 | 0xd5 | 0xd6 | 0xd7 | 0xd8 | 0xd9 | 0xda | 0xdb | 0xdc | 0xdd | 0xde | 0xdf |
 *   0xe0 | 0xe1 | 0xe2 | 0xe3 | 0xe4 | 0xe5 | 0xe6 | 0xe7 | 0xe8 | 0xe9 | 0xea | 0xeb | 0xec | 0xed | 0xee | 0xef |
 *   0xf0 | 0xf1 | 0xf2 | 0xf3 | 0xf4 | 0xf5 | 0xf6 | 0xf7 | 0xf8 | 0xf9 | 0xfa | 0xfb | 0xfc | 0xfd | 0xfe | 0xff |
 */
    static int      block_emulator                             BYTE_EMULATOR_ARGUMENTS;


    static int      rest_check                          (instruction_intent& instruction, unsigned int options,
                                                         unsigned int immediate_size);


    // -----------------------------------------------------------------------------------------------------------------
    //      decoding bytes
    // -----------------------------------------------------------------------------------------------------------------


    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x00)
    // BYTE_EMULATOR_DEFINITION(0x00)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x01)
    // BYTE_EMULATOR_DEFINITION(0x01)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x02)
    // BYTE_EMULATOR_DEFINITION(0x02)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x03)
    // BYTE_EMULATOR_DEFINITION(0x03)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x04)
    // BYTE_EMULATOR_DEFINITION(0x04)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x05)
    // BYTE_EMULATOR_DEFINITION(0x05)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x06)
    // BYTE_EMULATOR_DEFINITION(0x06)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x07)
    // BYTE_EMULATOR_DEFINITION(0x07)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x08)
    // BYTE_EMULATOR_DEFINITION(0x08)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x09)
    // BYTE_EMULATOR_DEFINITION(0x09)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x0a)
    // BYTE_EMULATOR_DEFINITION(0x0a)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x0b)
    // BYTE_EMULATOR_DEFINITION(0x0b)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x0c)
    // BYTE_EMULATOR_DEFINITION(0x0c)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x0d)
    // BYTE_EMULATOR_DEFINITION(0x0d)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x0e)
    // BYTE_EMULATOR_DEFINITION(0x0e)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * 2-byte escape code.
     *
     * This opcode signifies that the following byte is still part of the opcode. Reaching this will take
     * instruction decoding to the second level and continue decoding the next byte.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x0f)
    // BYTE_EMULATOR_DEFINITION(0x0f)

    /* Valid in second round
     *
     * ## Second round ##
     *
     * if no prefix present
     *   movups xmm, xmm/m128
     *
     * Moves a 128-bit operand from an xmm register or 128-bit memory location, into an xmm register.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x10)
    BYTE_EMULATOR_DEFINITION(0x10)

    /* Valid in second round
     *
     * ## Second round ##
     *
     * no prefix present
     *   movups Wps, Vps
     *
     * moves a 128-bit operand from an xmm register to another xmm register or a 128-bit memory location.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x11)
    BYTE_EMULATOR_DEFINITION(0x11)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x12)
    // BYTE_EMULATOR_DEFINITION(0x12)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x13)
    // BYTE_EMULATOR_DEFINITION(0x13)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x14)
    // BYTE_EMULATOR_DEFINITION(0x14)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x15)
    // BYTE_EMULATOR_DEFINITION(0x15)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x16)
    // BYTE_EMULATOR_DEFINITION(0x16)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x17)
    // BYTE_EMULATOR_DEFINITION(0x17)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x18)
    // BYTE_EMULATOR_DEFINITION(0x18)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x19)
    // BYTE_EMULATOR_DEFINITION(0x19)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x1a)
    // BYTE_EMULATOR_DEFINITION(0x1a)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x1b)
    // BYTE_EMULATOR_DEFINITION(0x1b)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x1c)
    // BYTE_EMULATOR_DEFINITION(0x1c)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x1d)
    // BYTE_EMULATOR_DEFINITION(0x1d)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x1e)
    // BYTE_EMULATOR_DEFINITION(0x1e)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x1f)
    // BYTE_EMULATOR_DEFINITION(0x1f)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x20)
    // BYTE_EMULATOR_DEFINITION(0x20)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x21)
    // BYTE_EMULATOR_DEFINITION(0x21)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x22)
    // BYTE_EMULATOR_DEFINITION(0x22)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x23)
    // BYTE_EMULATOR_DEFINITION(0x23)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x24)
    // BYTE_EMULATOR_DEFINITION(0x24)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x25)
    // BYTE_EMULATOR_DEFINITION(0x25)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x26)
    // BYTE_EMULATOR_DEFINITION(0x26)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x27)
    // BYTE_EMULATOR_DEFINITION(0x27)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x28)
    // BYTE_EMULATOR_DEFINITION(0x28)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x29)
    // BYTE_EMULATOR_DEFINITION(0x29)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x2a)
    // BYTE_EMULATOR_DEFINITION(0x2a)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x2b)
    // BYTE_EMULATOR_DEFINITION(0x2b)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x2c)
    // BYTE_EMULATOR_DEFINITION(0x2c)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x2d)
    // BYTE_EMULATOR_DEFINITION(0x2d)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x2e)
    // BYTE_EMULATOR_DEFINITION(0x2e)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x2f)
    // BYTE_EMULATOR_DEFINITION(0x2f)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x30)
    // BYTE_EMULATOR_DEFINITION(0x30)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x31)
    // BYTE_EMULATOR_DEFINITION(0x31)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x32)
    // BYTE_EMULATOR_DEFINITION(0x32)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x33)
    // BYTE_EMULATOR_DEFINITION(0x33)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x34)
    // BYTE_EMULATOR_DEFINITION(0x34)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x35)
    // BYTE_EMULATOR_DEFINITION(0x35)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x36)
    // BYTE_EMULATOR_DEFINITION(0x36)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x37)
    // BYTE_EMULATOR_DEFINITION(0x37)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x38)
    // BYTE_EMULATOR_DEFINITION(0x38)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x39)
    // BYTE_EMULATOR_DEFINITION(0x39)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x3a)
    // BYTE_EMULATOR_DEFINITION(0x3a)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x3b)
    // BYTE_EMULATOR_DEFINITION(0x3b)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x3c)
    // BYTE_EMULATOR_DEFINITION(0x3c)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x3d)
    // BYTE_EMULATOR_DEFINITION(0x3d)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x3e)
    // BYTE_EMULATOR_DEFINITION(0x3e)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x3f)
    // BYTE_EMULATOR_DEFINITION(0x3f)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x40)
    // BYTE_EMULATOR_DEFINITION(0x40)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.B prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x41)
    // BYTE_EMULATOR_DEFINITION(0x41)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.X prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x42)
    // BYTE_EMULATOR_DEFINITION(0x42)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.XB prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x43)
    // BYTE_EMULATOR_DEFINITION(0x43)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.R prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x44)
    // BYTE_EMULATOR_DEFINITION(0x44)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.RB prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x45)
    // BYTE_EMULATOR_DEFINITION(0x45)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.RX prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x46)
    // BYTE_EMULATOR_DEFINITION(0x46)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.RXB prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x47)
    // BYTE_EMULATOR_DEFINITION(0x47)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.W prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x48)
    // BYTE_EMULATOR_DEFINITION(0x48)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.WB prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x49)
    // BYTE_EMULATOR_DEFINITION(0x49)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.WX prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x4a)
    // BYTE_EMULATOR_DEFINITION(0x4a)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.WXB prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x4b)
    // BYTE_EMULATOR_DEFINITION(0x4b)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.WR prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x4c)
    // BYTE_EMULATOR_DEFINITION(0x4c)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.WRB prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x4d)
    // BYTE_EMULATOR_DEFINITION(0x4d)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.WRX prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x4e)
    // BYTE_EMULATOR_DEFINITION(0x4e)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents REX.WRXB prefix.
     *
     * For the REX bytes the four least significant bits are stored in the access_intent. Thus, no matter which of the REX
     * prefixes are encountered, the action is the same for all. Since these four bits are literally saved EXTRA_REX_MASK
     * from access_intent.h is used to mask out the last four bits, and these are shifted into place using EXTRA_REX_OFFSET
     * from access_intent.h, after which they're finally put into the access_intent.extra_info field.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x4f)
    // BYTE_EMULATOR_DEFINITION(0x4f)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x50)
    // BYTE_EMULATOR_DEFINITION(0x50)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x51)
    // BYTE_EMULATOR_DEFINITION(0x51)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x52)
    // BYTE_EMULATOR_DEFINITION(0x52)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x53)
    // BYTE_EMULATOR_DEFINITION(0x53)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x54)
    // BYTE_EMULATOR_DEFINITION(0x54)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x55)
    // BYTE_EMULATOR_DEFINITION(0x55)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x56)
    // BYTE_EMULATOR_DEFINITION(0x56)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x57)
    // BYTE_EMULATOR_DEFINITION(0x57)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x58)
    // BYTE_EMULATOR_DEFINITION(0x58)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x59)
    // BYTE_EMULATOR_DEFINITION(0x59)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x5a)
    // BYTE_EMULATOR_DEFINITION(0x5a)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x5b)
    // BYTE_EMULATOR_DEFINITION(0x5b)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x5c)
    // BYTE_EMULATOR_DEFINITION(0x5c)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x5d)
    // BYTE_EMULATOR_DEFINITION(0x5d)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x5e)
    // BYTE_EMULATOR_DEFINITION(0x5e)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x5f)
    // BYTE_EMULATOR_DEFINITION(0x5f)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x60)
    // BYTE_EMULATOR_DEFINITION(0x60)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x61)
    // BYTE_EMULATOR_DEFINITION(0x61)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x62)
    // BYTE_EMULATOR_DEFINITION(0x62)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x63)
    // BYTE_EMULATOR_DEFINITION(0x63)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x64)
    // BYTE_EMULATOR_DEFINITION(0x64)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x65)
    // BYTE_EMULATOR_DEFINITION(0x65)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * 0x66 is the operand-size override prefix in the first round. The presence of this group 3 refix byte is stored in
     * the prefixes field in the access_intent.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x66)
    // BYTE_EMULATOR_DEFINITION(0x66)

    /* Valid in: first round
     * ## First round ##
     *
     * 0x66 is the address-size override prefix in the first round. The presence of this group 3 refix byte is stored in
     * the prefixes field in the access_intent.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x67)
    // BYTE_EMULATOR_DEFINITION(0x67)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x68)
    // BYTE_EMULATOR_DEFINITION(0x68)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x69)
    // BYTE_EMULATOR_DEFINITION(0x69)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x6a)
    // BYTE_EMULATOR_DEFINITION(0x6a)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x6b)
    // BYTE_EMULATOR_DEFINITION(0x6b)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x6c)
    // BYTE_EMULATOR_DEFINITION(0x6c)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x6d)
    // BYTE_EMULATOR_DEFINITION(0x6d)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x6e)
    // BYTE_EMULATOR_DEFINITION(0x6e)

    /* Valid in second round
     *
     * ## Second round ##
     *
     * f3 prefix present
     *   MOVDQU xmm, xmm/m128
     *
     *   The destination operand is an XMM register. The source operand is either an XMM register or a 128-bit memory
     *   location, depending on the content of the following ModR/M byte. Only a VEX or EVEX prefix can change the
     *   size of the data used. When none is present, it is always 128-bit.
     *
     * 66 pr3fix present
     *   movdqa xmm. xmm/m128
     *
     *   The destination operand is an XMM register. The source operand is either an XMM register or a 128-bit memory
     *   location, depending on the content of the following ModR/M byte.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x6f)
    BYTE_EMULATOR_DEFINITION(0x6f)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x70)
    // BYTE_EMULATOR_DEFINITION(0x70)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x71)
    // BYTE_EMULATOR_DEFINITION(0x71)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x72)
    // BYTE_EMULATOR_DEFINITION(0x72)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x73)
    // BYTE_EMULATOR_DEFINITION(0x73)

    /* Valid in: second round
     *
     * ## Second round ##
     *
     * if no VEX or EVEX prefix present:
     *   PCMPEQB Pq, Qq
     *
     *   A ModR/M byte follows this opcode byte. The source operand is a MMX register or a memory reference, depending
     *   on the ModR/M byte. The destination register is a MMX register. The instruction handles a quadword, regardless
     *   of operand size prefix.
     *
     *   This instruction compares for equality of bytes in a quadword. Every data element found to be equal will be
     *   set to all 1's in the destination, or all 0's otherwise.
     *
     * if 0x66 prefix and VEX or EVEX present:
     *   VPCMPEQB Vx, Hx, Wx
     *
     *   A ModR/M byte follows this opcode byte. The source operand is an XMM, YMM, ZMM register, or a memory reference,
     *   depending on the ModR/M byte. The destination is an XMM, Ymm, or ZMM register. The size used for this
     *   instruction is dependent on the vector size.
     *
     *   This instruction compares the first source operand (i.e. the second operand) and the second source operand
     *   (i.e. the third operand) and sets the corresponding bytes in the destination (the first operand) to all 1's
     *   if the bytes are equal, or all 0's otherwise.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x74)
    BYTE_EMULATOR_DEFINITION(0x74)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x75)
    // BYTE_EMULATOR_DEFINITION(0x75)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x76)
    // BYTE_EMULATOR_DEFINITION(0x76)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x77)
    // BYTE_EMULATOR_DEFINITION(0x77)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x78)
    // BYTE_EMULATOR_DEFINITION(0x78)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x79)
    // BYTE_EMULATOR_DEFINITION(0x79)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x7a)
    // BYTE_EMULATOR_DEFINITION(0x7a)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x7b)
    // BYTE_EMULATOR_DEFINITION(0x7b)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x7c)
    // BYTE_EMULATOR_DEFINITION(0x7c)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x7d)
    // BYTE_EMULATOR_DEFINITION(0x7d)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x7e)
    // BYTE_EMULATOR_DEFINITION(0x7e)

    /* Valid in second round
     *
     * ## Second round ##
     *
     * if prefix 0x66 present
     *   VMOVDQA Wx, Vx
     *
     *   Here a ModR/M byte will follow the instruction, potentially in combination with a SIB. The destination
     *   operand is 128-bit XMM register, a 256-bit YMM register, or a memory address determined by the ModR/M and SIB.
     *   The source operand is a 128-bit XMM or 256-bit YMM register. The operand size attribute determines whether
     *   128-bit or 256-bit is used.
     *
     *   This instruction is affected by the VEX prefixes. When no VEX prefix is present: a double quadword (128-bits)
     *   will be moved from source to destination.
     *
     *   In case an EVEX prefix is present, 512 ZMM registers can also be accessed.
     *
     * if prefix 0xf3 present
     *   VMOVDQU Wx, Vx
     *
     *   Here a ModR/M byte will follow the instruction, potentially in combination with a SIB. The destination
     *   operand is 128-bit XMM register, a 256-bit YMM register, or a memory address determined by the ModR/M and SIB.
     *   The source operand is a 128-bit XMM or 256-bit YMM register. The operand size attribute determines whether
     *   128-bit or 256-bit is used.
     *
     *   In case an EVEX prefix is present, 512 ZMM registers can also be accessed.
     *
     * if prefix 0xf2 present
     *   invalid
     *
     * else
     *   movq Qq, Pq
     *
     *   Here a ModR/M byte will follow the instruction, potentially in combination with a SIB. The destination operand
     *   is either an MMX register or a memory address. The source operand is a MMX register. The operand size is
     *   always a quadword, regardless of operand size attribute.
     *
     * ## Other round ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x7f)
    // BYTE_EMULATOR_DEFINITION(0x7f)

    /* Valid in first round
     *
     * ## First round ##
     *
     * Immediate Grp 1 Eb, Ib - ModR/M bits [5,3] used as opcode extension
     *
     * opcode extensions
     *   * 000: ADD - not yet implemented
     *   * 001: OR  - not yet implemented
     *   * 010: ADC - not yet implemented
     *   * 011: SBB - not yet implemented
     *   * 100: AND - not yet implemented
     *   * 101: SUB - not yet implemented
     *   * 110: XOR - not yet implemented
     *   * 111: CMP - CMP r/m8, imm8
     *
     * CMP r/m8, imm8
     *
     *   destination operand is either an 8-bit general purpose register, or an 8-bit memory location. The source
     *   operand is an 8-bit immediate operand.
     *
     *   This instruction compares the first and second operand and sets the EFLAGS register accordingly. Comparison is
     *   performed by subtracting the second operand from the first, the setting of the bits in the EFLAGS register is
     *   identical to how it is performed when performing the SUB instruction. The result of this SUB operation is
     *   stored in the destination operand.
     *
     * ## Other round ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x80)
    BYTE_EMULATOR_DEFINITION(0x80)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x81)
    // BYTE_EMULATOR_DEFINITION(0x81)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x82)
    // BYTE_EMULATOR_DEFINITION(0x82)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x83)
    // BYTE_EMULATOR_DEFINITION(0x83)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x84)
    // BYTE_EMULATOR_DEFINITION(0x84)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x85)
    // BYTE_EMULATOR_DEFINITION(0x85)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x86)
    // BYTE_EMULATOR_DEFINITION(0x86)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x87)
    // BYTE_EMULATOR_DEFINITION(0x87)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents mov Eb, Gb - move second operand into first operand
     *
     * Here direction is set so the first operand, the destinaton, is a general purpose register/memory location and the
     * second, the source, is a general purpose register. The operand size is 8 bits, regardless of the presence of any
     * REX or other prefixes.
     *
     * This opcode will by followed by a ModR/M byte, so after decoding this, we'll call decode addressing if everything
     * else is in order and return the result from that call.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x88)
    BYTE_EMULATOR_DEFINITION(0x88)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents move Ev, Gv - move second operand into first operand
     *
     * Here direction is set so the first operand, the destination, is a general purpose register/memory location and
     * the second, the source, is a general purpose register. The operand size is 16 or 32 bits, depending on the
     * presence of prefix byte 0x66. If REX.W is present in 64 bit program, operand size will become 64 bit,
     * regardless of other prefixes.
     *
     * This opcode will by followed by a ModR/M byte, so after decoding this, we'll call decode addressing if everything
     * else is in order and return the result from that call.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x89)
    BYTE_EMULATOR_DEFINITION(0x89)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents move Gb, Eb - move second operand into first operand
     *
     * Here direction is set so the first operand, the destination, is a general purpose register and the second operand,
     * the source, is a general purpose register/memory location. The operand size is 8 bits, regardless of REX or other
     * prefixes.
     *
     * This opcode will by followed by a ModR/M byte, so after decoding this, we'll call decode addressing if everything
     * else is in order and return the result from that call.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x8a)
    BYTE_EMULATOR_DEFINITION(0x8a)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents move Gv, Ev - move second operand into first operand
     *
     * Here direction is set so the first operand, the destination, is a general purpose register and the second operand,
     * the source, is a general purpose register/memory location. The operand size is either 16 or 32 bits, depending on
     * the precense of prefix 0x66. When REX.W is present, operand size is 64 bits, regardless of other prefixes.
     *
     * This opcode will by followed by a ModR/M byte, so after decoding this, we'll call decode addressing if everything
     * else is in order and return the result from that call.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x8b)
    BYTE_EMULATOR_DEFINITION(0x8b)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents move Ev, Sw - move second operand into first operand, using segment register
     *
     * Instead of a general purpose register, a segment register is used. Here direction is set so the first operand, the
     * destination, is a general purpose register/memory location and the second operand, the source, is a 16-bit segment
     * register. The source is either a 16 or 32-bit register depending on the presence of prefix 0x66, but always 16-bit
     * if it's a memory location. If REX.W is present the destination register will be a 64-bit register, this prefix does
     * not influence the destination if it's a memory location.
     *
     * The segment register is zero extended.
     *
     * This opcode will by followed by a ModR/M byte, so after decoding this, we'll call decode addressing if everything
     * else is in order and return the result from that call.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x8c)
    BYTE_EMULATOR_DEFINITION(0x8c)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x8d)
    // BYTE_EMULATOR_DEFINITION(0x8d)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * Represents move Sw, Ev - move second operand into first operand, using segment register
     *
     * Instead of a general purpose register, a segment register is used. Here direction is set so the first operand, the
     * destination, is a 16-bit segment register and the second operand, the source, is a general purpose register/memory
     * location. The source specifies a 16 bit general purpose register or memory location, it does not depend on 0x66 to
     * access a 32-bit register or memory location. if REX.W is present, however, the lower 16 bits of a 64-bit general
     * purpose register or memory location will be moved to the destination.
     *
     * This opcode will by followed by a ModR/M byte, so after decoding this, we'll call decode addressing if everything
     * else is in order and return the result from that call.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0x8e)
    BYTE_EMULATOR_DEFINITION(0x8e)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x8f)
    // BYTE_EMULATOR_DEFINITION(0x8f)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x90)
    // BYTE_EMULATOR_DEFINITION(0x90)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x91)
    // BYTE_EMULATOR_DEFINITION(0x91)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x92)
    // BYTE_EMULATOR_DEFINITION(0x92)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x93)
    // BYTE_EMULATOR_DEFINITION(0x93)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x94)
    // BYTE_EMULATOR_DEFINITION(0x94)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x95)
    // BYTE_EMULATOR_DEFINITION(0x95)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x96)
    // BYTE_EMULATOR_DEFINITION(0x96)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x97)
    // BYTE_EMULATOR_DEFINITION(0x97)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x98)
    // BYTE_EMULATOR_DEFINITION(0x98)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x99)
    // BYTE_EMULATOR_DEFINITION(0x99)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x9a)
    // BYTE_EMULATOR_DEFINITION(0x9a)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x9b)
    // BYTE_EMULATOR_DEFINITION(0x9b)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x9c)
    // BYTE_EMULATOR_DEFINITION(0x9c)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x9d)
    // BYTE_EMULATOR_DEFINITION(0x9d)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x9e)
    // BYTE_EMULATOR_DEFINITION(0x9e)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0x9f)
    // BYTE_EMULATOR_DEFINITION(0x9f)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xa0)
    // BYTE_EMULATOR_DEFINITION(0xa0)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xa1)
    // BYTE_EMULATOR_DEFINITION(0xa1)

    /* Valid in second round
     *
     * ## Second round ##
     *
     * cpuid
     *
     * Returns processor identification and feature information in the EAX, EBX, ACX, and EDX registers. Our current
     * use for the emulation of this instruction is blocking the use of YMM and ZMM registers.
     *
     * overrides:
     *
     * eax 0x01 | ecx | bit  0 - SSE 3
     *          |     | bit  9 - SSE 3
     *          |     | bit 12 - FMA                                                                                (?)
     *          |     | bit 19 - SSE 4.1
     *          |     | bit 20 - SSE 4.2
     *          |     | bit 28 - AVX
     *          |     |
     *          | edx |
     *          |     |
     * eax 0x07 | ebx | bit  5 - AVX2
     *          |     | bit 16 - AVX512F
     *          |     | bit 17 - AVX512DQ
     *          |     | bit 21 - AVX512_IFMA
     *          |     | bit 26 - AVX512PF
     *          |     | bit 27 - AVX512ER
     *          |     | bit 28 - AVX512CD
     *          |     | bit 30 - AVX512BW
     *          |     | bit 31 - AVX512VL
     *          |     |
     *          | ecx | bit  1 - AVX512_VBMI
     *          |     | bit  6 - AVX512_VBMI2
     *          |     | bit 10 - VPCLMULQDQ
     *          |     | bit 11 - AVX512_VNNI
     *          |     | bit 12 - AVX512_BITALG
     *          |     | bit 14 - AVX512_VPOPCNTDQ
     *          |     |
     *          | edx | bit  2 - AVX512_4VNNIW
     *          |     | bit  3 - AVX512_4FMAPS
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0xa2)
    BYTE_EMULATOR_DEFINITION(0xa2)
#define FEATURE_ECX_BLOCKS                  ~((0b1u <<  0u) |                                                          \
                                              (0b1u <<  9u) |                                                          \
                                              (0b1u << 12u) |                                                          \
                                              (0b1u << 19u) |                                                          \
                                              (0b1u << 20u) |                                                          \
                                              (0b1u << 28u)  )

#define EXTENDED_FEATURE_EBX_BLOCKS         ~((0b1u <<   5u) |                                                         \
                                              (0b1u <<  16u) |                                                         \
                                              (0b1u <<  17u) |                                                         \
                                              (0b1u <<  21u) |                                                         \
                                              (0b1u <<  26u) |                                                         \
                                              (0b1u <<  27u) |                                                         \
                                              (0b1u <<  28u) |                                                         \
                                              (0b1u <<  30u) |                                                         \
                                              (0b1u <<  31u)  )

#define EXTENDED_FEATURE_ECX_BLOCKS         ~((0b1u <<   1u) |                                                         \
                                              (0b1u <<   6u) |                                                         \
                                              (0b1u <<  10u) |                                                         \
                                              (0b1u <<  11u) |                                                         \
                                              (0b1u <<  12u) |                                                         \
                                              (0b1u <<  14u)  )

#define EXTENDED_FEATURE_EDX_BLOCKS         ~((0b1u <<   2u) |                                                         \
                                              (0b1u <<   3u)  )


    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xa3)
    // BYTE_EMULATOR_DEFINITION(0xa3)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xa4)
    // BYTE_EMULATOR_DEFINITION(0xa4)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xa5)
    // BYTE_EMULATOR_DEFINITION(0xa5)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xa6)
    // BYTE_EMULATOR_DEFINITION(0xa6)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xa7)
    // BYTE_EMULATOR_DEFINITION(0xa7)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xa8)
    // BYTE_EMULATOR_DEFINITION(0xa8)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xa9)
    // BYTE_EMULATOR_DEFINITION(0xa9)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xaa)
    // BYTE_EMULATOR_DEFINITION(0xaa)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xab)
    // BYTE_EMULATOR_DEFINITION(0xab)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xac)
    // BYTE_EMULATOR_DEFINITION(0xac)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xad)
    // BYTE_EMULATOR_DEFINITION(0xad)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xae)
    // BYTE_EMULATOR_DEFINITION(0xae)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xaf)
    // BYTE_EMULATOR_DEFINITION(0xaf)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xb0)
    // BYTE_EMULATOR_DEFINITION(0xb0)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xb1)
    // BYTE_EMULATOR_DEFINITION(0xb1)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xb2)
    // BYTE_EMULATOR_DEFINITION(0xb2)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xb3)
    // BYTE_EMULATOR_DEFINITION(0xb3)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xb4)
    // BYTE_EMULATOR_DEFINITION(0xb4)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xb5)
    // BYTE_EMULATOR_DEFINITION(0xb5)

    /* Valid in: second round
     *
     * ## Second round ##
     *
     * movzx Gv, Eb - move second operand into first operand and zero extends it.
     *
     * Direction is set so that the first operand, the destination, is a general purpose register and the second
     * operand, the source, is a memory location or another general purpose register. The size of the source is always
     * a byte, regardless of other prefixes, and the size of the destination is 16, 32, or 64-bit. This instruction
     * will zero extend the data moved into the destination.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0xb6)
    BYTE_EMULATOR_DEFINITION(0xb6)

    /* Valid in: second round
     *
     * ## Second round ##
     *
     * movzx Gv, Ew - move second operand into first operand and zero expand it if necessary.
     *
     * Direction is set so that the first operand, the destination, is a general purpose register and the second
     * operand, the source, is a memory location or another general purpose register. The size of the source is always
     * 16-bit, regardless of other prefixes, and the size of the destination is 16, 32, or 64-bit. This instruction
     * will zero extend the data moved into the destination if necessary.
     *
     * ## Other round ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0xb7)
    BYTE_EMULATOR_DEFINITION(0xb7)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xb8)
    // BYTE_EMULATOR_DEFINITION(0xb8)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xb9)
    // BYTE_EMULATOR_DEFINITION(0xb9)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xba)
    // BYTE_EMULATOR_DEFINITION(0xba)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xbb)
    // BYTE_EMULATOR_DEFINITION(0xbb)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xbc)
    // BYTE_EMULATOR_DEFINITION(0xbc)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xbd)
    // BYTE_EMULATOR_DEFINITION(0xbd)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xbe)
    // BYTE_EMULATOR_DEFINITION(0xbe)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xbf)
    // BYTE_EMULATOR_DEFINITION(0xbf)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xc0)
    // BYTE_EMULATOR_DEFINITION(0xc0)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xc1)
    // BYTE_EMULATOR_DEFINITION(0xc1)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xc2)
    // BYTE_EMULATOR_DEFINITION(0xc2)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xc3)
    // BYTE_EMULATOR_DEFINITION(0xc3)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * VEX+2 byte
     *
     * Marks the start of a VEX prefix. Two more bytes will follow this one describing the actual prefix content. The
     * content is as follows:
     *
     * +-------+-----------+    +---+---------+---+-----+
     * | R X B | m m m m m |    | W | v v v v | L | p p |
     * +-------+-----------+    +---+---------+---+-----+
     *
     * ## Other round ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0xc4)
    // BYTE_EMULATOR_DEFINITION(0xc4)

    /* Valid in: first round
     *
     * ## First round ##
     *
     * VEX+1 byte
     *
     * Marks the start of a VEX prefix. One more byte will follow this one describing the actual prefix content. The
     * content is as follows:
     *
     * +---+---------+---+-----+
     * | R | v v v v | L | p p |
     * +---+---------+---+-----+
     *
     * ## Other round ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0xc5)
    // BYTE_EMULATOR_DEFINITION(0xc5)

    /* Valid in first round
     *
     * ## First round ##
     *
     * MOV Eb, Ib
     *
     * A ModR/M byte follows the opcode specifying the destination operand. This destination can be either a general
     * purpose register or a memory location. The source operand represents immediate data that will follow at the tail
     * end of the instruction. This instruction takes exactly one byte as source and moves it into a byte sized
     * destination.
     *
     * ## Other round ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0xc6)
    BYTE_EMULATOR_DEFINITION(0xc6)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xc7)
    // BYTE_EMULATOR_DEFINITION(0xc7)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xc8)
    // BYTE_EMULATOR_DEFINITION(0xc8)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xc9)
    // BYTE_EMULATOR_DEFINITION(0xc9)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xca)
    // BYTE_EMULATOR_DEFINITION(0xca)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xcb)
    // BYTE_EMULATOR_DEFINITION(0xcb)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xcc)
    // BYTE_EMULATOR_DEFINITION(0xcc)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xcd)
    // BYTE_EMULATOR_DEFINITION(0xcd)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xce)
    // BYTE_EMULATOR_DEFINITION(0xce)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xcf)
    // BYTE_EMULATOR_DEFINITION(0xcf)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd0)
    // BYTE_EMULATOR_DEFINITION(0xd0)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd1)
    // BYTE_EMULATOR_DEFINITION(0xd1)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd2)
    // BYTE_EMULATOR_DEFINITION(0xd2)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd3)
    // BYTE_EMULATOR_DEFINITION(0xd3)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd4)
    // BYTE_EMULATOR_DEFINITION(0xd4)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd5)
    // BYTE_EMULATOR_DEFINITION(0xd5)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd6)
    // BYTE_EMULATOR_DEFINITION(0xd6)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd7)
    // BYTE_EMULATOR_DEFINITION(0xd7)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd8)
    // BYTE_EMULATOR_DEFINITION(0xd8)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xd9)
    // BYTE_EMULATOR_DEFINITION(0xd9)

    /* Valid in: second round
     *
     * ## Second round ##
     *
     * if no prefix present:
     *   pminub mm1, mm2/m64
     *
     * if 66 prefix present:
     *   pminub xmm1, xmm2/m128
     *
     * Destination operand is either an mm or xmm register. Source operand can either be an mm or xmm register, or an
     * equally sized memory reference. The size of destination and source operand always matches. Compares the
     * individual bytes of the source operand with the destination operand and writes the minimum value to the
     * destination.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0xda)
    BYTE_EMULATOR_DEFINITION(0xda)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xdb)
    // BYTE_EMULATOR_DEFINITION(0xdb)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xdc)
    // BYTE_EMULATOR_DEFINITION(0xdc)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xdd)
    // BYTE_EMULATOR_DEFINITION(0xdd)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xde)
    // BYTE_EMULATOR_DEFINITION(0xde)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xdf)
    // BYTE_EMULATOR_DEFINITION(0xdf)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe0)
    // BYTE_EMULATOR_DEFINITION(0xe0)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe1)
    // BYTE_EMULATOR_DEFINITION(0xe1)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe2)
    // BYTE_EMULATOR_DEFINITION(0xe2)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe3)
    // BYTE_EMULATOR_DEFINITION(0xe3)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe4)
    // BYTE_EMULATOR_DEFINITION(0xe4)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe5)
    // BYTE_EMULATOR_DEFINITION(0xe5)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe6)
    // BYTE_EMULATOR_DEFINITION(0xe6)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe7)
    // BYTE_EMULATOR_DEFINITION(0xe7)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe8)
    // BYTE_EMULATOR_DEFINITION(0xe8)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xe9)
    // BYTE_EMULATOR_DEFINITION(0xe9)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xea)
    // BYTE_EMULATOR_DEFINITION(0xea)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xeb)
    // BYTE_EMULATOR_DEFINITION(0xeb)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xec)
    // BYTE_EMULATOR_DEFINITION(0xec)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xed)
    // BYTE_EMULATOR_DEFINITION(0xed)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xee)
    // BYTE_EMULATOR_DEFINITION(0xee)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xef)
    // BYTE_EMULATOR_DEFINITION(0xef)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xf0)
    // BYTE_EMULATOR_DEFINITION(0xf0)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xf1)
    // BYTE_EMULATOR_DEFINITION(0xf1)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xf2)
    // BYTE_EMULATOR_DEFINITION(0xf2)

    /* Valid in first round
     *
     * ## First round ##
     *
     * REP or REPE/REPZ prefix
     *
     * Applies only to string and I/O operations,a lso a mandatory prefix for POPCNT, LZCNT and ADOX instructions.
     * Causes an instruction to be executed for each element of a string.
     *
     * ## Other rounds ##
     *
     * If encountered in other rounds, ILLEGAL_ACCESS should be set as operation and the decoding should be terminated
     * returning ILLEGAL_ACCESS_TERMINATION.
     */
    BYTE_LOADER_DEFINITION(0xf3)
    // BYTE_EMULATOR_DEFINITION(0xf3)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xf4)
    // BYTE_EMULATOR_DEFINITION(0xf4)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xf5)
    // BYTE_EMULATOR_DEFINITION(0xf5)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xf6)
    // BYTE_EMULATOR_DEFINITION(0xf6)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xf7)
    // BYTE_EMULATOR_DEFINITION(0xf7)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xf8)
    // BYTE_EMULATOR_DEFINITION(0xf8)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xf9)
    // BYTE_EMULATOR_DEFINITION(0xf9)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xfa)
    // BYTE_EMULATOR_DEFINITION(0xfa)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xfb)
    // BYTE_EMULATOR_DEFINITION(0xfb)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xfc)
    // BYTE_EMULATOR_DEFINITION(0xfc)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xfd)
    // BYTE_EMULATOR_DEFINITION(0xfd)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xfe)
    // BYTE_EMULATOR_DEFINITION(0xfe)

    /* Not implemented - blocked */
    // BYTE_LOADER_DEFINITION(0xff)
    // BYTE_EMULATOR_DEFINITION(0xff)

    // -----------------------------------------------------------------------------------------------------------------
    //      lookup table
    // -----------------------------------------------------------------------------------------------------------------

    static constexpr const emulation_lookup lookup_table[256] =
    {
            {&block_loader          , &block_emulator},                                              // 0x00
            {&block_loader          , &block_emulator},                                              // 0x01
            {&block_loader          , &block_emulator},                                              // 0x02
            {&block_loader          , &block_emulator},                                              // 0x03
            {&block_loader          , &block_emulator},                                              // 0x04
            {&block_loader          , &block_emulator},                                              // 0x05
            {&block_loader          , &block_emulator},                                              // 0x06
            {&block_loader          , &block_emulator},                                              // 0x07
            {&block_loader          , &block_emulator},                                              // 0x08
            {&block_loader          , &block_emulator},                                              // 0x09
            {&block_loader          , &block_emulator},                                              // 0x0a
            {&block_loader          , &block_emulator},                                              // 0x0b
            {&block_loader          , &block_emulator},                                              // 0x0c
            {&block_loader          , &block_emulator},                                              // 0x0d
            {&block_loader          , &block_emulator},                                              // 0x0e
            {&BYTE_LOADER_NAME(0x0f), &block_emulator},                                               // 0x0f
            {&BYTE_LOADER_NAME(0x10), &BYTE_EMULATOR_NAME(0x10)},                               // 0x10
            {&BYTE_LOADER_NAME(0x11), &BYTE_EMULATOR_NAME(0x11)},                               // 0x11
            {&block_loader          , &block_emulator},                                              // 0x12
            {&block_loader          , &block_emulator},                                              // 0x13
            {&block_loader          , &block_emulator},                                              // 0x14
            {&block_loader          , &block_emulator},                                              // 0x15
            {&block_loader          , &block_emulator},                                              // 0x16
            {&block_loader          , &block_emulator},                                              // 0x17
            {&block_loader          , &block_emulator},                                              // 0x18
            {&block_loader          , &block_emulator},                                              // 0x19
            {&block_loader          , &block_emulator},                                              // 0x1a
            {&block_loader          , &block_emulator},                                              // 0x1b
            {&block_loader          , &block_emulator},                                              // 0x1c
            {&block_loader          , &block_emulator},                                              // 0x1d
            {&block_loader          , &block_emulator},                                              // 0x1e
            {&block_loader          , &block_emulator},                                              // 0x1f
            {&block_loader          , &block_emulator},                                              // 0x20
            {&block_loader          , &block_emulator},                                              // 0x21
            {&block_loader          , &block_emulator},                                              // 0x22
            {&block_loader          , &block_emulator},                                              // 0x23
            {&block_loader          , &block_emulator},                                              // 0x24
            {&block_loader          , &block_emulator},                                              // 0x25
            {&block_loader          , &block_emulator},                                              // 0x26
            {&block_loader          , &block_emulator},                                              // 0x27
            {&block_loader          , &block_emulator},                                              // 0x28
            {&block_loader          , &block_emulator},                                              // 0x29
            {&block_loader          , &block_emulator},                                              // 0x2a
            {&block_loader          , &block_emulator},                                              // 0x2b
            {&block_loader          , &block_emulator},                                              // 0x2c
            {&block_loader          , &block_emulator},                                              // 0x2d
            {&block_loader          , &block_emulator},                                              // 0x2e
            {&block_loader          , &block_emulator},                                              // 0x2f
            {&block_loader          , &block_emulator},                                              // 0x30
            {&block_loader          , &block_emulator},                                              // 0x31
            {&block_loader          , &block_emulator},                                              // 0x32
            {&block_loader          , &block_emulator},                                              // 0x33
            {&block_loader          , &block_emulator},                                              // 0x34
            {&block_loader          , &block_emulator},                                              // 0x35
            {&block_loader          , &block_emulator},                                              // 0x36
            {&block_loader          , &block_emulator},                                              // 0x37
            {&block_loader          , &block_emulator},                                              // 0x38
            {&block_loader          , &block_emulator},                                              // 0x39
            {&block_loader          , &block_emulator},                                              // 0x3a
            {&block_loader          , &block_emulator},                                              // 0x3b
            {&block_loader          , &block_emulator},                                              // 0x3c
            {&block_loader          , &block_emulator},                                              // 0x3d
            {&block_loader          , &block_emulator},                                              // 0x3e
            {&block_loader          , &block_emulator},                                              // 0x3f
            {&BYTE_LOADER_NAME(0x40), &block_emulator},                                              // 0x40
            {&BYTE_LOADER_NAME(0x41), &block_emulator},                                              // 0x41
            {&BYTE_LOADER_NAME(0x42), &block_emulator},                                              // 0x42
            {&BYTE_LOADER_NAME(0x43), &block_emulator},                                              // 0x43
            {&BYTE_LOADER_NAME(0x44), &block_emulator},                                              // 0x44
            {&BYTE_LOADER_NAME(0x45), &block_emulator},                                              // 0x45
            {&BYTE_LOADER_NAME(0x46), &block_emulator},                                              // 0x46
            {&BYTE_LOADER_NAME(0x47), &block_emulator},                                              // 0x47
            {&BYTE_LOADER_NAME(0x48), &block_emulator},                                              // 0x48
            {&BYTE_LOADER_NAME(0x49), &block_emulator},                                              // 0x49
            {&BYTE_LOADER_NAME(0x4a), &block_emulator},                                              // 0x4a
            {&BYTE_LOADER_NAME(0x4b), &block_emulator},                                              // 0x4b
            {&BYTE_LOADER_NAME(0x4c), &block_emulator},                                              // 0x4c
            {&BYTE_LOADER_NAME(0x4d), &block_emulator},                                              // 0x4d
            {&BYTE_LOADER_NAME(0x4e), &block_emulator},                                              // 0x4e
            {&BYTE_LOADER_NAME(0x4f), &block_emulator},                                              // 0x4f
            {&block_loader          , &block_emulator},                                              // 0x50
            {&block_loader          , &block_emulator},                                              // 0x51
            {&block_loader          , &block_emulator},                                              // 0x52
            {&block_loader          , &block_emulator},                                              // 0x53
            {&block_loader          , &block_emulator},                                              // 0x54
            {&block_loader          , &block_emulator},                                              // 0x55
            {&block_loader          , &block_emulator},                                              // 0x56
            {&block_loader          , &block_emulator},                                              // 0x57
            {&block_loader          , &block_emulator},                                              // 0x58
            {&block_loader          , &block_emulator},                                              // 0x59
            {&block_loader          , &block_emulator},                                              // 0x5a
            {&block_loader          , &block_emulator},                                              // 0x5b
            {&block_loader          , &block_emulator},                                              // 0x5c
            {&block_loader          , &block_emulator},                                              // 0x5d
            {&block_loader          , &block_emulator},                                              // 0x5e
            {&block_loader          , &block_emulator},                                              // 0x5f
            {&block_loader          , &block_emulator},                                              // 0x60
            {&block_loader          , &block_emulator},                                              // 0x61
            {&block_loader          , &block_emulator},                                              // 0x62
            {&block_loader          , &block_emulator},                                              // 0x63
            {&block_loader          , &block_emulator},                                              // 0x64
            {&block_loader          , &block_emulator},                                              // 0x65
            {&BYTE_LOADER_NAME(0x66), &block_emulator},                                              // 0x66
            {&BYTE_LOADER_NAME(0x67), &block_emulator},                                              // 0x67
            {&block_loader          , &block_emulator},                                              // 0x68
            {&block_loader          , &block_emulator},                                              // 0x69
            {&block_loader          , &block_emulator},                                              // 0x6a
            {&block_loader          , &block_emulator},                                              // 0x6b
            {&block_loader          , &block_emulator},                                              // 0x6c
            {&block_loader          , &block_emulator},                                              // 0x6d
            {&block_loader          , &block_emulator},                                              // 0x6e
            {&BYTE_LOADER_NAME(0x6f), &BYTE_EMULATOR_NAME(0x6f)},                               // 0x6f
            {&block_loader          , &block_emulator},                                              // 0x70
            {&block_loader          , &block_emulator},                                              // 0x71
            {&block_loader          , &block_emulator},                                              // 0x72
            {&block_loader          , &block_emulator},                                              // 0x73
            {&BYTE_LOADER_NAME(0x74), &BYTE_EMULATOR_NAME(0x74)},                               // 0x74
            {&block_loader          , &block_emulator},                                              // 0x75
            {&block_loader          , &block_emulator},                                              // 0x76
            {&block_loader          , &block_emulator},                                              // 0x77
            {&block_loader          , &block_emulator},                                              // 0x78
            {&block_loader          , &block_emulator},                                              // 0x79
            {&block_loader          , &block_emulator},                                              // 0x7a
            {&block_loader          , &block_emulator},                                              // 0x7b
            {&block_loader          , &block_emulator},                                              // 0x7c
            {&block_loader          , &block_emulator},                                              // 0x7d
            {&block_loader          , &block_emulator},                                              // 0x7e
            {&BYTE_LOADER_NAME(0x7f), &block_emulator},                                              // 0x7f
            {&BYTE_LOADER_NAME(0x80), &BYTE_EMULATOR_NAME(0x80)},                               // 0x80
            {&block_loader          , &block_emulator},                                              // 0x81
            {&block_loader          , &block_emulator},                                              // 0x82
            {&block_loader          , &block_emulator},                                              // 0x83
            {&block_loader          , &block_emulator},                                              // 0x84
            {&block_loader          , &block_emulator},                                              // 0x85
            {&block_loader          , &block_emulator},                                              // 0x86
            {&block_loader          , &block_emulator},                                              // 0x87
            {&BYTE_LOADER_NAME(0x88), &BYTE_EMULATOR_NAME(0x88)},                               // 0x88
            {&BYTE_LOADER_NAME(0x89), &BYTE_EMULATOR_NAME(0x89)},                               // 0x89
            {&BYTE_LOADER_NAME(0x8a), &BYTE_EMULATOR_NAME(0x8a)},                               // 0x8a
            {&BYTE_LOADER_NAME(0x8b), &BYTE_EMULATOR_NAME(0x8b)},                               // 0x8b
            {&BYTE_LOADER_NAME(0x8c), &BYTE_EMULATOR_NAME(0x8c)},                               // 0x8c
            {&block_loader          , &block_emulator},                                              // 0x8d
            {&BYTE_LOADER_NAME(0x8e), &BYTE_EMULATOR_NAME(0x8e)},                               // 0x8e
            {&block_loader          , &block_emulator},                                              // 0x8f
            {&block_loader          , &block_emulator},                                              // 0x90
            {&block_loader          , &block_emulator},                                              // 0x91
            {&block_loader          , &block_emulator},                                              // 0x92
            {&block_loader          , &block_emulator},                                              // 0x93
            {&block_loader          , &block_emulator},                                              // 0x94
            {&block_loader          , &block_emulator},                                              // 0x95
            {&block_loader          , &block_emulator},                                              // 0x96
            {&block_loader          , &block_emulator},                                              // 0x97
            {&block_loader          , &block_emulator},                                              // 0x98
            {&block_loader          , &block_emulator},                                              // 0x99
            {&block_loader          , &block_emulator},                                              // 0x9a
            {&block_loader          , &block_emulator},                                              // 0x9b
            {&block_loader          , &block_emulator},                                              // 0x9c
            {&block_loader          , &block_emulator},                                              // 0x9d
            {&block_loader          , &block_emulator},                                              // 0x9e
            {&block_loader          , &block_emulator},                                              // 0x9f
            {&block_loader          , &block_emulator},                                              // 0xa0
            {&block_loader          , &block_emulator},                                              // 0xa1
            {&BYTE_LOADER_NAME(0xa2), &BYTE_EMULATOR_NAME(0xa2)},                               // 0xa2
            {&block_loader          , &block_emulator},                                              // 0xa3
            {&block_loader          , &block_emulator},                                              // 0xa4
            {&block_loader          , &block_emulator},                                              // 0xa5
            {&block_loader          , &block_emulator},                                              // 0xa6
            {&block_loader          , &block_emulator},                                              // 0xa7
            {&block_loader          , &block_emulator},                                              // 0xa8
            {&block_loader          , &block_emulator},                                              // 0xa9
            {&block_loader          , &block_emulator},                                              // 0xaa
            {&block_loader          , &block_emulator},                                              // 0xab
            {&block_loader          , &block_emulator},                                              // 0xac
            {&block_loader          , &block_emulator},                                              // 0xad
            {&block_loader          , &block_emulator},                                              // 0xae
            {&block_loader          , &block_emulator},                                              // 0xaf
            {&block_loader          , &block_emulator},                                              // 0xb0
            {&block_loader          , &block_emulator},                                              // 0xb1
            {&block_loader          , &block_emulator},                                              // 0xb2
            {&block_loader          , &block_emulator},                                              // 0xb3
            {&block_loader          , &block_emulator},                                              // 0xb4
            {&block_loader          , &block_emulator},                                              // 0xb5
            {&BYTE_LOADER_NAME(0xb6), &BYTE_EMULATOR_NAME(0xb6)},                               // 0xb6
            {&BYTE_LOADER_NAME(0xb7), &block_emulator},                                              // 0xb7
            {&block_loader          , &block_emulator},                                              // 0xb8
            {&block_loader          , &block_emulator},                                              // 0xb9
            {&block_loader          , &block_emulator},                                              // 0xba
            {&block_loader          , &block_emulator},                                              // 0xbb
            {&block_loader          , &block_emulator},                                              // 0xbc
            {&block_loader          , &block_emulator},                                              // 0xbd
            {&block_loader          , &block_emulator},                                              // 0xbe
            {&block_loader          , &block_emulator},                                              // 0xbf
            {&block_loader          , &block_emulator},                                              // 0xc0
            {&block_loader          , &block_emulator},                                              // 0xc1
            {&block_loader          , &block_emulator},                                              // 0xc2
            {&block_loader          , &block_emulator},                                              // 0xc3
            {&block_loader          , &block_emulator},                                              // 0xc4
            {&block_loader          , &block_emulator},                                              // 0xc5
            {&BYTE_LOADER_NAME(0xc6), &BYTE_EMULATOR_NAME(0xc6)},                            // 0xc6
            {&block_loader          , &block_emulator},                                              // 0xc7
            {&block_loader          , &block_emulator},                                              // 0xc8
            {&block_loader          , &block_emulator},                                              // 0xc9
            {&block_loader          , &block_emulator},                                              // 0xca
            {&block_loader          , &block_emulator},                                              // 0xcb
            {&block_loader          , &block_emulator},                                              // 0xcc
            {&block_loader          , &block_emulator},                                              // 0xcd
            {&block_loader          , &block_emulator},                                              // 0xce
            {&block_loader          , &block_emulator},                                              // 0xcf
            {&block_loader          , &block_emulator},                                              // 0xd0
            {&block_loader          , &block_emulator},                                              // 0xd1
            {&block_loader          , &block_emulator},                                              // 0xd2
            {&block_loader          , &block_emulator},                                              // 0xd3
            {&block_loader          , &block_emulator},                                              // 0xd4
            {&block_loader          , &block_emulator},                                              // 0xd5
            {&block_loader          , &block_emulator},                                              // 0xd6
            {&block_loader          , &block_emulator},                                              // 0xd7
            {&block_loader          , &block_emulator},                                              // 0xd8
            {&block_loader          , &block_emulator},                                              // 0xd9
            {&BYTE_LOADER_NAME(0xda), &BYTE_EMULATOR_NAME(0xda)},                               // 0xda
            {&block_loader          , &block_emulator},                                              // 0xdb
            {&block_loader          , &block_emulator},                                              // 0xdc
            {&block_loader          , &block_emulator},                                              // 0xdd
            {&block_loader          , &block_emulator},                                              // 0xde
            {&block_loader          , &block_emulator},                                              // 0xdf
            {&block_loader          , &block_emulator},                                              // 0xe0
            {&block_loader          , &block_emulator},                                              // 0xe1
            {&block_loader          , &block_emulator},                                              // 0xe2
            {&block_loader          , &block_emulator},                                              // 0xe3
            {&block_loader          , &block_emulator},                                              // 0xe4
            {&block_loader          , &block_emulator},                                              // 0xe5
            {&block_loader          , &block_emulator},                                              // 0xe6
            {&block_loader          , &block_emulator},                                              // 0xe7
            {&block_loader          , &block_emulator},                                              // 0xe8
            {&block_loader          , &block_emulator},                                              // 0xe9
            {&block_loader          , &block_emulator},                                              // 0xea
            {&block_loader          , &block_emulator},                                              // 0xeb
            {&block_loader          , &block_emulator},                                              // 0xec
            {&block_loader          , &block_emulator},                                              // 0xed
            {&block_loader          , &block_emulator},                                              // 0xee
            {&block_loader          , &block_emulator},                                              // 0xef
            {&block_loader          , &block_emulator},                                              // 0xf0
            {&block_loader          , &block_emulator},                                              // 0xf1
            {&block_loader          , &block_emulator},                                              // 0xf2
            {&BYTE_LOADER_NAME(0xf3), &block_emulator},                                              // 0xf3
            {&block_loader          , &block_emulator},                                              // 0xf4
            {&block_loader          , &block_emulator},                                              // 0xf5
            {&block_loader          , &block_emulator},                                              // 0xf6
            {&block_loader          , &block_emulator},                                              // 0xf7
            {&block_loader          , &block_emulator},                                              // 0xf8
            {&block_loader          , &block_emulator},                                              // 0xf9
            {&block_loader          , &block_emulator},                                              // 0xfa
            {&block_loader          , &block_emulator},                                              // 0xfb
            {&block_loader          , &block_emulator},                                              // 0xfc
            {&block_loader          , &block_emulator},                                              // 0xfd
            {&block_loader          , &block_emulator},                                              // 0xfe
            {&block_loader          , &block_emulator},                                              // 0xff
    };
};

#endif //REMON_INSTRUCTION_INTENT_EMULATION_H
