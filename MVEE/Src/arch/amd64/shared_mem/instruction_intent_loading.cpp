//
// Created by jonas on 13/03/2020.
//


// implemented header
#include <MVEE.h>
#include "instruction_intent_emulation.h"


// =====================================================================================================================
//      set macros
// =====================================================================================================================

#define SET_EFFECTIVE_OPCODE(instruction, round)                                                                       \
instruction.extra_info &= ~EXTRA_INFO_ROUND_CODE_MASK;                                                                 \
instruction.extra_info |= (round << EXTRA_INFO_ROUND_CODE_OFFSET) & EXTRA_INFO_ROUND_CODE_MASK;                        \
                                                                                                                       \
instruction.effective_opcode_index = instruction.byte_accessed;


// =====================================================================================================================
//      lookup table definition
// =====================================================================================================================
constexpr const emulation_lookup instruction_intent_emulation::lookup_table[256];


// =====================================================================================================================
//      loading functions
// =====================================================================================================================
int         instruction_intent_emulation::block_loader              (instruction_intent& instruction,
                                                                     unsigned int round)
{
    // return that there has been an illegal access attempt
    return ILLEGAL_ACCESS_TERMINATION;
}


int         instruction_intent_emulation::rest_check                (instruction_intent& instruction,
                                                                     unsigned int options, unsigned int immediate_size)
{
    // modrm size addition
    if (options & REST_CHECK_MODRM)
    {
        // this is the byte we're currently on, so we can add it to the size already
        instruction.size++;
        __uint8_t modrm = instruction.current_byte();

        // check if SIB used
        if (GET_MOD_CODE((unsigned) modrm) != 0b11u && GET_RM_CODE((unsigned) modrm) == 0b100u)
        {
            if (instruction++ >= MAX_INSTRUCTION_SIZE)
                return ILLEGAL_ACCESS_TERMINATION;
            instruction.size++;
        }

        // scheck for displacement
        if (GET_MOD_CODE((unsigned) modrm) == 0b01)
        {
            // 1 byte displacement
            if (instruction++ >= MAX_INSTRUCTION_SIZE)
                return ILLEGAL_ACCESS_TERMINATION;
            instruction.size++;
        }
        else if (GET_MOD_CODE((unsigned) modrm) == 0b10 ||
                (GET_MOD_CODE((unsigned) modrm) == 0b00 && GET_RM_CODE((unsigned ) modrm) == 0b101))
        {
            // 4 byte displacement
            // 1 byte displacement
            if ((instruction+=4) >= MAX_INSTRUCTION_SIZE)
                return ILLEGAL_ACCESS_TERMINATION;
            instruction.size+=4;
        }
    }

    // immediate size addition
    if (immediate_size > 0)
    {
        instruction.immediate_operand_index = instruction.current_index() + 1;

        if ((instruction += (int) immediate_size) >= MAX_INSTRUCTION_SIZE)
            return ILLEGAL_ACCESS_TERMINATION;
        instruction.size += immediate_size;
    }

    return ACCESS_OK_TERMINATION;
}

// =====================================================================================================================
//      byte loaders
// =====================================================================================================================

/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x00)


/* Valid in first round */
BYTE_LOADER_IMPL(0x01)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set efective opcode
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)

        // decode following modrm byte
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x02)


/* Not implemented - blocked */
BYTE_LOADER_IMPL(0x03)
{
    // add Gv, Ev
    if (round && INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x04)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x05)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x06)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x07)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x08)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x09)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x0a)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x0b)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x0c)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x0d)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x0e)


/* Allowed in first round */
BYTE_LOADER_IMPL(0x0f)
{
    // go to second round if this occurs in the first round
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // go to second round
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_SECOND_LEVEL)
    }
    // other rounds are not allowed
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Valid in second round */
BYTE_LOADER_IMPL(0x10)
{
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal otherwise
    return -1;
}


/* Valid in second round */
BYTE_LOADER_IMPL(0x11)
{
    // valid
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal access
    else
        return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x12)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x13)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x14)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x15)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x16)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x17)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x18)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x19)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x1a)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x1b)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x1c)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x1d)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x1e)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x1f)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x20)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x21)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x22)


/* Valid in first round */
BYTE_LOADER_IMPL(0x23)
{
    // valid
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal access
    else
        return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x24)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x25)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x26)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x27)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x28)


/* Valid in second round */
BYTE_LOADER_IMPL(0x29)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        // illegal if REPZ or REPNZ prefix present
        if (PREFIXES_GRP_ONE_PRESENT(instruction) &&
                (PREFIXES_GRP_ONE(instruction) == REPZ_PREFIX_CODE ||
                 PREFIXES_GRP_ONE(instruction) == REPNZ_PREFIX_CODE))
            return -1;

        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Valid in second round */
BYTE_LOADER_IMPL(0x2a)
{
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_LOADER_IMPL(0x2b)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x2c)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x2d)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x2e)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x2f)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x30)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x31)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x32)


/* Valid in first round */
BYTE_LOADER_IMPL(0x33)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x34)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x35)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x36)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x37)


/* Valid in first round */
BYTE_LOADER_IMPL(0x38)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Valid in first round */
BYTE_LOADER_IMPL(0x39)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x3a)


/* Valid in first round */
BYTE_LOADER_IMPL(0x3b)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x3c)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x3d)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x3e)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x3f)


/* Allowed */
BYTE_LOADER_IMPL(0x40)
{
    // byte represents REX prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x41)
{
    // byte represents REX.B prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
BYTE_LOADER_IMPL(0x42)
{
    // byte represents REX.X prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x43)
{
    // byte represents REX.XB prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x44)
{
    // byte represents REX.R prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x45)
{
    // byte represents REX.RB prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x46)
{
    // byte represents REX.RX prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x47)
{
    // byte represents REX.RXB prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x48)
{
    // byte represents REX.W prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x49)
{
    // byte represents REX.WB prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x4a)
{
    // byte represents REX.WX prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x4b)
{
    // byte represents REX.WXB prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x4c)
{
    // byte represents REX.WR prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x4d)
{
    // byte represents REX.WRB prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x4e)
{
    // byte represents REX.WRX prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed */
BYTE_LOADER_IMPL(0x4f)
{
    // byte represents REX.WRXB prefix
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set rex as used
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        // clear rex field in access_intent, just to be sure the bits are cleared before setting them
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        // opcode byte can be shifted PREFIXES_REX_FIELDS_OFFSET since it's the lower 4 bits we're interested in
        instruction.prefixes |= PREFIXES_REX_FIELDS_MASK & ((unsigned) instruction.current_byte()
                << PREFIXES_REX_FIELDS_OFFSET);

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x50)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x51)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x52)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x53)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x54)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x55)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x56)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x57)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x58)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x59)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x5a)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x5b)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x5c)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x5d)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x5e)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x5f)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x60)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x61)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x62)


/* Allowed in first round */
BYTE_LOADER_IMPL(0x63)
{
    // movsxd Gv, Ev
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x64)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x65)


/* Allowed in first round */
BYTE_LOADER_IMPL(0x66)
{
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set group 3 prefix
        instruction.prefixes |= (PREFIXES_GRP_THREE_PRESENT_MASK);

        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed in first round */
BYTE_LOADER_IMPL(0x67)
{
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // currently blocking as its functionality is not implemented
        warnf("0x67 prefix requested\n");
        return -1;

        // set group 4 prefix
        instruction.prefixes |= (PREFIXES_GRP_FOUR_PRESENT_MASK);

        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x68)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x69)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x6a)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x6b)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x6c)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x6d)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x6e)


/* Valid in second round */
BYTE_LOADER_IMPL(0x6f)
{
    // valid in second round, done for now
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal instruction
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x70)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x71)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x72)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x73)


/* Valid in second round */
BYTE_LOADER_IMPL(0x74)
{
    // valid in second round, done for now
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal otherwise
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x75)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x76)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x77)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x78)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x79)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x7a)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x7b)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x7c)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x7d)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x7e)


/* Valid in second round */
BYTE_LOADER_IMPL(0x7f)
{
    // valid in second round, done for now
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal access in other rounds
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Valid in first round */
BYTE_LOADER_IMPL(0x80)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 1)
    }
    // illegal instruction
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
BYTE_LOADER_IMPL(0x81)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, (PREFIXES_GRP_THREE_PRESENT(instruction) ? 2 : 4))
    }

    // illegal access otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x82)


/* Valid in first round */
BYTE_LOADER_IMPL(0x83)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 1)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x84)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x85)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x86)


/* Allowed in first round */
BYTE_LOADER_IMPL(0x87)
{
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed in first round */
BYTE_LOADER_IMPL(0x88)
{
    // done for now
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal access instruction
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed in first round */
BYTE_LOADER_IMPL(0x89)
{
    // done for now
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal access
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed in first round */
BYTE_LOADER_IMPL(0x8a)
{
    // done for now
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed in first round */
BYTE_LOADER_IMPL(0x8b)
{
    // done for now
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal access instruction
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Allowed in first round */
BYTE_LOADER_IMPL(0x8c)
{
    // done for now
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal access instruction
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x8d)


/* Allowed in first round */
BYTE_LOADER_IMPL(0x8e)
{
    // done for now
    if (round & INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
        // illegal access instruction
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x8f)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x90)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x91)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x92)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x93)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x94)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x95)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x96)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x97)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x98)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x99)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x9a)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x9b)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x9c)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x9d)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x9e)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0x9f)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xa0)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xa1)


/* Valid in second round */
BYTE_LOADER_IMPL(0xa2)
{
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, round)

        // update instruction size
        instruction.size++;

        // special case done
        return ACCESS_OK_TERMINATION;
    }

    // illegal access otherwise
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xa3)


/* Valid in first round */
BYTE_LOADER_IMPL(0xa4)
{
    // movsb
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set effective opcode index
        SET_EFFECTIVE_OPCODE(instruction, round)
        instruction.size++;

        // no modrm follows, this is all there's to it
        return ACCESS_OK_TERMINATION;
    }

    // illegal otherwise
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xa5)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xa6)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xa7)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xa8)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xa9)


/* Valid in first round */
BYTE_LOADER_IMPL(0xaa)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, round)

        // update instruction size
        instruction.size++;
        return ACCESS_OK_TERMINATION;
    }

    // illegal otherwise
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Valid in first round */
BYTE_LOADER_IMPL(0xab)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, round)

        // update instruction size
        instruction.size++;
        return ACCESS_OK_TERMINATION;
    }

    // illegal otherwise
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xac)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xad)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xae)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xaf)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xb0)


/* Valid in second round */
BYTE_LOADER_IMPL(0xb1)
{
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xb2)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xb3)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xb4)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xb5)


/* Valid in second round */
BYTE_LOADER_IMPL(0xb6)
{
    // done for now
    if (round & INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // other rounds are not allowed
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Valid in second round */
BYTE_LOADER_IMPL(0xb7)
{
    // done for now
    if (round & INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // other rounds are not allowed
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xb8)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xb9)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xba)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xbb)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xbc)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xbd)


/* Valid in second round */
BYTE_LOADER_IMPL(0xbe)
{
    // movsx Gv, Eb
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xbf)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xc0)


/* Valid in first round */
BYTE_LOADER_IMPL(0xc1)
{
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xc2)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xc3)


/* blocked - AVX block */
BYTE_LOADER_IMPL(0xc4)
{
    return ILLEGAL_ACCESS_TERMINATION;
    // VEX+2 byte
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set VEX as used
        instruction.prefixes &= ~PREFIXES_VEX_SIZE_MASK;
        instruction.prefixes |= (VEX_2_BYTE_PREFIX << PREFIXES_VEX_SIZE_OFFSET) & PREFIXES_VEX_SIZE_MASK;


        // go to next byte and decode
        if (instruction++ >= MAX_INSTRUCTION_SIZE)
            return ILLEGAL_ACCESS_TERMINATION;

        // set REX as used (not sure about this one though) and update REX fields content (W will be inserted in next
        // byte)
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        instruction.prefixes |= (~(((unsigned) instruction.current_byte() >> 0x05u) & 0x07u)
                << PREFIXES_REX_FIELDS_OFFSET)
                & PREFIXES_REX_FIELDS_MASK;

        // decode mmmmm, we just need the lower 2 bits to decide what level to go to next
        unsigned long next_level;
        switch ((unsigned) instruction.current_byte() & 0x03u)
        {
            case 0b01:
                next_level = INSTRUCTION_DECODING_SECOND_LEVEL;
                break;
            case 0b10:
                next_level = INSTRUCTION_DECODING_THIRD_LEVEL;
                break;
            case 0b11:
                next_level = INSTRUCTION_DECODING_FOURTH_LEVEL;
                break;
            case 0b00:
            default:
                return ILLEGAL_ACCESS_TERMINATION;
        }


        // go to next byte and decode
        if (instruction++ >= MAX_INSTRUCTION_SIZE)
            return ILLEGAL_ACCESS_TERMINATION;

        // check for existence of W for REX prefix
        instruction.prefixes |= (((unsigned) ((instruction.current_byte() & 0b10000000u) > 0u) << REX_FIELD_W_OFFSET)
                << PREFIXES_REX_FIELDS_OFFSET) & PREFIXES_REX_FIELDS_MASK;

        // set vvvv
        instruction.prefixes &= ~PREFIXES_VEX_VVVV_MASK;
        instruction.prefixes |= (((unsigned) instruction.current_byte() >> 0x03u) << PREFIXES_VEX_VVVV_OFFSET)
                & PREFIXES_VEX_VVVV_MASK;

        // set L (only the first bit is set in VEX
        instruction.prefixes &= ~PREFIXES_VEX_L_MASK;
        instruction.prefixes |= ((unsigned) ((instruction.current_byte() & 0b100u) > 0u) << PREFIXES_VEX_L_OFFSET)
                & PREFIXES_VEX_L_MASK;

        // decode pp
        switch (instruction.current_byte() & 0x03u)
        {
            case 0b01:
                // 0x66 prefix => group three prefix
                instruction.prefixes |= PREFIXES_GRP_THREE_PRESENT_MASK;
                break;
            case 0b10:
                // 0xf3 prefix => group one prefix
                instruction.prefixes |= PREFIXES_GRP_ONE_PRESENT_MASK;
                instruction.prefixes &= ~PREFIXES_GRP_ONE_VALUES_MASK;
                instruction.prefixes |= (REPZ_PREFIX_CODE << PREFIXES_GRP_ONE_VALUES_OFFSET)
                        & PREFIXES_GRP_ONE_VALUES_MASK;
                break;
            case 0b11:
                // 0xf2 prefix => group one prefix
                instruction.prefixes |= PREFIXES_GRP_ONE_PRESENT_MASK;
                instruction.prefixes &= ~PREFIXES_GRP_ONE_VALUES_MASK;
                instruction.prefixes |= (REPNZ_PREFIX_CODE << PREFIXES_GRP_ONE_VALUES_OFFSET)
                        & PREFIXES_GRP_ONE_VALUES_MASK;
                break;
            case 0b00:
            default:
                return ILLEGAL_ACCESS_TERMINATION;
        }


        // go to next byte, depending on the level selected by m-mmmm
        LOAD_NEXT_INSTRUCTION_BYTE(next_level)
    }
    // illegal access
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* blocked - AVX block */
BYTE_LOADER_IMPL(0xc5)
{
    return ILLEGAL_ACCESS_TERMINATION;
    // VEX+1 byte
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set VEX as used
        instruction.prefixes &= ~PREFIXES_VEX_SIZE_MASK;
        instruction.prefixes |= (VEX_1_BYTE_PREFIX << PREFIXES_VEX_SIZE_OFFSET) & PREFIXES_VEX_SIZE_MASK;


        // go to next byte and decode
        if (instruction++ >= MAX_INSTRUCTION_SIZE)
            return ILLEGAL_ACCESS_TERMINATION;

        // set REX as present and fill in R bit
        instruction.prefixes |= PREFIXES_REX_PRESENT_MASK;
        instruction.prefixes &= ~PREFIXES_REX_FIELDS_MASK;
        instruction.prefixes |= ((((unsigned) ((instruction.current_byte() & 0b10000000u) == 0u)) << REX_FIELD_R_OFFSET)
                << PREFIXES_REX_FIELDS_OFFSET) & PREFIXES_REX_FIELDS_MASK;

        // set vvvv
        instruction.prefixes &= ~PREFIXES_VEX_VVVV_MASK;
        instruction.prefixes |= (((unsigned) instruction.current_byte() >> 0x03u) << PREFIXES_VEX_VVVV_OFFSET)
                           & PREFIXES_VEX_VVVV_MASK;

        // set L (only the first bit is set in VEX
        instruction.prefixes &= ~PREFIXES_VEX_L_MASK;
        instruction.prefixes |= ((unsigned) ((instruction.current_byte() & 0b100u) > 0u) << PREFIXES_VEX_L_OFFSET)
                           & PREFIXES_VEX_L_MASK;

        // decode pp
        switch (instruction.current_byte() & 0x03u)
        {
            case 0b01:
                // 0x66 prefix => group three prefix
                instruction.prefixes |= PREFIXES_GRP_THREE_PRESENT_MASK;
                break;
            case 0b10:
                // 0xf3 prefix => group one prefix
                instruction.prefixes |= PREFIXES_GRP_ONE_PRESENT_MASK;
                instruction.prefixes &= ~PREFIXES_GRP_ONE_VALUES_MASK;
                instruction.prefixes |= (REPZ_PREFIX_CODE << PREFIXES_GRP_ONE_VALUES_OFFSET)
                        & PREFIXES_GRP_ONE_VALUES_MASK;
                break;
            case 0b11:
                // 0xf2 prefix => group one prefix
                instruction.prefixes |= PREFIXES_GRP_ONE_PRESENT_MASK;
                instruction.prefixes &= ~PREFIXES_GRP_ONE_VALUES_MASK;
                instruction.prefixes |= (REPNZ_PREFIX_CODE << PREFIXES_GRP_ONE_VALUES_OFFSET)
                        & PREFIXES_GRP_ONE_VALUES_MASK;
                break;
            case 0b00:
            default:
                return ILLEGAL_ACCESS_TERMINATION;
        }


        // go to next byte, go to next level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_SECOND_LEVEL)
    }
    // illegal access
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Valid in first round */
BYTE_LOADER_IMPL(0xc6)
{
    // MOVE Eb, Ib, done for now
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 1)
    }
    // illegal access
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Valid in first round */
BYTE_LOADER_IMPL(0xc7)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, (PREFIXES_GRP_THREE_PRESENT(instruction) ? 2 : 4))
    }

    // illegal otherwise
    return -1;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xc8)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xc9)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xca)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xcb)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xcc)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xcd)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xce)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xcf)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd0)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd1)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd2)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd3)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd4)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd5)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd6)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd7)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd8)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xd9)


/* Valid in second round */
BYTE_LOADER_IMPL(0xda)
{
    // pminub mm, mm/m64 | pminub xmm, xmm/m128
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_SECOND_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }
    // illegal access
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xdb)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xdc)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xdd)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xde)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xdf)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xe0)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xe1)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xe2)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xe3)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xe4)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xe5)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xe6)


/* Valid in second round */
BYTE_LOADER_IMPL(0xe7)
{
    // movntdq/movntq
    if (round == INSTRUCTION_DECODING_SECOND_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, round)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 0)
    }

    // illegal otherwise
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xe8)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xe9)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xea)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xeb)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xec)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xed)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xee)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xef)


/* Valid in first round */
BYTE_LOADER_IMPL(0xf0)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set group one prefix as used
        instruction.prefixes |= PREFIXES_GRP_ONE_PRESENT_MASK;

        // set LOCK prefix code
        instruction.prefixes &= ~PREFIXES_GRP_ONE_VALUES_MASK;
        instruction.prefixes |= (LOCK_PREFIX_CODE << PREFIXES_GRP_ONE_VALUES_OFFSET) & PREFIXES_GRP_ONE_VALUES_MASK;

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
        // other rounds: return illegal access
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xf1)


/* Not implemented - blocked */
BYTE_LOADER_IMPL(0xf2)
{
    // repnz prefix
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set group one prefix as used
        instruction.prefixes |= PREFIXES_GRP_ONE_PRESENT_MASK;

        // set repnz prefix code
        instruction.prefixes &= ~PREFIXES_GRP_ONE_VALUES_MASK;
        instruction.prefixes |= (REPNZ_PREFIX_CODE << PREFIXES_GRP_ONE_VALUES_OFFSET) & PREFIXES_GRP_ONE_VALUES_MASK;

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }

    // illegal otherwise
    return ILLEGAL_ACCESS_TERMINATION;
}


/* Implemented - allowed in round 1 */
BYTE_LOADER_IMPL(0xf3)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        // set group one prefix as used
        instruction.prefixes |= PREFIXES_GRP_ONE_PRESENT_MASK;

        // set REPZ prefix code
        instruction.prefixes &= ~PREFIXES_GRP_ONE_VALUES_MASK;
        instruction.prefixes |= (REPZ_PREFIX_CODE << PREFIXES_GRP_ONE_VALUES_OFFSET) & PREFIXES_GRP_ONE_VALUES_MASK;

        // go to next byte, same level
        LOAD_NEXT_INSTRUCTION_BYTE(INSTRUCTION_DECODING_FIRST_LEVEL)
    }
    // other rounds: return illegal access
    else
        return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xf4)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xf5)


/* Valid in first round */
BYTE_LOADER_IMPL(0xf6)
{
    if (round == INSTRUCTION_DECODING_FIRST_LEVEL)
    {
        SET_EFFECTIVE_OPCODE(instruction, INSTRUCTION_DECODING_FIRST_LEVEL)
        LOAD_REST_OF_INSTRUCTION(REST_CHECK_MODRM, 1)
    }
    // illegal otherwise
    else
      return ILLEGAL_ACCESS_TERMINATION;
}


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xf7)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xf8)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xf9)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xfa)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xfb)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xfc)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xfd)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xfe)


/* Not implemented - blocked */
// BYTE_LOADER_IMPL(0xff)
