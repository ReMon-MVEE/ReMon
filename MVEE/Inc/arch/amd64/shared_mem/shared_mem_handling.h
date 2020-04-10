//
// Created by jonas on 26/02/2020.
//

#ifndef REMON_SHARED_MEM_HANDLING_H
#define REMON_SHARED_MEM_HANDLING_H


#include <cstdlib>
#include <cstdint>
#include <bits/types/siginfo_t.h>
#include <vector>
#include <string>


#include "shared_mem_operations.h"
#include "instruction_intent_emulation.h"


// =====================================================================================================================
//      forward definitions
// =====================================================================================================================
class monitor;
class variantstate;
class instruction_intent_emulation;


// =====================================================================================================================
//      debug
// =====================================================================================================================
#define START_OUTPUT_DEBUG                                                                                             \
std::stringstream output;                                                                                              \
output.str();

#define ADD_OUTPUT_DEBUG(message, pointer, byte_count)                                                                 \
output << message << "\n";                                                                                             \
output << "\thex:    | ";                                                                                              \
for (int i = 0; i < byte_count; i++)                                                                                   \
    output << (((__uint8_t*)pointer)[i] > 0x0f ? "" : "0")                                                             \
        << std::hex << (((__uint8_t*)pointer)[i] & 0xffu) << " ";                                                      \
output << "\n";                                                                                                        \
output << "\tcontent | ";                                                                                              \
for (int i = 0; i < byte_count; i++)                                                                                   \
{                                                                                                                      \
    if ((((__uint8_t*)pointer)[i] & 0xffu) == 0)                                                                       \
        output << "\\0" << " ";                                                                                        \
    else if ((((__uint8_t*)pointer)[i] & 0xffu) == 0x10)                                                               \
        output << "\\n" << " ";                                                                                        \
    else if ((((__uint8_t*)pointer)[i] & 0xffu) == 0x13)                                                               \
        output << "\\r" << " ";                                                                                        \
    else                                                                                                               \
        output << " " << (char)(((__uint8_t*)pointer)[i] & 0xffu) << " ";                                              \
}                                                                                                                      \
output << "\n";

#define PRINT_OUTPUT_DEBUG                                                                                             \
warnf("\n%s\n", output.str().c_str());


// =====================================================================================================================
//      constants
// =====================================================================================================================

// intent_instruction ==================================================================================================
/* Defines the maximum length of instruction we'll retrieve and use, here set to what x86 calls their max length. */
#define MAX_INSTRUCTION_SIZE                    15


// register info -------------------------------------------------------------------------------------------------------
/* Source or destination is a specific general purpose register. */
#define REG_TYPE_SET_0                          0x00u
/* Source or destination is a specific segment, control, or debug register or a MM or ST register. */
#define REG_TYPE_SET_1                          0x01u
/* Source or destination is a specific XMM, YMM, or ZMM register. */
#define REG_TYPE_SET_2                          0x02u
/* Source or destination does not reference anything. */
#define REG_TYPE_SET_3                          0x03u

/* register describes an 8-bit location, either in register, or memory location when addressing is used */
#define SIZE_USED_08                            0x00u
/* register describes a 16-bit location, either in register, or memory location when addressing is used */
#define SIZE_USED_16                            0x01u
/* register describes a 32-bit location, either in register, or memory location when addressing is used */
#define SIZE_USED_32                            0x02u
/* register describes a 64-bit location, either in register, or memory location when addressing is used */
#define SIZE_USED_64                            0x03u
/* register describes a 128-bit location, either in register, or memory location when addressing is used. Due to the
 * structure this value is only used in the operand size field in extra_info. */
#define SIZE_USED_128                           0x04u
/* register describes a 256-bit location, either in register, or memory location when addressing is used. Due to the
 * structure this value is only used in the operand size field in extra_info. */
#define SIZE_USED_256                           0x05u
/* register describes a 512-bit location, either in register, or memory location when addressing is used. Due to the
 * structure this value is only used in the operand size field in extra_info. */
#define SIZE_USED_512                           0x06u
// ---------------------------------------------------------------------------------------------------------------------


// prefix constants ----------------------------------------------------------------------------------------------------
#define LOCK_PREFIX_CODE                        0x00u
#define REPNZ_PREFIX_CODE                       0x01u
#define REPZ_PREFIX_CODE                        0x02u
#define BND_PREFIX_CODE                         0x03u

#define VEX_1_BYTE_PREFIX                       0x01u
#define VEX_2_BYTE_PREFIX                       0x02u
#define EVEX_PREFIX                             0x03u
// ---------------------------------------------------------------------------------------------------------------------


// masks and offsets for extra info ------------------------------------------------------------------------------------
#define EXTRA_INFO_ROUND_CODE_OFFSET            0x00u

#define EXTRA_INFO_ROUND_CODE_MASK              (0x03u << EXTRA_INFO_ROUND_CODE_OFFSET)
// ---------------------------------------------------------------------------------------------------------------------


// masks and offsets for prefixes --------------------------------------------------------------------------------------
#define PREFIXES_REX_PRESENT_OFFSET             0x00u
#define PREFIXES_REX_FIELDS_OFFSET              0x01u
#define PREFIXES_GRP_ONE_PRESENT_OFFSET         0x05u
#define PREFIXES_GRP_TWO_PRESENT_OFFSET         0x06u
#define PREFIXES_GRP_ONE_VALUES_OFFSET          0x07u
#define PREFIXES_GRP_TWO_VALUES_OFFSET          0x09u
#define PREFIXES_GRP_THREE_PRESENT_OFFSET       0x0cu
#define PREFIXES_GRP_FOUR_PRESENT_OFFSET        0x0du
#define PREFIXES_VEX_SIZE_OFFSET                0x0eu
#define PREFIXES_VEX_L_OFFSET                   0x10u
#define PREFIXES_VEX_VVVV_OFFSET                0x12u
// #define PREFIXES_VEX_MMMMM_OFFSET            0x16u
#define PREFIXES_EVEX_R_OFFSET                  0x18u
#define PREFIXES_EVEX_X_OFFSET                  0x19u
#define PREFIXES_EVEX_V_OFFSET                  0x1au
#define PREFIXES_EVEX_AAA_OFFSET                0x1bu
#define PREFIXES_EVEX_Z_OFFSET                  0x1eu
#define PREFIXES_EVEX_B_OFFSET                  0x1fu


#define PREFIXES_REX_PRESENT_MASK               (0x01u << PREFIXES_REX_PRESENT_OFFSET)
#define PREFIXES_REX_FIELDS_MASK                (0x0fu << PREFIXES_REX_FIELDS_OFFSET)
#define PREFIXES_GRP_ONE_PRESENT_MASK           (0x01u << PREFIXES_GRP_ONE_PRESENT_OFFSET)
#define PREFIXES_GRP_TWO_PRESENT_MASK           (0x01u << PREFIXES_GRP_TWO_PRESENT_OFFSET)
#define PREFIXES_GRP_ONE_VALUES_MASK            (0x03u << PREFIXES_GRP_ONE_VALUES_OFFSET)
#define PREFIXES_GRP_TWO_VALUES_MASK            (0x07u << PREFIXES_GRP_TWO_VALUES_OFFSET)
#define PREFIXES_GRP_THREE_PRESENT_MASK         (0x01u << PREFIXES_GRP_THREE_PRESENT_OFFSET)
#define PREFIXES_GRP_FOUR_PRESENT_MASK          (0x01u << PREFIXES_GRP_FOUR_PRESENT_OFFSET)
#define PREFIXES_VEX_SIZE_MASK                  (0x03u << PREFIXES_VEX_SIZE_OFFSET)
#define PREFIXES_VEX_L_MASK                     (0x03u << PREFIXES_VEX_L_OFFSET)
#define PREFIXES_VEX_VVVV_MASK                  (0x0fu << PREFIXES_VEX_VVVV_OFFSET)
// #define PREFIXES_VEX_MMMMM_MASK              (0x03u << PREFIXES_VEX_MMMMM_OFFSET)
#define PREFIXES_EVEX_R_MASK                    (0x01u << PREFIXES_EVEX_R_OFFSET)
#define PREFIXES_EVEX_X_MASK                    (0x01u << PREFIXES_EVEX_X_OFFSET)
#define PREFIXES_EVEX_V_MASK                    (0x01u << PREFIXES_EVEX_V_OFFSET)
#define PREFIXES_EVEX_AAA_MASK                  (0x07u << PREFIXES_EVEX_AAA_OFFSET)
#define PREFIXES_EVEX_Z_MASK                    (0x01u << PREFIXES_EVEX_Z_OFFSET)
#define PREFIXES_EVEX_B_MASK                    (0x01u << PREFIXES_EVEX_B_OFFSET)

// offsets inside REX field [ WRXB ]
#define REX_FIELD_B_OFFSET                      0x00u
#define REX_FIELD_X_OFFSET                      0x01u
#define REX_FIELD_R_OFFSET                      0x02u
#define REX_FIELD_W_OFFSET                      0x03u
// ---------------------------------------------------------------------------------------------------------------------


// reaply intent buffer masks and offsets ------------------------------------------------------------------------------
#define LEADER_WAITING_OFFSET                   0x00u
#define VARIANTS_WAITING_OFFSET                 0x01u

#define LEADER_WAITING_MASK                     (0x01u << LEADER_WAITING_OFFSET)
#define VARIANTS_WAITING_MASK                   (0x01u << VARIANTS_WAITING_OFFSET)
// ---------------------------------------------------------------------------------------------------------------------


// =====================================================================================================================
//      macros
// =====================================================================================================================

// access_intent =======================================================================================================
// macros to obtain fields from prefixes -------------------------------------------------------------------------------
#define PREFIXES_REX_PRESENT(instruction)       (instruction.prefixes & PREFIXES_REX_PRESENT_MASK)
#define PREFIXES_REX_FIELDS(intent)             ((intent.prefixes & PREFIXES_REX_FIELDS_MASK)                          \
                                                        >> PREFIXES_REX_FIELDS_OFFSET)
#define PREFIXES_GRP_ONE_PRESENT(intent)        (intent.prefixes & PREFIXES_GRP_ONE_PRESENT_MASK)
#define PREFIXES_GRP_TWO_PRESENT(intent)        (intent.prefixes & PREFIXES_GRP_TWO_PRESENT_MASK)
#define PREFIXES_GRP_ONE(intent)                ((intent.prefixes & PREFIXES_GRP_ONE_VALUES_MASK)                      \
                                                        >> PREFIXES_GRP_ONE_VALUES_OFFSET)
#define PREFIXES_GRP_TWO(intent)                ((intent.prefixes & PREFIXES_GRP_TWO_VALUES_MASK)                      \
                                                        >> PREFIXES_GRP_TWO_VALUES_OFFSET)
#define PREFIXES_GRP_THREE_PRESENT(intent)      (intent.prefixes & PREFIXES_GRP_THREE_PRESENT_MASK)
#define PREFIXES_GRP_FOUR_PRESENT(intent)       (intent.prefixes & PREFIXES_GRP_FOUR_PRESENT_MASK)
#define PREFIXES_VEX_SIZE(intent)               ((intent.prefixes & PREFIXES_VEX_SIZE_MASK) >> PREFIXES_VEX_SIZE_OFFSET)
#define PREFIXES_VEX_L(intent)                  ((intent.prefixes & PREFIXES_VEX_L_MASK) >> PREFIXES_VEX_L_OFFSET)
#define PREFIXES_VEX_VVVV(intent)               ((intent.prefixes & PREFIXES_VEX_VVVV_MASK) >> PREFIXES_VEX_VVVV_OFFSET)
// #define PREFIXES_VEX_MMMMM(intent)           ((intent.prefixes & PREFIXES_VEX_MMMMM_MASK)
//                                                         >> PREFIXES_VEX_MMMMM_OFFSET)
#define PREFIXES_EVEX_R(intent)                 (intent.prefixes & PREFIXES_EVEX_R_MASK)
#define PREFIXES_EVEX_X(intent)                 (intent.prefixes & PREFIXES_EVEX_X_MASK)
#define PREFIXES_EVEX_V(intent)                 (intent.prefixes & PREFIXES_EVEX_V_MASK)
#define PREFIXES_EVEX_AAA(intent)               ((intent.prefixes & PREFIXES_EVEX_AAA_MASK)                            \
                                                        >> PREFIXES_EVEX_AAA_OFFSET)
#define PREFIXES_EVEX_Z(intent)                 (intent.prefixes & PREFIXES_EVEX_Z_MASK)
#define PREFIXES_EVEX_B(intent)                 (intent.prefixes & PREFIXES_EVEX_B_MASK)


// Macros to obtain REX fields specifically
/* Gives > 0 if REX.B is given. */
#define PREFIXES_REX_FIELD_B(intent)            (((intent.prefixes & PREFIXES_REX_FIELDS_MASK)                         \
                                                        >> PREFIXES_REX_FIELDS_OFFSET) & 0x01u)  /* 0b0001 */
/* Gives > 0 if REX.X is given. */
#define PREFIXES_REX_FIELD_X(intent)            (((intent.prefixes & PREFIXES_REX_FIELDS_MASK)                         \
                                                        >> PREFIXES_REX_FIELDS_OFFSET) & 0x02u)  /* 0b0010 */
/* Gives > 0 if REX.R is given. */
#define PREFIXES_REX_FIELD_R(intent)            (((intent.prefixes & PREFIXES_REX_FIELDS_MASK)                         \
                                                        >> PREFIXES_REX_FIELDS_OFFSET) & 0x04u)  /* 0b0100 */
/* Gives > 0 if REX.Z is given. */
#define PREFIXES_REX_FIELD_W(intent)            (((intent.prefixes & PREFIXES_REX_FIELDS_MASK)                         \
                                                        >> PREFIXES_REX_FIELDS_OFFSET) & 0x08u)  /* 0b1000 */
// ---------------------------------------------------------------------------------------------------------------------


// extra info ----------------------------------------------------------------------------------------------------------
#define EXTRA_INFO_ROUND_CODE(instruction)      (((unsigned) instruction.extra_info >> EXTRA_INFO_ROUND_CODE_OFFSET) & \
                                                        EXTRA_INFO_ROUND_CODE_MASK)
// ---------------------------------------------------------------------------------------------------------------------


// some static function like macros ------------------------------------------------------------------------------------
#define SHARED_MEMORY_ACCESS(variant_num, signal)                                                                      \
        (siginfo.si_signo == SIGSEGV && siginfo.si_addr != 0)
// ---------------------------------------------------------------------------------------------------------------------


// =====================================================================================================================
//      intent instruction class definition
// =====================================================================================================================
/**/
class instruction_intent
{
    friend class instruction_intent_emulation;
    friend class monitor;
    friend class intent_replay_buffer;
private:
    /**/
    uint8_t                             instruction[MAX_INSTRUCTION_SIZE] = { 0 };

    /* +---+---+-------+---+---+---+-----+---------+-----+-----+---+---+-------+-----+---+---+---------+---+
     * | _ | _ | _ _ _ | _ | _ | _ | _ _ | _ _ _ _ | _ _ | _ _ | _ | _ | _ _ _ | _ _ | _ | _ | _ _ _ _ | _ |
     * +---+---+-------+---+---+---+-----+---------+-----+-----+---+---+-------+-----+---+---+---------+---+
     *  \   \   \       \   \   \   \     \         \     \     \   \   \       \     \   \   \         \
     *   \   \   \       \   \   \   \     \         \     \     \   \   \       \     \   \   \         +-> REX present
     *    \   \   \       \   \   \   \     \         \     \     \   \   \       \     \   \   +-> REX prefixes [WRXB]
     *     \   \   \       \   \   \   \     \         \     \     \   \   \       \     \   +-> prefix group 1 present
     *      \   \   \       \   \   \   \     \         \     \     \   \   \       \     +-> prefix group 2 present
     *       \   \   \       \   \   \   \     \         \     \     \   \   \       +-> prefix group 1
     *        \   \   \       \   \   \   \     \         \     \     \   \   +-> prefix group 2
     *         \   \   \       \   \   \   \     \         \     \     \   +-> prefix group 3
     *          \   \   \       \   \   \   \     \         \     \     +-> prefix group 4
     *           \   \   \       \   \   \   \     \         \     +-> VEX size
     *            \   \   \       \   \   \   \     \         +-> VEX.L
     *             \   \   \       \   \   \   \     +-> VEX.vvvv
     *              \   \   \       \   \   \   +-> VEX.mmmmm
     *               \   \   \       \   \   +-> EVEX.R'
     *                \   \   \       \   +-> EVEX.X
     *                 \   \   \       +-> EVEX.V'
     *                  \   \   +-> EVEX.aaa
     *                   \   +-> EVEX.z
     *                    +-> EVEX.b
     *
     *
     * 0x00 || REX present              || 1 if rex byte was present, 0 otherwise.
     * 0x01 || REX prefixes             || Describes the content of the REX prefix as 4 bits, in order:
     *      ||                          ||   REX.W REX.R REX.X REX.B.
     * 0x05 || prefix group one present || 1 if group one prefix was present, 0 otherwise.
     * 0x06 || prefix group two present || 1 if group two prefix was present, 0 otherwise.
     * 0x07 || prefix group one         || Describes which group one prefix was present, encoded in two bits:
     *      ||                          ||  *  00 - 0xf0 - LOCK
     *      ||                          ||  *  01 - 0xf2 - REPNE/REPNZ
     *      ||                          ||  *  10 - 0xf3 - REPE/REPZ (REP)
     *      ||                          ||  *  11 - 0xf2 - BND (requires other conditions)
     * 0x09 || prefix group two         || Describes which group two prefix was present, encoded in three bits:
     *      ||                          ||  * 000 - 0x2e - CS segment override (use with branch instruction reserved)
     *      ||                          ||  * 001 - 0x36 - SS segment override (use with branch instruction reserved)
     *      ||                          ||  * 010 - 0x3e - DS segment override (use with branch instruction reserved)
     *      ||                          ||  * 011 - 0x26 - ES segment override (use with branch instruction reserved)
     *      ||                          ||  * 100 - 0x64 - FS segment override (use with branch instruction reserved)
     *      ||                          ||  * 101 - 0x65 - GS segment override (use with branch instruction reserved)
     *      ||                          ||  * 110 - 0x2e - branch not taken (used only with Jcc instructions)
     *      ||                          ||  * 111 - 0x3e - branch taken (used only with Jcc instructions)
     * 0x0c || prefix group three       || Operand size override.
     * 0x0d || prefix group four        || Address size override.
     * 0x0e || VEX size                 || Size of the VEX prefix present, encoded as 2 bits:
     *      ||                          ||  * 00 - no VEX prefix
     *      ||                          ||  * 01 - 2 byte VEX prefix
     *      ||                          ||  * 10 - 3 byte VEX prefix
     *      ||                          ||  * 11 - EVEX prefix
     *      || VEX.pp                   || XX not encoded, merged into group one and three prefixes, as this VEX field
     *      ||                          ||   replaces them. We will treat these VEX bits as if the matching normal
     *      ||                          ||   prefixes are present.
     * 0x10 || VEX.L                    || describes vector length, encode as two bits:
     *      ||                          ||  * 00 - scalar or 128-bit vector
     *      ||                          ||  * 01 - 256-bit vector
     *      ||                          ||  * 10 - 512-bit vector
     *      ||                          ||  * 11 - reserved
     * 0x12 || VEX.vvvv                 || An extra register specifier, 1111 if unused.
     *      || VEX.mmmmm                || XX not used
     *      ||                          ||   VEX.mmmm field is currently encoded as only 2 bits, as most is currently
     *      ||                          ||   reserved. Can be expanded again if need arises. encoding:
     *      ||                          ||  * 00 - illegal
     *      ||                          ||  * 01 - implied 0x0f leading opcode byte
     *      ||                          ||  * 10 - implied 0x0f 0x38 leading opcode byte
     *      ||                          ||  * 11 - implied 0x0f 0x3a leading opcode byte
     * 0x18 || EVEX.R'                  || High 16 register specifier
     * 0x19 || EVEX.X                   || High 16 register specifier
     * 0x1a || EVEX.V'                  || High 16 VVVV register specifier
     * 0x1b || EVEX.aaa                 || embedded opmask register specifier
     * 0x1e || EVEX.z                   || Zeroing/merging
     * 0x1f || EVEX.b                   || Broadcast/RC/SAE context
     */
    __uint32_t                          prefixes;

    /* The index of the effective useful opcode byte, i.e. the byte that actually describes the function of the
     * instruction. */
    __uint8_t                           effective_opcode_index;

    /* The index of the immediate operand, if present, 0 if not. Should be safe, as the x86 instruction set never
     * starts with the immediate operand. */
    __uint8_t                           immediate_operand_index;

    /* Holds some extra info that will allow is to take some shortcuts when replaying intents.
     *
     * +-------------+-----+
     * | X X X X X X | _ _ |
     * +-------------+-----+
     *  \             \
     *   \             +-> round for effective opcode
     *    +-> unused
     */
    __uint8_t                           extra_info;

    /* Describes the size of the instruction the access_intent object describes. This is used to skip the instruction
     * when emulating the access. */
    __uint8_t                           size;

    /**/
    void*                               instruction_pointer;

    /* The faulting address as reported by the kernel when the signal is received. This avoids having to calculate it.
     */
    void*                               effective_address;

    /**/
    int                                 byte_accessed;

    /**/
    pid_t*                              variant_pid;

    /**/
    int*                                variant_num;
public:

    // construction and destruction ------------------------------------------------------------------------------------
    /* Sets the object's variant_pid and initialises all other fields to their defaults.
     *
     * defaults:
     *  * instruction:         zero filled array
     *  * instruction_pointer: 0x00
     *  * byte_accessed:       0
     *  * instruction_length:  MAX_INSTRUCTION_LENGTH
     */
                    explicit instruction_intent         (pid_t* variant_pid, int* variant_num);

    /* For completion. Objects of this class should only be deleted when their coupled variant is terminated. */
                    ~instruction_intent                 ();
    // -----------------------------------------------------------------------------------------------------------------


    // updating --------------------------------------------------------------------------------------------------------
    /* Updates the instruction to whatever < instruction_pointer > is pointing to. */
    int             update                              (void* new_instruction_pointer = nullptr,
                                                         void* new_effective_address   = nullptr);

    /* Updates the variant id of this instruction to < variant_pid > */
    void            update_variant_info                 (pid_t* new_variant_pid, int* new_variant_num);
    // -----------------------------------------------------------------------------------------------------------------


    // retrieval of info -----------------------------------------------------------------------------------------------
    /* Returns the current byte being looked at, i.e. the uint8_t indexed by byte_accessed. */
    uint8_t         current_byte                        ();

    /* Returns the index of the byte currently being accessed. */
    int             current_index                       ();

    /* Resets the currently accessed byte to index 0. */
    void            reset_current_index                 ();

    /* Obtain instruction pointer this instruction points to. */
    void*           obtain_instruction_pointer          ();

    /* Obtain relevant opcode byte for this instruction. */
    __uint8_t       opcode                              ();

    /* Obtain relevant opcode byte for this instruction. */
    int             determine_monitor_pointer           (monitor& relevant_monitor, variantstate* variant,
                                                         void* variant_address, void** monitor_pointer);
    // -----------------------------------------------------------------------------------------------------------------


    // operator overloading --------------------------------------------------------------------------------------------
    /**/
    int             operator++                          (int second);

    /**/
    int             operator+                           (int second);

    /**/
    int             operator+=                          (int second);


    /**/
    int             operator--                          (int second);

    /**/
    int             operator-                           (int second);

    /**/
    int             operator-=                          (int second);


    /**/
    uint8_t         operator[]                          (size_t index);
    // -----------------------------------------------------------------------------------------------------------------


    // debug printing --------------------------------------------------------------------------------------------------
    /* Debug logs the instruction using logf. The instruction is logged looking like:
     *
     * JNS_DEBUG_INTENT_INSTRUCTION
     * ==========================================
     * \tvariant: variant_pid
     * \t
     * \t+------+  > instruction_pointer
     * \t| 0x__ |
     * \t| ...  |  > accessed
     * \t| 0x__ |
     * \t+------+  > instruction_pointer + MAX_INSTRUCTION_SIZE
     * ==========================================
     *
     */
    void            debug_print                         ();
    void            debug_print_minimal                 ();
    // -----------------------------------------------------------------------------------------------------------------
};


// =====================================================================================================================
//      translation record
// =====================================================================================================================
struct translation_record
{
    // addresses in variant address space
    void*           variant_base;
    void*           variant_end;

    // index to actual memory area as mapped in monitor
    unsigned long   memory_id;
};


// =====================================================================================================================
//      translation table
// =====================================================================================================================
class shared_mem_translation_table
{
private:
    std::vector<translation_record>
                    table;
public:
    // map init and destruction ----------------------------------------------------------------------------------------
                shared_mem_translation_table                        ();


                ~shared_mem_translation_table                       ();
    // -----------------------------------------------------------------------------------------------------------------


    // map updating ----------------------------------------------------------------------------------------------------
    int         add_record                                          (void* variant_base, void* variant_end,
                                                                     unsigned long memory_id);


    int         remove_record                                       (void* variant_base);
    // -----------------------------------------------------------------------------------------------------------------


    // map access ------------------------------------------------------------------------------------------------------
    translation_record*
                operator[]                                          (void* variant_address);
    // -----------------------------------------------------------------------------------------------------------------


    // debug -----------------------------------------------------------------------------------------------------------
    void        debug_log                                           ();
    // -----------------------------------------------------------------------------------------------------------------
};


// =====================================================================================================================
//      memory mapping struct
// =====================================================================================================================
struct monitor_mapping
{
    void*           base_addr;
    size_t          size;
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
    const char*    file;
#endif
};


// =====================================================================================================================
//      monitor mapping table\
// =====================================================================================================================
class memory_mapping_table
{
private:
    std::vector<monitor_mapping>
                    monitor_addresses;
    std::vector<unsigned long>
                    free_ids;


    void        insert_free_id                                      (unsigned long free_id);
public:
    // construction and destruction ------------------------------------------------------------------------------------
                memory_mapping_table                                ();

                ~memory_mapping_table                               ();
    // -----------------------------------------------------------------------------------------------------------------


    //updating ---------------------------------------------------------------------------------------------------------
#ifndef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
    unsigned long   add                                             (void* monitor_base, size_t size);
#else
    unsigned long   add                                             (void* monitor_base, size_t size,
                                                                     const std::string &file);
#endif

    int             remove                                          (void* monitor_base);

    int             remove                                          (unsigned long memory_id);
    // -----------------------------------------------------------------------------------------------------------------


    // access ----------------------------------------------------------------------------------------------------------
    monitor_mapping operator[]                                      (unsigned long index);
    // -----------------------------------------------------------------------------------------------------------------
};


// =====================================================================================================================
//      intent replaying data
// =====================================================================================================================
struct intent_replay
{
    __uint8_t       instruction[MAX_INSTRUCTION_SIZE];
    __uint8_t       instruction_size;
    __uint8_t       data_size;
    // todo -- maybe dynamic allocation
    __uint8_t       data[16];
    void*           monitor_address;
};


// =====================================================================================================================
// intent replaying buffer
// =====================================================================================================================
#ifndef INTENT_REPLAY_BUFFER_SIZE
#define INTENT_REPLAY_BUFFER_SIZE               10
#endif
class intent_replay_buffer
{
private:
    intent_replay   buffer[INTENT_REPLAY_BUFFER_SIZE] = {};
    unsigned int    variant_count;
    int*            variant_indexes;
    monitor*        relevant_monitor;

public:
                    intent_replay_buffer                            (monitor* relevant_monitor, int variant_count);
                    ~intent_replay_buffer                           ();

    int             continue_access                                 (unsigned int variant_num);
    int             maybe_resume_leader                             ();
    int             access_data                                     (unsigned int variant_num,
                                                                     instruction_intent* instruction, __uint8_t** data,
                                                                     __uint8_t data_size, void* monitor_pointer);

    /*
     * +-------------+---+---+
     * | X X X X X X | _ | _ |
     * +-------------+---+---+
     *  \             \   \
     *   \             \   +-> leader waiting
     *    \             +-> variant waiting
     *     +-> unused
     *
     * | 0x00 | leader waiting  | set if the leader is currently waiting to resume intent handling. This value should
     * |      |                 | checked after a variant has used the current slot in the buffer, after which a test
     * |      |                 | has to be done to see if all variants are caught up. Only then can the leader resume.
     * |      |                 |
     * | 0x01 | variant waiting | set if a variant is currently waiting to resume intent handling
     * | 0x02 | unused          |
     */
    __uint8_t       extra;
};


// =====================================================================================================================
//      instruction tracing
// =====================================================================================================================
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
class instruction_tracing
{
public:
    static int      log_shared_instruction                          (monitor &relevant_monitor,
                                                                     variantstate* variant, void* address);
};

struct access_data {
    const char* identification;
    int hits;
    access_data* next;
};

struct tracing_data
{
    const char* instruction;
    unsigned int hits;
    struct files {
        const char* file;
        unsigned int hits;
        files* next;
    } files_accessed;
    tracing_data* next;
};
#endif


#endif //REMON_SHARED_MEM_HANDLING_H