//
// Created by jonas on 26/02/2020.
//

// implemented header
#include "shared_mem_handling.h"

#include <ios>
#include <memory>
#include <MVEE.h>
#include <MVEE_mman.h>
#include <MVEE_monitor.h>
#include <sys/mman.h>
#include <arch/amd64/hde.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include "shared_mem_reg_access.h"
#include "MVEE_interaction.h"


// =====================================================================================================================
//      executing instruction implementation
// =====================================================================================================================

// construction and destruction ========================================================================================
                instruction_intent::instruction_intent              (pid_t* init_variant_pid, int* init_variant_num)
{
    prefixes                = 0x00;
    effective_opcode_index  = 0x00;
    extra_info              = 0x00;
    immediate_operand_index = 0x00;
    effective_address       = nullptr;
    size                    = 0x00;
    instruction_pointer     = nullptr;
    byte_accessed           = 0;
    variant_pid             = init_variant_pid;
    variant_num             = init_variant_num;
}


                instruction_intent::~instruction_intent             () = default;


// updating ============================================================================================================
int             instruction_intent::update                          (void* new_instruction_pointer,
                                                                     void* new_effective_address)
{
    // overwrite instruction pointer and address accessed
    instruction_pointer = new_instruction_pointer;
    effective_address   = new_effective_address;

    // return < 0 if instruction pointer is 0x00, this can be ignored if it was meant this way
    if (!instruction_pointer)
        return -1;

    // reset byte accessed and size
    byte_accessed = 0;
    size          = 0;

    // reset prefixes and extra info
    prefixes = 0;
    extra_info = 0;

    // read instruction
    // return ok if all bytes have been read
    if (!interaction::read_memory(*variant_pid, instruction_pointer, MAX_INSTRUCTION_SIZE,
            &instruction))
        return -1;

    // check instruction
    if (instruction_intent_emulation::lookup_table[(*this)[0]].loader(*this, INSTRUCTION_DECODING_FIRST_LEVEL))
        return -1;
    return 0;
}


void            instruction_intent::update_variant_info             (pid_t* new_variant_pid, int* new_variant_num)
{
    variant_pid = new_variant_pid;
    variant_num = new_variant_num;
}


// retrieval of info ===================================================================================================
uint8_t         instruction_intent::current_byte                    ()
{
    return instruction[byte_accessed];
}


int             instruction_intent::current_index                   ()
{
    return byte_accessed;
}

void            instruction_intent::reset_current_index             ()
{
    byte_accessed = 0;
}

void*           instruction_intent::obtain_instruction_pointer      ()
{
    return instruction_pointer;
}

__uint8_t       instruction_intent::opcode                          ()
{
    return instruction[effective_opcode_index];
}

unsigned long long
                shm_handling::shared_memory_determine_offset        (shared_monitor_map_info* monitor_map,
                                                                     unsigned long long variant_address,
                                                                     unsigned long long access_size)
{

    if (variant_address < monitor_map->variant_base ||
            ((unsigned long long) variant_address + access_size) >
            ROUND_UP(monitor_map->variant_base + monitor_map->size, PAGE_SIZE))
    {
        warnf("Instruction, %p + %llx, will go out of range of shared mapping. [ %p ; %p )\n",
              (void*) variant_address, access_size,
              (void*) monitor_map->variant_base,
              (void*) (monitor_map->variant_base + monitor_map->size));
        return -1;
    }

    return (unsigned long long) variant_address - monitor_map->variant_base;
}

int             shm_handling::determine_from_shared_proxy           (variantstate* variant, monitor &relevant_monitor,
                                                                     instruction_intent &instruction,
                                                                     void** typed, uint8_t* proxy, void* shared,
                                                                     shared_monitor_map_info* mapping_info,
                                                                     unsigned long long offset, unsigned long long size,
                                                                     bool try_shadow)
{
    void* shared_address = mapping_info->monitor_base + offset;
    void* shadow_address = mapping_info->variant_shadows[variant->variant_num].monitor_base + offset;
    if (!variant->variant_num)
    {
        memcpy(proxy, shared ? shared : shared_address, size);
        if (try_shadow && (memcmp(proxy, shadow_address, size) == 0))
        {
            int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, shared_address, instruction,
                    nullptr, (size = 0));
            if (result < 0)
                return result;
            *typed = (uint8_t*)shadow_address;
            // warnf(" > new leader using shadow\n");
        }
        else
        {
            void* buffer;
            int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, shared_address, instruction,
                    &buffer, size);
            if (result < 0)
                return result;
            memcpy(buffer, proxy, size);
            *typed = proxy;
        }
    }
    else
    {
        void* buffer;
        int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, shared_address,
                instruction, &buffer, size);
        if (result < 0)
            return result;
        if (buffer)
        {
            memcpy(proxy, buffer, size);
            *typed = proxy;
        }
        else
        {
            // warnf(" > new follower using shadow\n");
            *typed = (uint8_t*)shadow_address;
        }
    }
    return 0;
}

int             shm_handling::determine_from_shared_proxy_buffer    (variantstate* variant, monitor &relevant_monitor,
                                                                     instruction_intent &instruction,
                                                                     void** typed, uint8_t* proxy, void* shared,
                                                                     shared_monitor_map_info* mapping_info,
                                                                     unsigned long long offset, void** buffer,
                                                                     unsigned long long &size,
                                                                     unsigned long long raw_size, bool try_shadow)
{
    void* shared_address = mapping_info->monitor_base + offset;
    void* shadow_address = mapping_info->variant_shadows[variant->variant_num].monitor_base + offset;
    if (!variant->variant_num)
    {
        memcpy(proxy, shared ? shared : shared_address, size);
        if (try_shadow && (memcmp(proxy, shadow_address, size) == 0))
        {
            size = raw_size;
            int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, shared_address, instruction,
                    buffer, raw_size);
            if (result < 0)
                return result;
            *typed = (uint8_t*)shadow_address;
            // warnf(" > new leader using shadow\n");
        }
        else
        {
            size += raw_size;
            int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, shared_address, instruction,
                    buffer, size);
            if (result < 0)
                return result;
            memcpy(buffer, proxy, size);
            *typed = proxy;
        }
    }
    else
    {
        int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, shared_address,
                instruction, buffer, size);
        if (result < 0)
            return result;
        if (size > raw_size)
        {
            memcpy(proxy, buffer, size);
            *typed = proxy;
        }
        else
        {
            // warnf(" > new follower using shadow\n");
            *typed = (uint8_t*)shadow_address;
        }
    }
    return 0;
}

int             shm_handling::determine_source_from_shared_normal   (variantstate* variant,
                                                                     monitor &relevant_monitor,
                                                                     instruction_intent &instruction,
                                                                     void** source,
                                                                     shared_monitor_map_info* mapping_info,
                                                                     unsigned long long offset,
                                                                     unsigned long long size, bool try_shadow)
{
    void* monitor_pointer = (void*) (mapping_info->monitor_base + offset);
    /* leader variant case */
    if (!variant->variant_num)
    {
        /* area of memory is known to be written to by variants */
        void* variant_shadow = (void*) (mapping_info->variant_shadows[variant->variant_num].monitor_base + offset);
        /* If area does not contain same content anymore, we detect it as bi-directional shared memory. */
        /* In this case we take the data from the shared memory segment. */
        if (try_shadow && memcmp(monitor_pointer, variant_shadow, size) == 0)
        {
            *source = variant_shadow;

            /* Essentially puts an empty entry in the replay buffer */

            int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer,
                instruction, nullptr, (size = 0));
            if (result < 0)
                return result;
        }
        /* Otherwise we'll just use the local copy instead */
        else
        {
            int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer,
                    instruction, source, size);
            if (result < 0)
                return result;
            memcpy(*source, monitor_pointer, size);
        }
    }
    /* followers */
    else
    {
        int result = relevant_monitor.buffer.obtain_buffer(variant->variant_num, monitor_pointer, instruction,
                source, size);
        if (result < 0)
            return result;

        /* If buffer has not been filled, use local copy */
        if (!*source) {
            *source = (mapping_info->variant_shadows[variant->variant_num].monitor_base + offset); }
    }

    return 0;
}

// operator overloading ================================================================================================
int             instruction_intent::operator++                      (int second)
{
    if (byte_accessed + 1 < MAX_INSTRUCTION_SIZE)
        byte_accessed++;
    else
        return MAX_INSTRUCTION_SIZE;
    return byte_accessed;
}

int             instruction_intent::operator+                       (int second)
{
    if (byte_accessed + second < MAX_INSTRUCTION_SIZE)
        byte_accessed += second;
    else
        return MAX_INSTRUCTION_SIZE;
    return byte_accessed;
}

int             instruction_intent::operator+=                      (int second)
{
    if (byte_accessed + second < MAX_INSTRUCTION_SIZE)
        byte_accessed += second;
    else
        return MAX_INSTRUCTION_SIZE;
    return byte_accessed;
}


int             instruction_intent::operator--                      (int second)
{
    if (byte_accessed - 1 >= 0)
        byte_accessed--;
    return byte_accessed;
}

int             instruction_intent::operator-                       (int second)
{
    if (byte_accessed - second >= 0)
        byte_accessed -= second;
    return byte_accessed;
}

int             instruction_intent::operator-=                      (int second)
{
    if (byte_accessed - second >= 0)
        byte_accessed -= second;
    return byte_accessed;
}


uint8_t         instruction_intent::operator[]                      (size_t index)
{
    if (index >= MAX_INSTRUCTION_SIZE)
        return instruction[MAX_INSTRUCTION_SIZE - 1];
    else
        return instruction[index];
}


// debug printing ======================================================================================================


void            instruction_intent::debug_print                     ()
{
#define BYTE_TO_HIGHER_HEX(byte)            (((byte & 0xf0u) >> 0x04u) + ((byte & 0xf0u) < 0xa0u ? '0' : 'a' - 0x0au))
#define BYTE_TO_LOWER_HEX(byte)             ((byte & 0x0fu) + ((byte & 0x0fu) < 0x0au ? '0' : 'a' - 0x0au))
    // string stream to help format output
    std::stringstream output;

    // some basic stuff to help identify the output
    output << "JNS_DEBUG_INTENT_INSTRUCTION\n";
    output << "==========================================\n";

    // variant pid
    output << "\tvariant: " << *variant_pid << "\n";
    output << "\t\n";

    // instruction pointer
    output << "\t+------+  > 0x"<< std::hex << (unsigned long long) instruction_pointer << "\n";

    // instruction
    for (int index = 0; index < MAX_INSTRUCTION_SIZE; index++)
    {
        output << "\t| 0x" << (instruction[index] > 0x0f ? "" : "0") << std::hex << (int) instruction[index] << " |"
                << (index == byte_accessed ? "  < accessed\n" : "\n");
    }

    // wrap up
    output << "\t+------+  > 0x" << std::hex << (unsigned long long) instruction_pointer + MAX_INSTRUCTION_SIZE << "\n";
    output << "\n";
    output << "size:   ";
    output << ((int) this->size) << "\n";
    output << "opcode: 0x";
    output << std::hex << (this->instruction[this->effective_opcode_index] & 0xffu) << "\n";
    output << "==========================================\n";

    // print output
    debugf("%s", output.str().c_str());
}

void instruction_intent::debug_print_minimal                        ()
{
#ifdef JNS_DEBUG
    if (size)
    {
        START_OUTPUT_DEBUG
        output << "variant number:      " << *variant_num << "\n";
        output << "instruction pointer: " << std::hex << instruction_pointer << " - " << (int) size << "\n";
        output << "faulting address:    " << std::hex << effective_address << "\n";
        ADD_OUTPUT_DEBUG("instruction:", instruction, size)
        PRINT_OUTPUT_DEBUG
    }
    else
        debug_print();
#endif
}


// =====================================================================================================================
// intent replaying buffer
// =====================================================================================================================
// construction --------------------------------------------------------------------------------------------------------
                replay_buffer::replay_buffer                        (monitor* relevant_monitor,
                                                                     unsigned int replay_buffer_size)
{
    // init
    this->buffer           = (replay_entry*) malloc(replay_buffer_size * sizeof(replay_entry));
    this->buffer_size      = replay_buffer_size;
    this->variant_states   = (replay_state*) malloc(mvee::numvariants * sizeof(replay_state));
    this->variant_count    = mvee::numvariants;
#ifndef MVEE_SHARED_MEMORY_REPLAY_LEADER
    this->head             = 0;
#endif
    this->state            = 0;
    this->relevant_monitor = relevant_monitor;

    passed_mask = 0;
    for (int i = 0; i < mvee::numvariants - 1; i++)
        passed_mask |= (1u<<(unsigned)i);

    // set default values
    for (unsigned int i = 0; i < this->buffer_size; i++)
    {
        this->buffer[i].lock            = false;
        this->buffer[i].passed          = this->passed_mask;
        this->buffer[i].buffer          = this->buffer[i].static_buffer;
    }
    for (unsigned int i = 0; i < this->variant_count; i++)
    {
        this->variant_states[i].state         = REPLAY_STATE_RUNNING;
        this->variant_states[i].current_index = 0;
    }

}


                replay_buffer::~replay_buffer                       ()
{
    for (unsigned int i = 0; i < this->buffer_size; i++)
        if (this->buffer[i].buffer && this->buffer[i].buffer != this->buffer[i].static_buffer)
            free(this->buffer[i].buffer);
    free(this->buffer);
    free(this->variant_states);
}

// access and updating -------------------------------------------------------------------------------------------------
#ifndef MVEE_SHARED_MEMORY_REPLAY_LEADER
int             replay_buffer::obtain_buffer                        (unsigned int variant_num, void* monitor_pointer,
                                                                     instruction_intent &instruction, void** requested,
                                                                     unsigned long long requested_size)
{
    if (variant_num >= this->variant_count)
        return REPLAY_BUFFER_RETURN_ERROR;

    // get current state and entry
    replay_state* current_state = &this->variant_states[variant_num];
    replay_entry* current_entry = &this->buffer[current_state->current_index];

    // entry currently empty
    if (current_entry->entry_state == REPLAY_ENTRY_EMPTY_STATE)
    {
        // fill entry
        for (int i = 0; i < instruction.size; i++)
            current_entry->instruction[i] = instruction.instruction[i];
        current_entry->instruction_size = instruction.size;

        if (requested)
        {
            if (requested_size > REPLAY_ENTRY_STATIC_BUFFER_SIZE)
            {
                current_entry->buffer = (__uint8_t*) malloc(requested_size);
                if (!current_entry->buffer)
                {
                    warnf("could not allocate buffer of size %llu\n", requested_size);
                    return REPLAY_BUFFER_RETURN_ERROR;
                }
            }
            else
                current_entry->buffer = current_entry->static_buffer;
            *requested = current_entry->buffer;
            current_entry->buffer_size = requested_size;
        }
        else
        {
            current_entry->buffer      = nullptr;
            current_entry->buffer_size = 0;
        }

        current_entry->monitor_pointer = monitor_pointer;
        current_entry->variants_passed = 0;
        current_entry->entry_state     = REPLAY_ENTRY_FILLED_STATE;

        // set head
        this->head = current_state->current_index;
        return REPLAY_BUFFER_RETURN_FIRST;
    }
    // entry not empty, are we leading, i.e. waiting for an empty?
    else if (current_state->state == REPLAY_STATE_EXPECTING_EMPTY)
    {
        this->state |= REPLAY_BUFFER_VARIANTS_WAITING;
        current_state->state = REPLAY_STATE_WAITING;
        return REPLAY_BUFFER_RETURN_WAIT;
    }
    // this is the entry we're looking for
    else
    {
        // compare instruction
        if (instruction.size != current_entry->instruction_size)
            return REPLAY_BUFFER_RETURN_ERROR;
        for (int i = 0; i < current_entry->instruction_size; i++)
            if (current_entry->instruction[i] != instruction.instruction[i])
                return REPLAY_BUFFER_RETURN_ERROR;

        // compare monitor pointer
        if (current_entry->monitor_pointer != monitor_pointer)
            return REPLAY_BUFFER_RETURN_ERROR;

        // return buffer
        if (requested)
        {
            if (current_entry->buffer_size != requested_size)
                return REPLAY_BUFFER_RETURN_ERROR;
            *requested = current_entry->buffer;
        }
        // ok
        return REPLAY_BUFFER_RETURN_OK;
    }
}


int             replay_buffer::advance                              (unsigned int variant_num)
{
    if (variant_num >= this->variant_count)
        return REPLAY_BUFFER_RETURN_ERROR;

    // get current state and entry
    replay_state* current_state = &this->variant_states[variant_num];
    replay_entry* current_entry = &this->buffer[current_state->current_index];
    // int temp = current_state->current_index;

    // advance
    bool change_lead = current_state->current_index == this->head;
    current_state->current_index = (current_state->current_index + 1) % this->buffer_size;
    if (change_lead)
    {
        // warnf("changing lead\n");
        for (unsigned int i = 0; i < this->variant_count; i++)
        {
            if (variant_states[i].state == REPLAY_STATE_EXPECTING_EMPTY &&
                    variant_states[i].current_index != current_state->current_index)
            {
                variant_states[i].state = REPLAY_STATE_RUNNING;
            }
        }
        current_state->state = REPLAY_STATE_EXPECTING_EMPTY;
    }

    // entry should be emptied?
    current_entry->variants_passed++;
    if (current_entry->variants_passed >= this->variant_count)
    {
        if (current_entry->buffer != current_entry->static_buffer)
            free(current_entry->buffer);
        current_entry->buffer = nullptr;

        current_entry->variants_passed = 0;
        current_entry->entry_state     = REPLAY_ENTRY_EMPTY_STATE;

        // check if variants were waiting for this
        if (this->state & REPLAY_BUFFER_VARIANTS_WAITING)
        {
            this->state &= ~REPLAY_BUFFER_VARIANTS_WAITING;

            for (unsigned int i = 0; i < this->variant_count; i++)
            {
                if (this->variant_states[i].state == REPLAY_STATE_WAITING)
                {
                    variantstate* variant = &this->relevant_monitor->variants[i];
                    if (current_state->current_index == this->head)
                        this->variant_states[i].state = REPLAY_STATE_EXPECTING_EMPTY;
                    else
                        this->variant_states[i].state = REPLAY_STATE_RUNNING;

                    if (instruction_intent_emulation::lookup_table[variant->instruction.opcode()].emulator(
                            variant->instruction, *this->relevant_monitor, variant) != 0)
                        return REPLAY_BUFFER_RETURN_ERROR;

                    variant->regs.rip += variant->instruction.size;
                    if (!interaction::write_all_regs(variant->variantpid, &variant->regs))
                        return REPLAY_BUFFER_RETURN_ERROR;

                    this->relevant_monitor->call_resume((int) i);
                }
            }
        }
    }

    return REPLAY_BUFFER_RETURN_OK;
}
#else
int             replay_buffer::obtain_buffer                        (unsigned int variant_num, void* monitor_pointer,
                                                                     instruction_intent &instruction, void** requested,
                                                                     unsigned long long &requested_size)
{
    if (variant_num >= this->variant_count)
    {
        warnf("variant_num out of bounds %d\n", variant_num);
        return REPLAY_BUFFER_RETURN_ERROR;
    }

    // get current state and entry
    replay_state* current_state = &this->variant_states[variant_num];
    replay_entry* current_entry = &this->buffer[current_state->current_index];

    if (!variant_num)
    {
        // entry currently empty
        if (current_entry->lock)
        {
            if (requested && requested_size > 0)
            {
                *requested = current_entry->buffer;
                requested_size = current_entry->buffer_size;
            }
            current_entry->lock = false;
            return REPLAY_BUFFER_RETURN_FIRST;
        }
        else if (current_entry->passed == this->passed_mask)
        {
            // fill entry
            for (int i = 0; i < instruction.size; i++)
                current_entry->instruction[i] = instruction.instruction[i];
            current_entry->instruction_size = instruction.size;

            if (requested && requested_size > 0)
            {
                if (requested_size > REPLAY_ENTRY_STATIC_BUFFER_SIZE)
                {
                    current_entry->buffer = (__uint8_t*) malloc(requested_size);
                    if (!current_entry->buffer)
                    {
                        warnf("could not allocate buffer of size %llu\n", requested_size);
                        return REPLAY_BUFFER_RETURN_ERROR;
                    }
                }
                else
                    current_entry->buffer = current_entry->static_buffer;
                *requested = current_entry->buffer;
                current_entry->buffer_size = requested_size;
            }
            else
            {
                current_entry->buffer      = nullptr;
                current_entry->buffer_size = 0;
            }

            current_entry->monitor_pointer = monitor_pointer;

            current_entry->lock = PREFIXES_GRP_ONE_PRESENT(instruction) &&
                    (PREFIXES_GRP_ONE(instruction) == LOCK_PREFIX_CODE);

            if (PREFIXES_GRP_ONE_PRESENT(instruction) && (PREFIXES_GRP_ONE(instruction) == LOCK_PREFIX_CODE))
            {
                current_entry->lock = true;
                current_entry->passed = passed_mask;

                // check which variants are already waiting
                if (this->state & REPLAY_BUFFER_VARIANTS_WAITING)
                {
                    this->state &= ~REPLAY_BUFFER_VARIANTS_WAITING;

                    for (unsigned int i = 1; i < this->variant_count; i++)
                    {
                        if (this->variant_states[i].state == REPLAY_STATE_WAITING)
                        {
                            this->variant_states[i].state = REPLAY_STATE_RUNNING;
                            current_entry->passed &= ~(1u << (i - 1));
                        }
                    }
                }

                return current_entry->passed ? REPLAY_BUFFER_RETURN_HOLD : REPLAY_BUFFER_RETURN_CONTINUE;
            }
            else
            {
                current_entry->lock = false;
                return REPLAY_BUFFER_RETURN_FIRST;
            }
        }
        // entry not empty
        else
        {
            this->state |= REPLAY_BUFFER_LEADER_WAITING;
            current_state->state = REPLAY_STATE_WAITING;
            return REPLAY_BUFFER_RETURN_WAIT;
        }
    }
    else
    {
        if (current_entry->lock)
        {
            current_entry->passed &= ~(1u << (variant_num - 1));
            return current_entry->passed ? REPLAY_BUFFER_RETURN_HOLD : REPLAY_BUFFER_RETURN_CONTINUE;
        }
        // entry currently empty
        else if (!(current_entry->passed & (1u << (variant_num - 1))))
        {
            // compare instruction
            if (instruction.size != current_entry->instruction_size)
            {
                warnf("instruction size differs\n");
                return REPLAY_BUFFER_RETURN_ERROR;
            }
            for (int i = 0; i < current_entry->instruction_size; i++)
            {
                if (current_entry->instruction[i] != instruction.instruction[i])
                {
                    warnf("instruction intent differs\n");
                    return REPLAY_BUFFER_RETURN_ERROR;
                }
            }

            // compare monitor pointer
            if (current_entry->monitor_pointer != monitor_pointer)
            {
                warnf("monitor_pointer differs | leader %p - variant %d %p\n", current_entry->monitor_pointer,
                      variant_num, monitor_pointer);
                return REPLAY_BUFFER_RETURN_ERROR;
            }

            // return buffer
            if (requested)
            {
                /* todo - removing this check technically allows for out of bounds accesses, but is needed for now
                if (current_entry->buffer_size != requested_size)
                {
                    warnf("buffer size not as requested\n");
                    return REPLAY_BUFFER_RETURN_ERROR;
                }
                */
                requested_size = current_entry->buffer_size;
                *requested = current_entry->buffer;
            }
            // ok
            return REPLAY_BUFFER_RETURN_OK;
        }
        else
        {
            this->state |= REPLAY_BUFFER_VARIANTS_WAITING;
            current_state->state = REPLAY_STATE_WAITING;
            return REPLAY_BUFFER_RETURN_WAIT;
        }
    }
}


int             replay_buffer::advance                              (unsigned int variant_num)
{
    if (variant_num >= this->variant_count)
        return REPLAY_BUFFER_RETURN_ERROR;

    // get current state and entry
    replay_state* current_state = &this->variant_states[variant_num];
    replay_entry* current_entry = &this->buffer[current_state->current_index];

    // advance
    current_state->current_index = (current_state->current_index + 1) % this->buffer_size;
    if (!variant_num)
    {
        current_entry->passed = 0;
        if (this->state & REPLAY_BUFFER_VARIANTS_WAITING)
        {
            this->state &= ~REPLAY_BUFFER_VARIANTS_WAITING;

            for (unsigned int i = 1; i < this->variant_count; i++)
            {
                if (this->variant_states[i].state == REPLAY_STATE_WAITING)
                {
                    variantstate* variant = &this->relevant_monitor->variants[i];
                    this->variant_states[i].state = REPLAY_STATE_RUNNING;

                    if (instruction_intent_emulation::lookup_table[variant->instruction.opcode()].emulator(
                            variant->instruction, *this->relevant_monitor, variant) != 0)
                    {
                        warnf("follower emulation failed\n");
                        return REPLAY_BUFFER_RETURN_ERROR;
                    }

                    variant->regs.rip += variant->instruction.size;
                    if (!interaction::write_all_regs(variant->variantpid, &variant->regs))
                    {
                        warnf("writing follower regs failed - errno: %d\n", errno);
                        if (errno == ESRCH)
                            continue;
                        return REPLAY_BUFFER_RETURN_ERROR;
                    }

                    this->relevant_monitor->call_resume((int) i);
                }
            }
        }
    }
    else
        current_entry->passed |= (1u << (variant_num - 1));


    // entry should be emptied?
    if (current_entry->passed == this->passed_mask)
    {
        if (current_entry->buffer && current_entry->buffer != current_entry->static_buffer)
            free(current_entry->buffer);
        current_entry->buffer = nullptr;

        // check if variants were waiting for this
        if (this->state & REPLAY_BUFFER_LEADER_WAITING)
        {
            this->state &= ~REPLAY_BUFFER_LEADER_WAITING;

            variantstate* variant = &this->relevant_monitor->variants[0];
            this->variant_states[0].state = REPLAY_STATE_RUNNING;

            int result = instruction_intent_emulation::lookup_table[variant->instruction.opcode()].emulator(
                    variant->instruction, *this->relevant_monitor, variant);
            switch (result) {
                case REPLAY_BUFFER_RETURN_HOLD:
                {
                    break;
                }
                case REPLAY_BUFFER_RETURN_OK:
                {
                    variant->regs.rip += variant->instruction.size;
                    if (!interaction::write_all_regs(variant->variantpid, &variant->regs))
                    {
                        warnf("writing leader regs failed\n");
                        return REPLAY_BUFFER_RETURN_ERROR;
                    }

                    this->relevant_monitor->call_resume((int) 0);
                    break;
                }
                default:
                {
                    warnf("leader emulation failed - %d\n", result);
                    return REPLAY_BUFFER_RETURN_ERROR;
                }
            }

        }
    }

    return REPLAY_BUFFER_RETURN_OK;
}
#endif


void            replay_buffer::debug_print                          ()
{
    debugf("===================================================================================================\n");
    for (int variant = 0; variant < mvee::numvariants; variant++)
    {
        debugf("variant %d index: %d\n", variant, variant_states[variant].current_index);
        debugf("\n");
    }
    debugf("===================================================================================================\n");
}


// =====================================================================================================================
//      shadow maintenance
// =====================================================================================================================
                shared_monitor_map_info::shared_monitor_map_info(shared_monitor_map_info* monitor_map_from)
        : variant_base(monitor_map_from->variant_base)
        , monitor_base(monitor_map_from->monitor_base)
        , shmid(monitor_map_from->shmid)
        , size(monitor_map_from->size)
        , variant_shadows(mvee::numvariants)
{
    for (int i = 0; i < mvee::numvariants; i++)
        variant_shadows[i] = monitor_map_from->variant_shadows[i];
}
                shared_monitor_map_info::shared_monitor_map_info    (unsigned long long variant_base,
                                                                     __uint8_t* monitor_base, unsigned long long size,
                                                                     int shmid)
        : variant_base(variant_base)
        , monitor_base(monitor_base)
        , shmid(shmid)
        , size(size)
        , variant_shadows(mvee::numvariants)
{
    for (int i = 0; i < mvee::numvariants; i++)
        variant_shadows[i] = { -1, nullptr, 0x00 };
}


                shared_monitor_map_info::~shared_monitor_map_info()
{
    cleanup_shm();
}


int                shared_monitor_map_info::setup_shm               ()
{
    for (int variant_num = 0; variant_num < mvee::numvariants; variant_num++)
    {
        int shadow_shmid = shmget(IPC_PRIVATE, this->size, IPC_CREAT | S_IRUSR | S_IWUSR);
        if (shadow_shmid == -1)
        {
            warnf("problem setting up variant local shadow for variant %d - errno: %d\n", variant_num, errno);
            return -1;
        }
        auto* shm_addr = (__uint8_t*) shmat(shadow_shmid, nullptr, 0);
        if (shm_addr == (void*) -1)
        {
            warnf("problem attaching to variant local shadow (shmid: %d) for variant %d - errno: %d\n", shadow_shmid,
                  variant_num, errno);
            return -1;
        }

        this->variant_shadows[variant_num] =
                {
                        shadow_shmid,
                        shm_addr,
                        0x00
                };
    }


    return 0;
}


void               shared_monitor_map_info::cleanup_shm             ()
{
    if (this->monitor_base)
    {
        if (this->shmid == -1)
            munmap(this->monitor_base, this->size);
        else
            shmdt(this->monitor_base);
        this->variant_base = 0;
        this->monitor_base = nullptr;
    }
    for (int i = 0; i < mvee::numvariants; i++)
    {
        if (this->variant_shadows[i].monitor_base)
        {
            shmdt(this->variant_shadows[i].monitor_base);
            this->variant_shadows[i].variant_base = 0;
            this->variant_shadows[i].monitor_base = nullptr;
        }
    }

    this->shmid = -1;
    this->size = 0;
}



int             mmap_table::shadow_map                              (variantstate* variant, fd_info* info,
                                                                     unsigned long long variant_base,
                                                                     shared_monitor_map_info** shadow,
                                                                     size_t size, int protection, int flags, int offset)
{
    // open file
    int fd = -1;
    if (info->file_type == FT_MEMFD)
    {
        std::stringstream memfd_file_path;
        memfd_file_path << "/proc/" << variant->variantpid << "/fd/" << info->fds[0];
        fd = open(memfd_file_path.str().c_str(), info->access_flags & ~(O_TRUNC | O_CREAT));
    }
    else
        fd = open(info->paths[0].c_str(), info->access_flags & ~(O_TRUNC | O_CREAT));


    if (fd < 0)
    {
        warnf("could not open file %s to open shared mapping... | error %d\n", info->paths[0].c_str(), errno);
#ifndef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
        // we won't be using this anyway if we're logging
        return -1;
#endif
    }


    // map shadow
    errno = 0;
    void* temp_shadow = mmap(nullptr, size, protection, flags, fd, offset);
    if (temp_shadow == MAP_FAILED)
    {
        warnf("\tsize:       %zu\n", size);
        warnf("\tprotection: %d\n", protection);
        warnf("\tflags:      %d\n", flags);
        warnf("\tfd:         %d\n", fd);
        warnf("\toffset:     %d\n", offset);
        warnf("could not map shared file %s | error %d\n", info->paths[0].c_str(), errno);
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
        temp_shadow = nullptr;
#else
        // we won't be using this anyway if we're logging
        close(fd);
        return -1;
#endif
    }

    close(fd);

    // bookkeeping
    *shadow = init_shared_info(variant_base, temp_shadow, (unsigned long long) size);
    if (!(*shadow))
        return -1;

#ifdef JNS_DEBUG
    debugf("shadow mapping ====================================\n");
    debugf("file:                  %s\n", info->paths[0].c_str());
    debugf("shadow base:           %p\n", (void*) (*shadow)->monitor_base);
    debugf("shadow size:           %zu\n", (*shadow)->size);
    debugf("===================================================\n");
#endif

    // return ok
    return 0;
}

int             mmap_table::shadow_shmat                            (variantstate* variant, int shmid,
                                                                     unsigned long long variant_base,
                                                                     shared_monitor_map_info** shadow,
                                                                     unsigned long long size)
{
    // map shadow
    errno = 0;
    void* temp_shadow = shmat(shmid, nullptr, 0);
    if (temp_shadow == MAP_FAILED)
    {
        warnf("could not map shared memory segment %d | error %d\n", shmid, errno);
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
        temp_shadow = nullptr;
#else
        // we won't be using this anyway if we're logging
        return -1;
#endif
    }

    // bookkeeping
    *shadow = init_shared_info(variant_base, temp_shadow, size, shmid);
    if (!(*shadow))
        return -1;

#ifdef JNS_DEBUG
    debugf("shadow mapping ====================================\n");
    debugf("shmid:                 %d\n", shmid);
    debugf("shadow base:           %p\n", (void*) (*shadow)->monitor_base);
    debugf("shadow size:           %zu\n", (*shadow)->size);
    debugf("===================================================\n");
#endif
    // return ok
    return 0;
}


shared_monitor_map_info*
                mmap_table::init_shared_info                        (unsigned long long variant_base,
                                                                     void* monitor_base, unsigned long long size,
                                                                     int shmid)
{
    unsigned long long end = variant_base + size;
    auto monitor_map = new shared_monitor_map_info(variant_base, (__uint8_t*) monitor_base, size, shmid);


    if (variant_mappings.empty() || end <= (unsigned long long) variant_mappings.front()->variant_base)
    {
        variant_mappings.insert(variant_mappings.begin(), monitor_map);
        return monitor_map;
    }

    for (auto iter = variant_mappings.begin(); iter != (variant_mappings.end() - 1); iter++) {
        if (((*iter)->variant_base + (*iter)->size) <= monitor_map->variant_base && (*(iter + 1))->variant_base >= end)
        {
            variant_mappings.insert(iter + 1, monitor_map);
            return monitor_map;
        }
    }

    if (monitor_map->variant_base >= variant_mappings.back()->variant_base + variant_mappings.back()->size)
    {
        variant_mappings.insert(variant_mappings.end(), monitor_map);
        return monitor_map;
    }

    return nullptr;
}


shared_monitor_map_info*
                mmap_table::get_shared_info                         (unsigned long long address)
{
    for (auto &iter: variant_mappings)
        if (address >= iter->variant_base && address < (iter->variant_base + iter->size))
            return iter;

    return nullptr;
}


shared_monitor_map_info*
                mmap_table::remove_shared_info                      (unsigned long long address)
{
    for (auto shadow = variant_mappings.begin(); shadow != variant_mappings.end(); shadow++)
    {
        if (address >= (*shadow)->variant_base && address < ((*shadow)->variant_base + (*shadow)->size))
        {
            (*shadow)->cleanup_shm();
            variant_mappings.erase(shadow);
            return (*shadow);
        }
    }

    return nullptr;
}


int             mmap_table::split_variant_shadow_region             (shared_monitor_map_info* monitor_map,
                                                                     unsigned long long split_address)
{
    // using exit to terminate here as we currently don't implement it.
    exit(-1);
    /*
    if (split_address <= monitor_map->variant_base || split_address >= monitor_map->variant_base + monitor_map->size ||
            (split_address & PAGE_MASK))
        return -1;

    warnf("We don't do that here. - splitting shared region\n\n");
    return -1;
     */
}
int             mmap_table::merge_variant_shadow_region             (shared_monitor_map_info* monitor_map1,
                                                                     shared_monitor_map_info* monitor_map2)
{
    // using exit to terminate here as we currently don't implement it.
    exit(-1);
    /*
    if (monitor_map1->variant_base + monitor_map1->size != monitor_map2->variant_base &&
            monitor_map1->variant_base != monitor_map2->variant_base + monitor_map2->size)
        return -1;

    warnf("We don't do that here. - merging shared regions\n\n");
    return -1;
     */
}


void            mmap_table::debug_shared                            ()
{
    std::stringstream output;
    output << "mappings:\n";
    for (const auto& iter: this->variant_mappings)
        output << "\t  > variant: [ " << std::hex << (unsigned long long) iter->variant_base << "; "
                << std::hex << (unsigned long long) iter->variant_base + iter->size << " ) => "
                << " monitor: [ " << std::hex << (unsigned long long) iter->monitor_base << "; "
                << std::hex << (unsigned long long) iter->monitor_base + iter->size << " )\n";
    output << "\n";

    warnf("%s\n", output.str().c_str());
}

void            mmap_table::attach_shared_memory                    ()
{
    for (auto shared_mapping: variant_mappings)
    {
        if (shared_mapping->shmid != -1)
            shared_mapping->monitor_base =
                    (uint8_t*)shmat(shared_mapping->shmid, nullptr, 0);
        for (auto &shared_shadow: shared_mapping->variant_shadows)
            shared_shadow.monitor_base = (uint8_t*) shmat(shared_shadow.shmid, nullptr, 0);
    }
}


// =====================================================================================================================
//      instruction tracing
// =====================================================================================================================
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
int             instruction_tracing::log_shared_instruction         (monitor &relevant_monitor,
                                                                     variantstate* variant, void* address,
                                                                     mmap_region_info* variant_map_info)
{
    // temporary local variables
    int status;


    // logging stage ---------------------------------------------------------------------------------------------------
    // retrieve instruction
    __uint8_t instruction[MAX_INSTRUCTION_SIZE];
    if (!interaction::read_memory(variant->variantpid, (void*) variant->regs.rip, MAX_INSTRUCTION_SIZE, instruction))
        return -1;
    hde64s disassembled;
    unsigned int instruction_size = hde64_disasm(instruction, &disassembled);


    std::stringstream instruction_strstream;
    for (int i = 0; i < MAX_INSTRUCTION_SIZE; i++)
        instruction_strstream << (instruction[i] < 0x10 ? "0" : "") << std::hex <<
                              ((unsigned int) instruction[i] & 0xffu) << ((i == MAX_INSTRUCTION_SIZE - 1) ? "" : "-");
    instruction_strstream << (char) 0x00;
    char* full_instruction = static_cast<char *>(malloc(instruction_strstream.str().size()));
    strncpy(full_instruction, instruction_strstream.str().c_str(), instruction_strstream.str().size());


    if (disassembled.flags & (F_ERROR | F_ERROR_OPCODE | F_ERROR_LENGTH | F_ERROR_LOCK | F_ERROR_OPERAND) ||
            instruction_size == 0)
    {
        // log instruction
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOG_FULL
        // determine binary
        mmap_region_info* binary = relevant_monitor.set_mmap_table->get_region_info(variant->variant_num,
                variant->regs.rip);
        if (!binary)
        {
            warnf("no binary could be determined\n");
        }

        std::stringstream output;
        output << std::hex << variant->regs.rip << ";";
        output << "false;";
        output << ";";
        output << ";";
        output << ";";
        output << ";";
        output << ";";
        output << instruction_strstream.str().c_str() << ";";
        output << std::hex << address << ";";
        output << relevant_monitor.monitorid << ";";
        output << variant_map_info->region_backing_file_path << ";";
        output << (variant_map_info->shadow->shadow_base == nullptr ? "not shadowed" : "shadowed") << ";";
        output << binary->region_backing_file_path.c_str() << ";";
        output << std::hex << (unsigned long long) binary->original_base << ";";
        output << std::hex << (unsigned long long) binary->region_base_address;

        pthread_mutex_lock(&mvee::tracing_lock);
        fprintf(mvee::instruction_log, "%s\n", output.str().c_str());
        pthread_mutex_unlock(&mvee::tracing_lock);
#else
        unsigned int result_file_len = variant_map_info->region_backing_file_path.size() + 1;
        char *result_file = (char*) malloc(result_file_len);
        strncpy(result_file, variant_map_info->region_backing_file_path.c_str(), result_file_len);

        char* instruction_identification = (char*) malloc(instruction_strstream.str().size());
        strncpy(instruction_identification, instruction_strstream.str().c_str(), instruction_strstream.str().size());

        pthread_mutex_lock(&mvee::tracing_lock);
        tracing_lost_t **lost = &mvee::instruction_log_lost;
        while (*lost != nullptr) {
            if (strcmp((*lost)->instruction, instruction_identification) == 0)
                break;
            lost = &(*lost)->next;
        }

        if (*lost == nullptr)
        {
            *lost = (tracing_lost_t*) malloc(sizeof(tracing_lost_t));
            (*lost)->instruction = instruction_identification;
            (*lost)->hits = 1;
            (*lost)->next = nullptr;
            (*lost)->files_accessed =
            {
                    result_file,
                    1,
                    variant_map_info->shadow->shadow_base == nullptr ? "not shadowed" : "shadowed",
                    nullptr
            };
            (*lost)->instructions =
            {
                    full_instruction,
                    variant->regs.rip,
                    instruction_size,
                    1,
                    nullptr
            };
        }
        else
        {
            (*lost)->hits++;
            tracing_lost_t::files_t *files = &(*lost)->files_accessed;
            bool already_accessed = false;
            do {
                if (strcmp(files->file, result_file) == 0) {
                    already_accessed = true;
                    break;
                }
                if (files->next == nullptr)
                    break;
                files = files->next;
            } while (true);

            if (already_accessed)
                files->hits++;
            else {
                files->next = (tracing_lost_t::files_t *) malloc(sizeof(tracing_lost_t::files_t));
                files->next->file = result_file;
                files->next->hits = 1;
                files->next->shadowed = variant_map_info->shadow->shadow_base == nullptr ? "not shadowed" : "shadowed";
                files->next->next = nullptr;
            }


            // full instruction
            tracing_lost_t::instruction_t* instructions = &(*lost)->instructions;
            bool already_seen = false;
            do {
                if (strcmp(instructions->full, full_instruction) == 0) {
                    already_accessed = true;
                    break;
                }
                if (instructions->next == nullptr)
                    break;
                instructions = instructions->next;
            } while (true);

            if (already_seen)
                instructions->hits++;
            else
            {
                instructions->next =
                        static_cast<tracing_lost_t::instruction_t*>(malloc(sizeof(tracing_lost_t::instruction_t)));
                instructions->next->full = full_instruction;
                instructions->next->instruction_pointer = variant->regs.rip;
                instructions->next->size = instruction_size;
                instructions->next->hits = 1;
                instructions->next->next = nullptr;
            }
        }
        pthread_mutex_unlock(&mvee::tracing_lock);
#endif
    }
    else
    {
        // prefixes
        std::stringstream prefix_strstream;
        if (disassembled.flags & F_PREFIX_REX) {
            unsigned int rex = 0x40;
            rex |= (disassembled.rex_b ? 0b0001u : 0b0000u);
            rex |= (disassembled.rex_x ? 0b0010u : 0b0000u);
            rex |= (disassembled.rex_r ? 0b0100u : 0b0000u);
            rex |= (disassembled.rex_w ? 0b1000u : 0b0000u);
            prefix_strstream << std::hex << ((unsigned int) rex & 0xffu);
            prefix_strstream << "-";
        }
        if (disassembled.flags & F_PREFIX_66)
            prefix_strstream << "66-";
        if (disassembled.flags & F_PREFIX_67)
            prefix_strstream << "67-";
        if (disassembled.flags & F_PREFIX_REPNZ)
            prefix_strstream << "f2-";
        if (disassembled.flags & F_PREFIX_REPX)
            prefix_strstream << "f3-";
        if (disassembled.flags & F_PREFIX_LOCK)
            prefix_strstream << "f0-";
        if (disassembled.flags & F_PREFIX_SEG)
            prefix_strstream << std::hex << ((unsigned int) disassembled.p_seg & 0xffu) << "-";

        char *prefixes = (char *) malloc(prefix_strstream.str().empty() ? 1 : prefix_strstream.str().size());
        if (!prefix_strstream.str().empty())
            strncpy(prefixes, prefix_strstream.str().c_str(), (int) prefix_strstream.str().size());
        prefixes[prefix_strstream.str().empty() ? 0 : prefix_strstream.str().size() - 1] = 0x00;

        // opcode
        std::stringstream opcode_strstream;
        opcode_strstream << (disassembled.opcode < 0x10 ? "0" : "") << std::hex
                         << ((unsigned int) disassembled.opcode & 0xffu);
        if (disassembled.opcode == 0x0f)
            opcode_strstream << "-" << (disassembled.opcode2 < 0x10 ? "0" : "")
                             << std::hex << ((unsigned int) disassembled.opcode2 & 0xffu);
        opcode_strstream << (char) 0x00;

        char *opcode = (char *) malloc(opcode_strstream.str().size());
        strncpy(opcode, opcode_strstream.str().c_str(), (int) opcode_strstream.str().size());

        // modrm/sib+displacement
        std::stringstream modrm_strstream;
        if (disassembled.flags & F_MODRM)
            modrm_strstream << (disassembled.modrm < 0x10 ? "0": "")
                    << std::hex << ((unsigned int) disassembled.modrm);
        if (disassembled.flags & F_SIB)
            modrm_strstream << "-" << (disassembled.sib < 0x10 ? "0" : "")
                    << std::hex << ((unsigned int) disassembled.sib);
        if (disassembled.flags & F_DISP8)
            modrm_strstream << "-" << (disassembled.disp.disp8 < 0x10 ? "0" : "")
                    << std::hex << ((unsigned int) disassembled.disp.disp8 & 0xffu);
        else if (disassembled.flags & F_DISP16)
            for (unsigned int i = 0; i < 2; i++)
                modrm_strstream << "-"
                        << ((((unsigned) disassembled.disp.disp16 >> (i * 8u)) & 0xffu) < 0x10 ? "0" : "")
                        << std::hex << (((unsigned) disassembled.disp.disp16 >> (i * 8u)) & 0xffu);
        else if (disassembled.flags & F_DISP32)
            for (unsigned int i = 0; i < 4; i++)
                modrm_strstream << "-"
                        << ((((unsigned) disassembled.disp.disp32 >> (i * 8u)) & 0xffu) < 0x10 ? "0" : "")
                        << std::hex << (((unsigned) disassembled.disp.disp32 >> (i * 8u)) & 0xffu);
        modrm_strstream << (char) 0x00;

        char *modrm = (char *) malloc(modrm_strstream.str().size());
        strncpy(modrm, modrm_strstream.str().c_str(), (int) modrm_strstream.str().size());
        unsigned int immediate_size = 0;

        // immediate
        std::stringstream immediate_strstream;
        if (disassembled.flags & F_IMM8)
        {
            immediate_size = 8;
            immediate_strstream << (disassembled.imm.imm8 < 0x10 ? "0" : "")
                    << std::hex << ((unsigned int) disassembled.imm.imm8);
        }
        else if (disassembled.flags & F_IMM16)
        {
            immediate_size = 16;
            immediate_strstream << (disassembled.imm.imm16 < 0x10 ? "0" : "")
                    << std::hex << ((unsigned int) disassembled.imm.imm16);
        }
        else if (disassembled.flags & F_IMM32)
        {
            immediate_size = 32;
            immediate_strstream << (disassembled.imm.imm32 < 0x10 ? "0" : "")
                    << std::hex << ((unsigned int) disassembled.imm.imm32);
        }
        else if (disassembled.flags & F_IMM64)
        {
            immediate_size = 64;
            immediate_strstream << (disassembled.imm.imm64 < 0x10 ? "0" : "")
                    << std::hex << ((unsigned int) disassembled.imm.imm64);
        }
        immediate_strstream << (char) 0x00;
        char *immediate = (char *) malloc(immediate_strstream.str().size());
        strncpy(immediate, immediate_strstream.str().c_str(), (int) immediate_strstream.str().size());


        // log instruction
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOG_FULL
        // determine binary
        mmap_region_info* binary = relevant_monitor.set_mmap_table->get_region_info(variant->variant_num,
                                                                                    variant->regs.rip);
        if (!binary)
        {
            warnf("no binary could be determined\n");
        }

        std::stringstream output;
        output << std::hex << variant->regs.rip << ";";
        output << "true;";
        output << prefixes << ";";
        output << opcode << ";";
        output << modrm << ";";
        output << immediate << ";";
        output << immediate_size << ";";
        for (unsigned int i = 0; i < instruction_size; i++)
            output << (instruction[i] < 0x10 ? "0" : "") << std::hex << ((unsigned int) instruction[i] & 0xff)
                    << (i == instruction_size - 1 ? ";" : "-");
        output << std::hex << address << ";";
        output << relevant_monitor.monitorid << ";";
        output << variant_map_info->region_backing_file_path << ";";
        output << (variant_map_info->shadow->shadow_base == nullptr ? "not shadowed" : "shadowed") << ";";
        output << binary->region_backing_file_path.c_str() << ";";
        output << std::hex << (unsigned long long) binary->original_base << ";";
        output << std::hex << (unsigned long long) binary->region_base_address;

        pthread_mutex_lock(&mvee::tracing_lock);
        fprintf(mvee::instruction_log, "%s\n", output.str().c_str());
        pthread_mutex_unlock(&mvee::tracing_lock);

        free(prefixes);
        free(opcode);
        free(modrm);
        free(immediate);
#else
        unsigned int result_file_len = variant_map_info->region_backing_file_path.size() + 1;
        char *result_file = (char *) malloc(result_file_len);
        strncpy(result_file, variant_map_info->region_backing_file_path.c_str(), result_file_len);


        pthread_mutex_lock(&mvee::tracing_lock);
        tracing_data_t **data = &mvee::instruction_log_result;
        while (*data != nullptr) {
            if (strcmp((*data)->opcode, opcode) == 0)
                break;
            data = &(*data)->next;
        }

        if (*data == nullptr) {
            *data = (tracing_data_t *) malloc(sizeof(tracing_data_t));
            (*data)->opcode = opcode;
            (*data)->prefixes =
            {
                    prefixes, 1, nullptr
            };
            (*data)->modrm =
            {
                    modrm, 1, nullptr
            };
            (*data)->immediate =
            {
                    immediate, immediate_size, 1, nullptr
            };
            (*data)->hits = 1;
            (*data)->files_accessed =
            {
                    result_file,
                    1,
                    variant_map_info->shadow->shadow_base == nullptr ? "not shadowed" : "shadowed",
                    nullptr
            };
            (*data)->instructions =
            {
                    full_instruction,
                    variant->regs.rip,
                    instruction_size,
                    1,
                    nullptr
            };
            (*data)->next = nullptr;
        }
        else
        {
            (*data)->hits++;

            // prefix data
            tracing_data_t::prefixes_t* prefixes_data = &(*data)->prefixes;
            bool already_prefixed = false;
            do {
                if (strcmp(prefixes_data->prefixes, prefixes) == 0) {
                    already_prefixed = true;
                    break;
                }
                if (prefixes_data->next == nullptr)
                    break;
                prefixes_data = prefixes_data->next;
            } while (true);

            if (already_prefixed)
                prefixes_data->hits++;
            else {
                prefixes_data->next = (tracing_data_t::prefixes_t*) malloc(sizeof(tracing_data_t::prefixes_t));
                prefixes_data->next->prefixes = prefixes;
                prefixes_data->next->hits = 1;
                prefixes_data->next->next = nullptr;
            }

            // modrm data
            tracing_data_t::modrm_t* modrm_data = &(*data)->modrm;
            bool modrm_already_used = false;
            do {
                if (strcmp(modrm_data->modrm, modrm) == 0) {
                    modrm_already_used = true;
                    break;
                }
                if (modrm_data->next == nullptr)
                    break;
                modrm_data = modrm_data->next;
            } while (true);

            if (modrm_already_used)
                modrm_data->hits++;
            else {
                modrm_data->next = (tracing_data_t::modrm_t*) malloc(sizeof(tracing_data_t::modrm_t));
                modrm_data->next->modrm = modrm;
                modrm_data->next->hits = 1;
                modrm_data->next->next = nullptr;
            }

            // immediate data
            tracing_data_t::immediate_t* immediate_data = &(*data)->immediate;
            bool already_used = false;
            do {
                if (strcmp(immediate_data->immediate, immediate) == 0 && immediate_data->size == immediate_size) {
                    already_used = true;
                    break;
                }
                if (immediate_data->next == nullptr)
                    break;
                immediate_data = immediate_data->next;
            } while (true);

            if (already_used)
                immediate_data->hits++;
            else {
                immediate_data->next = (tracing_data_t::immediate_t*) malloc(sizeof(tracing_data_t::immediate_t));
                immediate_data->next->immediate = immediate;
                immediate_data->next->hits = 1;
                immediate_data->size = immediate_size;
                immediate_data->next->next = nullptr;
            }

            // file access data
            tracing_data_t::files_t* files = &(*data)->files_accessed;
            bool already_accessed = false;
            do {
                if (strcmp(files->file, result_file) == 0) {
                    already_accessed = true;
                    break;
                }
                if (files->next == nullptr)
                    break;
                files = files->next;
            } while (true);

            if (already_accessed)
                files->hits++;
            else {
                files->next = (tracing_data_t::files_t*) malloc(sizeof(tracing_data_t::files_t));
                files->next->file = result_file;
                files->next->hits = 1;
                files->next->shadowed = variant_map_info->shadow->shadow_base == nullptr ? "not shadowed" : "shadowed";
                files->next->next = nullptr;
            }


            // full instruction
            tracing_data_t::instruction_t* instructions = &(*data)->instructions;
            bool already_seen = false;
            do {
                if (strcmp(instructions->full, full_instruction) == 0) {
                    already_accessed = true;
                    break;
                }
                if (instructions->next == nullptr)
                    break;
                instructions = instructions->next;
            } while (true);

            if (already_seen)
                instructions->hits++;
            else
            {
                instructions->next =
                        static_cast<tracing_data_t::instruction_t*>(malloc(sizeof(tracing_data_t::instruction_t)));
                instructions->next->full = full_instruction;
                instructions->next->instruction_pointer = variant->regs.rip;
                instructions->next->size = instruction_size;
                instructions->next->hits = 1;
                instructions->next->next = nullptr;
            }
        }
        pthread_mutex_unlock(&mvee::tracing_lock);
#endif
    }
    // -----------------------------------------------------------------------------------------------------------------

    acquire_shm_protected_memory_for_access shm_access(relevant_monitor, variant_map_info, variant, address);

    debugf("Acquiring first mapping...\n");
    debugf("%p\n", (void*) address);
    if (!shm_access.acquire()) {
        warnf("Mapping shared memory as temporarily accessible failed! - make sure LD_LOADER is configured\n");
        return -1;
    }

    // -----------------------------------------------------------------------------------------------------------------


    // perform actual instruction --------------------------------------------------------------------------------------
    if (!interaction::write_all_regs(variant->variantpid, &variant->regs))
        return -1;

    if (ptrace(PTRACE_SINGLESTEP, variant->variantpid, nullptr, nullptr) != 0)
        return -1;
    waitpid(variant->variantpid, &status, 0);

    if (!interaction::read_all_regs(variant->variantpid, &variant->regs))
        return -1;

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV)
    {
        siginfo_t siginfo;
        if (ptrace(PTRACE_GETSIGINFO, variant->variantpid, nullptr, &siginfo) != 0)
            return -1;

        acquire_shm_protected_memory_for_access second_shm_access(relevant_monitor, variant, siginfo.si_addr);

        debugf("Acquiring second mapping...\n");

        if (!second_shm_access.acquire()) {
            warnf("Mapping second shared memory as temporarily accessible failed!\n");
            return -1;
        }

        // retry, actually exit if this faults
        if (!interaction::write_all_regs(variant->variantpid, &variant->regs))
            return -1;

        if (ptrace(PTRACE_SINGLESTEP, variant->variantpid, nullptr, nullptr) != 0)
            return -1;
        waitpid(variant->variantpid, &status, 0);

        if (!interaction::read_all_regs(variant->variantpid, &variant->regs))
            return -1;

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV)
            return -1;

        if (!second_shm_access.release(false /* the next shm_access.release will do the restore_registers */)) {
            warnf("Mapping second shared memory as no longer accessible failed!\n");
            return -1;
        }
    }
    // -----------------------------------------------------------------------------------------------------------------

    if (!shm_access.release()) {
        warnf("Mapping shared memory as no longer acessible failed!\n");
        return -1;
    }


    if (!interaction::resume_until_syscall(variant->variantpid, 0))
        return -1;
    // return ok
    return 0;
    // -----------------------------------------------------------------------------------------------------------------
}

acquire_shm_protected_memory_for_access::acquire_shm_protected_memory_for_access
    (monitor& relevant_monitor, mmap_region_info* variant_map_info, variantstate* variant, void* address)
    : relevant_monitor(relevant_monitor),
      variant_map_info(variant_map_info),
      variant(variant),
      address(address)
{
}

acquire_shm_protected_memory_for_access::acquire_shm_protected_memory_for_access
    (monitor& relevant_monitor, variantstate* variant, void* address)
    : relevant_monitor(relevant_monitor),
      variant(variant),
      address(address)
{
    // get shared mem info
    variant_map_info = relevant_monitor.set_mmap_table->get_shared_info(variant->variant_num,
            (unsigned long long) address);
    if (!variant_map_info)
    {
        warnf("Could not identify shared mapping in constructor of acquire_shm_protected_memory_for_access...\n");
    }
}


bool acquire_shm_protected_memory_for_access::acquire()
{
    user_regs_struct temp_regs = variant->regs;
    int status;

    // remove protection on mapping ------------------------------------------------------------------------------------
    // mprotect syscall to enable shared mapping
    temp_regs.orig_rax = __NR_mprotect;
    temp_regs.rax = __NR_mprotect;
    temp_regs.rdi = variant_map_info->region_base_address;
    temp_regs.rsi = variant_map_info->region_size;
    temp_regs.rdx = variant_map_info->connected ?
            variant_map_info->connected->region_prot_flags : variant_map_info->region_prot_flags;
    temp_regs.rip = (unsigned long long) variant->syscall_pointer;

    if (!interaction::write_all_regs(variant->variantpid, &temp_regs)) {
        return false;
    }

    // have variant execute call
    if (!interaction::resume_until_syscall(variant->variantpid, 0)) {
        return false;
    }

    waitpid(variant->variantpid, &status, 0);

    // syscall enter
    if (!interaction::resume_until_syscall(variant->variantpid, 0)) {
        return false;
    }

    waitpid(variant->variantpid, &status, 0);

    // syscall exit
    // check for mprotect result 0
    if (!interaction::read_all_regs(variant->variantpid, &temp_regs)) {
        return false;
    }

    if (temp_regs.rax != 0)
    {
        warnf("mprotect failed while enabling - %lld\n", temp_regs.rax);
        warnf("address:    %p\n", address);
        warnf("protection: %d\n", variant_map_info->connected ?
                variant_map_info->connected->region_prot_flags : variant_map_info->region_prot_flags);
        warnf("base:       %p\n", (void*) variant_map_info->region_base_address);
        warnf("size:       %p\n", (void*) variant_map_info->region_size);
        warnf("backing:    %s\n", (void*) variant_map_info->region_backing_file_path.c_str());
        warnf("returned:   %d\n", (int) temp_regs.rax);
        warnf("make sure LD_LOADER is configured for tracing\n");

        relevant_monitor.set_mmap_table->debug_shared();

        return false;
    }

    return true;
}

bool acquire_shm_protected_memory_for_access::release(bool restore_registers)
{
    user_regs_struct temp_regs = variant->regs;
    int status;

    // reset protection ------------------------------------------------------------------------------------------------
    // mprotect syscall to disable shared mapping
    temp_regs.orig_rax = __NR_mprotect;
    temp_regs.rax = __NR_mprotect;
    temp_regs.rdi = variant_map_info->region_base_address;
    temp_regs.rsi = variant_map_info->region_size;
    temp_regs.rdx = PROT_NONE;
    temp_regs.rip = (unsigned long long) variant->syscall_pointer;

    if (!interaction::write_all_regs(variant->variantpid, &temp_regs))
        return false;

    // start syscall
    if (!interaction::resume_until_syscall(variant->variantpid, 0)) {
        return false;
    }
    waitpid(variant->variantpid, &status, 0);

    // syscall entered
    if (!interaction::resume_until_syscall(variant->variantpid, 0)) {
        return false;
    }
    waitpid(variant->variantpid, &status, 0);

    // syscall exit, check for mprotect failure
    if (!interaction::read_all_regs(variant->variantpid, &temp_regs)) {
        return false;
    }

    if (temp_regs.rax != 0)
    {
        warnf("mprotect failed while disabling\n");
        warnf("address:    %p\n", address);
        warnf("protection: %d\n", variant_map_info->region_prot_flags);
        warnf("base:       %p\n", (void*) variant_map_info->region_base_address);
        warnf("size:       %p\n", (void*) variant_map_info->region_size);
        warnf("backing:    %s\n", (void*) variant_map_info->region_backing_file_path.c_str());
        warnf("returned:   %d\n", (int) temp_regs.rax);
        return false;
    }
    // -----------------------------------------------------------------------------------------------------------------

    if (restore_registers) {
        // prepare to resume execution as if nothing happened ----------------------------------------------------------
        if (!interaction::write_all_regs(variant->variantpid, &variant->regs)) {
            return false;
        }
    }

    return true;
}
#endif


void* decode_address_tag(void* address, const variantstate* variant)
{
  return (void*)decode_address_tag((unsigned long)address, variant);
}

void* encode_address_tag(void* address, const variantstate* variant)
{
  return decode_address_tag(address, variant);
}
unsigned long decode_address_tag(unsigned long address, const variantstate* variant)
{
  unsigned long high = address & 0xffffffff00000000ull;
  unsigned long low  = address & 0x00000000ffffffffull;
  return (high ^ variant->shm_tag) + low;
}

unsigned long encode_address_tag(unsigned long address, const variantstate* variant)
{
  return decode_address_tag(address, variant);
}


#ifdef MVEE_SHM_INSTRUCTION_ACCESS_DEBUGGING
void            monitor::add_instruction                            (int variant_num, instruction_intent* intent)
{
    if (this->instruction_list[variant_num].size() >= 250)
        this->instruction_list[variant_num].erase(this->instruction_list[variant_num].begin());
    monitor::instruction_info_t info = {
            { 0 },
            intent->size,
            (unsigned long) intent->instruction_pointer,
            (unsigned long) intent->effective_address,
            (unsigned long) -1,
            false,
            (unsigned long) -1,
            false,
            (unsigned long) -1,
            (unsigned long) -1
    };
    memcpy(info.instruction, intent->instruction, intent->size);
    instruction_list[variant_num].emplace_back(info);
}


void            monitor::print_instruction_list                     ()
{
    std::stringstream ss;
    for (unsigned long variant = 0; variant < instruction_list.size(); variant++)
    {
        debugf("===================================================================================================\n");
        debugf("variant %ld\n", variant);
        debugf("\n");
        for (unsigned long instruction = 0; instruction < instruction_list[variant].size(); instruction++)
        {
            debugf("instruction %ld\n", instruction);
            ss.str("");
            for (unsigned long i = 0; i < instruction_list[variant][instruction].size; i++)
                ss << ((unsigned long long) instruction_list[variant][instruction].instruction[i] > 0xf ? "" : "0")
                        << std::hex << (unsigned long long) instruction_list[variant][instruction].instruction[i]
                        << ((i + 1 == instruction_list[variant][instruction].size) ? "" : " - ");
            debugf(" > instruction:         %s\n", ss.str().c_str());
            debugf(" > instruction pointer: %p\n", (void*) instruction_list[variant][instruction].instruction_pointer);
            debugf(" > faulting address:    %p\n", (void*) instruction_list[variant][instruction].faulting_address);
            debugf(" > source pointer:      %p\n", (void*) instruction_list[variant][instruction].src_ptr);
            debugf(" > destination pointer: %p\n", (void*) instruction_list[variant][instruction].dst_ptr);
            debugf(" > source:              %lx\n", instruction_list[variant][instruction].src);
            debugf(" > destination:         %lx\n", instruction_list[variant][instruction].dst);
        }
        debugf("===================================================================================================\n");
    }
    debugf("===================================================================================================\n");
    debugf("\n");
}


void            monitor::set_instruction_src_ptr                    (int variant_num, unsigned long src_ptr,
                                                                     unsigned long src)
{
    if (instruction_list[variant_num].empty())
        return;
    instruction_list[variant_num].back().src_ptr = src_ptr;
    instruction_list[variant_num].back().src_reg = false;
    instruction_list[variant_num].back().src = src;
}


void            monitor::set_instruction_dst_ptr                    (int variant_num, unsigned long dst_ptr,
                                                                     unsigned long dst)
{
    if (instruction_list[variant_num].empty())
        return;
    instruction_list[variant_num].back().dst_ptr = dst_ptr;
    instruction_list[variant_num].back().dst_reg = false;
    instruction_list[variant_num].back().dst = dst;
}


void            monitor::set_instruction_src_reg                    (int variant_num, unsigned long src)
{
    if (instruction_list[variant_num].empty())
        return;
    instruction_list[variant_num].back().src_ptr = (unsigned long) -1;
    instruction_list[variant_num].back().src_reg = true;
    instruction_list[variant_num].back().src = src;
}


void            monitor::set_instruction_dst_reg                    (int variant_num, unsigned long dst)
{
    if (instruction_list[variant_num].empty())
        return;
    instruction_list[variant_num].back().dst_ptr = (unsigned long) -1;
    instruction_list[variant_num].back().dst_reg = true;
    instruction_list[variant_num].back().dst = dst;
}
#endif
