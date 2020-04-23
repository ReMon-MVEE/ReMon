//
// Created by jonas on 26/02/2020.
//

// implemented header
#include "shared_mem_handling.h"

#include <ios>
#include <MVEE.h>
#include <MVEE_monitor.h>
#include <sys/mman.h>
#include <arch/amd64/hde.h>
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
    // overwrite instruction pointer
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

int             instruction_intent::determine_monitor_pointer       (monitor& relevant_monitor, variantstate* variant,
                                                                     void* variant_address, void** monitor_pointer)
{
    // translate variant address to monitor address
    translation_record* translation = variant->translation_table[variant_address];
    if (!translation)
    {
        warnf("variant %d address %lx does not have an associated monitor mapping\n",
              variant->variant_num, (unsigned long) variant_address);
        return -1;
    }

    monitor_mapping monitor_effective_mapping = relevant_monitor.memory_table[translation->memory_id];
    if (monitor_effective_mapping.base_addr == nullptr)
    {
        warnf("variant %d address %lx maps to monitor mapping with id %lu, which points to null...\n",
              variant->variant_num, (unsigned long)variant_address, translation->memory_id);
        return -1;
    }

    if (variant_address >= translation->variant_end || variant_address < translation->variant_base)
    {
        warnf("No offset could be calculated.\n");
        warnf("Variant effective address 0x%p does not fall between mapping in variant: [0x%p, 0x%p).\n",
              variant_address, translation->variant_base, translation->variant_end);
        return -1;
    }

    unsigned long long offset = (unsigned long long) variant_address - (unsigned long long) translation->variant_base;
    *monitor_pointer = (void*) ((unsigned long long) monitor_effective_mapping.base_addr + offset);

    // return ok
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
#ifdef JNS_DEBUG
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
    output << "size: ";
    output << ((int) this->size) << "\n";
    output << "==========================================\n";

    // print output
    mvee::logf("%s", output.str().c_str());
#endif
}

void instruction_intent::debug_print_minimal                        ()
{
#ifdef JNS_DEBUG
    if (size)
    {
        START_OUTPUT_DEBUG
        output << "instruction pointer: " << std::hex << instruction_pointer << "\n";
        output << "faulting address: " << std::hex << effective_address << "\n";
        ADD_OUTPUT_DEBUG("instruction:", instruction, size)
        PRINT_OUTPUT_DEBUG
    }
    else
        debug_print();
#endif
}


// =====================================================================================================================
// translation table
// =====================================================================================================================

// map init and destruction ============================================================================================
                shared_mem_translation_table::shared_mem_translation_table
                                                                    (): table()
{
}


                shared_mem_translation_table::~shared_mem_translation_table
                                                                    () = default;


// map updating ========================================================================================================
int             shared_mem_translation_table::add_record            (void *variant_base, void *variant_end,
                                                                     unsigned long memory_id)
{
    // insert before any other mapping
    if (this->table.empty() || variant_end <= this->table.front().variant_base)
    {
        this->table.insert(this->table.begin(), {variant_base, variant_end, memory_id});
        return 0;
    }


    for (auto iterator = this->table.begin(); iterator != table.end(); iterator++)
    {
        if (variant_end <= (*(iterator+1)).variant_base)
        {
            if (variant_base >= (*iterator).variant_end)
            {
                this->table.insert(iterator+1, {variant_base, variant_end, memory_id});
                return 0;
            }
            else
                return -1;
        }
    }

    // insert at end
    if (variant_base >= this->table.back().variant_end)
    {
        this->table.insert(this->table.end(), {variant_base, variant_end, memory_id});
        return 0;
    }
    return -1;
}


int             shared_mem_translation_table::remove_record         (void *variant_base)
{
    for (auto iterator = this->table.begin(); iterator != table.end(); iterator++)
    {
        if ((*iterator).variant_base == variant_base)
        {
            this->table.erase(iterator);
            return 0;
        }
    }

    return -1;
}


// table access ========================================================================================================
translation_record*
                shared_mem_translation_table::operator[]            (void *variant_address)
{
    for (auto iterator = this->table.begin(); iterator != table.end(); iterator++)
    {
        if (variant_address >= (*iterator).variant_base)
        {
            if (variant_address >= (*iterator).variant_end)
                return nullptr;
            else
                return &(*iterator);
        }
    }

    return nullptr;
}


// debug ===============================================================================================================
void            shared_mem_translation_table::debug_log             ()
{
#ifdef JNS_DEBUG
    debugf("\ttranslation table:\n");
    for (auto & iterator : this->table)
        debugf("\t\t%lu\t| %llx > %llx\n", iterator.memory_id, (unsigned long long) iterator.variant_base,
               (unsigned long long) iterator.variant_end);
#endif
}


// =====================================================================================================================
//      monitor mapping table
// =====================================================================================================================

// construction and destruction ========================================================================================
                memory_mapping_table::memory_mapping_table          () : monitor_addresses(),
                                                                         free_ids()
{

}

                memory_mapping_table::~memory_mapping_table         () = default;


// updating ============================================================================================================
#ifndef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
unsigned long   memory_mapping_table::add                           (void *monitor_base, size_t size)
{
    unsigned long memory_id;
    if (!free_ids.empty())
    {
        memory_id = this->free_ids.front();
        this->free_ids.erase(this->free_ids.begin());

        this->monitor_addresses[memory_id] = {monitor_base, size};
    }
    else
    {
        memory_id = this->monitor_addresses.size();
        this->monitor_addresses.push_back({monitor_base, size});
    }

    return memory_id;
}
#else
unsigned long   memory_mapping_table::add                           (void *monitor_base, size_t size,
                                                                     const std::string &file)
{
    unsigned long memory_id;
    if (!free_ids.empty())
    {
        memory_id = this->free_ids.front();
        this->free_ids.erase(this->free_ids.begin());

        char* file_pointer = (char*) malloc(file.size() + 1);
        strncpy(file_pointer, file.c_str(), file.size());
        file_pointer[file.size()] = 0x00;
        this->monitor_addresses[memory_id] = { monitor_base, size, file_pointer };
    }
    else
    {
        memory_id = this->monitor_addresses.size();

        char* file_pointer = (char*) malloc(file.size() + 1);
        strncpy(file_pointer, file.c_str(), file.size());
        file_pointer[file.size()] = 0x00;
        this->monitor_addresses.push_back({monitor_base, size, file_pointer });
    }

    return memory_id;
}
#endif

int             memory_mapping_table::remove                        (void *monitor_base)
{
    for (unsigned long id = 0; id < this->monitor_addresses.size(); id++)
    {
        if (this->monitor_addresses[id].base_addr == monitor_base)
        {
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
            monitor_mapping mapping = *this->monitor_addresses.erase(this->monitor_addresses.begin() + id);
            free((void*) mapping.file);
#else
            this->monitor_addresses.erase(this->monitor_addresses.begin() + id);
#endif

            this->insert_free_id(id);
            return 0;
        }
    }

    return -1;
}


int             memory_mapping_table::remove                        (unsigned long memory_id)
{
    if (memory_id >= this->monitor_addresses.size())
        return -1;

    this->monitor_addresses.erase(this->monitor_addresses.begin() + memory_id);
    this->insert_free_id(memory_id);

    return 0;
}


// access ==============================================================================================================
monitor_mapping memory_mapping_table::operator[]                    (unsigned long index)
{
    if (index >= this->monitor_addresses.size())
        return {nullptr, 0, nullptr};

    return this->monitor_addresses[index];
}


// private functions ===================================================================================================
void            memory_mapping_table::insert_free_id                (unsigned long free_id)
{
    if (free_id > this->free_ids.back())
        this->free_ids.insert(this->free_ids.end(), free_id);
    else
    {
        for (auto iterator = this->free_ids.begin(); iterator != this->free_ids.end(); iterator++) {
            if (*iterator < free_id) {
                this->free_ids.insert(iterator, free_id);
                break;
            }
        }
    }
}


// =====================================================================================================================
// intent replaying buffer
// =====================================================================================================================
                intent_replay_buffer::intent_replay_buffer          (monitor* relevant_monitor, int variant_count)
{
    this->variant_count = variant_count;
    this->variant_indexes = (int*) malloc(variant_count * sizeof(int));
    this->variant_indexes[0] = 0;
    for (int variant = 1; variant < variant_count; variant++)
        this->variant_indexes[variant] = -1;
    this->variant_indexes[0] = 0;
    this->relevant_monitor = relevant_monitor;
    this->extra = 0;
}

                intent_replay_buffer::~intent_replay_buffer         ()
{
    free(this->variant_indexes);
}


int             intent_replay_buffer::continue_access               (unsigned int variant_num)
{
    variantstate* variant = &relevant_monitor->variants[variant_num];
    variant_indexes[variant_num]--;

    if (instruction_intent_emulation::lookup_table[variant->instruction.opcode()].emulator
            (variant->instruction, *relevant_monitor, variant) < 0)
        return -1;

    variant->regs.rip += variant->instruction.size;
    if (!interaction::write_all_regs(variant->variantpid, &variant->regs))
        return -1;

    relevant_monitor->call_resume((int) variant_num);
    return 0;
}


int             intent_replay_buffer::maybe_resume_leader           ()
{
    // check if all other variants are sufficiently caught up
    extra &= ~LEADER_WAITING_MASK;
    for (unsigned int variant = 1; variant < variant_count; variant++)
    {
        if (variant_indexes[variant] == variant_indexes[0])
        {
            extra |= LEADER_WAITING_MASK;
            break;
        }
    }

    if (!(extra & LEADER_WAITING_MASK))
    {
        variant_indexes[0]++;
        return continue_access(0);
    }
    return 0;
}


int             intent_replay_buffer::access_data                   (unsigned int variant_num,
                                                                     instruction_intent* instruction, __uint8_t** data,
                                                                     __uint8_t data_size, void* monitor_pointer)
{
    // bounds check
    if (variant_num >= variant_count)
        return -1;

    // update content of entry, since this
    if (variant_num == 0)
    {
        // check if all other variants are sufficiently caught up
        extra &= ~LEADER_WAITING_MASK;
        for (unsigned int variant = 1; variant < variant_count; variant++)
        {
            if (variant_indexes[variant] == variant_indexes[0])
            {
                extra |= LEADER_WAITING_MASK;
                break;
            }
        }
        if (extra & LEADER_WAITING_MASK)
            return 1;

        // fill in data in intent_replay
        intent_replay* entry = &buffer[variant_indexes[variant_num]];

        for (unsigned int i = 0; i < instruction->size; i++)
            entry->instruction[i] = instruction->instruction[i];
        entry->instruction_size = instruction->size;

        // todo -- check if this causes race conditions when mapping is being updated, maybe use single instructions.
        for (unsigned int i = 0; i < data_size; i++)
            entry->data[i] = (*data)[i];
        entry->data_size = data_size;
        entry->monitor_address = monitor_pointer;

        // we'll be using the buffer copy, since the monitor runs single threaded, this shouldn't be an issue
        *data = buffer[variant_indexes[variant_num]].data;

        // move along to next slot in buffer, this can safely be done
        variant_indexes[variant_num]++;
        variant_indexes[variant_num] %= INTENT_REPLAY_BUFFER_SIZE;

        // run any variant that has been waiting
        if (extra & VARIANTS_WAITING_MASK)
        {
            for (unsigned int variant = 1; variant < variant_count; variant++)
                if (variant_indexes[variant] >= INTENT_REPLAY_BUFFER_SIZE)
                    if (continue_access(variant) < 0)
                        return -1;
            extra &= ~VARIANTS_WAITING_MASK;
        }

        return 0;
    }


    // move along to next slot in buffer, this can safely be done
    variant_indexes[variant_num]++;
    variant_indexes[variant_num] %= INTENT_REPLAY_BUFFER_SIZE;
    if (variant_indexes[variant_num] == variant_indexes[0])
    {
        // make variant wait for more data
        extra |= VARIANTS_WAITING_MASK;
        variant_indexes[variant_num]+=INTENT_REPLAY_BUFFER_SIZE;
        return 1;
    }
    else if (monitor_pointer != buffer[variant_indexes[variant_num]].monitor_address)
        // The same instruction is accessing different memory in the monitor mapping
        {warnf("%p - %p\n", monitor_pointer, buffer[variant_indexes[variant_num]].monitor_address); return -1;}

    // we'll be using the buffer copy, since the monitor runs single threaded, this shouldn't be an issue
    *data = buffer[variant_indexes[variant_num]].data;

    // tell variant to proceed
    return 0;
}


// =====================================================================================================================
//      instruction tracing
// =====================================================================================================================
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
int             instruction_tracing::log_shared_instruction         (monitor &relevant_monitor,
                                                                     variantstate* variant, void* address)
{
    // temporary local variables
    int status;
    user_regs_struct temp_regs;


    // logging stage ---------------------------------------------------------------------------------------------------
    // retrieve instruction
    __uint8_t instruction[MAX_INSTRUCTION_SIZE];
    if (!interaction::read_memory(variant->variantpid, (void*) variant->regs.rip, MAX_INSTRUCTION_SIZE, instruction))
        return -1;
    hde64s disassembled;
    unsigned int instruction_size = hde64_disasm(instruction, &disassembled);

    // get shared mem info
    translation_record* record = variant->translation_table[address];
    variant->shared_base = record->variant_base;
    variant->shared_size = (unsigned int)
            ((unsigned long long) record->variant_end - (unsigned long long) record->variant_base);

    // log instruction
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOG_FULL
    std::stringstream output;
    output << std::hex << variant->regs.rip << ";";
    for (unsigned int i = 0; i < instruction_size; i++)
        output << ((instruction[i] & 0xffu) < 0x10 ? "0" : "")
                << std::hex << (instruction[i] & 0xffu) << ((i == (instruction_size - 1)) ? ";" : "-");
    output << std::hex << address << ";";
    output << (relevant_monitor.memory_table[record->memory_id].file ?
            relevant_monitor.memory_table[record->memory_id].file : "unknown") << ";";
    fprintf(mvee::instruction_log, "%s\n", output.str().c_str());
#else
    std::stringstream instruction_identification;
    for (unsigned int i = 0; i < instruction_size; i++)
        instruction_identification << ((instruction[i] & 0xffu) < 0x10 ? "0" : "")
               << std::hex << (instruction[i] & 0xffu) << ((i == (instruction_size - 1)) ? "" : "-");
    instruction_identification << '\0';

    char* result_instruction_identification = (char*) malloc(instruction_identification.str().size());
    strncpy(result_instruction_identification, instruction_identification.str().c_str(),
            instruction_identification.str().size());

    char* result_file = (char*) malloc(strlen(relevant_monitor.memory_table[record->memory_id].file) + 1);
    strncpy(result_file, relevant_monitor.memory_table[record->memory_id].file,
            strlen(relevant_monitor.memory_table[record->memory_id].file) + 1);


    tracing_data** data = &variant->result;
    while (*data != nullptr)
    {
        if (strcmp((*data)->instruction, instruction_identification.str().c_str()) == 0)
            break;
        data = &(*data)->next;
    }

    if (*data == nullptr)
    {
        *data = (tracing_data*) malloc(sizeof(tracing_data));
        (*data)->instruction = result_instruction_identification;
        (*data)->hits = 1;
        (*data)->files_accessed = {
                result_file, 1, nullptr
        };
        (*data)->next = nullptr;
    }
    else
    {
        (*data)->hits++;
        tracing_data::files* files = &(*data)->files_accessed;
        bool already_accessed = false;
        while (files->next != nullptr)
        {
            if (strcmp(files->file, result_file) == 0)
            {
                already_accessed = true;
                break;
            }
            files = files->next;
        }

        if (already_accessed)
            files->hits++;
        else
        {
            files->next = (tracing_data::files*) malloc(sizeof(tracing_data::files));
            files->next->file = result_file;
            files->next->hits = 1;
            files->next->next = nullptr;
        }
    }
#endif
    // -----------------------------------------------------------------------------------------------------------------


    // user local register struct --------------------------------------------------------------------------------------
    temp_regs = variant->regs;
    // -----------------------------------------------------------------------------------------------------------------


    // remove protection on mapping ------------------------------------------------------------------------------------

    // mprotect syscall to enable shared mapping
    temp_regs.orig_rax = __NR_mprotect;
    temp_regs.rax = __NR_mprotect;
    temp_regs.rdi = (unsigned long long) variant->shared_base;
    temp_regs.rsi = (unsigned long long) variant->shared_size;
    temp_regs.rdx = PROT_READ | PROT_WRITE;
    temp_regs.rip = (unsigned long long) variant->syscall_pointer;

    if (!interaction::write_all_regs(variant->variantpid, &temp_regs))
        return -1;

    // have variant execute call
    if (!interaction::resume_until_syscall(variant->variantpid, 0))
        return -1;
    waitpid(variant->variantpid, &status, 0);

    // syscall enter
    if (!interaction::resume_until_syscall(variant->variantpid, 0))
        return -1;
    waitpid(variant->variantpid, &status, 0);

    // syscall exit
    // check for mprotect result 0
    if (!interaction::read_all_regs(variant->variantpid, &temp_regs))
        return -1;
    if (temp_regs.rax != 0)
    {
        warnf("mprotect failed while enabling\n");
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
    // -----------------------------------------------------------------------------------------------------------------


    // reset protection ------------------------------------------------------------------------------------------------
    // mprotect syscall to disable shared mapping
    temp_regs = variant->regs;
    temp_regs.orig_rax = __NR_mprotect;
    temp_regs.rax = __NR_mprotect;
    temp_regs.rdi = (unsigned long long) variant->shared_base;
    temp_regs.rsi = (unsigned long long) variant->shared_size;
    temp_regs.rdx = PROT_NONE;
    temp_regs.rip = (unsigned long long) variant->syscall_pointer;

    if (!interaction::write_all_regs(variant->variantpid, &temp_regs))
        return -1;

    // start syscall
    if (!interaction::resume_until_syscall(variant->variantpid, 0))
        return -1;
    waitpid(variant->variantpid, &status, 0);

    // syscall entered
    if (!interaction::resume_until_syscall(variant->variantpid, 0))
        return -1;
    waitpid(variant->variantpid, &status, 0);

    // syscall exit, check for mprotect failure
    if (!interaction::read_all_regs(variant->variantpid, &temp_regs))
        return -1;
    if (temp_regs.rax != 0)
    {
        warnf("mprotect failed while disabling\n");
        return -1;
    }
    // -----------------------------------------------------------------------------------------------------------------


    // resume execution as if nothing happened -------------------------------------------------------------------------
    if (!interaction::write_all_regs(variant->variantpid, &variant->regs))
        return -1;

    if (!interaction::resume_until_syscall(variant->variantpid, 0))
        return -1;
    // return ok
    return 0;
    // -----------------------------------------------------------------------------------------------------------------
}

#endif