//
// Created by jonas on 26/02/2020.
//

// implemented header
#include "shared_mem_handling.h"

#include <ios>
#include <MVEE.h>
#include <MVEE_monitor.h>
#include <MVEE_mman.h>
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
    mmap_region_info* variant_map_info = relevant_monitor.set_mmap_table->get_shared_info(variant->variant_num,
            (unsigned long long) variant_address);
    if (!variant_map_info)
    {
        warnf("variant %d address %lx does not have an associated monitor mapping\n",
              variant->variant_num, (unsigned long) variant_address);
        return -1;
    }

    std::shared_ptr<shared_monitor_map_info> monitor_map_info = variant_map_info->shadow;
    if (!monitor_map_info || monitor_map_info->shadow_base == nullptr)
    {
        warnf("variant %d address %lx maps to monitor mapping that points to null or none at all...\n",
              variant->variant_num, (unsigned long)variant_address);
        return -1;
    }

    if ((unsigned long long) variant_address >=
            (variant_map_info->region_base_address + variant_map_info->region_size) ||
            (unsigned long long) variant_address < variant_map_info->region_base_address)
    {
        warnf("No offset can be calculated.\n");
        warnf("Variant effective address 0x%p does not fall between mapping in variant: [0x%p, 0x%p).\n",
              variant_address, (void*) variant_map_info->region_base_address,
              (void*) (variant_map_info->region_base_address + variant_map_info->region_size));
        return -1;
    }

    unsigned long long offset = (unsigned long long) variant_address - variant_map_info->region_base_address;
    *monitor_pointer = (void*) ((unsigned long long) monitor_map_info->shadow_base + offset);

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
                                                                     __uint8_t data_size, void* monitor_pointer,
                                                                     __uint8_t** result, __uint8_t result_size)
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

        if (*result)
        {
            for (unsigned int i = 0; i < result_size; i++)
                entry->result[i] = (*result)[i];
            entry->result_size = result_size;
        }

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
    if (*result)
        *result = buffer[variant_indexes[variant_num]].result;

    // tell variant to proceed
    return 0;
}


// =====================================================================================================================
//      shadow maintenance
// =====================================================================================================================
                shared_monitor_map_info::shared_monitor_map_info    (void* shadow_base, size_t size)
{
    this->shadow_base = shadow_base;
    this->size = size;
}
                shared_monitor_map_info::~shared_monitor_map_info   ()
{
    if (this->shadow_base)
        munmap(this->shadow_base, this->size);
}

int             mmap_table::shadow_map                              (const char* backing_file,
                                                                     unsigned int backing_flags, FileType type,
                                                                     std::shared_ptr<shared_monitor_map_info>* shadow,
                                                                     size_t size, int protection, int flags, int offset)
{
    debugf("opening shadow mapping for %s\n", backing_file);
    unsigned int backing_file_len = strlen(backing_file);

    // open file
    int fd = -1;
    if (type == FT_MEMFD)
    {
        unsigned int added = strlen("/memfd:");
        if (added <= backing_file_len)
            fd = memfd_create(backing_file + added, backing_flags & (MFD_HUGETLB | MFD_ALLOW_SEALING | MFD_CLOEXEC));
    }
    else
        fd = open(backing_file, backing_flags & ~(O_TRUNC | O_CREAT));
    if (fd < 0)
    {
        warnf("could not open file %s to open shared mapping... | error %d\n", backing_file, errno);
#ifndef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
        // we won't be using this anyway
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
        warnf("could not map shared file %s | error %d\n", backing_file, errno);
        temp_shadow = nullptr;
#ifndef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
        // we won't be using this anyway
        close(fd);
        return -1;
#endif
    }

    close(fd);

    // bookkeeping
    char* backing = (char*) malloc(backing_file_len + 1);
    strncpy(backing, backing_file, backing_file_len + 1);
    *shadow = std::shared_ptr<shared_monitor_map_info>(
            (shared_monitor_map_info*) malloc((sizeof(shared_monitor_map_info))));
    (*shadow)->shadow_base = temp_shadow;
    (*shadow)->size = size;

    // return ok
    return 0;
}


int             mmap_table::insert_variant_shared_region            (int variant, mmap_region_info* region)
{
    unsigned long long end = region->region_base_address + region->region_size;

    if (variant_mappings[variant].empty() || end <= variant_mappings[variant].front()->region_base_address)
    {
        variant_mappings[variant].insert(variant_mappings[variant].begin(), region);
        return 0;
    }

    for (auto iter = variant_mappings[variant].begin(); iter != (variant_mappings[variant].end() - 1); iter++)
    {
        if (((*iter)->region_base_address + (*iter)->region_size) <= region->region_base_address&&
                (*(iter + 1))->region_base_address >= end)
        {
            variant_mappings[variant].insert(iter + 1, region);
            return 0;
        }
    }

    if (region->region_base_address >= (variant_mappings[variant].back()->region_base_address) +
                                               variant_mappings[variant].back()->region_size)
    {
        variant_mappings[variant].insert(variant_mappings[variant].end(), region);
        return 0;
    }

    return -1;
}


mmap_region_info*
                mmap_table::get_shared_info                         (int variant, unsigned long long address)
{
    for (auto &iter: variant_mappings[variant])
    {
        if (address >= iter->region_base_address && address < (iter->region_base_address + iter->region_size))
            return iter;
    }

    return nullptr;
}


int             mmap_table::munmap_variant_shadow_region            (int variant, mmap_region_info* region_info)
{
    for (unsigned int i = 0; i < variant_mappings[variant].size(); i++)
    {
        if (*(variant_mappings[variant].begin() + i) == region_info)
        {
            variant_mappings[variant].erase(variant_mappings[variant].begin() + i);
            break;
        }
    }

    region_info->shadow = nullptr;

    return 0;
}
int             mmap_table::split_variant_shadow_region             (int variant, mmap_region_info* region_info)
{
    return 0;
}
int             mmap_table::merge_variant_shadow_region             (int variant, mmap_region_info* region_info1,
                                                                     mmap_region_info* region_info2)
{
    if (region_info1->shadow != region_info2->shadow)
        return -1;

    region_info1->shadow = nullptr;

    int to_erase = -1;
    for (unsigned int i = 0; i < variant_mappings[variant].size(); i++)
    {
        if (*(variant_mappings[variant].begin() + i) == region_info2)
        {
            to_erase = (int) i;
            variant_mappings[variant].erase(variant_mappings[variant].begin() + i);
            break;
        }
    }

    if (to_erase == -1)
        return -1;

    return 0;
}


void               mmap_table::debug_shared                         ()
{
    std::stringstream output;
    output << "mappings:\n";
    for (int i = 0; i < mvee::numvariants; i++)
    {
        output << "\tvariant " << i << ":\n";
        for (auto iter: variant_mappings[i])
            output << "[ " << iter->region_base_address << "; " << iter->region_base_address + iter->region_size
                    << " )  -  " << iter->region_backing_file_path.c_str() << "\n";
    }
    output << "\n";

    warnf("%s\n", output.str().c_str());
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
    mmap_region_info* variant_map_info = relevant_monitor.set_mmap_table->get_shared_info(variant->variant_num,
            (unsigned long long) address);
    if (!variant_map_info)
    {
        warnf("Could not identify shared mapping...\n");
        return -1;
    }


    if (disassembled.flags & (F_ERROR | F_ERROR_OPCODE | F_ERROR_LENGTH | F_ERROR_LOCK | F_ERROR_OPERAND) ||
            instruction_size == 0)
    {
        std::stringstream instruction_strstream;
        for (int i = 0; i < MAX_INSTRUCTION_SIZE; i++)
            instruction_strstream << (instruction[i] < 0x10 ? "0" : "") << std::hex <<
                    ((unsigned int) instruction[i] & 0xffu) << ((i == MAX_INSTRUCTION_SIZE - 1) ? "" : "-");
        instruction_strstream << (char) 0x00;

        // log instruction
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOG_FULL
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
                    << std::hex << ((unsigned int) disassembled.sib) << "-";
        if (disassembled.flags & F_DISP8)
            modrm_strstream << "-" << (disassembled.disp.disp8 < 0x10 ? "0" : "")
                    << std::hex << ((unsigned int) disassembled.disp.disp8);
        else if (disassembled.flags & F_DISP16)
            modrm_strstream << "-" << (disassembled.disp.disp16 < 0x10 ? "0" : "")
                    << std::hex << ((unsigned int) disassembled.disp.disp16);
        else if (disassembled.flags & F_DISP32)
            modrm_strstream << "-" << (disassembled.disp.disp32 < 0x10 ? "0" : "")
                    << std::hex << ((unsigned int) disassembled.disp.disp32);
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
        }
        pthread_mutex_unlock(&mvee::tracing_lock);
#endif
    }
    // -----------------------------------------------------------------------------------------------------------------


    // user local register struct --------------------------------------------------------------------------------------
    temp_regs = variant->regs;
    // -----------------------------------------------------------------------------------------------------------------

    temp_regs.orig_rax = __NR_mprotect;
    temp_regs.rax = __NR_mprotect;
    temp_regs.rdi = variant_map_info->region_base_address;
    temp_regs.rsi = variant_map_info->region_size;
    temp_regs.rdx = variant_map_info->region_prot_flags;
    temp_regs.rip = (unsigned long long) variant->syscall_pointer;

    if (!interaction::write_all_regs(variant->variantpid, &temp_regs)) {
        return false;
    }

    acquire_shm_protected_memory_for_access shm_access(relevant_monitor, variant_map_info, variant, address);

    debugf("Acquiring first mapping...\n");
    if (!shm_access.acquire()) {
        warnf("Mapping shared memory as temporarily accessible failed!\n");
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

    if (WIFSTOPPED(status) && WSTOPSIG(status) == 11)
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

        if (WIFSTOPPED(status) && WSTOPSIG(status) == 11)
            return -1;

        if (!second_shm_access.release(false /* the next shm_access.release will do the restore_registers */)) {
            warnf("Mapping second shared memory as no longer acessible failed!\n");
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
    variant_map_info = relevant_monitor.set_mmap_table->get_shared_info(variant->variant_num, (unsigned long long) address);
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
    temp_regs.rdx = variant_map_info->region_prot_flags;
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
        warnf("address: %p\n", address);
        warnf("protection: %d\n", variant_map_info->region_prot_flags);
        warnf("base: %p\n", (void*) variant_map_info->region_base_address);

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
    temp_regs = variant->regs;
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
        warnf("accessed: %p\n", address);
        warnf("protection: %d\n", variant_map_info->region_prot_flags);
        warnf("address: %p\n", (void*) variant_map_info->region_base_address);
        return false;
    }
    // -----------------------------------------------------------------------------------------------------------------

    if (restore_registers) {
        // prepare to resume execution as if nothing happened -------------------------------------------------------------------------
        if (!interaction::write_all_regs(variant->variantpid, &variant->regs)) {
            return false;
        }
    }

    return true;
}

#endif
