#include "MVEE.h"
#include "PMVEE.h"
#include "MVEE_interaction.h"
#include "MVEE_monitor.h"
#include "MVEE_syscalls.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h> 
#include <sys/shm.h>

/*-----------------------------------------------------------------------------
    call_calculate_equivalent_function_addresses
-----------------------------------------------------------------------------*/
void monitor::convert_equivalent_pointer_array()
{
    #ifndef MVEE_CONNECTED_MMAP_REGIONS
    #define MVEE_CONNECTED_MMAP_REGIONS
    #endif
    #ifdef MVEE_CONNECTED_MMAP_REGIONS
    std::vector<unsigned long> input = std::vector<unsigned long>(
            (pmvee_state_copy_zone.state_copy_end - pmvee_state_copy_zone.state_alter_start)/sizeof(unsigned long));
    interaction::read_memory(variants[0].variantpid, (void*)pmvee_state_copy_zone.state_alter_start,
            pmvee_state_copy_zone.state_copy_end - pmvee_state_copy_zone.state_alter_start, input.data());

    std::vector<unsigned long> output;
    for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
    {
        output = std::vector<unsigned long>();
        for (unsigned long address: input)
        {
            // warnf(" > translating %p...\n", (void*)address);

            mmap_region_info* region = set_mmap_table->get_region_info(0, address);
            if (!region)
            {
                // warnf("   > could not find region\n");
                output.push_back(address);
                continue;
            }
            // warnf("   > found region @ %p (offset: %lx)!\n", (void*)region->region_base_address, address - region->region_base_address + region->region_backing_file_offset);

            int added = 0;
            unsigned long *jumps_a = &(pmvee_jump_addresses[1]);
            for (unsigned long jump_i = 0; jump_i < pmvee_jump_addresses[0]; jump_i+=mvee::numvariants)
            {
                unsigned long *jump = &(jumps_a[jump_i]);
                if (jump[0] == address)
                {
                    // warnf("   > found equivalent address @ %p\n", (void*)jump[variant_i]);
                    output.push_back(jump[variant_i]);
                    added = 1;
                    break;
                }
            }
            if (added)
                continue;
            // warnf("   > could not find pre-computed equivalent for %p.\n", (void*)address);

            // for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
            // //     warnf(" >> [%d] new base: (%p)%p%p\n", variant_i, (void*)&region->connected_regions->regions[variant_i], (void*)&region->connected_regions->regions[variant_i]->region_base_address, (void*)region->connected_regions->regions[variant_i]->region_base_address);
            if (region->connected_regions)
            {
                // warnf("   > maps to connected region @ %p\n", (void*)region->connected_regions->regions[variant_i]->region_base_address);
                output.push_back(address - region->region_base_address + region->connected_regions->regions[variant_i]->region_base_address);
            }
            else
            {
                // warnf("   > not translating.\n");
                output.push_back(address);
            }
        }
        // for (unsigned long i = 0; i < input.size(); i++) warnf(" >%p -> %p\n", (void*)input[i], (void*)output[i]);
        interaction::write_memory(variants[variant_i].variantpid, (void*)pmvee_state_copy_zone.state_alter_start, pmvee_state_copy_zone.state_copy_end - pmvee_state_copy_zone.state_alter_start, output.data());
    }
    #else
    warnf(" > MVEE_CONNECTED_MMAP_REGIONS required,\n");
    shutdown(false);
    #endif
}


unsigned long monitor::get_equivalent_address(int variant_i, unsigned long address, mmap_region_info* region)
{
        // warnf("   > found region @ %p (offset: %lx)!\n", (void*)region->region_base_address, address - region->region_base_address + region->region_backing_file_offset);
        unsigned long *jumps_a = &(pmvee_jump_addresses[1]);
        for (unsigned long jump_i = 0; jump_i < pmvee_jump_addresses[0]; jump_i+=mvee::numvariants)
        {
            unsigned long *jump = &(jumps_a[jump_i]);
            if (jump[0] == address)
                return (jump[variant_i]);
        }
        // warnf("   > could not find pre-computed equivalent for %p.\n", (void*)address);

        // for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
        // //     warnf(" >> [%d] new base: (%p)%p%p\n", variant_i, (void*)&region->connected_regions->regions[variant_i], (void*)&region->connected_regions->regions[variant_i]->region_base_address, (void*)region->connected_regions->regions[variant_i]->region_base_address);
        if (region->connected_regions)
        {
            // warnf("   > maps to connected region @ %p\n", (void*)region->connected_regions->regions[variant_i]->region_base_address);
            return (address - region->region_base_address + region->connected_regions->regions[variant_i]->region_base_address);
        }
        else
        {
            // warnf("   > not translating.\n");
            return (address);
        }
}


void monitor::copy_migration()
{
    #ifndef MVEE_CONNECTED_MMAP_REGIONS
    #define MVEE_CONNECTED_MMAP_REGIONS
    #endif
    #ifdef MVEE_CONNECTED_MMAP_REGIONS

    // copy_migration_ipmon();
    // char* ipmon_migration = (char*)malloc(pmvee_state_copy_zone.state_copy_end - pmvee_zone_pt);
    // memcpy(ipmon_migration, variants[1].pmvee_communication_mon_pt, pmvee_state_copy_zone.state_copy_end - pmvee_zone_pt);

    unsigned long address_end = (pmvee_state_copy_zone.state_copy_end - pmvee_state_copy_zone.state_alter_start) / 8;
    unsigned long* address = (unsigned long*)(
            (char*)variants[0].pmvee_communication_mon_pt + pmvee_state_copy_zone.state_alter_start - variants[0].pmvee_communication_pt);
    for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
    {
        memcpy(variants[variant_i].pmvee_communication_mon_pt, variants[0].pmvee_communication_mon_pt,
                pmvee_state_copy_zone.state_alter_start - variants[0].pmvee_communication_pt);
        unsigned long* output = (unsigned long*)(
                (char*)variants[variant_i].pmvee_communication_mon_pt +
                pmvee_state_copy_zone.state_alter_start -
                variants[0].pmvee_communication_pt);
        unsigned long address_i;
        for (address_i = 0; address_i < address_end; address_i++)
        {
            mmap_region_info* region = set_mmap_table->get_region_info(0, address[address_i]);
            if (!region)
            {
                if (address[address_i] != PMVEE_SCANNINGG_START)
                {
                    output[address_i] = address[address_i];
                    continue;
                }
                else
                {
                    output[address_i] = address[address_i];
                    address_i++;
                    while (address[address_i])
                    {
                        output[address_i] = address[address_i];
                        address_i++;
                        region = set_mmap_table->get_region_info(0, address[address_i]);
                        if (region)
                            output[address_i] = get_equivalent_address(variant_i, address[address_i], region);
                        else
                        {
                            output[address_i] = address[address_i];
                        }
                        address_i++;
                    }
                    output[address_i] = address[address_i];
                    continue;
                    
                }
            }
            else
                output[address_i] = get_equivalent_address(variant_i, address[address_i], region);
        }
    }

    
    #else
    warnf(" > MVEE_CONNECTED_MMAP_REGIONS required,\n");
    shutdown(false);
    #endif


    // for (unsigned long index = 0; index < (pmvee_state_copy_zone.state_copy_end - pmvee_zone_pt)/8; index++)
    // {
    //     if (((unsigned long*)ipmon_migration)[index] != ((unsigned long*)variants[1].pmvee_communication_mon_pt)[index])
    //         shutdown(false);
// 
    //     warnf(" > [%s] - %lx | %lx\n", ((unsigned long*)ipmon_migration)[index] == ((unsigned long*)variants[1].pmvee_communication_mon_pt)[index] ? "o" : "x", ((unsigned long*)ipmon_migration)[index], ((unsigned long*)variants[1].pmvee_communication_mon_pt)[index]);
    // }
    // free(ipmon_migration);
}


#if 0
static void print_migration_targets(char* pmvee_migration_mon_pt)
{
    unsigned long* current_migration_count = (unsigned long*) pmvee_migration_mon_pt;
    unsigned long* current_pointer_count   = &((unsigned long*)pmvee_migration_mon_pt)[1];
    warnf(" > <%p> current migration count: %ld\n", (void*)current_migration_count, *current_migration_count);
    warnf(" > <%p> current pointer count:   %ld\n", (void*)current_pointer_count, *current_pointer_count);
    auto variant_migration_infos = (mvee::pmvee_migration_info_t*)
            (((char*)pmvee_migration_mon_pt) + 2*sizeof(unsigned long));
    auto variant_pointer_infos = (unsigned long*) (
            ((char*)pmvee_migration_mon_pt) +
            (2*sizeof(unsigned long)) + ((*current_migration_count) * sizeof(mvee::pmvee_migration_info_t)));
    for (unsigned long migration_i = 0; migration_i < *current_migration_count; migration_i++)
        warnf( " > <%p> migration[%s%lu]: %p (%lu)\n",
            (void*)&variant_migration_infos[migration_i],
            migration_i < 100 ? (migration_i < 10 ? "00" : "0") : "", migration_i,
            (void*)variant_migration_infos[migration_i].offset, variant_migration_infos[migration_i].size);
    for (unsigned long pointer_i = 0; pointer_i < *current_pointer_count; pointer_i++)
        warnf( " > <%p> pointer[%s%lu]: %p\n",
            (void*)&variant_pointer_infos[pointer_i],
            pointer_i < 100 ? (pointer_i < 10 ? "00" : "0") : "", pointer_i,
            (void*)variant_pointer_infos[pointer_i]);
}


void print_simple_addresses(unsigned long* simple_mappings)
{
    unsigned long* mapping_count = simple_mappings;
    struct pmvee_mappings_info_t* mappings = (struct pmvee_mappings_info_t*)(simple_mappings + 1);

    warnf(" > count: %ld\n", *mapping_count);
    for (unsigned long mapping_i = 0; mapping_i < (*mapping_count); mapping_i++)
        warnf("   > mapping[%ld]: [ %p ; %p ) (%lx)\n", mapping_i, mappings[mapping_i].start, mappings[mapping_i].end, mappings[mapping_i].prot);
}
#endif

void monitor::add_connected_region_at_index(unsigned long index, connected_region_info* connected_regions)
{
    struct pmvee_mappings_info_t* mappings = (struct pmvee_mappings_info_t*)
            (((char*)pmvee_translations) + sizeof(struct pmvee_translation_unit_t));
    if (index < pmvee_translations->mapping_count)
    {
        memmove(
            &mappings[index + mvee::numvariants],
            &mappings[index],
            sizeof(struct pmvee_mappings_info_t) * (pmvee_translations->mapping_count - (index))
        );
    }
    struct pmvee_mappings_info_t* inserted = &mappings[index];

    for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
        inserted[variant_i] =
        {
            (char*)connected_regions->regions[variant_i]->region_base_address,
            (char*)connected_regions->regions[variant_i]->region_base_address + connected_regions->regions[variant_i]->region_size,
            connected_regions->regions[variant_i]->region_prot_flags
        };
    pmvee_translations->mapping_count+=mvee::numvariants;
}

void monitor::add_connected_regions_to_map(connected_region_info* connected_regions)
{
    struct pmvee_mappings_info_t* mappings = (struct pmvee_mappings_info_t*)
            (((char*)pmvee_translations) + sizeof(struct pmvee_translation_unit_t));

    char* start = (char*)connected_regions->regions[0]->region_base_address;
    char* end   = (char*)(start + connected_regions->regions[0]->region_size);

    unsigned long mapping_i = 0;
    for (; mapping_i < pmvee_translations->mapping_count; mapping_i+=mvee::numvariants)
    {
        if (start <= mappings[mapping_i].end)
            break;
    }

    if (mapping_i == pmvee_translations->mapping_count)
    {
        add_connected_region_at_index(mapping_i, connected_regions);
        return;
    }


    if (start > mappings[mapping_i].start)
    {
        mappings[mapping_i].end = start;
        for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
        {
            if ((char*)connected_regions->regions[variant_i]->region_base_address > mappings[mapping_i + variant_i].start)
                mappings[mapping_i + variant_i].end = (char*)connected_regions->regions[variant_i]->region_base_address;
        }
        mapping_i+=mvee::numvariants;
        if (mapping_i >= pmvee_translations->mapping_count)
        {
            add_connected_region_at_index(mapping_i, connected_regions);
            return;
        }
    }

    while ((mapping_i + mvee::numvariants) < pmvee_translations->mapping_count && mappings[mapping_i].end <= end)
    {
        memmove(
            &mappings[mapping_i],
            &mappings[mapping_i + mvee::numvariants],
            sizeof(struct pmvee_mappings_info_t) * (pmvee_translations->mapping_count - (mapping_i + mvee::numvariants))
        );
        pmvee_translations->mapping_count-=mvee::numvariants;
    }
    if (mappings[mapping_i].end <= end)
        pmvee_translations->mapping_count-=mvee::numvariants;
    else if (mappings[mapping_i].start < end)
    {
        mappings[mapping_i].start = end;
        for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
        {
            if ((char*)connected_regions->regions[variant_i]->region_base_address < mappings[mapping_i + variant_i].end)
                mappings[mapping_i + variant_i].start = (char*)connected_regions->regions[variant_i]->region_base_address + connected_regions->regions[variant_i]->region_size;
        }
    }
    add_connected_region_at_index(mapping_i, connected_regions);
}


void mmap_table::add_address_to_mmap(unsigned long address, size_t size, unsigned long prot)
{
    unsigned long* mapping_count = simple_mappings;
    struct pmvee_mappings_info_t* mappings = (struct pmvee_mappings_info_t*)(simple_mappings + 1);

    char* start = (char*)address;
    char* end   = start + size;

    unsigned long mapping_i = 0;
    for (; mapping_i < (*mapping_count); mapping_i++)
    {
        if (start <= mappings[mapping_i].end)
            break;
    }

    if (mapping_i == (*mapping_count))
    {
        mappings[(*mapping_count)] = { start, end, prot };
        (*mapping_count)++;
        // print_simple_addresses(simple_mappings);
        return;
    }

    if (end < mappings[mapping_i].start)
    {
        memmove(
            &mappings[mapping_i + 1],
            &mappings[mapping_i],
            sizeof(struct pmvee_mappings_info_t) * ((*mapping_count) - (mapping_i + 1))
        );
        mappings[mapping_i] = { start, end, prot };
        (*mapping_count)++;
    }
    else if (end == mappings[mapping_i].start)
    {
        if (mappings[mapping_i].prot == prot)
            mappings[mapping_i].start = start;
        else
        {
            memmove(
                &mappings[mapping_i + 1],
                &mappings[mapping_i],
                sizeof(struct pmvee_mappings_info_t) * ((*mapping_count) - (mapping_i + 1))
            );
            mappings[mapping_i] = { start, end, prot };
            (*mapping_count)++;
        }
    }
    else if (end <= mappings[mapping_i].end)
    {
        if (mappings[mapping_i].prot == prot)
        {
            if (start < mappings[mapping_i].start)
                mappings[mapping_i].start = start;
        }
        else
        {
            if (start <= mappings[mapping_i].start)
            {
                memmove(
                    &mappings[mapping_i + 1],
                    &mappings[mapping_i],
                    sizeof(struct pmvee_mappings_info_t) * ((*mapping_count) - (mapping_i + 1))
                );
                mappings[mapping_i] = { start, end, prot };
                mappings[mapping_i + 1].start = end;
                (*mapping_count)++;
            }
            else
            {
                memmove(
                    &mappings[mapping_i + 2],
                    &mappings[mapping_i],
                    sizeof(struct pmvee_mappings_info_t) * ((*mapping_count) - (mapping_i + 1))
                );
                mappings[mapping_i].end = start;
                mappings[mapping_i + 1] = { start, end, prot };
                mappings[mapping_i + 2].start = end;
                (*mapping_count)+=2;
            }
        }
    }
    else
    {
        if (prot == mappings[mapping_i].prot)
        {
            if (start < mappings[mapping_i].start)
                mappings[mapping_i].start = start;
            mappings[mapping_i].end = end;
        }
        else
        {
            if (start <= mappings[mapping_i].start)
            {
                mappings[mapping_i].start = start;
                mappings[mapping_i].end = end;
            }
            else
            {
                if ((mapping_i + 1) < (*mapping_count))
                {
                    memmove(
                        &mappings[mapping_i + 2],
                        &mappings[mapping_i + 1],
                        sizeof(struct pmvee_mappings_info_t) * ((*mapping_count) - (mapping_i + 2))
                    );
                    (*mapping_count)++;
                }
                mappings[mapping_i].end = start;
                mapping_i++;
                mappings[mapping_i] = { start, end, prot };
            }
        }
            
        unsigned long mapping_i_next = mapping_i + 1;
        while (mapping_i_next < (*mapping_count))
        {
            if (mappings[mapping_i_next].start > end)
                break;
            else if (mappings[mapping_i_next].end <= end)
            {
                memmove(
                    &mappings[mapping_i_next],
                    &mappings[mapping_i_next + 1],
                    sizeof(struct pmvee_mappings_info_t) * ((*mapping_count) - (mapping_i_next + 1))
                );
                (*mapping_count)--;
            }
            else if (mappings[mapping_i_next].start < end)
            {
                memmove(
                    &mappings[mapping_i_next + 1],
                    &mappings[mapping_i_next],
                    sizeof(struct pmvee_mappings_info_t) * ((*mapping_count) - (mapping_i_next + 1))
                );
                mappings[mapping_i_next].start = end;
                (*mapping_count)++;
                break;
            }
            else if (mappings[mapping_i_next].prot == mappings[mapping_i].prot)
            {
                mappings[mapping_i].end = mappings[mapping_i_next].end;
                memmove(
                    &mappings[mapping_i_next],
                    &mappings[mapping_i_next + 1],
                    sizeof(struct pmvee_mappings_info_t) * ((*mapping_count) - (mapping_i_next + 1))
                );
                (*mapping_count)--;
                break;
            }
            else
                break;
        }
    }
    // print_simple_addresses(simple_mappings);
}


void mmap_table::remove_address_from_mmap(unsigned long address, size_t size)
{
    unsigned long* mapping_count = simple_mappings;
    struct pmvee_mappings_info_t* mappings = (struct pmvee_mappings_info_t*)(simple_mappings + 1);

    char* start = (char*)address;
    char* end   = start + size;

    unsigned long mapping_i = 0;
    for (; mapping_i < (*mapping_count); mapping_i++)
    {
        if (start <= mappings[mapping_i].end)
            break;
    }

    if (mapping_i == (*mapping_count))
    {
        // print_simple_addresses(simple_mappings);
        return;
    }


    if (start > mappings[mapping_i].start)
    {
        mappings[mapping_i].end = start;
        mapping_i++;
        if ((mapping_i) >= (*mapping_count))
        {
            // print_simple_addresses(simple_mappings);
            return;
        }
    }

    while ((mapping_i + 1) < (*mapping_count) && mappings[mapping_i].end <= end)
    {
        memmove(
            &mappings[mapping_i],
            &mappings[mapping_i + 1],
            sizeof(struct pmvee_mappings_info_t) * ((*mapping_count) - (mapping_i + 1))
        );
        (*mapping_count)--;
    }

    if (mappings[mapping_i].start < end)
        mappings[mapping_i].start = end;
    
    // print_simple_addresses(simple_mappings);
}


void mmap_table::reset_simple_mappings(unsigned long* new_mappings)
{
    if (simple_mappings)
        memcpy(new_mappings, simple_mappings, (*(unsigned long*)simple_mappings)*sizeof(pmvee_mappings_info_t) + sizeof(unsigned long));
    simple_mappings = new_mappings;
}


void monitor::setup_pmvee_communication(monitor *parent)
{
    debugf(" > setting up communication\n");

#ifdef IPMON_PMVEE_HANDLING
    int pmvee_sync_id = shmget(IPC_PRIVATE, sizeof(struct pmvee_sync_t), IPC_CREAT | S_IRUSR | S_IWUSR);
    if (pmvee_sync_id == -1)
    {
        warnf(" > Could not get shm segemnt for simple mmaps | errno: %d\n", errno);
        shutdown(false);
    }
    multi_exec = (struct pmvee_sync_t*)shmat(pmvee_sync_id, 0, 0);
    if (multi_exec == MAP_FAILED)
    {
        warnf(" > Could not attach to shm segemnt %d for simple mmaps | errno: %d\n",
                pmvee_sync_id, errno);
        shutdown(false);
    }
    if (shmctl(pmvee_sync_id, IPC_RMID, NULL))
    {
        warnf(" > Could not set IPC_RMID on shm segemnt %d for simple mmaps | errno: %d\n",
                pmvee_sync_id, errno);
        shutdown(false);
    }
    multi_exec->pmvee_sync_id = pmvee_sync_id;
#endif

    simple_mappings_id = shmget(IPC_PRIVATE, PMVEE_SIMPLE_MAPPINGS_SIZE, IPC_CREAT | S_IRUSR | S_IWUSR);
    if (simple_mappings_id == -1)
    {
        warnf(" > Could not get shm segemnt for simple mmaps | errno: %d\n", errno);
        shutdown(false);
    }
    unsigned long* simple_mappings = (unsigned long*)shmat(simple_mappings_id, 0, 0);
    if (simple_mappings == MAP_FAILED)
    {
        warnf(" > Could not attach to shm segemnt %d for simple mmaps | errno: %d\n",
                simple_mappings_id, errno);
        shutdown(false);
    }
    set_mmap_table->reset_simple_mappings(simple_mappings);
    if (shmctl(simple_mappings_id, IPC_RMID, NULL))
    {
        warnf(" > Could not set IPC_RMID on shm segemnt %d for simple mmaps | errno: %d\n",
                simple_mappings_id, errno);
        shutdown(false);
    }

    translation_id = shmget(IPC_PRIVATE, PMVEE_COPY_DEFAULT_SIZE, IPC_CREAT | S_IRUSR | S_IWUSR);
    if (translation_id == -1)
    {
        warnf(" > Could not get shm segemnt for simple mmaps | errno: %d\n", errno);
        shutdown(false);
    }
    pmvee_translations = (struct pmvee_translation_unit_t *)shmat(translation_id, 0, 0);
    if (pmvee_translations == (void*)-1)
    {
        warnf(" > Could not attach to shm segemnt %d for simple mmaps | errno: %d\n",
                translation_id, errno);
        shutdown(false);
    }
    if (parent)
        memcpy(pmvee_translations, parent->pmvee_translations, (sizeof(struct pmvee_translation_unit_t) + (parent->pmvee_translations->mapping_count * sizeof(pmvee_mappings_info_t) * mvee::numvariants)));
    else
    {
        *pmvee_translations =
        {
            { 0 },
            0,
            0,
            0
        };
    }
    if (shmctl(translation_id, IPC_RMID, NULL))
    {
        warnf(" > Could not set IPC_RMID on shm segemnt %d for simple mmaps | errno: %d\n",
                translation_id, errno);
        shutdown(false);
    };

    pmvee_translations->jumps_id = shmget(IPC_PRIVATE, PMVEE_COPY_DEFAULT_SIZE, IPC_CREAT | S_IRUSR | S_IWUSR);
    if (pmvee_translations->jumps_id == -1)
    {
        warnf(" > Could not get shm segemnt for simple mmaps | errno: %d\n", errno);
        shutdown(false);
    }
    pmvee_jump_addresses = (unsigned long *)shmat(pmvee_translations->jumps_id, 0, 0);
    if (pmvee_jump_addresses == (void*)-1)
    {
        warnf(" > Could not attach to shm segemnt %d for simple mmaps | errno: %d\n",
                pmvee_translations->jumps_id, errno);
        shutdown(false);
    }
    if (parent)
        memcpy(pmvee_jump_addresses, parent->pmvee_jump_addresses, (sizeof(size_t) + (sizeof(void*)*parent->pmvee_jump_addresses[0])));
    if (shmctl(pmvee_translations->jumps_id, IPC_RMID, NULL))
    {
        warnf(" > Could not set IPC_RMID on shm segemnt %d for simple mmaps | errno: %d\n",
                pmvee_translations->jumps_id, errno);
        shutdown(false);
    };

    for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
    {
        variants[variant_i].pmvee_communication_id = shmget(IPC_PRIVATE, PMVEE_COMMUNICATION_SIZE, IPC_CREAT | S_IRUSR | S_IWUSR);
        if (variants[variant_i].pmvee_communication_id == -1)
        {
            warnf(" > Variant %d could not get shm segemnt | errno: %d\n", variant_i, errno);
            shutdown(false);
        }
        variants[variant_i].pmvee_communication_mon_pt = shmat(variants[variant_i].pmvee_communication_id, 0, 0);
        if (variants[variant_i].pmvee_communication_mon_pt == MAP_FAILED)
        {
            warnf(" > Variant %d could not attach to shm segemnt %d | errno: %d\n",
                    variant_i, variants[variant_i].pmvee_communication_id, errno);
            shutdown(false);
        }
        if (shmctl(variants[variant_i].pmvee_communication_id, IPC_RMID, NULL))
        {
            warnf(" > Variant %d could not set IPC_RMID on shm segemnt %d | errno: %d\n",
                    variant_i, variants[variant_i].pmvee_communication_id, errno);
            shutdown(false);
        }
        pmvee_translations->communication_ids[variant_i] = variants[variant_i].pmvee_communication_id;


        variants[variant_i].pmvee_migration_id = shmget(IPC_PRIVATE, mvee::pmvee_migration_size + mvee::pmvee_pointer_size + 1, IPC_CREAT | S_IRUSR | S_IWUSR);
        if (variants[variant_i].pmvee_migration_id == -1)
        {
            warnf(" > Variant %d could not get shm segemnt | errno: %d\n", variant_i, errno);
            shutdown(false);
        }
        void* pmvee_migration_pt = shmat(variants[variant_i].pmvee_migration_id, 0, 0);
        if (pmvee_migration_pt == MAP_FAILED)
        {
            warnf(" > Variant %d could not attach to shm segemnt %d | errno: %d\n",
                    variant_i, variants[variant_i].pmvee_migration_id, errno);
            shutdown(false);
        }
        if (shmctl(variants[variant_i].pmvee_migration_id, IPC_RMID, NULL))
        {
            warnf(" > Variant %d could not set IPC_RMID on shm segemnt %d | errno: %d\n",
                    variant_i, variants[variant_i].pmvee_migration_id, errno);
            shutdown(false);
        }

        if (variants[variant_i].pmvee_migration_mon_pt)
        {
            memcpy(pmvee_migration_pt, variants[variant_i].pmvee_migration_mon_pt, (2*sizeof(unsigned long)) + (mvee::pmvee_migration_count*(2*sizeof(unsigned long)))+(mvee::pmvee_pointer_count*(sizeof(unsigned long))));
        }
        else
        {
            ((unsigned long*)pmvee_migration_pt)[0] = 0;
            ((unsigned long*)pmvee_migration_pt)[1] = 0;
        }
        variants[variant_i].pmvee_migration_mon_pt = pmvee_migration_pt;
        // print_migration_targets((char*)variants[variant_i].pmvee_migration_mon_pt);
    }
}



void monitor::call_jump_to_equivalent_function_addresses ()
{
    interaction::read_all_regs(variants[0].variantpid, &variants[0].regs);

    unsigned long *jumps_a = &(pmvee_jump_addresses[1]);
    for (unsigned long jump_i = 0; jump_i < pmvee_jump_addresses[0]; jump_i+=mvee::numvariants)
    {
        unsigned long *jump = &(jumps_a[jump_i]);
        if (jump[0] == variants[0].regs.rip)
        {
            for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
            {
                interaction::write_specific_reg(variants[variant_i].variantpid, RSP * 8, variants[variant_i].rollback_rsp);
                interaction::write_specific_reg(variants[variant_i].variantpid, RIP * 8, jump[variant_i]);
            }
            return;
        }
    }
    shutdown(false);
    log_variant_backtrace(0);
    
    std::string caller = set_mmap_table->get_caller_info(0, variants[0].variantpid, variants[0].regs.rip, 0);
    if (caller.find("couldn't find code address: ") != std::string::npos || 
            caller.find("couldn't get") != std::string::npos)
    {
        warnf("problem determining symbol at rip %p | result: %s\n", (void*)variants[0].regs.rip, caller.c_str());
        shutdown(true);
        return;
    }
    
    size_t symbol_substring_start = caller.find(": ") + 2;
    size_t symbol_substring_end = caller.find(" at ");
    std::string symbol = caller.substr(symbol_substring_start, symbol_substring_end - symbol_substring_start);
    size_t lib_substring_start = caller.find_last_of("(") + 1;
    size_t lib_substring_end = caller.find_last_of(")");
    std::string lib = caller.substr(lib_substring_start, lib_substring_end - lib_substring_start);

    for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
    {
        interaction::write_specific_reg(variants[variant_i].variantpid, RSP * 8, variants[variant_i].rollback_rsp);
        std::string alias = mvee::get_alias(variant_i, lib);
        unsigned long address = set_mmap_table->resolve_symbol(variant_i, symbol.c_str(), (alias != "" ? alias : lib).c_str());
        // unsigned long offset = address;
        // address += set_mmap_table->find_image_base(variant_i, (alias != "" ? alias : lib).c_str());
        interaction::write_specific_reg(variants[variant_i].variantpid, RIP * 8, address);
    }
}


void monitor::insert_migration_targets(fd_info* info, std::vector<unsigned long> base_addresses, size_t size)
{
    for (mvee::pmvee_migration_t migration: mvee::migrations)
    {
        if (migration.file_name == info->paths[0])
        {
            unsigned long mmap_base = base_addresses[0] - info->mmapped_bases[0];
            auto injected_migrations = std::vector<mvee::pmvee_migration_info_t>();
            for (mvee::pmvee_migration_info_t migration_info: migration.migration)
            {
                if (migration_info.offset >= mmap_base && migration_info.offset < (mmap_base + size))
                    injected_migrations.push_back( { migration_info.offset, migration_info.size } );
            }
            auto injected_pointers = std::vector<unsigned long>();
            for (unsigned long pointer_info: migration.pointers)
            {
                if (pointer_info >= mmap_base && pointer_info < (mmap_base + size))
                    injected_pointers.push_back(pointer_info);
            }

            for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
            {
                unsigned long* current_migration_count = (unsigned long*)variants[variant_i].pmvee_migration_mon_pt;
                unsigned long* current_pointer_count = &((unsigned long*)variants[variant_i].pmvee_migration_mon_pt)[1];
                auto variant_migration_infos = (mvee::pmvee_migration_info_t*)
                        (((char*)variants[variant_i].pmvee_migration_mon_pt) + 2*sizeof(unsigned long));
                auto variant_pointer_infos = (unsigned long*) (
                        ((char*)variants[variant_i].pmvee_migration_mon_pt) +
                        (2*sizeof(unsigned long)) + ((*current_migration_count) * sizeof(mvee::pmvee_migration_info_t)));
                if (injected_migrations.size())
                {
                    memmove(
                        ((char*) variant_pointer_infos) + (sizeof(mvee::pmvee_migration_info_t)*(injected_migrations.size())),
                        variant_pointer_infos,
                        (*current_pointer_count) * sizeof(unsigned long)
                    );
                    variant_pointer_infos = (unsigned long*)(((char*) variant_pointer_infos) + (sizeof(mvee::pmvee_migration_info_t)*(injected_migrations.size())));

                    for (mvee::pmvee_migration_info_t migration_i: injected_migrations)
                        variant_migration_infos[(*current_migration_count)++] = { info->mmapped_bases[variant_i] + migration_i.offset, migration_i.size };
                }
                for (unsigned long pointer_i: injected_pointers)
                    variant_pointer_infos[(*current_pointer_count)++] = info->mmapped_bases[variant_i] + pointer_i;
                // print_migration_targets((char*)variants[variant_i].pmvee_migration_mon_pt);
            }

            break;
        }
    }
}


void monitor::remove_migration_targets(int variantnum, unsigned long base_address, size_t size)
{
    unsigned long* current_migration_count = (unsigned long*)variants[variantnum].pmvee_migration_mon_pt;
    unsigned long* current_pointer_count = &((unsigned long*)variants[variantnum].pmvee_migration_mon_pt)[1];
    auto variant_migration_infos = (mvee::pmvee_migration_info_t*) 
        ( ( (char*)variants[variantnum].pmvee_migration_mon_pt ) + ( 2*sizeof(unsigned long) ) );

    for (unsigned long migration_i = 0; migration_i < *current_migration_count; migration_i++)
    {
        if (variant_migration_infos[migration_i].offset >= base_address && 
                variant_migration_infos[migration_i].offset < (base_address + size))
        {
            memmove(
                    &variant_migration_infos[migration_i],
                    &variant_migration_infos[migration_i + 1],
                    sizeof(unsigned long)*(((*current_migration_count)*2) + ((*current_pointer_count)) - (2*(migration_i + 1)))
            );
            (*current_migration_count)--;
        }
    }

    auto variant_pointer_infos = (unsigned long*) (
            ((char*)variants[variantnum].pmvee_migration_mon_pt) +
            (2*sizeof(unsigned long)) + ((*current_migration_count) * sizeof(mvee::pmvee_migration_info_t)));

    for (unsigned long pointer_i = 0; pointer_i < *current_migration_count; pointer_i++)
    {
        if (variant_pointer_infos[pointer_i] >= base_address && 
                variant_pointer_infos[pointer_i] < (base_address + size))
        {
            memmove(
                    &(variant_pointer_infos[pointer_i]),
                    &(variant_pointer_infos[pointer_i + 1]),
                    sizeof(unsigned long) * ((*current_pointer_count) - (pointer_i + 1))
            );
            (*current_pointer_count)--;
        }
    }
    // print_migration_targets((char*)variants[variantnum].pmvee_migration_mon_pt);
}


void monitor::insert_jump_targets(fd_info* info, std::vector<unsigned long> base_addresses, std::vector<unsigned long> offsets)
{
    // warnf(" > inserting targets for %s\n", info->paths[0].c_str());
    for (mvee::pmvee_mapping_t mapping: mvee::mappings)
    {
        // warnf(" > %s == %s?\n", mapping.leader_file.c_str(), info->paths[0].c_str());
        if (mapping.leader_file == info->paths[0])
        {
            std::vector<unsigned long> jumps = std::vector<unsigned long>();
            for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
                jumps.push_back(base_addresses[variant_i] + (variant_i ? mapping.follower_offset : mapping.leader_offset) - offsets[variant_i]);
            debugf(" > %p -> %p\n", (void*)jumps[0], (void*)jumps[1]);
            if (mapping.type == 0)
            {
                for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
                {
                    (&(pmvee_jump_addresses[1]))[pmvee_jump_addresses[0]] = jumps[variant_i];
                    debugf(" > [%ld] = %ld\n", pmvee_jump_addresses[0], (&(pmvee_jump_addresses[1]))[pmvee_jump_addresses[0]]);
                    pmvee_jump_addresses[0]++;
                }
                debugf("added jump\n");
            }
            else if (mapping.type == 1)
            {
                pmvee_state_copies.push_back(jumps);
                debugf("added copy: %p -> %p\n", (void*)jumps[0], (void*)jumps[1]);
            }
            else if (mapping.type == 2)
            {
                pmvee_state_migrations.push_back(jumps);
                debugf("added migration: %p -> %p\n", (void*)jumps[0], (void*)jumps[1]);
            }
            else
                debugf("type: %d\n", mapping.type);
        }
    }
}


#define FILL_HEX_CHARS(__data, __start, __end, __hex_string, __length)                                            \
{                                                                                                                 \
    unsigned long diff_i = 0;                                                                                     \
    for (;diff_i < __length && __start + diff_i < __end; diff_i++)                                                \
    {                                                                                                             \
        __hex_string[(diff_i*2)]     = (__data[__start + diff_i] >> 4) & 0xf;                                     \
        __hex_string[(diff_i*2)]     += __hex_string[(diff_i*2)]     > 0x9 ? 'a' - 0xa : '0';                     \
        __hex_string[(diff_i*2) + 1] =  __data[__start + diff_i]       & 0xf;                                     \
        __hex_string[(diff_i*2) + 1] += __hex_string[(diff_i*2) + 1] > 0x9 ? 'a' - 0xa : '0';                     \
    }                                                                                                             \
    for (;diff_i < __length; diff_i++)                                                                            \
    {                                                                                                             \
        __hex_string[(diff_i*2)]     = '_';                                                                       \
        __hex_string[(diff_i*2) + 1] = '_';                                                                       \
    }                                                                                                             \
}


#ifdef MVEE_CONNECTED_MMAP_REGIONS
void mmap_table::diff_memory(int leader_pid, int follower, int follower_pid, int initial, int include_exec)
{
    warnf("Memory diffing disable for now.\n");
    return;
    if (mvee::numvariants <= 1)
        return;

#ifndef MVEE_BENCHMARK
    void (*outputf) (const char* format, ...) = &mvee::logf;
#else
    return;
    void (*outputf) (const char* format, ...) = &mvee::warnf;
#endif

    outputf("memory diff>>===============start===============\n");
    if (initial)
        outputf("memory diff>>initial state\n");
    outputf("memory diff>>mp: [ %p ; %p )\n", (void*)mp_start, (void*)mp_end);
    for (auto it = full_map[0].begin();it != full_map[0].end(); ++it)
    {
        mmap_region_info* region = *it;
        unsigned long base_i;
        
        mmap_region_info* follower_region;
        if (region->connected_regions)
        {
            follower_region = region->connected_regions->regions[follower];
        }
        else
        {
            follower_region = get_region_info(follower, region->region_base_address, 1);
            if (!follower_region || follower_region->region_base_address != region->region_base_address)
            {
                outputf("memory diff>>no connected or equivalent region at address [ %p ; %p )\n",
                        (void*)region->region_base_address, (void*)(region->region_base_address + region->region_size));
                continue;
            }
        }
        if (region->region_prot_flags & PROT_EXEC)
            continue;

        char* leader_data = (char*)malloc(region->region_size);
        if (!interaction::read_memory(leader_pid, (void*)region->region_base_address, region->region_size, leader_data))
        {
            outputf("memory diff>>issue reading from leader mapping [ %p ; %p )\n",
                    (void*)region->region_base_address, (void*)(region->region_base_address + region->region_size));
            continue;
        }

        char* follower_data = (char*)malloc(follower_region->region_size);
        if (!interaction::read_memory(follower_pid, (void*)follower_region->region_base_address,
                follower_region->region_size, follower_data))
        {
            outputf("memory diff>>issue reading from follower mapping [ %p ; %p )\n",
                    (void*)follower_region->region_base_address,
                    (void*)(follower_region->region_base_address + follower_region->region_size));
            continue;
        }

        size_t max_region_size = region->region_size < follower_region->region_size ? 
                region->region_size :
                follower_region->region_size;
        outputf("memory diff>>DIFFING>>%s vs %s\n", region->region_backing_file_path.c_str(), follower_region->region_backing_file_path.c_str());
        outputf("memory diff>>REGION>>[ %p ; %p ) vs [ %p ; %p ) \n",
                (void*)region->region_base_address, (void*)(region->region_base_address + region->region_size),
                (void*)follower_region->region_base_address, (void*)(follower_region->region_base_address + follower_region->region_size));
        char leader_first_part[9]    = { 0 };
        char leader_second_part[9]   = { 0 };
        char follower_first_part[9]  = { 0 };
        char follower_second_part[9] = { 0 };

        for (base_i = 0; base_i < (max_region_size / 8); base_i++)
        {
            if (base_i >= (region->region_size / 8) || base_i >= (follower_region->region_size / 8))
                break;
            if (((unsigned long*)leader_data)[base_i] == ((unsigned long*)follower_data)[base_i])
                continue;

            unsigned int diff_base_i = 8 * base_i;
            FILL_HEX_CHARS(leader_data, diff_base_i, region->region_size, leader_first_part, 4);
            FILL_HEX_CHARS(leader_data, diff_base_i + 4, region->region_size, leader_second_part, 4);
            outputf("memory diff>>leader   %x: %s %s\n", diff_base_i, leader_first_part, leader_second_part);

            FILL_HEX_CHARS(follower_data, diff_base_i, follower_region->region_size, follower_first_part, 4);
            FILL_HEX_CHARS(follower_data, diff_base_i + 4, follower_region->region_size, follower_second_part, 4);

            for (unsigned long diff_i = 0;diff_i < 8; diff_i++)
            {
                leader_first_part[diff_i]  = (follower_first_part[diff_i]   == leader_first_part[diff_i]  ) ? ' ' : 'X';
                leader_second_part[diff_i] = (follower_second_part[diff_i]  == leader_second_part[diff_i] ) ? ' ' : 'X';
            }

            outputf("memory diff>>         %x: %s %s\n", diff_base_i, leader_first_part, leader_second_part);
            outputf("memory diff>>follower %x: %s %s\n", diff_base_i, follower_first_part, follower_second_part);
        }
        if ((base_i * 8) < region->region_size)
        {
            outputf("memory diff>>leader area longer than follower\n");
        }
        if ((base_i * 8) < follower_region->region_size)
        {
            outputf("memory diff>>follower area longer than follower\n");
        }

        outputf("memory diff>>pointer diff\n");
        
        for (base_i = 0; base_i < (max_region_size / 8); base_i++)
        {
            if (base_i >= (region->region_size / 8) || base_i >= (follower_region->region_size / 8))
                break;
            if (((unsigned long*)leader_data)[base_i] == ((unsigned long*)follower_data)[base_i])
                continue;

            for (unsigned long diff_i = (base_i * 8); diff_i <= base_i * 8; diff_i++)
            {
                unsigned long leader_pt = *(unsigned long*)(leader_data + diff_i);
                unsigned long follower_pt = *(unsigned long*)(follower_data + diff_i);
                if (leader_pt != follower_pt)
                {
                    mmap_region_info* leader_pt_region = get_region_info(0, leader_pt, 1);
                    if (!leader_pt_region)
                        continue;

                    int equivalent_region = 1;
                    mmap_region_info* follower_pt_region;
                    if (leader_pt_region->connected_regions)
                        follower_pt_region = leader_pt_region->connected_regions->regions[follower];
                    if (!follower_pt_region || follower_pt < follower_pt_region->region_base_address ||
                            follower_pt >= follower_pt_region->region_base_address + follower_pt_region->region_size)
                    {
                        equivalent_region = 0;
                        follower_pt_region = get_region_info(follower, follower_pt, 1);
                    }


                    outputf("memory diff>>diverging pointers @0x%lx: %lx != %lx in %s mappings\n",
                            diff_i, leader_pt, follower_pt, equivalent_region ? "equivalent" : "different");
                    outputf("memory diff>>leader pointer: 0x%lx in %s@0x%x\n",
                            leader_pt - leader_pt_region->region_base_address,
                            leader_pt_region->region_backing_file_path.c_str(), 
                            leader_pt_region->region_backing_file_offset);
                    outputf("memory diff>>variant %d pointer: 0x%lx in %s@0x%x\n",
                            follower,
                            follower_pt_region ? follower_pt - follower_pt_region->region_base_address : 0,
                            follower_pt_region ? follower_pt_region->region_backing_file_path.c_str() : "unknown", 
                            follower_pt_region ? follower_pt_region->region_backing_file_offset : 0);
                    diff_i+=8;
                }
            }
        }
        if ((base_i * 8) < region->region_size)
        {
            outputf("memory diff>>leader area longer than follower\n");
        }
        if ((base_i * 8) < follower_region->region_size)
        {
            outputf("memory diff>>follower area longer than follower\n");
        }

        free(leader_data);
        free(follower_data);
    }
    outputf("memory diff>>===============end===============\n");
}
#endif


std::vector<mvee::pmvee_mapping_t> mvee::mappings = std::vector<pmvee_mapping_t>();
void mvee::init_pmvee_mappings(const char* file)
{
    int fd = open(file, O_RDONLY);
    if (fd == -1)
    {
        warnf(" > could not open file %s | errno: %d\n", file, errno);
    }

    struct stat file_stats;
    if (fstat(fd, &file_stats))
    {
        warnf(" > could not stat file %s | errno: %d\n", file, errno);
    }

    char* buffer = (char*)malloc(file_stats.st_size);
    if (read(fd, buffer, file_stats.st_size) != file_stats.st_size)
    {
        free(buffer);
        warnf(" > could not read file %s contents | errno %d\n", file, errno);
    }
    close(fd);

    char* index_pt = buffer;
    char* start_pt;
    std::string name;
    unsigned long leader_offset;
    std::string leader_file;
    unsigned long follower_offset;
    std::string follower_file;
    int type;
    #define FIND_NEXT do {index_pt++;} while (index_pt - buffer < file_stats.st_size && *index_pt != ';' && *index_pt != '\n' && *index_pt != 0); if (index_pt - buffer >= file_stats.st_size) break;
    while (index_pt)
    {
        type = 0;
        if (*index_pt == 'c')
            type = 1;
        if (*index_pt == 'm')
            type = 2;

        FIND_NEXT
        index_pt++;

        start_pt = index_pt;
        FIND_NEXT
        name = std::string(start_pt, index_pt - start_pt);
        index_pt++;

        leader_offset = 0;
        while (*index_pt != ';')
        {
            leader_offset *= 10;
            leader_offset += *index_pt - '0';
            index_pt++;
        }
        index_pt++;

        start_pt = index_pt;
        FIND_NEXT
        leader_file = std::string(start_pt, index_pt - start_pt);
        index_pt++;

        follower_offset = 0;
        while (*index_pt != ';')
        {
            follower_offset *= 10;
            follower_offset += *index_pt - '0';
            index_pt++;
        }
        index_pt++;

        start_pt = index_pt;
        FIND_NEXT
        follower_file = std::string(start_pt, index_pt - start_pt);
        index_pt++;

        mappings.push_back({
            std::string(name),
            leader_offset,
            std::string(leader_file),
            follower_offset,
            std::string(follower_file),
            type
        });
    }
    
    free(buffer);
}



std::vector<mvee::pmvee_migration_t> mvee::migrations = std::vector<pmvee_migration_t>();
unsigned long mvee::pmvee_migration_count = 0;
unsigned long mvee::pmvee_pointer_count = 0;
unsigned long mvee::pmvee_migration_size = 0;
unsigned long mvee::pmvee_pointer_size = 0;
void mvee::init_pmvee_migrations(const char* file)
{
    warnf(" > setting up pmvee migrations from %s\n", file);
    int fd = open(file, O_RDONLY);
    if (fd == -1)
    {
        warnf(" > could not open file %s | errno: %d\n", file, errno);
        return;
    }

    struct stat file_stats;
    if (fstat(fd, &file_stats))
    {
        warnf(" > could not stat file %s | errno: %d\n", file, errno);
        return;
    }

    char* buffer = (char*)malloc(file_stats.st_size);
    if (read(fd, buffer, file_stats.st_size) != file_stats.st_size)
    {
        free(buffer);
        warnf(" > could not read file %s contents | errno %d\n", file, errno);
        return;
    }
    close(fd);

    int index = 0;
    while (index < file_stats.st_size)
    {
        std::vector<struct pmvee_migration_info_t> migration = std::vector<struct pmvee_migration_info_t>();
        std::vector<unsigned long> pointers = std::vector<unsigned long>();

        char* name_index = buffer + index;
        while (index < file_stats.st_size && buffer[index] != '\0')
            index++;
        char* name_index_end = buffer + index;
        index++;
        unsigned long sub_migration_count = *(unsigned long*)(buffer + index);
        mvee::pmvee_migration_count+=sub_migration_count;
        index += 8;
        unsigned long* migration_index = (unsigned long*)(buffer + index);
        for (unsigned long migration_i = 0; migration_i < (sub_migration_count*2); migration_i+=2)
        {
            migration.push_back({ migration_index[migration_i], migration_index[migration_i + 1] });
            mvee::pmvee_migration_size+=migration_index[migration_i + 1];
        }
        index+=(sub_migration_count*2*8);
        unsigned long sub_pointer_count = *(unsigned long*)(buffer + index);
        mvee::pmvee_pointer_count+=sub_pointer_count;
        index += 8;
        unsigned long* pointer_index = (unsigned long*)(buffer + index);
        for (unsigned long pointer_i = 0; pointer_i < sub_pointer_count; pointer_i++)
        {
            pointers.push_back(pointer_index[pointer_i]);
            mvee::pmvee_pointer_size+=8;
        }
        index+=(sub_pointer_count*8);
        mvee::migrations.push_back( { std::string(name_index, name_index_end - name_index), migration, pointers } );
    }
    
    free(buffer);
}


connected_region_info::connected_region_info()
{
    regions = std::vector<mmap_region_info*>(mvee::numvariants, 0);
    split_regions = std::vector<connected_region_info*>(0);
    split = 0;
    new_region = nullptr;
}

connected_region_info::connected_region_info(connected_region_info* source)
{
    regions = std::vector<mmap_region_info*>(source->regions);
    split_regions = std::vector<connected_region_info*>(0);
    split = 0;
    new_region = nullptr;
}

connected_region_info::~connected_region_info()
{
    exit(-1);
}


#if 1
unsigned long monitor::pmvee_translate_at_index(int numvariants, unsigned long** addresses, unsigned long index)
{
    unsigned long address = addresses[0][index];

    unsigned long *jumps_a = &(pmvee_jump_addresses[1]);
    unsigned long jump_i;
    for (jump_i = 0; jump_i < pmvee_jump_addresses[0]; jump_i+=numvariants)
    {
        unsigned long *jump = &(jumps_a[jump_i]);
        if (jump[0] == address)
        {
            for (int variant_i = 1; variant_i < numvariants; variant_i++)
                addresses[variant_i][index] = jump[variant_i];
            return 0;
        }
    }

    struct pmvee_mappings_info_t *pmvee_translation_table = 
            (struct pmvee_mappings_info_t*)((char*)pmvee_translations + sizeof(struct pmvee_translation_unit_t));
    for (unsigned long transtatlion_i = 0; transtatlion_i < (pmvee_translations->mapping_count * numvariants); transtatlion_i+=numvariants)
    {
        if (address >= (unsigned long)pmvee_translation_table[transtatlion_i].start &&
                address < (unsigned long)pmvee_translation_table[transtatlion_i].end)
        {
            for (int variant_i = 1; variant_i < numvariants; variant_i++)
                addresses[variant_i][index] = (unsigned long)pmvee_translation_table[transtatlion_i + variant_i].start + (addresses[0][index] - (unsigned long)pmvee_translation_table[transtatlion_i].start);
            return 0;
        }
    }

    for (int variant_i = 1; variant_i < numvariants; variant_i++)    
        addresses[variant_i][index] = addresses[0][index];
    return 1;
}

void monitor::copy_migration_ipmon()
{
    unsigned long pmvee_pointer_start = pmvee_state_copy_zone.state_alter_start - pmvee_zone_pt;
    unsigned long pmvee_migration_end = pmvee_state_copy_zone.state_copy_end - pmvee_zone_pt;

    
    struct pmvee_mappings_info_t *pmvee_translation_table = 
            (struct pmvee_mappings_info_t*)((char*)pmvee_translations + sizeof(struct pmvee_translation_unit_t));
    for (unsigned long transtatlion_i = 0; transtatlion_i < (pmvee_translations->mapping_count * mvee::numvariants); transtatlion_i+=mvee::numvariants)
    {
        mmap_region_info* region_info = set_mmap_table->get_region_info(0, (unsigned long)pmvee_translation_table[transtatlion_i].start);
        if (!region_info) { warnf(" > what?? no region??\n"); continue; }
        else if (!region_info->connected_regions) { warnf(" > what?? no connected region??\n"); shutdown(false); }
        else if (region_info->connected_regions->regions[1]->region_base_address != (unsigned long)pmvee_translation_table[transtatlion_i + 1].start) { warnf(" > what?? region mismatch??\n"); shutdown(false); }
    }

    unsigned long* pointer_migrations[2];
    for (int variant_i = 0; variant_i < mvee::numvariants; variant_i++)
        pointer_migrations[variant_i] = (unsigned long*)(((char*)variants[variant_i].pmvee_communication_mon_pt) + pmvee_pointer_start);

    for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
        memcpy(variants[variant_i].pmvee_communication_mon_pt, variants[0].pmvee_communication_mon_pt, pmvee_pointer_start);

    unsigned long address_i;
    for (address_i = 0; address_i < ((pmvee_migration_end - pmvee_pointer_start) / sizeof(void*)); address_i++)
    {
        if (pmvee_translate_at_index(mvee::numvariants, pointer_migrations, address_i))
        {
            if (pointer_migrations[0][address_i] == PMVEE_SCANNINGG_START)
            {
                address_i++;
                while (pointer_migrations[0][address_i])
                {
                    for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
                    {
                        pointer_migrations[variant_i][address_i] = pointer_migrations[0][address_i];
                        address_i++;
                        pmvee_translate_at_index(mvee::numvariants, pointer_migrations, address_i);
                        address_i++;
                    }
                }
                for (int variant_i = 1; variant_i < mvee::numvariants; variant_i++)
                {
                    pointer_migrations[variant_i][address_i] = pointer_migrations[0][address_i];
                }
                continue;
            }
        }
    }
}
#endif