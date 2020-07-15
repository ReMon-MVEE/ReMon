/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*
 * NOTES:
 * 1) We try to mimic the kernel's mman bookkeeping, i.e., our bookkeeping
 * should match what we read from /proc/<pid>/maps. At this time though, it's
 * not entirely clear to me what the rules for merging regions are...
 * Anonymous regions are particularly cumbersome. We tend to merge adjacent
 * anonymous regions (provided that they have the same protection flags and so
 * on). The kernel does not seem to merge them every time..
 * Either way, the way MVEE_mman currently works is sufficient for our purposes.
 * We can deduct the properties for every byte of mapped memory from our book-
 * keeping. In the future we might have to reproduce /proc/<pid>/maps even
 * more accurately.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <unistd.h>
#include <sys/mman.h>
#include <sstream>
#include <random>
#include "MVEE.h"
#include "MVEE_filedesc.h"
#include "MVEE_logging.h"
#include "MVEE_mman.h"
#include "MVEE_private_arch.h"
#include "MVEE_macros.h"

/*-----------------------------------------------------------------------------
    mmap_region_info class
-----------------------------------------------------------------------------*/
mmap_region_info::mmap_region_info
(
    int           variantnum,
    unsigned long address,
    unsigned long size,
    unsigned int  prot_flags,
    fd_info*      backing_file,
    unsigned int  backing_file_offset,
    unsigned int  map_flags
)
    : region_base_address(address),
    region_size(size),
    region_prot_flags(prot_flags),
    region_backing_file_offset(backing_file_offset),
    region_backing_file_unsynced(false),
    region_is_so(false),
    shadow(nullptr)
{
    region_map_flags = map_flags & ~(MAP_FIXED);

    if (backing_file)
    {
        region_backing_file_fd    = backing_file->fds[variantnum];
        region_backing_file_path  = backing_file->paths[variantnum];
        if (backing_file->paths[variantnum].rfind(".so") == backing_file->paths[variantnum].size() - 3)
            region_is_so = true;
        region_backing_file_flags = backing_file->access_flags;
        region_backing_file_size  = backing_file->original_file_size;
		region_backing_file_unsynced = backing_file->unsynced_access;
    }
    else
    {
        region_backing_file_fd    = MVEE_ANONYMOUS_FD;
        region_backing_file_path  = "[anonymous]";
        region_backing_file_flags = 0;
        region_backing_file_size  = 0;
    }

#ifdef MVEE_MMAN_DEBUG
    debugf("mvee_mman_create_region_info(%d, " PTRSTR "-" PTRSTR ", %d (%s))\n",
               variantnum, address, region_size+address,
               region_backing_file_fd,
               region_backing_file_path.c_str());
#endif
}

/*-----------------------------------------------------------------------------
    mmap_region_info::get_addr2line_proc - get the current addr2line proc
    associated with this region or create it if needed

    MUST RETURN A VALID REGION!!!!
-----------------------------------------------------------------------------*/
mmap_addr2line_proc* mmap_region_info::get_addr2line_proc(int variantnum, pid_t variantpid)
{
    if (region_addr2line_proc)
        return region_addr2line_proc.get();

    MutexLock lock(&mvee::global_lock);
    region_addr2line_proc = mvee::get_addr2line_proc(region_backing_file_path);

    if (!region_addr2line_proc)
    {
        region_addr2line_proc = std::shared_ptr<mmap_addr2line_proc>(
            new mmap_addr2line_proc(region_backing_file_path, variantnum, variantpid, region_base_address, region_size));
        mvee::addr2line_cache.insert(std::pair<std::string, std::weak_ptr<mmap_addr2line_proc> >(
                                         region_backing_file_path, region_addr2line_proc));
    }

    return region_addr2line_proc.get();
}

/*-----------------------------------------------------------------------------
    mmap_region_info::get_dwarf_info
-----------------------------------------------------------------------------*/
dwarf_info* mmap_region_info::get_dwarf_info(int variantnum, pid_t variantpid)
{
    if (region_dwarf_info)
        return region_dwarf_info.get();

    MutexLock lock(&mvee::global_lock);
    region_dwarf_info = mvee::get_dwarf_info(region_backing_file_path);

    if (!region_dwarf_info)
    {
        region_dwarf_info = std::shared_ptr<dwarf_info>(new dwarf_info(region_backing_file_path, variantnum, variantpid, this));
		mvee::dwarf_cache.insert(std::pair<std::string, std::weak_ptr<dwarf_info> >(region_backing_file_path, region_dwarf_info));
    }

    return region_dwarf_info.get();
}

/*-----------------------------------------------------------------------------
    print_region_info
-----------------------------------------------------------------------------*/
void mmap_region_info::print_region_info(const char* log_prefix, void (*logfunc)(const char* format, ...))
{
    if (!logfunc)
        logfunc = mvee::logf;

    std::stringstream stream;
    if (shadow)
        stream << " - [ " << std::hex << shadow->shadow_base << " ; " << std::hex <<
                ((unsigned long long) shadow->shadow_base + shadow->size) << " )";
    else
        stream.str("");
    logfunc("%s - " PTRSTR "-" PTRSTR " - %s - %s - %s - %d bytes%s\n",
            log_prefix,
            region_base_address, region_base_address + region_size,
            region_backing_file_path.c_str(),
            getTextualProtectionFlags(region_prot_flags).c_str(),
            getTextualMapType(region_map_flags).c_str(),
            region_backing_file_size,
            stream.str().c_str());
}

/*-----------------------------------------------------------------------------
    mmap_table class
-----------------------------------------------------------------------------*/
void mmap_table::init()
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&mmap_lock, &attr);
}

mmap_table::mmap_table()
    : mmap_execve_id(0),
	  have_diversified_variants(false),
#ifdef MVEE_FILTER_LOGGING
	  set_logging_enabled(false),
#else
	  set_logging_enabled(true),
#endif
	  thread_group_shutting_down(false),
	  enlarged_initial_stacks(false),
	  mmap_base(0),
	  variant_mappings()
{
    init();
    full_map.resize(mvee::numvariants);
    cached_instrs.resize(mvee::numvariants);
	mmap_startup_info.resize(mvee::numvariants);

	// Pick a random 1/256th chunk of the address space as our mmap region.
	// Excluding the lowest and top ones...
	std::random_device rd;
	std::mt19937_64 mt(rd());
	std::uniform_int_distribution<> distr(1, 254);
	mmap_base = distr(mt) * (HIGHEST_USERMODE_ADDRESS >> 8);
//	warnf("mmap_base is 0x" PTRSTR "\n", mmap_base);

    for (int i = 0; i < mvee::numvariants; i++)
        variant_mappings.emplace_back();
#ifdef MVEE_MMAN_DEBUG
    print_mmap_table(mvee::logf);
#endif
}

mmap_table::mmap_table(const mmap_table& parent)
        : variant_mappings()
{
    init();

    mmap_execve_id             = parent.mmap_execve_id;
	mmap_startup_info          = parent.mmap_startup_info;
	have_diversified_variants  = parent.have_diversified_variants;
#ifdef MVEE_FILTER_LOGGING
    set_logging_enabled        = parent.set_logging_enabled;
#endif
    enlarged_initial_stacks    = parent.enlarged_initial_stacks;
    cached_instrs              = parent.cached_instrs;
    cached_syms                = parent.cached_syms;
	thread_group_shutting_down = false;
	mmap_base                  = parent.mmap_base;

    full_map.resize(mvee::numvariants);

    for (int i = 0; i < mvee::numvariants; i++)
        variant_mappings.emplace_back();

    for (int i = 0; i < mvee::numvariants; ++i)
    {
		// copy memory map
        for (auto it = parent.full_map[i].begin(); it != parent.full_map[i].end(); ++it)
        {
            auto new_region = new mmap_region_info(**it);
            full_map[i].insert(new_region);

            if ((*it)->shadow != nullptr)
                insert_variant_shared_region(i, new_region);
        }
    }
}

mmap_table::~mmap_table()
{
    truncate_table();
}

/*-----------------------------------------------------------------------------
    truncate_table
-----------------------------------------------------------------------------*/
void mmap_table::truncate_table()
{
//    warnf("truncating mmap table\n");

    enlarged_initial_stacks = 0;

    for (int i = 0; i < mvee::numvariants; ++i)
        truncate_table_variant(i);

    // clear resolved symbols
    cached_syms.clear();
}

/*-----------------------------------------------------------------------------
    truncate_table_variant
-----------------------------------------------------------------------------*/
void mmap_table::truncate_table_variant(int variantnum)
{
//    warnf("truncating table for variant: %d - full map has %d regions\n",
//      variantnum, full_map[variantnum].size());

    // clear resolved instructions
    cached_instrs[variantnum].clear();

    // clear resolved regions
    for (std::set<mmap_region_info*>::iterator it = full_map[variantnum].begin();
         it != full_map[variantnum].end();
         ++it)
    {
        //(*it)->print_region_info("deleting region", mvee::warnf);
        delete *it;
    }

    full_map[variantnum].clear();
}

/*-----------------------------------------------------------------------------
    grab_lock
-----------------------------------------------------------------------------*/
void mmap_table::grab_lock()
{
    pthread_mutex_lock(&mmap_lock);
}

/*-----------------------------------------------------------------------------
    release_lock
-----------------------------------------------------------------------------*/
void mmap_table::release_lock()
{
    pthread_mutex_unlock(&mmap_lock);
}

/*-----------------------------------------------------------------------------
    full_release_lock
-----------------------------------------------------------------------------*/
void mmap_table::full_release_lock()
{
    while (mmap_lock.__data.__owner == syscall(__NR_gettid))
        release_lock();
}

/*-----------------------------------------------------------------------------
    print_mmap_table
-----------------------------------------------------------------------------*/
void mmap_table::print_mmap_table(void (*logfunc)(const char* format, ...))
{
    if (!logfunc)
        logfunc = mvee::logf;
    logfunc("======================================== MMAN TABLE DUMP ========================================\n");
    grab_lock();
    logfunc("ORIGINAL MONITORID: %d\n", mmap_execve_id);

	for (int i = 0; i < mvee::numvariants; ++i)
	{
		logfunc("PROC %d: %s %s\n", i, 
				mmap_startup_info[i].image.c_str(), 
				mmap_startup_info[i].serialized_argv.c_str());
	}

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        for (std::set<mmap_region_info*, region_sort>::iterator it = full_map[i].begin();
             it != full_map[i].end(); ++it)
        {
            char prefix[100];
            sprintf(prefix, "variant %d ->", i);
            (*it)->print_region_info(prefix, logfunc);
        }
    }

    release_lock();
    logfunc("=================================================================================================\n");
}

/*-----------------------------------------------------------------------------
    get_region_info
-----------------------------------------------------------------------------*/
mmap_region_info* mmap_table::get_region_info (int variantnum, unsigned long address, unsigned long region_size)
{
    mmap_region_info                                   tmp_region(variantnum, address, region_size, 0, NULL, 0, 0);

    std::set<mmap_region_info*, region_sort>::iterator it =
        full_map[variantnum].find(&tmp_region);

    if (it != full_map[variantnum].end())
        return *it;

    return NULL;
}

/*-----------------------------------------------------------------------------
    merge_regions - attempts to merge region1 and region2. If these regions
    cannot be merged, the function will return NULL.

    If the regions CAN be merged, the function will delete region2 from the
    table and region1 will become the merged region.
-----------------------------------------------------------------------------*/
mmap_region_info* mmap_table::merge_regions(int variantnum, mmap_region_info* region1, mmap_region_info* region2, bool dont_touch_maps)
{
    if (region1 && region2 &&
        (region1->region_base_address + region1->region_size == region2->region_base_address
         || region2->region_base_address + region2->region_size == region1->region_base_address))
    {
        if (is_same_region(region1, region2))
        {
            std::set<mmap_region_info*>::iterator it;

            // additional check. If the regions are backed by a file, they can only be merged if
            // the regions are also consecutive in the backing file
            if ((int)region1->region_backing_file_fd > 0 || region1->region_backing_file_path[0] != '[')
            {
                if (region2->region_backing_file_offset
                    != region1->region_backing_file_offset + region1->region_size)
                    return NULL;
            }

            int                                   reinsert = 0;
            if (!dont_touch_maps)
            {
                it = full_map[variantnum].find(region1);

                if (it != full_map[variantnum].end())
                {
                    reinsert = 1;
                    full_map[variantnum].erase(it);
                }
            }

            unsigned long                         new_base = region1->region_base_address > region2->region_base_address ? region2->region_base_address : region1->region_base_address;
            unsigned long                         new_size = region1->region_base_address > region2->region_base_address ? region1->region_base_address + region1->region_size - region2->region_base_address : region2->region_base_address + region2->region_size - region1->region_base_address;

#ifdef MVEE_MMAN_DEBUG
            debugf("merging regions\n");
            region1->print_region_info(">>> region1: ");
            region2->print_region_info(">>> region2: ");
#endif

            region1->region_base_address = new_base;
            region1->region_size         = new_size;

#ifdef MVEE_MMAN_DEBUG
            region1->print_region_info(">>> merged region: ");
#endif

            // update shadow reference count
            if (region1->shadow && region2->shadow)
                merge_variant_shadow_region(variantnum, region1, region2);
            if (region1->connected && region2->connected)
                merge_regions(variantnum, region1->connected, region2->connected, dont_touch_maps);

            if (!dont_touch_maps)
            {
                it = full_map[variantnum].find(region2);
                if (it != full_map[variantnum].end())
                {
                    delete *it;
                    full_map[variantnum].erase(it);
                }

                if (reinsert)
                    full_map[variantnum].insert(region1);
            }


            return region1;
        }
    }

    return NULL;
}

/*-----------------------------------------------------------------------------
    split_region - returns the lower part of the split.
    existing_region becomes the upper part!!!
-----------------------------------------------------------------------------*/
mmap_region_info* mmap_table::split_region(int variantnum, mmap_region_info* existing_region, unsigned long split_address)
{
#ifdef MVEE_MMAN_DEBUG
    existing_region->print_region_info(">>> splitting region: ");
#endif

    std::set<mmap_region_info*>::iterator it           =
        full_map[variantnum].find(existing_region);
    if (it != full_map[variantnum].end())
        full_map[variantnum].erase(it);

    mmap_region_info*                     lower_region = new mmap_region_info(*existing_region);
    mmap_region_info*                     upper_region = existing_region;

    // at this point, both the upper and lower regions are copies of the original region
    // the lower region has been inserted into the map by copy_region_info
    upper_region->region_base_address = split_address;
    upper_region->region_size         = lower_region->region_base_address + lower_region->region_size - split_address;
    lower_region->region_size         = split_address - lower_region->region_base_address;
    if (upper_region->region_backing_file_path[0] != '[')
        upper_region->region_backing_file_offset = lower_region->region_backing_file_offset + lower_region->region_size;
    full_map[variantnum].insert(lower_region);
    full_map[variantnum].insert(upper_region);

    // another region is referencing this shadow
    if (upper_region->shadow)
        split_variant_shadow_region(variantnum, existing_region);

#ifdef MVEE_MMAN_DEBUG
    lower_region->print_region_info(">>> lower split: ");
    upper_region->print_region_info(">>> upper split: ");
#endif

    return lower_region;
}

/*-----------------------------------------------------------------------------
    get_vdso_region
-----------------------------------------------------------------------------*/
mmap_region_info* mmap_table::get_vdso_region(int variantnum)
{
    std::set<mmap_region_info*, region_sort>::iterator it;

    for (it = full_map[variantnum].begin(); it != full_map[variantnum].end(); ++it)
        if ((*it)->region_backing_file_path == "[vdso]")
            return (*it);

    return NULL;
}

/*-----------------------------------------------------------------------------
    get_heap_region
-----------------------------------------------------------------------------*/
mmap_region_info* mmap_table::get_heap_region(int variantnum)
{
    std::set<mmap_region_info*, region_sort>::iterator it;

    for (it = full_map[variantnum].begin(); it != full_map[variantnum].end(); ++it)
        if ((*it)->region_backing_file_path == "[heap]")
            return (*it);

    return NULL;
}

/*-----------------------------------------------------------------------------
    get_ld_loader_bounds
-----------------------------------------------------------------------------*/
bool mmap_table::get_ld_loader_bounds(int variantnum, unsigned long& loader_base, unsigned long& loader_size)
{
    auto info = get_region_info(variantnum, MVEE_LD_LOADER_BASE, 0);	

    if (info)
    {
		info->print_region_info("Found loader base");

        // also look for the data segment
        std::set<mmap_region_info*, region_sort>::iterator it =
            full_map[variantnum].find(info);
        if (it != full_map[variantnum].end())
        {
            it++;
            if (it != full_map[variantnum].end())
            {
                unsigned long loader_end = (*it)->region_base_address
                                           + (*it)->region_size;

                loader_base = info->region_base_address;
                loader_size = loader_end - loader_base;
                return true;
            }
        }
    }

    return false;
}

/*-----------------------------------------------------------------------------
    is_same_region
-----------------------------------------------------------------------------*/
bool mmap_table::is_same_region(mmap_region_info* region1, mmap_region_info* region2)
{
    if (region1->region_prot_flags != region2->region_prot_flags)
        return false;

    if ((region1->region_map_flags & MAP_TYPE) != (region2->region_map_flags & MAP_TYPE))
        return false;

    /* different filename = different region unless one region is a stack and the other is an anonymous region */
    if (region1->region_backing_file_path != region2->region_backing_file_path)
    {
		if (region1->region_backing_file_unsynced &&
			region2->region_backing_file_unsynced)
			return true;

        if (!(region1->region_backing_file_path.find("[stack:") == 0 && 
			  region2->region_backing_file_path.find("[stack:") == 0))
            return false;
    }

    return true;
}

/*-----------------------------------------------------------------------------
    check_region_overlap
-----------------------------------------------------------------------------*/
bool mmap_table::check_region_overlap(mmap_region_info* region_a, mmap_region_info* region_b)
{
    if (!region_a || !region_b)
        return false;

    if (region_a->region_base_address < region_b->region_base_address)
        return (region_a->region_base_address + region_a->region_size > region_b->region_base_address) ? true : false;
    else
        return (region_b->region_base_address + region_b->region_size > region_a->region_base_address) ? true : false;
}

/*-----------------------------------------------------------------------------
    compare_region_addresses
-----------------------------------------------------------------------------*/
bool mmap_table::compare_region_addresses (std::vector<unsigned long>& addresses)
{
    std::vector<mmap_region_info*> infos(mvee::numvariants);
    int                            infos_found = 0;

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        infos[i] = get_region_info(i, addresses[i]);
        if (infos[i])
            infos_found++;
    }

    if (infos_found == 0)
        return true;

    if (infos_found != mvee::numvariants)
    {
#ifdef MVEE_MMAN_DEBUG
        SERIALIZEVECTOR(addresses, str);
        debugf("only found %d info structs while comparing addresses: %s\n", infos_found, str.c_str());
#endif
        return false;
    }


#ifdef MVEE_MMAN_DEBUG
    SERIALIZEVECTOR(addresses, str);
    debugf("comparing addresses: %s\n", str.c_str());
#endif

    // check if they're backed by the same file and if the length matches
    for (int i = 1; i < mvee::numvariants; ++i)
        if ((infos[i]->region_backing_file_path != infos[i-1]->region_backing_file_path)
            || (infos[i]->region_prot_flags != infos[i-1]->region_prot_flags))
            return false;

    // mmaping not found => assume it's a match
    return true;
}

/*-----------------------------------------------------------------------------
    insert_region
-----------------------------------------------------------------------------*/
bool mmap_table::insert_region(int variantnum, mmap_region_info* region)
{
    return full_map[variantnum].insert(region).second;
}

/*-----------------------------------------------------------------------------
  foreach_region - steps over an entire region, performing a
  callback for each set of regions found in the process

  returns 0 if successful or non-0 if any of the callback invocations returned
  non-0
-----------------------------------------------------------------------------*/
int mmap_table::foreach_region
(
    std::vector<unsigned long>& addresses,
    unsigned long size,
    void* callback_param,
    bool (*callback)(mmap_table* table, std::vector<mmap_region_info*>&, void*)
)
{
    std::vector<mmap_region_info*>                          initial_infos(mvee::numvariants);
    std::vector<mmap_region_info*>                          infos(mvee::numvariants);
    std::vector<unsigned long>                              __addresses(mvee::numvariants);
    unsigned long                                           initial_address = addresses[0];
    int                                                     infos_found     = 0;
    int                                                     result          = 0;

    std::fill(initial_infos.begin(), initial_infos.end(), nullptr);

    for (int i = 0; i < mvee::numvariants; ++i)
        __addresses[i] = addresses[i];

#ifdef MVEE_MMAN_DEBUG
    debugf("foreach region\n");
    for (int i = 0; i < mvee::numvariants; ++i)
        debugf("region %d => 0x" PTRSTR "-0x" PTRSTR "\n", i, addresses[i], addresses[i]+size);
#endif

    // get the lower bounds
    std::vector<
        std::set<mmap_region_info*, region_sort>::iterator> it(mvee::numvariants);
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        initial_infos[i] = new mmap_region_info(i, __addresses[i], 0, 0, NULL, 0, 0);
        it[i]            = full_map[i].lower_bound(initial_infos[i]);
        if (it [i]!= full_map[i].end())
        {
            if ((*(it[i]))->region_base_address + (*(it[i]))->region_size < __addresses[i])
            {
                it[i]++;
                if (it[i] != full_map[i].end())
                {
                    infos_found++;
                    __addresses[i] = (*(it[i]))->region_base_address;
                    infos[i]       = *(it[i]);
                }
            }
            else
            {
                infos_found++;
                __addresses[i] = (*(it[i]))->region_base_address;
                infos[i]       = *(it[i]);
            }
        }
    }

#ifdef MVEE_MMAN_DEBUG
    for (int i = 0; i < mvee::numvariants; ++i)
        if (infos[i])
            infos[i]->print_region_info(">>> found region: ");

#endif

    // no lower bound found... => set is empty?
    if (!infos_found)
    {
        goto out;
    }

    // this isn't right...
    if (infos_found != mvee::numvariants)
    {
        warnf("infos_found != mvee::numvariants\n");
        result = -1;
        goto out;
    }

    while (__addresses[0] < initial_address + size)
    {
        for (int i = 0; i < mvee::numvariants; ++i)
            initial_infos[i]->region_base_address = infos[i]->region_base_address;

        if (!callback(this, infos, callback_param))
        {
            warnf("callback failed\n");
            result = -1;
            goto out;
        }

        // do we have to look for more regions?
        unsigned char need_more = 0;
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            if (__addresses[i] + infos[i]->region_size < initial_infos[i]->region_base_address + size)
            {
                need_more = 1;
                break;
            }
        }

        if (!need_more)
        {
            result = 0;
            goto out;
        }

        infos_found = 0;
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            it[i] = full_map[i].upper_bound(initial_infos[i]);
            if (it[i] != full_map[i].end())
            {
                infos_found++;
                infos[i] = *(it[i]);
            }
            else
                infos[i] = NULL;
        }

        if (infos_found == 0)
        {
            result = 0;
            goto out;
        }

        if (infos_found != mvee::numvariants)
        {
            warnf("only found %d regions while iterating over ranges:\n", infos_found);
            for (int i = 0; i < mvee::numvariants; ++i)
            {
                warnf("> variant %d range: 0x" PTRSTR "-0x" PTRSTR "\n", i, addresses[i], addresses[i] + size);
            }
            warnf("> last valid address for the master was: 0x" PTRSTR "\n", __addresses[0]);
            for (int i = 0; i < mvee::numvariants; ++i)
            {
                if (infos[i])
                    warnf("> variant %d region found: 0x" PTRSTR "-0x" PTRSTR " (%s)\n", i, infos[i]->region_base_address,
                                infos[i]->region_base_address + infos[i]->region_size, infos[i]->region_backing_file_path.c_str());
                else
                    warnf("> variant %d region not found\n", i);
            }
            throw;
            return -1;
        }
        __addresses[0] = infos[0]->region_base_address;
    }

out:

    std::vector<mmap_region_info*>::iterator infos_it;
    for (infos_it = initial_infos.begin(); infos_it != initial_infos.end(); ++infos_it)
        SAFEDELETE(*infos_it);

    return result;
}

/*-----------------------------------------------------------------------------
    foreach_region_one_variant - iterates over all regions for the
    specified variant only

    WARNING: the semantics are slightly different! The callback function
    gets a pointer to the mmap_region_info rather than a pointer to an
    mmap_region_info arrayy!!!
-----------------------------------------------------------------------------*/
int mmap_table::foreach_region_one_variant
(
    int variantnum,
    unsigned long address,
    unsigned long size,
    void* callback_param,
    bool (* callback)(mmap_table*, mmap_region_info*, void*)
)
{
    mmap_region_info                                   initial_info(variantnum, address, 0, 0, NULL, 0, 0);
    mmap_region_info*                                  info;
    unsigned long                                      initial_address = address;

#ifdef MVEE_MMAN_DEBUG
    debugf("foreach region\n");
    debugf("region %d => 0x" PTRSTR "-0x" PTRSTR "\n", variantnum, address, address+size);
#endif

    // get the lower bounds
    std::set<mmap_region_info*, region_sort>::iterator it;
    it = full_map[variantnum].lower_bound(&initial_info);
    if (it != full_map[variantnum].end())
    {
        if ((*it)->region_base_address + (*it)->region_size < address)
        {
            it++;
            if (it != full_map[variantnum].end())
            {
                address = (*it)->region_base_address;
                info    = *(it);
            }
            else
            {
                return 0;
            }
        }
        else
        {
            address = (*it)->region_base_address;
            info    = *(it);
        }
    }
    else
    {
        return 0;
    }

    while (address < initial_address + size)
    {
        //warnf("iter - address: %08x - limit: %08x\n", address, initial_address + size);
        initial_info.region_base_address = info->region_base_address;

        if (!callback(this, info, callback_param))
            return -1;

        it                               = full_map[variantnum].upper_bound(&initial_info);
        if (it == full_map[variantnum].end())
            return 0;
        info                             = *it;
        address                          = info->region_base_address;
    }

    return 0;
}

/*-----------------------------------------------------------------------------
    mvee_mman_compare_ranges - returns true if regions match
-----------------------------------------------------------------------------*/
static bool mvee_mman_compare_ranges_callback(mmap_table* table, std::vector<mmap_region_info*>& infos, void* callback_param)
{
    // check if regions match
    for (int i = 1; i < mvee::numvariants; ++i)
    {
        if (!mmap_table::is_same_region(infos[0], infos[i]))
        {
            warnf("region mismatch\n");
            infos[0]->print_region_info("region 0 >>>", mvee::warnf);
            infos[i]->print_region_info("slave region >>>", mvee::warnf);
            table->print_mmap_table(mvee::warnf);

            return false;
        }
    }

    return true;
}

bool mmap_table::compare_ranges(std::vector<unsigned long>& addresses, unsigned long size)
{
    return foreach_region(addresses, size, NULL, mvee_mman_compare_ranges_callback) == 0 ? true : false;
}

/*-----------------------------------------------------------------------------
    mprotect_range - changes the protection flags for an entire
    memory range.

    NOTES:
    * POSIX doesn't specify the behavior for mprotecting non-mapped regions
    * Linux DOES allow mprotecting non-mapped regions but it will of course
    only change the flags for the mapped portions of those regions
    * mprotecting partial regions is allowed!
-----------------------------------------------------------------------------*/
static __thread int           __mprotect_variantnum;
static __thread unsigned long __mprotect_base;
static __thread unsigned long __mprotect_size;
static __thread unsigned int  __mprotect_new_prot_flags;

bool mmap_table::mman_mprotect_range_callback(mmap_table* table, mmap_region_info* region_info, void* callback_param)
{
    // watch out for partial mprotects!
    if (__mprotect_base > region_info->region_base_address)
        // split_region returns the lower part. the existing region info becomes the upper part...
        table->split_region(__mprotect_variantnum, region_info, __mprotect_base);
    if (__mprotect_base + __mprotect_size < region_info->region_base_address + region_info->region_size)
        region_info = table->split_region(__mprotect_variantnum, region_info, __mprotect_base + __mprotect_size);
    //mvee_mman_print_region_info("mprotecting region => ", region_info);
    region_info->region_prot_flags = __mprotect_new_prot_flags;
    return true;
}

bool mmap_table::mprotect_range (int variantnum, unsigned long base, unsigned long size, unsigned int new_prot_flags)
{
    base                      = ROUND_DOWN(base, 4096);
    size                      = ROUND_UP(size, 4096);
    __mprotect_variantnum       = variantnum;
    __mprotect_base           = base;
    __mprotect_size           = size;
    __mprotect_new_prot_flags = new_prot_flags;
    if (foreach_region_one_variant(variantnum, base, size, (void*)(unsigned long)variantnum, mmap_table::mman_mprotect_range_callback) != 0)
        return false;

    // try to merge everything in this range
    mmap_region_info                                   info(variantnum, base - PAGE_SIZE, size + PAGE_SIZE, 0, NULL, 0, 0);
    std::set<mmap_region_info*, region_sort>::iterator it   =
        full_map[variantnum].lower_bound(&info);

    mmap_region_info*                                  prev = NULL;
    for (; it != full_map[variantnum].end(); ++it)
    {
        if (!prev)
        {
            prev = *it;
            continue;
        }

        if ((*it)->region_base_address > base + size + PAGE_SIZE)
            break;

        // if merging succeeds, then iterator will be invalidated
        // and the object the iterator pointed to will be deleted
        if (merge_regions(variantnum, prev, *it))
            it = full_map[variantnum].find(prev);

        prev = *it;
    }

    return true;
}

/*-----------------------------------------------------------------------------
    munmap_range - removes all mapped regions in the specified
    range.

    NOTES:
    * POSIX doesn't specify the behavior for munmapping non-mapped regions
    * Linux DOES allow munmapping non-mapped regions but it will of course
    only munmap the mapped portions of those regions
    * munmapping partial regions is allowed
-----------------------------------------------------------------------------*/
static __thread int           __munmap_variantnum;
static __thread unsigned long __munmap_base;
static __thread unsigned long __munmap_size;

bool mmap_table::mman_munmap_range_callback(mmap_table* table, mmap_region_info* region_info, void* callback_param)
{
    unsigned long long base_offset = 0;
    if (region_info->connected)
        base_offset = __munmap_base - region_info->region_base_address;
    //  warnf("munmap callback: region: 0x%08x-0x%08x\n", region_info->region_base_address, region_info->region_base_address + region_info->region_size);
    // watch out for partial mprotects!
    if (__munmap_base > region_info->region_base_address)
    {
        if (region_info->connected)
            table->split_region(__munmap_variantnum, region_info->connected,
                    region_info->connected->region_base_address + base_offset);
        // split_region returns the lower part. the existing region info becomes the upper part...
        table->split_region(__munmap_variantnum, region_info, __munmap_base);
        //	warnf("splitting because munmap base > region base\n");
    }
    if (__munmap_base + __munmap_size < region_info->region_base_address + region_info->region_size)
    {
        //	warnf("splitting because munmap_limit < region limit\n");
        if (region_info->connected)
            table->split_region(__munmap_variantnum, region_info->connected,
                    region_info->connected->region_base_address + base_offset + __munmap_size);
        region_info = table->split_region(__munmap_variantnum, region_info, __munmap_base + __munmap_size);
    }

    // shared memory?
    if (region_info->shadow)
        table->munmap_variant_shadow_region(__munmap_variantnum, region_info);

    // delete the region from the table
    if (region_info->connected)
    {
        std::set<mmap_region_info*, region_sort>::iterator it =
                table->full_map[(unsigned long)callback_param].find(region_info->connected);
        if (it != table->full_map[(unsigned long)callback_param].end())
            table->full_map[(unsigned long)callback_param].erase(it);
        delete region_info->connected;
    }
    std::set<mmap_region_info*, region_sort>::iterator it =
        table->full_map[(unsigned long)callback_param].find(region_info);
    if (it != table->full_map[(unsigned long)callback_param].end())
        table->full_map[(unsigned long)callback_param].erase(it);
    delete region_info;

    return true;
}

bool mmap_table::munmap_range (int variantnum, unsigned long base, unsigned long size)
{
    base              = ROUND_DOWN(base, 4096);
    size              = ROUND_UP(size, 4096);
    __munmap_variantnum = variantnum;
    __munmap_base     = base;
    __munmap_size     = size;
    //    warnf("munmapping range: 0x%08x-0x%08x for variant: %d\n", base, base+size, variantnum);
    if (foreach_region_one_variant(variantnum, base, size, (void*)(unsigned long)variantnum, mmap_table::mman_munmap_range_callback) != 0)
        return false;
    return true;
}

/*-----------------------------------------------------------------------------
    map_range - maps a new region

    NOTES:
    * Linux allows for mapping over existing regions (partial or completely)

    Pass NULL as the region_backing_file if we're creating an anonymous region!
-----------------------------------------------------------------------------*/
bool mmap_table::map_range (int variantnum, unsigned long address, unsigned long size, unsigned int map_flags,
                            unsigned int prot_flags, fd_info* region_backing_file,
                            unsigned int region_backing_file_offset, std::shared_ptr<shared_monitor_map_info> shadow,
                            mmap_region_info* connected)
{
    address = ROUND_DOWN(address, 4096);
    size    = ROUND_UP(size, 4096);

    // munmap the range first
    munmap_range(variantnum, address, size);

    // now we can just create a new region without having to deal with
    // overlap scenarios
    mmap_region_info* new_region = new mmap_region_info(variantnum, address, size, prot_flags, region_backing_file,
            region_backing_file_offset, map_flags);

    if (shadow)
    {
        new_region->shadow = shadow;
        new_region->shadow->mmap();

        if (insert_variant_shared_region(variantnum, new_region) < 0)
        {
            warnf("big oopsie! - [%p; %p)\n\n",
                  (void*) new_region->region_base_address,
                  (void*) (new_region->region_base_address + new_region->region_size));
        }
    }
    new_region->connected = connected;
//    new_region->print_region_info("inserting region: ", mvee::warnf);
    if (!full_map[variantnum].insert(new_region).second)
    {
        delete new_region;
        warnf("failed to insert new region....\n");
    }

    return true;
}

/*-----------------------------------------------------------------------------
    find_image_base - Kind of like win32 GetModuleHandle
-----------------------------------------------------------------------------*/
unsigned long mmap_table::find_image_base (int variantnum, std::string image_name)
{
	for (auto it : full_map[variantnum])
	{
		if (it->region_backing_file_path.compare(image_name) == 0)
			return it->region_base_address;
	}

	return 0;
}

/*-----------------------------------------------------------------------------
    calculate_disjoint_bases - The monitor has seen a new mmap call
    that maps in code. We want to:
    1) force strong randomization => ASLR will only randomize the 16 higher
    order bits of the base address
    2) force disjunct code regions => no pointer should ever reference a valid
    code region in more than one variant
-----------------------------------------------------------------------------*/
void mmap_table::calculate_disjoint_bases (unsigned long size, std::vector<unsigned long>& bases)
{
    std::set<mmap_region_info*, region_sort>           merged_regions;
    std::set<mmap_region_info*, region_sort>::iterator it;
    std::set<mmap_region_info*, region_sort>::iterator it2;
    std::set<mmap_region_info*, region_sort>::iterator prev;

    // step 0: Attempt to enlarge each variant's stack to stack_limit size so
    // we don't accidentally map anything too close to the stack, preventing it
    // from growing to its maximum size...
    //
    // We only have to do this ONCE!
    unsigned long                                      stack_limit = mvee::os_get_stack_limit();
    // TODO: Should we also do this for thread stacks? I don't know if
    // they have the same stack limit...
    if (stack_limit && !enlarged_initial_stacks)
    {
//		warnf("stack limit: %lu\n", stack_limit);
        enlarged_initial_stacks = 1;
		unsigned long stack_top = 0;
        for (int i = 0; i < mvee::numvariants; ++i)
        {
            mmap_region_info* stack                    = NULL;
            mmap_region_info* first_region_below_stack = NULL;
            it = full_map[i].end();
            --it;
            while (true)
            {
                if (!stack)
                {
                    if ((*it)->region_backing_file_path == "[stack]")
					{
                        stack = *it;
						stack_top = stack->region_base_address + stack->region_size;
					}
                }
                else
                {
					// some NUTJOB could've split the stack in two,
					// e.g. by making it partially executable
                    if ((*it)->region_backing_file_path == "[stack]")
					{
                        stack = *it;
					}
					else
					{
						first_region_below_stack = *it;
						break;
					}
                }

                if (it == full_map[i].begin())
                    break;

                --it;
            }

            // now enlarge it
            if (stack)
            {
//				stack->print_region_info("stack > ", mvee::warnf);

                // it should not overlap with anything that had been mapped below the stack before we could apply DCL
                if (first_region_below_stack && (first_region_below_stack->region_base_address + first_region_below_stack->region_size > (stack_top - stack_limit - PAGE_SIZE))) // minus PAGE_SIZE b/c of the guard page
                {
					unsigned long previous_region_top = first_region_below_stack->region_base_address + first_region_below_stack->region_size;

                    stack->region_size         = (stack->region_base_address + stack->region_size) - previous_region_top;
                    stack->region_base_address = previous_region_top;
                }
                // OK. No overlaps => just enlarge to stack limit
                else
                {
//					warnf("enlarged stack\n");

					// account for the guard page below the stack!!!
					unsigned long old_base     = stack->region_base_address;
                    stack->region_base_address = stack_top - stack_limit - PAGE_SIZE;
                    stack->region_size         += (old_base - stack->region_base_address);
                }
            }
        }
    }


    // step 1: temporarily merge all existing code regions into one set
    // warnf("calculating disjunct code bases for this mmap call - size = %d bytes\n", size);
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        for (it = full_map[i].begin();
             it != full_map[i].end();
             ++it)
        {
            // code region => copy into merged_regions set
            if (((*it)->region_prot_flags & PROT_EXEC)
                && (*it)->region_backing_file_path != "[vsyscall]"
                && (*it)->region_backing_file_path.find("MVEE_LD_Loader") == std::string::npos)
            {
                mmap_region_info* new_region = new mmap_region_info(0, (*it)->region_base_address, (*it)->region_size, 0, NULL, 0, 0);

                if (!merged_regions.insert(new_region).second)
                {
                    // the region could already be in the set
                    SAFEDELETE(new_region);
                }
            }
        }
    }

    // step 1b: We also add a pseudo-region that indicates the highest possible code address we can use
    mmap_region_info* pseudo   = new mmap_region_info(0, HIGHEST_USERMODE_ADDRESS - 4096, 4096, 0, NULL, 0, 0);

    // try to insert. Might fail if there's something there already!
    if (!merged_regions.insert(pseudo).second)
        SAFEDELETE(pseudo);

    // warnf("merged set dump\n");
    //for (it = merged_regions.begin(); it != merged_regions.end(); ++it)
    //  warnf("> found region - 0x%08x-0x%08x\n", (*it)->region_base_address, (*it)->region_size + (*it)->region_base_address);

    // step 2: fill any holes that are not large enough to contain the new region
    unsigned long     prev_end = 0;
    for (it = merged_regions.begin(); it != merged_regions.end(); ++it)
    {
        // the gap between the current and the previous region is too small to
        // contain the new regions we're mmapping
        // => we fill the gap by creating a new region that spans from the previous
        // region's base address up till the current region's end address
        if ((*it)->region_base_address - prev_end < size)
        {
            //warnf("gap between regions at: 0x%08x-0x%08x and 0x%08x-0x%08x is too small to contain a new region - filling it up\n",
            //		(*prev)->region_base_address, (*prev)->region_size + (*prev)->region_base_address,
            //		(*it)->region_base_address, (*it)->region_size + (*it)->region_base_address);

            // prev might not be initialized here! This happens if the gap between address 0 and the first region
            // we encounter is not large enough.
            unsigned long new_size = (*it)->region_base_address + (*it)->region_size;

            // we merge the previous region with this one
            if (prev_end)
            {
                new_size            -= (*prev)->region_base_address;
                delete *it;
                merged_regions.erase(it);
                (*prev)->region_size = new_size;
                prev_end             = (*prev)->region_base_address + (*prev)->region_size;
                it                   = prev;
            }
            // no previous region, just adjust this one
            else
            {
                (*it)->region_base_address = 0;
                (*it)->region_size         = new_size;
            }
        }
        else
        {
            prev     = it;
            prev_end = (*it)->region_base_address + (*it)->region_size;
        }
    }

    // warnf("merged set dump\n");
    // for (it = merged_regions.begin(); it != merged_regions.end(); ++it)
    //	warnf("> found region - 0x%08x-0x%08x\n", (*it)->region_base_address, (*it)->region_size + (*it)->region_base_address);

    // step 3: for each variant, find a new base address that:
    // > a) does not overlap with code addresses in any other variants
    // > b) does not overlap with any regions in the variant itself
    mmap_region_info test_region(0, 0, 0, 0, NULL, 0, 0);
    for (int i = 0; i < mvee::numvariants; ++i)
    {
        // get the highest available code address
        it                              = merged_regions.end();
        it--;

        // warnf("testing base: 0x%08x for variant: %d\n", ((*it)->region_base_address - size) & ~4095, i);

        // Try to place the region just before the highest mapped region. This will
        // probably be the pseudo-region we added in step 1b
        test_region.region_base_address = ((*it)->region_base_address - size) & ~4095;
        test_region.region_size         = size;

        while (1)
        {
            // First check if this address is still available within the variant's own address space
            // If it is not available, find the lowest address that IS available
            while ((it2 = full_map[i].find(&test_region))
                   != full_map[i].end())
            {
                // warnf("overlap found within own address space. Adjusting\n");

                if (size > (*it2)->region_base_address)
                {
                    warnf("disjoint code layouting failed - there's not enough space left in variant %d's address space to place a region of size: " LONGRESULTSTR "\n", i,                           size);
                    warnf("we detected overlap with region: 0x" PTRSTR "-0x" PTRSTR " (%s)\n",                                                                         (*it2)->region_base_address, (*it2)->region_base_address +  (*it2)->region_size, (*it2)->region_backing_file_path.c_str());
                    throw;
                    return;
                }
                // see if we can adjust without overlapping with another code region
                test_region.region_base_address = ((*it2)->region_base_address - size) & ~4095;
            }

            // Now also check if this region would overlap with any code regions we already have
            // in other variants. If it does overlap, we have to do the whole thing all over again
            it = merged_regions.find(&test_region);
            if (it != merged_regions.end())
            {
                // after adjustment, the new base now overlaps with another code region
                // => skip that code region first, then continue looking within
                // the variant's own address space
                // warnf("also found overlap with an existing code region at: %08x\n", (*it)->region_base_address);

                if (size > (*it)->region_base_address)
                {
                    warnf("disjoint code layouting failed - there's not enough space left in the merged region set to place a code region of size: " LONGRESULTSTR "\n", size);
                    warnf("we detected overlap with megrged region: 0x" PTRSTR "-0x" PTRSTR "\n",                                                                        (*it)->region_base_address, (*it)->region_base_address +  (*it)->region_size);
                    throw;
                    return;
                }
                test_region.region_base_address = ((*it)->region_base_address - size) & ~4095;
            }
            else
            {
                break;
            }
        }

        // found a good base address
        bases[i] = test_region.region_base_address;

        // now we insert the region in the merged regions set
        // so the next variants won't get an overlapping region
        mmap_region_info* new_region = new mmap_region_info(0, test_region.region_base_address, test_region.region_size, 0, NULL, 0, 0);

        merged_regions.insert(new_region);
        // warnf("returning region 0x%08x-0x%08x for variant %d\n",
        //		bases[i], bases[i] + size, i);
    }

    for (it = merged_regions.begin(); it != merged_regions.end(); ++it)
        delete (*it);

    merged_regions.clear();
    //warnf("ALL DONE!\n");
}

/*-----------------------------------------------------------------------------
    mvee_mman_check_vdso_overlap
-----------------------------------------------------------------------------*/
int mmap_table::check_vdso_overlap(int variantnum)
{
    mmap_region_info* vdso = get_vdso_region(variantnum);

    if (!vdso)
        return -1;

    vdso->print_region_info("Checking overlap for VDSO");

    for (int i = 0; i < variantnum; ++i)
    {
        mmap_region_info* other = get_vdso_region(i);
        if (mmap_table::check_region_overlap(vdso, other))
        {
            debugf("overlapping vdsos:\n");
            vdso->print_region_info("VDSO for this variant");
            other->print_region_info("VDSO for other variant");
            return i;
        }
    }

    return -1;
}

/*-----------------------------------------------------------------------------
    is_available_in_all_variants
-----------------------------------------------------------------------------*/
bool mmap_table::is_available_in_all_variants(unsigned long base, unsigned long size)
{
	mmap_region_info tmp_region(0, base, size, 0, NULL, 0, 0);
	for (int i = 0; i < mvee::numvariants; ++i)
	{
		auto overlapping_region = full_map[i].find(&tmp_region);
		if (overlapping_region != full_map[i].end())
		{
			warnf("FIXME: Found a memory region that intersects with our chosen data mapping base address.\n");
			(*overlapping_region)->print_region_info("overlapping region", warnf);
			warnf("Tested region: 0x" PTRSTR "-0x" PTRSTR "\n", base, base + size);
			return false;
		}
	}

	return true;
}

/*-----------------------------------------------------------------------------
    calculate_data_mapping_base
-----------------------------------------------------------------------------*/
unsigned long mmap_table::calculate_data_mapping_base(unsigned long size)
{
	// We only do this for 64-bit platforms.
	if (sizeof(long) == 4)
		return 0;

	// find the lowest used address above the mmap_base
    mmap_region_info tmp_region(0, mmap_base, 0, 0, NULL, 0, 0);
	auto region_iterator = full_map[0].upper_bound(&tmp_region);

	// if there is no mapping above mmap base
	if (region_iterator == full_map[0].end() ||
		// or if the first mapping is outside of our randomized mmap region
		(*region_iterator)->region_base_address > mmap_base + (HIGHEST_USERMODE_ADDRESS >> 8))
	{
		// pick any address within our randomized mmap region
		std::random_device rd;
		std::mt19937_64 mt(rd());
		// we do >> 12 because we want to calculate the page number		
		std::uniform_int_distribution<unsigned long> distr(mmap_base >> 12, (mmap_base + (HIGHEST_USERMODE_ADDRESS >> 8) - ROUND_UP(size, 4096)) >> 12);

		//
		// This calculates a random page in the range:
		//
		// +-----------------------------------------------------+---------------+
		// | <---------------  viable addresses ---------------> | <--  size --> |
		// +-----------------------------------------------------+---------------+
		//
		// ^                                                                     ^
		// |                                                                     |
		// +-----+                                        +----------------------+
		//    mmap_base              mmap_base + 1/256th of the usable address space
		//
		unsigned long address = distr(mt);
		// back to a full address
		address <<= 12;

//		warnf("No mapping found in mmap base zone - selected address: 0x" PTRSTR " - size: %ld\n", address, size);

		// assert that this address is available. It should be if we implement
		// ASLR control correctly
		if (is_available_in_all_variants(address, ROUND_UP(size, 4096)))
			return address;
	}
	else
	{
		unsigned long address = (*region_iterator)->region_base_address - ROUND_UP(size, 4096);

		// We already have a mapping in our mmap region. See if we can extend it downwards
		if (address > mmap_base)
		{
//			warnf("Mapping found above mmap base - extended downwards address address: 0x" PTRSTR "\n", address);

			// yep
			if (is_available_in_all_variants(address, ROUND_UP(size, 4096)))
				return address;
		}
		else
		{
			// nope... See if we can squeeze this region in somewhere
			auto prev_region = region_iterator;
			for (region_iterator = ++region_iterator; region_iterator != full_map[0].end(); ++region_iterator)
			{
				// Found a hole to squeeze this region in
				if ((*region_iterator)->region_base_address - ((*prev_region)->region_base_address + (*prev_region)->region_size) > size)
				{
					if (is_available_in_all_variants((*region_iterator)->region_base_address - ROUND_UP(size, 4096), ROUND_UP(size, 4096)))
						return (*region_iterator)->region_base_address - ROUND_UP(size, 4096);
				}
			}
		}
	}

	return 0;
}

/*-----------------------------------------------------------------------------
    find_writable_region - find a PROT_WRITE region of at least len bytes
    long in the address space of variant variantnum
-----------------------------------------------------------------------------*/
mmap_region_info* mmap_table::find_writable_region
(
	int variantnum,
	unsigned long len,
	pid_t look_for_thread,
	bool is_main_thread
)
{
    std::set<mmap_region_info*, region_sort>::iterator region_iterator;
    std::set<mmap_region_info*, region_sort> *         region_table
        = &full_map[variantnum];

    char*                                              look_for_region = NULL;

    if (look_for_thread)
    {
        if (is_main_thread)
        {
            look_for_region = mvee::strdup("[stack]");
        }
        else
        {
            look_for_region = new char[20];
            sprintf(look_for_region, "[stack:%d]", look_for_thread);
        }
    }

    for (region_iterator = region_table->begin(); region_iterator != region_table->end(); ++region_iterator)
    {
        //warnf("checking if region is writable: %s\n", (*region_iterator)->region_backing_file_path);
        if (((*region_iterator)->region_prot_flags & PROT_WRITE)
            && (*region_iterator)->region_size >= len)
        {
            if (look_for_thread && (*region_iterator)->region_backing_file_path != look_for_region)
                continue;

            SAFEDELETEARRAY(look_for_region);
            return (*region_iterator);
        }
    }

    SAFEDELETEARRAY(look_for_region);
    return NULL;
}
