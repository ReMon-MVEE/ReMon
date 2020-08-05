/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_MMAN_H_INCLUDED
#define MVEE_MMAN_H_INCLUDED

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sys/user.h>
#include <libelf.h>
#include <libdwarf.h>
#include <dwarf.h>
#include <pthread.h>
#include <string>
#include <set>
#include <memory>
#include <deque>
#include <vector>
#include <map>
#include <atomic>
#include "MVEE_build_config.h"
#include "MVEE_private_arch.h"
#include "MVEE_filedesc.h"

/*-----------------------------------------------------------------------------
    Enumerations
-----------------------------------------------------------------------------*/
enum mvee_addr2line_status
{
    ADDR2LINE_FILE_STATUS_UNKNOWN,            // 0
    ADDR2LINE_FILE_NO_DEBUG_SYMS,             // 1
    ADDR2LINE_FILE_HAS_DEBUG_SYMS,            // 2
    ADDR2LINE_PROC_TERMINATED                 // 3
};

/*-----------------------------------------------------------------------------
    Class Definitions
-----------------------------------------------------------------------------*/
class mmap_region_info;
class fd_info;

class mvee_dwarf_context
{
public:
    PTRACE_REGS regs;
    long int    cfa;

    mvee_dwarf_context(pid_t variantpid);
};

//
// used for addr2line caching so we don't have to open new proc
// pipes every time during backtraces
//
class resolved_instruction
{
public:
    unsigned long instruction_address;        // instruction pointer
    std::string   instruction_info;           // <function> at <sourcefile>:<sourceline> (<library>)
    unsigned long instruction_file_offset;    // offset of the instruction within the binary/library file

    resolved_instruction();
};

//
// Addr2line process used to resolve instructions addresses to symbol names/offsets.
// We keep this process running until refcount drops to 0 and communicate with
// it using some sort of bi-directional pipe.
//
class mmap_addr2line_proc
{
public:
    std::string read_from_addr2line_pipe(const std::string& cmd, int variantnum);
    mmap_addr2line_proc(std::string& file, int variantnum, pid_t variantpid, unsigned long address, unsigned long region_size);
    ~mmap_addr2line_proc();

private:
    pthread_mutex_t addr2line_lock;
    std::string     addr2line_file;           // which file are we resolving for?
    pid_t           addr2line_pid;
    unsigned int    addr2line_fds[2];         // filedescs to communicate with the addr2line process
    mvee_addr2line_status
                    addr2line_status;

    void        pipe_create     (const std::string& lib_name);
    void        pipe_func       (unsigned int rfd, unsigned int wfd, const std::string& lib_name);
    void        close_proc      ();
    std::string read_internal   (const std::string& cmd);
};

//
// Dwarf info associated with one ELF file
//
class dwarf_info
{
public:
    bool         dwarf_in_memory;             // 1 if we're reading from an in-memory copy of the file
    bool         info_valid;
    union
    {
        int            dwarf_fd;              // fd to the open file
        unsigned char* dwarf_buffer;          // pointer to the in-memory file
    }            dwarf_data;
    Elf*         dwarf_elf;                   // Elf struct for the file
    Dwarf_Debug  dwarf_debug;                 // opaque struct that contains all of the debugging info for this file
    Dwarf_Cie *  cie_list;
    Dwarf_Fde *  fde_list;
    Dwarf_Signed cie_count;
    Dwarf_Signed fde_count;

    dwarf_info(std::string& file, int variantnum, pid_t variantpid, mmap_region_info* region_info);
    ~dwarf_info();
	void reset();
};


//
// Info about shared regions
//
class shared_monitor_map_info
{
public:
    void*       shadow_base;
    size_t      size;
    int         active_shadow_users;

                shared_monitor_map_info                 (void* shadow_base, size_t size);
                ~shared_monitor_map_info                ();
    int         mmap                                    ();
    int         unmap                                   ();
};

//
// Info about an mmap'ed region
//
class mmap_region_info
{
public:
    //
    // mandatory fields
    //
    unsigned long region_base_address;        // start address of the mapping. Can be different for every variant due to ASLR etc.
    unsigned long region_size;                // region size in bytes

    //
    // optional fields used for regions that are backed by files
    //
    unsigned int  region_prot_flags;          // e.g. PROT_EXEC | PROT_READ ...
    unsigned int  region_map_flags;           // e.g. MAP_ANONYMOUS | MAP_PRIVATE ...
    unsigned int  region_backing_file_fd;     // master fd of the backing file
    std::string   region_backing_file_path;   // path to the backing file. Kept here because the fd might be closed by the time we unmap
    unsigned int  region_backing_file_flags;  // e.g. O_RDWR
    unsigned int  region_backing_file_offset; // offset of the region within the backing file (in bytes)
    ssize_t       region_backing_file_size;   // (optional) original size of the backing file
	bool          region_backing_file_unsynced; // (optional) true if access to the backing file is unsynced. This is used for aliasing

    //
    // Optional fields used by the backtracer
    //
    bool          region_is_so;               // set to true if the backing file of this region is a shared library

    //
    // Shared memory shadow
    //
    std::shared_ptr<shared_monitor_map_info>
                  shadow;
    void*         original_base;
    mmap_region_info*
                  connected;

    //
    // Debugging/Backtracing support
    //
    void                 print_region_info          (const char* log_prefix, void (*logfunc)(const char* format, ...)=NULL);
    dwarf_info*          get_dwarf_info             (int variantnum, pid_t variantpid);
    mmap_addr2line_proc* get_addr2line_proc         (int variantnum, pid_t variantpid);
    unsigned long        map_memory_pc_to_file_pc   (int variantnum, pid_t variantpid, unsigned long in_memory_offset);

    //
    // Constructor
    //
    mmap_region_info(int variantnum, unsigned long address, unsigned long size, unsigned int prot_flags,
            fd_info* backing_file, unsigned int backing_file_offset, unsigned int map_flags,
            mmap_region_info* connected = nullptr);

private:
    std::shared_ptr<mmap_addr2line_proc>
                  region_addr2line_proc;      // set if we have an open addr2line pipe to read line numbers from this region's backing file
    std::shared_ptr<dwarf_info>
                  region_dwarf_info;
};

//
// Buffers to be written back on the next munmap postcall
// this is used for MAP_SHARED regions. we change them to MAP_PRIVATE
// see the original GHUMVEE (FPS12) paper for more info
//
class writeback_info
{
public:
    mmap_region_info** writeback_regions;
    unsigned char*     writeback_buffer;
    unsigned int       writeback_buffer_size;
    unsigned int       writeback_buffer_offset;
};

//
// region sort function
//
struct region_sort
{
    bool operator() (mmap_region_info* const& region1, mmap_region_info* const& region2)
    {
        // if there's an overlap between the regions
        // => always return false
        if ((region1->region_base_address >= region2->region_base_address
             && region1->region_base_address < region2->region_base_address + region2->region_size)
            || (region2->region_base_address >= region1->region_base_address
                && region2->region_base_address < region1->region_base_address + region1->region_size))
            return false;

        // no overlap => just order them
        return region1->region_base_address < region2->region_base_address;
    }
};

//
// Information about the execve call that created an address space
//
class startup_info
{
public:
	std::string              real_image;              // real name of the program we started (might differ from image because we use an interpreter binary)
	std::string              image;                   // original name of the program we wanted to start
	std::string              serialized_argv;         // serialized program arguments
	std::string              serialized_envp;         // serialized environment variables
	std::deque<std::string>  argv;                    // vectorized program arguments
	std::deque<std::string>  envp;                    // vectorized environment variables
	std::string              interp;                  // interpreter used to start the original program
};

//
// Mmap info table
//
class mmap_table
{
public:
    int         mmap_execve_id;                       // monitorid of the variant that created the table/address space
	std::vector<startup_info>
                mmap_startup_info;                    // information about the execve call used to create this address space
	bool        have_diversified_variants;            // Set to true if we have compile-time diversified variants
    bool        set_logging_enabled;                  // are we logging for this set
	std::atomic<bool>        
		        thread_group_shutting_down;           // is this thread group shutting down asynchronously?
    bool        enlarged_initial_stacks;              // we artificially enlarge the initial stacks to the stack limit to prevent DCL from mapping anything that might overlap with a future stack page

    //
    // Initialization functions
    //
    mmap_table                  ();
    mmap_table                  (const mmap_table& parent);
    ~mmap_table                 ();
    void truncate_table         ();
    void truncate_table_variant (int variantnum);

    //
    // Initial map building
    //
    static unsigned int get_numerical_prot_flags    (const char* textual_prot_flags);
    std::string         get_textual_prot_flags      (unsigned int prot_flags);
    void                refresh_variant_maps        (int variantnum, pid_t variantpid);

    //
    // Region functions
    //
    mmap_region_info* get_region_info             (int variantnum, unsigned long address, unsigned long region_size=0);
    mmap_region_info* merge_regions               (int variantnum, mmap_region_info* region1, mmap_region_info* region2, bool dont_touch_map=false);
    mmap_region_info* split_region                (int variantnum, mmap_region_info* existing_region, unsigned long split_address);
    mmap_region_info* get_vdso_region             (int variantnum);
    mmap_region_info* get_heap_region             (int variantnum);
    bool              get_ld_loader_bounds        (int variantnum, unsigned long& loader_base, unsigned long& loader_size);
    static bool       is_same_region              (mmap_region_info* region1, mmap_region_info* region2);
    static bool       check_region_overlap        (mmap_region_info* region1, mmap_region_info* region2);
    bool              compare_region_addresses    (std::vector<unsigned long>& addresses);
    bool              insert_region               (int variantnum, mmap_region_info* region);

    //
    // Iterators
    //
    int foreach_region              (std::vector<unsigned long>& addresses, unsigned long size, void* callback_param, bool (*callback)(mmap_table*, std::vector<mmap_region_info*>&, void*));
    int foreach_region_one_variant  (int variantnum, unsigned long address, unsigned long size, void* callback_param, bool (*callback)(mmap_table*, mmap_region_info*, void*));

    //
    // Range functions
    //
    bool compare_ranges              (std::vector<unsigned long>& addresses, unsigned long size);

    //
    // System call support
    //
    static bool mman_mprotect_range_callback(mmap_table* table, mmap_region_info* region_info, void* callback_param);
    bool        mprotect_range              (int variantnum, unsigned long base, unsigned long size, unsigned int new_prot_flags);
    static bool mman_munmap_range_callback  (mmap_table* table, mmap_region_info* region_info, void* callback_param);
    bool        munmap_range                (int variantnum, unsigned long base, unsigned long size);
    bool        map_range                   (int variantnum, unsigned long address, unsigned long size,
                                             unsigned int map_flags, unsigned int prot_flags,
                                             fd_info* region_backing_file, unsigned int region_backing_file_offset,
                                             std::shared_ptr<shared_monitor_map_info> shadow = nullptr,
                                             mmap_region_info* connected = nullptr);
	unsigned long find_image_base           (int variantnum, std::string image_name);

    //
    // Disjoint Code Layouting support
    //
    void calculate_disjoint_bases                  (unsigned long size, std::vector<unsigned long>& bases);
    int  check_vdso_overlap                        (int variantnum);

	//
	// ASLR control support
	//
	
	// Calculates a random base address for a read/write mapping of <size> bytes
	// The resulting address is available in _ALL_ variants
	unsigned long calculate_data_mapping_base      (unsigned long size);
	bool is_available_in_all_variants              (unsigned long base, unsigned long size);

    //
    // IP-MON Support
    //
    mmap_region_info* find_writable_region         (int variantnum, unsigned long len, pid_t look_for_thread=0, bool is_main_thread=false);

    //
    // Logging functions
    //
    void print_mmap_table                          (void (*logfunc)(const char* format, ...)=NULL);

    //
    // Debugging/Backtracing Support
    //
    long int*          select_dwarf_reg            (mvee_dwarf_context* context, int dwarf_reg);
    unsigned long long read_sleb128                (unsigned char** ptr, unsigned char* ptr_max);
    unsigned long long read_uleb128                (unsigned char** ptr, unsigned char* ptr_max);
    int                dwarf_step                  (int variantnum, pid_t variantpid, mvee_dwarf_context* context);
    std::string        get_caller_info             (int variantnum, pid_t variantpid, unsigned long address, int calculate_file_offsets=0);
    unsigned long      get_stack_base              (int variantnum);
    unsigned long      resolve_symbol              (int variantnum, const char* sym, const char* lib_name);
    std::string        get_normalized_map_dump     (int variantnum);
    char*              get_normalized_maps_output  (int variantnum, pid_t variantpid);
    void               verify_mman_table           (int variantnum, pid_t variantpid);

    //
    // Synchronization functions
    //
    void grab_lock                   ();
    void release_lock                ();
    void full_release_lock           ();

    //
    // Shared memory
    //
    int                shadow_map                   (variantstate* variant, fd_info* info,
                                                     std::shared_ptr<shared_monitor_map_info>* shadow,
                                                     size_t size, int protection, int flags, int offset);
    int                insert_variant_shared_region (int variant, mmap_region_info* region);
    mmap_region_info*  get_shared_info              (int variant, unsigned long long address);
    int                munmap_variant_shadow_region (int variant, mmap_region_info* region_info);
    int                split_variant_shadow_region  (int variant, mmap_region_info* region_info);
    int                merge_variant_shadow_region  (int variant, mmap_region_info* region_info1,
                                                     mmap_region_info* region_info2);
    void               debug_shared                 ();


private:
    void init();
    pthread_mutex_t mmap_lock;
	// If the MVEE controls ASLR (enabled through variant.global.settings.mvee_controlled_alsr), this is 
	// the region where we will place all of our randomized mappings. This must be the base address of a 
	// 1/256th chunk of the total available address space.
	unsigned long   mmap_base; 
    std::vector<
        std::set<mmap_region_info*, region_sort> >
                    full_map;                         // all mapped regions - separate for each variant since their address spaces might differ due to ASLR/DCL
    std::vector<
        std::map<unsigned long, resolved_instruction> >
                    cached_instrs;                    // cached addr2line results
    std::map<std::string,
             std::map<std::string, unsigned long> >
                    cached_syms;                      // maps libname -> symbol name -> symbol offset within lib
    std::vector<std::vector<mmap_region_info*>>
                    variant_mappings;
};

#endif /* MVEE_MMAN_H_INCLUDED */
