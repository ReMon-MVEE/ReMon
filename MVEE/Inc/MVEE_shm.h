/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_SHM_H_
#define MVEE_SHM_H_

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include "MVEE_build_config.h"
#include <map>
#include <memory>

/*-----------------------------------------------------------------------------
    IPC syscall calls, see linux/ipc.h
-----------------------------------------------------------------------------*/
#define SEMOP      1
#define SEMGET     2
#define SEMCTL     3
#define SEMTIMEDOP 4
#define MSGSND     11
#define MSGRCV     12
#define MSGGET     13
#define MSGCTL     14
#define SHMAT      21
#define SHMDT      22
#define SHMGET     23
#define SHMCTL     24

/*-----------------------------------------------------------------------------
    Enumerations
-----------------------------------------------------------------------------*/
enum mvee_base_atomics
{
    // LOAD OPERATIONS FIRST!!! DO NOT CHANGE THIS CONVENTION
    ATOMIC_FORCED_READ,
    ATOMIC_LOAD,
    // THE FOLLOWING IS NOT AN ACTUAL ATOMIC OPERATION, IT JUST DENOTES THE END OF THE LOAD-ONLY ATOMICS!!!
    ATOMIC_LOAD_MAX,
    // STORES AFTER LOADS
    CATOMIC_COMPARE_AND_EXCHANGE_VAL_ACQ,
    CATOMIC_COMPARE_AND_EXCHANGE_BOOL_ACQ,
    CATOMIC_AND,
    CATOMIC_OR,
    CATOMIC_EXCHANGE_AND_ADD,
    CATOMIC_ADD,
    CATOMIC_INCREMENT,
    CATOMIC_DECREMENT,
    CATOMIC_MAX,
    ATOMIC_COMPARE_AND_EXCHANGE_VAL_ACQ,
    ATOMIC_COMPARE_AND_EXCHANGE_BOOL_ACQ,
    ATOMIC_EXCHANGE_ACQ,
    ATOMIC_EXCHANGE_AND_ADD,
    ATOMIC_INCREMENT_AND_TEST,
    ATOMIC_DECREMENT_AND_TEST,
    ATOMIC_ADD_ZERO,
    ATOMIC_ADD,
    ATOMIC_INCREMENT,
    ATOMIC_DECREMENT,
    ATOMIC_BIT_TEST_SET,
    ATOMIC_BIT_SET,
    ATOMIC_AND,
    ATOMIC_STORE,
    ATOMIC_MAX,
    ATOMIC_DECREMENT_IF_POSITIVE,
    __THREAD_ATOMIC_CMPXCHG_VAL,
    __THREAD_ATOMIC_AND,
    __THREAD_ATOMIC_BIT_SET,
    ___UNKNOWN_LOCK_TYPE___,
    __MVEE_BASE_ATOMICS_MAX__
};

enum mvee_extended_atomics {
    mvee_atomic_load_n,
    mvee_atomic_load,
    mvee_atomic_store_n,
    mvee_atomic_store,
    mvee_atomic_exchange_n,
    mvee_atomic_exchange,
    mvee_atomic_compare_exchange_n,
    mvee_atomic_compare_exchange,
    mvee_atomic_add_fetch,
    mvee_atomic_sub_fetch,
    mvee_atomic_and_fetch,
    mvee_atomic_xor_fetch,
    mvee_atomic_or_fetch,
    mvee_atomic_nand_fetch,
    mvee_atomic_fetch_add,
    mvee_atomic_fetch_sub,
    mvee_atomic_fetch_and,
    mvee_atomic_fetch_xor,
    mvee_atomic_fetch_or,
    mvee_atomic_fetch_nand,
    mvee_atomic_test_and_set,
    mvee_atomic_clear,
    mvee_atomic_always_lock_free,
    mvee_atomic_is_lock_free,
    mvee_sync_fetch_and_add,
    mvee_sync_fetch_and_sub,
    mvee_sync_fetch_and_or,
    mvee_sync_fetch_and_and,
    mvee_sync_fetch_and_xor,
    mvee_sync_fetch_and_nand,
    mvee_sync_add_and_fetch,
    mvee_sync_sub_and_fetch,
    mvee_sync_or_and_fetch,
    mvee_sync_and_and_fetch,
    mvee_sync_xor_and_fetch,
    mvee_sync_nand_and_fetch,
    mvee_sync_bool_compare_and_swap,
    mvee_sync_val_compare_and_swap,
    mvee_sync_lock_test_and_set,
    mvee_sync_lock_release,
    mvee_atomic_ops_max
};

#define __TOTAL_ATOMIC_TYPES__   (__MVEE_BASE_ATOMICS_MAX__ + mvee_atomic_ops_max)
#define ___TOTAL_ATOMIC_TYPES___ __TOTAL_ATOMIC_TYPES__

enum mvee_high_level_sync_primitives
{
    PTHREAD_BARRIER,
    PTHREAD_COND,
    PTHREAD_COND_TIMED,
    PTHREAD_MUTEX,
    PTHREAD_MUTEX_TIMED,
    PTHREAD_RWLOCK,
    PTHREAD_RWLOCK_TIMED,
    PTHREAD_SPIN,
    PTHREAD_SEM,
    LIBC_BARRIER,
    LIBC_LOCK,
    LIBC_ATOMIC,
    CUSTOM_SYNC_LIBRARY
};

enum mvee_libc_alloc_types
{
    LIBC_MALLOC,
    LIBC_FREE,
    LIBC_REALLOC,
    LIBC_MEMALIGN,
    LIBC_CALLOC,
    MALLOC_TRIM,
    HEAP_TRIM,
    MALLOC_CONSOLIDATE,
    ARENA_GET2,
    _INT_MALLOC,
    _INT_FREE,
    _INT_REALLOC
};

/*-----------------------------------------------------------------------------
    Structures
-----------------------------------------------------------------------------*/
struct mvee_op_entry
{
    unsigned long counter_and_idx;
};

struct mvee_counter
{
    unsigned long lock;
    unsigned long counter;
    unsigned char padding[64 - 2 * sizeof(unsigned long)];
};

/*-----------------------------------------------------------------------------
    Class Definitions
-----------------------------------------------------------------------------*/
//
// This represents a shared buffer (e.g. for recording lock order).
// See "Replication of Multi-Threaded Software" paper for a conceptual overview
//
class _shm_info
{
public:
    int            id;                     // segment id returned by shmget
    int            sz;                     // segment size
    void*          ptr;                    // segment pointer returned by shmat
    int            eip_id;                 // segment id for the callstack buffer
    int            eip_sz;                 // size of the callstack buffer
    void*          eip_ptr;                // pointer to the callstack buffer
    unsigned int   requested_slot_size;    // might not be aligned
    unsigned int   actual_slot_size;       // aligned to sizeof(long) boundary
    bool           have_eip_segment;       // do we also have a secondary queue for callstacks?
    unsigned short eip_stack_depth;        // depth of the callstack in each slot
    unsigned int   dumpcount;              // set to 1 if we've dumped this queue to the log file already

    _shm_info();
    ~_shm_info();
};

//
// Shared mem segments for MVEE interposers
//
class shm_table
{
public:
    std::map<unsigned char,
             std::shared_ptr<_shm_info> >
                       table;              // maps the buffer type onto the shm info

#ifdef MVEE_GENERATE_LOCKSTATS
    std::map<unsigned short, unsigned long long>
                       op_cnt_per_type;
    std::map<unsigned long, unsigned long long>
                       op_cnt_per_word;
    std::map<unsigned short, unsigned long long>
                       op_cnt_per_thread;
    unsigned long long bounce_cnt;
    unsigned long long op_cnt_total;
    pid_t              prev_thread_id;
#endif

    void                       update_lock_stats(unsigned char shm_type, _shm_info* info);
    void                       update_all_lock_stats();
    void                       grab_lock();
    void                       release_lock();
    void                       full_release_lock();
    std::shared_ptr<_shm_info> create_info(unsigned char buffer_type, unsigned char add_to_list=1);

    shm_table();
    shm_table(const shm_table& parent);

private:
    pthread_mutex_t    lock;
    void init();
};

#endif /* MVEE_SHM_H_ */
