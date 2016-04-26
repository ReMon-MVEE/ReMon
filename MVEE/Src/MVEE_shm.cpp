/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include "MVEE.h"
#include "MVEE_shm.h"
#include "MVEE_fake_syscall.h"
#include "MVEE_macros.h"
#include "MVEE_private_arch.h"

/*-----------------------------------------------------------------------------
    shm_info class
-----------------------------------------------------------------------------*/
_shm_info::_shm_info  ()
    : id(-1),
    sz(0),
    ptr(NULL),
    eip_id(-1),
    eip_sz(0),
    eip_ptr(NULL),
    requested_slot_size(0),
    actual_slot_size(0),
    have_eip_segment(0),
    eip_stack_depth(0),
    dumpcount(0)
{
}

_shm_info::~_shm_info()
{
    if (ptr)
        shmdt(ptr);
    if (eip_ptr)
        shmdt(eip_ptr);
}

/*-----------------------------------------------------------------------------
    shm_table class
-----------------------------------------------------------------------------*/
void shm_table::init()
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&lock, &attr);

#ifdef MVEE_GENERATE_LOCKSTATS
    op_cnt_total   = 0;
    prev_thread_id = 0;
#endif
}

shm_table::shm_table()
{
    init();
}

shm_table::shm_table(const shm_table& parent)
{
    init();
    table = parent.table;
}

void shm_table::update_all_lock_stats()
{
#ifdef MVEE_GENERATE_LOCKSTATS
    for (std::map<unsigned char, std::shared_ptr<_shm_info> >::iterator it = table.begin();
         it != table.end();
         ++it)
    {
        _shm_info* info = it->second.get();
        update_lock_stats(it->first, info);
    }
#endif
}

/*-----------------------------------------------------------------------------
    update_lock_stats - THIS ONLY SUPPORTS THE PARTIAL LOCK ORDER QUEUES!!!

    This is called when:
    1) the queue is flushed
    2) the queue is getting deleted

    this function should ONLY be called with the lock locked!!!
-----------------------------------------------------------------------------*/
void shm_table::update_lock_stats(unsigned char shm_type, _shm_info* info)
{
#ifdef MVEE_GENERATE_LOCKSTATS

    if (shm_type != MVEE_LIBC_LOCK_LOCK_BUFFER
        || !info->ptr)
        return;

    //
    // We can currently parse the following log formats:
    //
    // Partial order normal layout:
    // bytes 0-7    : word_ptr
    // bytes 8-9    : thread id
    // bytes 9-...  : slave tags
    //
    // Partial order extended:
    // bytes 0-7    : word_ptr
    // bytes 8-9    : thread id
    // bytes 10-11  : operation type
    // bytes 12-... : slave tags
    //

    // determine position of the first buffer slot
    unsigned int  master_pos = *(unsigned int*)(ROUND_UP((unsigned long)info->ptr, 64) + sizeof(int));
    unsigned long data_start = (unsigned long)(ROUND_UP((unsigned long)info->ptr, 64) + mvee::numvariants * 64);

    bool          extended   = (info->requested_slot_size == sizeof(long) + sizeof(short) + (mvee::numvariants - 1)) ? false : true;

    for (unsigned int i = 0; i < master_pos; ++i)
    {
        unsigned long  word_ptr  = *(unsigned long*)(data_start + i * info->actual_slot_size);
        unsigned short thread_id = *(unsigned short*)(data_start + i * info->actual_slot_size + sizeof(long));
        unsigned short op_type   = extended ? *(unsigned short*)(data_start + i * info->actual_slot_size + sizeof(long) + sizeof(short)) : ___UNKNOWN_LOCK_TYPE___;

        // we set the lower bit to 1 if the operation is a store => clear it here
        word_ptr = (word_ptr & ~1);

        if (thread_id != prev_thread_id)
        {
            prev_thread_id = thread_id;
            bounce_cnt++;
        }

        op_cnt_total++;

#define INCR_COUNTER(type, search, m)                            \
    {                                                            \
        std::map<type, unsigned long long>::iterator it =        \
            m.find(search);                                      \
        if (it == m.end())                                       \
        {                                                        \
            m.insert(                                            \
                std::pair<type, unsigned long long>(search, 1)); \
        }                                                        \
        else                                                     \
        {                                                        \
            it->second++;                                        \
        }                                                        \
    }

        INCR_COUNTER(unsigned long,  word_ptr,  op_cnt_per_word);
        INCR_COUNTER(unsigned short, thread_id, op_cnt_per_thread);
        INCR_COUNTER(unsigned short, op_type,   op_cnt_per_type);
    }
#endif
}

/*-----------------------------------------------------------------------------
    grab_lock
-----------------------------------------------------------------------------*/
void shm_table::grab_lock()
{
    pthread_mutex_lock(&lock);
}

/*-----------------------------------------------------------------------------
    release_lock
-----------------------------------------------------------------------------*/
void shm_table::release_lock()
{
    pthread_mutex_unlock(&lock);
}

/*-----------------------------------------------------------------------------
    full_release_lock
-----------------------------------------------------------------------------*/
void shm_table::full_release_lock()
{
    while (lock.__data.__owner == syscall(__NR_gettid))
        release_lock();
}

/*-----------------------------------------------------------------------------
    create_info
-----------------------------------------------------------------------------*/
std::shared_ptr<_shm_info> shm_table::create_info(unsigned char buffer_type, unsigned char add_to_list)
{
    std::shared_ptr<_shm_info> result(new _shm_info());

    if (add_to_list)
        table.insert(std::pair<unsigned char, std::shared_ptr<_shm_info> >(buffer_type, result));

    return result;
}
