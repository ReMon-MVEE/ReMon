/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <unistd.h>
#include <string.h>
#include "../MVEE_multipolling/Inc/MVEE_fake_syscall.h"
#include "../MVEE_multipolling/Inc/MVEE_interposer_base_shared.h"

/*-----------------------------------------------------------------------------
    Global Vars
-----------------------------------------------------------------------------*/
unsigned short mvee_interposer_childnum        = 0;
unsigned short mvee_interposer_numchilds       = 0;
__thread int   mvee_interposer_masterthread_id = 0;

/*-----------------------------------------------------------------------------
    mvee_interposer_global_init - fetches childnum and numchilds
-----------------------------------------------------------------------------*/
void __attribute__((constructor))  mvee_interposer_global_init()
{
    int childmask = 0;
    syscall(MVEE_GET_THREAD_NUM, &mvee_interposer_childnum, &childmask);
    while ((childmask >> mvee_interposer_numchilds) & 0x1)
        mvee_interposer_numchilds++;
}

/*-----------------------------------------------------------------------------
    mvee_interposer_thread_init - refreshes masterthread_id
-----------------------------------------------------------------------------*/
void  mvee_interposer_thread_init()
{
    // we ignore this now, if childnum == 0, we already know that we're
    // the master variant
    int master_variant;
    mvee_interposer_masterthread_id = syscall(MVEE_GET_MASTERTHREAD_ID, &master_variant);
}

/*-----------------------------------------------------------------------------
    mvee_interposer_log_stack
-----------------------------------------------------------------------------*/
void  mvee_interposer_log_stack
(
    struct mvee_interposer_buffer_info* info,
    int                                 current_pos
)
{
    int i;
    for (i = 0; i < info->_eip_stack_depth; ++i)
    {
        int eip = 0;

        /* __builtin_return_address needs a constant argument :| */
        switch (i)
        {
        case 0: eip = (int)__builtin_return_address(1); break;
        case 1: eip = (int)__builtin_return_address(2); break;
        case 2: eip = (int)__builtin_return_address(3); break;
        case 3: eip = (int)__builtin_return_address(4); break;
        case 4: eip = (int)__builtin_return_address(5); break;
        case 5: eip = (int)__builtin_return_address(6); break;
        case 6: eip = (int)__builtin_return_address(7); break;
        case 7: eip = (int)__builtin_return_address(8); break;
        case 8: eip = (int)__builtin_return_address(9); break;
        case 9: eip = (int)__builtin_return_address(10); break;
        }

        *(int*)((unsigned int)info->_eip_buffer +
                /* select the right buffer slot */
                info->_eip_stack_depth * 4 * mvee_interposer_numchilds * current_pos +
                /* select this child's position in the slot	*/
                info->_eip_stack_depth * 4 * mvee_interposer_childnum +
                /* select this callee's position in the slot */
                i * 4
                )
            = eip;
    }
}

/*-----------------------------------------------------------------------------
    mvee_interposer_buffer_init -
    @param info struct that identifies the buffer
    @param buffer_type see MVEE/Inc/MVEE_fake_syscall.h for existing types
    @param log_eips if 1, a parallel eip buffer will be allocated
    @param eip_stack_depth depth of the stacks logged into this parallel buffer
-----------------------------------------------------------------------------*/
void  mvee_interposer_init_buffer
(
    struct mvee_interposer_buffer_info* info,
    int                                 buffer_type,
    uchar                               log_eips,
    ushort                              eip_stack_depth
)
{
    memset((void*)info, 0, sizeof(struct mvee_interposer_buffer_info));

    info->_shared_buffer_type = buffer_type;
    info->_shared_buffer_id   = syscall(MVEE_GET_SHARED_BUFFER,
                /* 0 = requesting normal buffer */
                                        0, buffer_type, &info->_shared_buffer_size,
                /* we're requesting 4 byte slots to garantuee that we'll have enough */
                /* slots in the eip buffer to log callstacks even for 8 bit data */
                                        4);

    if (info->_shared_buffer_id != -1)
    {
        info->_shared_buffer      = (void*)shmat(info->_shared_buffer_id, NULL, 0);
        info->_shared_buffer_pos  = (volatile int*)((unsigned int)info->_shared_buffer
                /* skip one position because of the spinlock */
                                                    + (mvee_interposer_childnum + 1) * 4);

        *info->_shared_buffer_pos = (1 + mvee_interposer_numchilds);

        /* also request an eip buffer if needed. this eip buffer */
        /* contains a partial callstack for every operation in the */
        /* normal buffer. Unlike the normal buffer though, */
        /* the eip buffer WILL contain data for EVERY child, not just */
        /* the master!!! */
        if (log_eips)
        {
            info->_eip_stack_depth = eip_stack_depth ? eip_stack_depth : 4;
            info->_eip_buffer_id   = syscall(MVEE_GET_SHARED_BUFFER,
                /* 1 = requesting eip buffer. */
                                             1, buffer_type, &info->_eip_buffer_size, info->_eip_stack_depth * 4 * mvee_interposer_numchilds,
                /* we pass the stack depth to the monitor as well so */
                /* the monitor can print out the eip buffer nicely */
                /* should a backtrace be requested */
                                             info->_eip_stack_depth);
            if (info->_eip_buffer_id != -1)
                info->_eip_buffer = (void*)shmat(info->_eip_buffer_id, NULL, 0);
        }
    }
}

/*-----------------------------------------------------------------------------
    mvee_interposer_write_lock_acquire -
-----------------------------------------------------------------------------*/
void  mvee_interposer_write_lock_acquire (struct mvee_interposer_buffer_info* info)
{
    while(!__sync_bool_compare_and_swap((int*)info->_shared_buffer, 0, 1));
}

/*-----------------------------------------------------------------------------
    mvee_interposer_write_data
-----------------------------------------------------------------------------*/
void  mvee_interposer_write_data (struct mvee_interposer_buffer_info* info, short data_size, void* data)
{
    int temppos = *(volatile int*)info->_shared_buffer_pos;

    /* select the appropriate writing function to log this operation */
    switch (data_size)
    {
    /* char sized */
    case 1:
        *(int*)(info->_shared_buffer + temppos * 4)
                                                  = mvee_interposer_masterthread_id | ((*(unsigned char*)data) << 24);
        *(volatile int*)info->_shared_buffer_pos += 1;
        break;
    /* short sized */
    case 2:
        *(int*)(info->_shared_buffer + temppos * 4 + 4)
                                                  = *(unsigned short*)data;
        /* the data should not be visible before the masterthread id is */
        __sync_synchronize();
        *(int*)(info->_shared_buffer + temppos * 4)
                                                  = mvee_interposer_masterthread_id | (1 << 16);
        *(volatile int*)info->_shared_buffer_pos += 2;
        break;
    /* int sized */
    case 4:
        *(int*)(info->_shared_buffer + temppos * 4 + 4)
                                                  = *(unsigned int*)data;
        __sync_synchronize();
        *(int*)(info->_shared_buffer + temppos * 4)
                                                  = mvee_interposer_masterthread_id | (1 << 16);
        *(volatile int*)info->_shared_buffer_pos += 2;
        break;
    /* ulonglong sized */
    case 8:
        *(ulonglong*)(info->_shared_buffer + temppos * 4 + 4)
                                                  = *(ulonglong*)data;
        __sync_synchronize();
        *(int*)(info->_shared_buffer + temppos * 4)
                                                  = mvee_interposer_masterthread_id | (2 << 16);
        *(volatile int*)info->_shared_buffer_pos += 3;
        break;

    }

    /* optionally, log a partial call stack */
    if (info->_eip_buffer)
        mvee_interposer_log_stack(info, temppos);

    /* And finally, move to the next position but beware of the */
    /* rollover! We want enough remaining space to log at least another */
    /* 64bit operation */
    if ((*info->_shared_buffer_pos) * 4 + 12 > info->_shared_buffer_size)
    {
        /* queue rolled over! Request a queue flush. This operation */
        /* will be synced by the monitor! So that the master will */
        /* only be able to move once when the slaves have all */
        /* reached the end of the queue themselves! */
        syscall(MVEE_FLUSH_SHARED_BUFFER, info->_shared_buffer_type);
        *(volatile int*)info->_shared_buffer_pos = (1 + mvee_interposer_numchilds);
    }
}

/*-----------------------------------------------------------------------------
    mvee_interposer_write_data
-----------------------------------------------------------------------------*/
void  mvee_interposer_write_lock_release (struct mvee_interposer_buffer_info* info)
{
    __sync_lock_release((int*)info->_shared_buffer);
}

/*-----------------------------------------------------------------------------
    mvee_interposer_read_data - this is probably the most inefficient function
    in all of the MVEE code... we spin in a busy loop until the masterthread
    id in the current slot matches our own...
-----------------------------------------------------------------------------*/
void  mvee_interposer_read_data (struct mvee_interposer_buffer_info* info, short data_size, void* data)
{
    while (1)
    {
        int temppos = *(volatile int*)(info->_shared_buffer_pos);

        /* make sure that we're still reading inside the bounds of the buffer */
        /* if we're not, one of our threads ought to be calling MVEE_FLUSH_BUFFER */
        if (temppos < info->_shared_buffer_size / 4)
        {
            int threadid = (*(int*)(info->_shared_buffer + temppos * 4) & 0xFFFF);

            if (threadid == mvee_interposer_masterthread_id)
            {
                /* check if the data_size matches what was recorded */
                int slot_size = (*(int*)(info->_shared_buffer + temppos * 4) & 0x00FF0000) >> 16;

                if ((slot_size == 0 && data_size != 1)
                    || (slot_size == 1 && data_size != 2 && data_size != 4)
                    || (slot_size == 2 && data_size != 8))
                {
                    /* inform the monitor */
                    syscall(224, 1337, 10000001, 76, temppos, slot_size, data_size);
                    return;
                }

                /* data size matches, fetch the data from the buffer */
                switch(data_size)
                {
                case 1:
                {
                    uchar _data = (uchar)((*(int*)(info->_shared_buffer + temppos * 4) & 0xFF000000) >> 24);
                    memcpy(data, &_data, 1);
                    break;
                }
                case 2:
                {
                    ushort _data = (ushort)*(int*)(info->_shared_buffer + temppos * 4 + 4);
                    memcpy(data, &_data, 2);
                    break;
                }
                case 4:
                {
                    uint _data = (uint)*(int*)(info->_shared_buffer + temppos * 4 + 4);
                    memcpy(data, &_data, 4);
                    break;
                }
                case 8:
                {
                    ulonglong _data = (ulonglong)*(int*)(info->_shared_buffer + temppos * 4 + 4);
                    memcpy(data, &_data, 8);
                    break;
                }
                }

                if (info->_eip_buffer)
                    mvee_interposer_log_stack(info, temppos);

                return;
            }

            /* FUTURE SUPER DUPER OPTIMIZATION: at the end of the loop, inspect the next */
            /* element (if any). If the next element contains a different thread id */
            /* then inform the MVEE. */
        }

        /* yield - we should REALLY get rid of this some time soon! */
        syscall(158);
    }
}

/*-----------------------------------------------------------------------------
    mvee_interposer_read_wake - move the pointer and handle rollover
-----------------------------------------------------------------------------*/
void  mvee_interposer_read_wake (struct mvee_interposer_buffer_info* info)
{
    int current_pos = *(volatile int*)info->_shared_buffer_pos;
    int slot_size   = (*(int*)(info->_shared_buffer + current_pos * 4) & 0x00FF0000) >> 16;

    *(info->_shared_buffer_pos) += 1 + slot_size;

    /* we have to get the current slot size from the buffer first */
    if ((*info->_shared_buffer_pos) * 4 + 12 > info->_shared_buffer_size)
    {
        /* queue rolled over! Request a queue flush. This operation */
        /* will be synced by the monitor! So that the master will */
        /* only be able to move once when the slaves have all */
        /* reached the end of the queue themselves! */
        syscall(MVEE_FLUSH_SHARED_BUFFER, info->_shared_buffer_type);
        *(volatile int*)info->_shared_buffer_pos = (1 + mvee_interposer_numchilds);
    }
}
