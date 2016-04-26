/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    This header describes the interposer base functionality implemented by
    the mvee lazy hooker
-----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Typedefs
-----------------------------------------------------------------------------*/
//
// extra typedefs to ensure that we can express every type without whitespaces
//
typedef unsigned char      uchar;
typedef unsigned short     ushort;
typedef unsigned int       uint;
typedef long long          longlong;
typedef unsigned long long ulonglong;

//
// All interposed operations performed by the master variant are logged
// into the shared buffer array(s). This shared buffer is shared between
// ALL variants.
//
// The master variant needs to grab a lock to write into this buffer
// (see below).
//
//
// Buffer layout:
//
// * normal buffer:
//   +------------+------+------+...+------+---------+--------+...+--------+
//   | spinlock   | pos1 | pos2 |...| posN | PADDING | data0  |...| dataN  |
//   +------------+------+------+...+------+---------+--------+...+--------+
//
//   NOTES:
//   + the spinlock is word-sized for obvious reasons
//   + every variant stores its current position in the buffer in its associated posX slot
//   + optional padding is inserted between posN and data0 so that data0 starts at a multiple
//     of slot_size
//
// * eip buffer:
//   +---------------------------+--------+...+--------+
//   | PADDING                   | data0  |...| dataN  |
//   +---------------------------+--------+...+--------+
//
//   NOTES:
//   + padding is inserted at the start of the buffer so that buffer_slot_pos
//   can be used as the position for both the normal buffer and the eip buffer
//   + every data slot contains partial callstacks for ALL variants
//
// As of December 2013, multiple data slots may be used to represent one operation.
// To support such behavior, a data slot will always be 4 bytes long. The first data
// slot that represents an operation contains the thread id in the lower 16 bits,
// the amount of data slots following the primary slot in bits 23-16 and the first
// 8 bits of the actual data in bits 31-24.
//
struct mvee_interposer_buffer_info
{
    int            _shared_buffer_type; // see MVEE/Inc/MVEE_fake_syscall.h
    int            _shared_buffer_id;   // shm id for the shared buffer
    void*          _shared_buffer;      // ptr to the buffer
    unsigned int   _shared_buffer_size; // size of the buffer - must be a multiple of the slot size
    volatile int*  _shared_buffer_pos;  // pointer to this process' position in the buffer
    int            _eip_buffer_id;      // shm id for the parallel eip buffer
    void*          _eip_buffer;         // ptr to the eip buffer
    unsigned int   _eip_buffer_size;    // size of the buffer - must be able to hold numvariants * stack_depth * shared_buffer_slot_size callees
    unsigned short _eip_stack_depth;    // stack depth for the partial callstacks
};

/*-----------------------------------------------------------------------------
    Shared global variables
-----------------------------------------------------------------------------*/
//
// Which variant are we (as seen by the monitor)
//
extern unsigned short mvee_interposer_variantnum;

//
// How many variants are there?
//
extern unsigned short mvee_interposer_numvariants;

//
// If we're not the master variant, this is the tid of this thread's
// equivalent thread in the master variant. We need to look for this
// tid in the shared buffer if we want to perform an interposed operation
//
extern __thread int   mvee_interposer_masterthread_id;

/*-----------------------------------------------------------------------------
    Shared interposer functions
-----------------------------------------------------------------------------*/
#ifdef __cplusplus
extern "C"
{
#endif
// interposer base initialization
void mvee_interposer_global_init           ();
void mvee_interposer_thread_init           ();

// initializes a shared buffer of the specified buffer_type
// > buffer_data_size is the size of the data we'll write into/read from each slot
// > log_eips allows us to create a separate, parallel buffer that logs partial callstacks
// > eip_stack_depth specifies the depth of this partial callstack
void mvee_interposer_init_buffer           (struct mvee_interposer_buffer_info* info, int buffer_type, uchar log_eips, ushort eip_stack_depth);

// logs a partial callstack into the separate eip buffer
void mvee_interposer_log_stack             (struct mvee_interposer_buffer_info* info, int current_pos);

// write the result of an operation into
void mvee_interposer_write_lock_acquire    (struct mvee_interposer_buffer_info* info);
void mvee_interposer_write_lock_release    (struct mvee_interposer_buffer_info* info);
void mvee_interposer_write_data            (struct mvee_interposer_buffer_info* info, short data_size, void* data);
void mvee_interposer_read_data             (struct mvee_interposer_buffer_info* info, short data_size, void* data);
void mvee_interposer_read_wake             (struct mvee_interposer_buffer_info* info);

#ifdef __cplusplus
}
#endif
