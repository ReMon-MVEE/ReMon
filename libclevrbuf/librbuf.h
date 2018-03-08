#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/unistd.h>
#include <unistd.h>
#include <errno.h>

#define cpu_relax() asm volatile("rep; nop" ::: "memory")
#define ROUND_UP(x, multiple) ((x + (multiple - 1)) & ~(multiple -1))
#define MVEE_FAKE_SYSCALL_BASE 0x6FFFFFFF
#define MVEE_GET_THREAD_NUM MVEE_FAKE_SYSCALL_BASE + 10
#define MVEE_GET_SHARED_BUFFER MVEE_FAKE_SYSCALL_BASE + 4
#define MVEE_ENABLE_XCHECKS MVEE_FAKE_SYSCALL_BASE + 18
#define MVEE_DISABLE_XCHECKS MVEE_FAKE_SYSCALL_BASE + 19
#define MVEE_RING_BUFFER 22
#define MAX_WAIT_CYCLES 10000

// get the rollover bit from a copy of the head field
// then mask out the bit in the copy
#define GET_WITH_ROLLOVER(head, head_copy, rollover)	\
	head_copy = head;									\
	rollover  = (head_copy) >> (sizeof(long) * 8 - 1);	\
	head_copy = ((head_copy) << 1) >> 1;

#define GET_NO_ROLLOVER(head, head_copy)		\
	head_copy = (head << 1) >> 1;

#define SET_WITH_ROLLOVER(head, head_copy, rollover)			\
	head = (head_copy) | ((rollover) << (sizeof(long) * 8 - 1));

struct buf_pos
{
	// for the master, the head is the position of the next
	// element to be written.
	// for the slaves, the head is the position of the next
	// element to be consumed

	// the upper bit of this field is toggled whenever we
	// roll over
	// by tracking rollovers, we can tell the difference
	// between a slave that has caught up with the master
	// and a slave that is a full ring buffer cycle behind
	volatile unsigned long head; 

	// for the master, this is the position of the oldest
	// element that has not been consumed yet
	// for the slaves, this is the position of the newest
	// element we know of
	unsigned long tail;

	// pad to the end of the cache line
	char pad[64 - 2 * sizeof(unsigned long)];
};

//
// Super scalable ring buffer for single master -> multiple slave streaming
//
struct rbuf
{
	//
	// cacheline 0: read-read sharing only
	//
	unsigned long elems;       // nr of data elements that can fit in the ring buffer
	unsigned long elem_size;   // size of data elements
	unsigned long data_offset; // where does the data start?
	unsigned long slaves;      // nr of slaves
	char pad[64 - sizeof(unsigned long) * 4];

	//
	// cacheline 1 - (slaves-1): position pointers
    //
	struct buf_pos pos[1];	

	//
	// cachelines n and up: data
	//
	// T data[];
};

template<typename T> 
struct rbuf* rbuf_init(size_t capacity, int variants)
{
	int buf_id, buf_sz;
	struct rbuf* buf = nullptr;

	// Not in the MVEE. This is just for native benchmarking.
	if (variants != 0)
	{
		buf_sz = ROUND_UP(64 * (variants + 1) + capacity * sizeof(T), 4096);		
		buf_id = shmget(IPC_PRIVATE, buf_sz, 
						IPC_CREAT | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

		// mark for deletion after we detach
		if (buf_id != -1)
		{
			buf = (struct rbuf*) shmat(buf_id, NULL, 0);

			if (buf == (void*) -1)
			{
				fprintf(stderr, "failed to attach to ring buffer\n");
				return nullptr;
			}

			struct shmid_ds buf_ds;
			if (shmctl(buf_id, IPC_STAT, &buf_ds) || 
				shmctl(buf_id, IPC_RMID, &buf_ds))
			{
				fprintf(stderr, "failed to mark ring buffer for deletion\n");
				return nullptr;
			}
		}
	}
	else
	{
		variants = syscall(MVEE_GET_THREAD_NUM, NULL);
		buf_sz = capacity;

		buf_id = syscall(MVEE_GET_SHARED_BUFFER, 
						 0, // normal buffer
						 MVEE_RING_BUFFER,
						 &buf_sz,
						 sizeof(T));

		if (buf_id == -1)
		{
			fprintf(stderr, "failed to allocate ring buffer\n");
			return nullptr;
		}

		buf = (struct rbuf*) shmat(buf_id, NULL, 0);

		if (buf == (void*) -1)
		{
			fprintf(stderr, "failed to attach to ring buffer\n");
			return nullptr;
		}
	}

	// buf->elems will most likely differ from capacity because we 
	// have to allocate page-sized ring buffers
	if (buf)
	{
		buf->elems = (buf_sz - 64 * (variants + 1)) / sizeof(T);
		buf->elem_size = sizeof(T);
		buf->data_offset = 64 * (variants + 1);
		buf->slaves = variants - 1;
	}

	return buf;
}

template<typename T>
void rbuf_push (struct rbuf* buf, T& elem)
{
	// tail = position of last non-consumed elem (that we know of)
	register unsigned long tail = buf->pos[0].tail, head, rollover;	
	unsigned wait = 0;
	
	// fetch the head value and rollover bit
	GET_WITH_ROLLOVER(buf->pos[0].head, head, rollover);

	// the head can catch up with the tail but can never
	// overtake it
	if (head == tail)
	{
		while (true)
		{
			char all_aligned = 1;
			unsigned long lowest_slave_head_ahead_of_tail = ~0;
			unsigned long lowest_slave_head_behind_tail = ~0;

			for (int i = 0; i < buf->slaves; ++i)
			{
				// for the slaves, the head is the next elem
				// we want to consume
				unsigned long slave_head, slave_rollover;
				GET_WITH_ROLLOVER(buf->pos[i+1].head, slave_head, slave_rollover);

				if (slave_head != head ||
					slave_rollover != rollover)
					all_aligned = 0;

				if (slave_head == tail &&
					slave_rollover != rollover)
					lowest_slave_head_ahead_of_tail = slave_head;

				// see if we can push the tail forward
				if (slave_head > tail &&
					slave_head < lowest_slave_head_ahead_of_tail)
					lowest_slave_head_ahead_of_tail = slave_head;				

				// (some of) the slaves might also have
				// rolled over by now, which moves
				// their heads behind our tail again.				
				if (slave_head < tail &&
					slave_head < lowest_slave_head_behind_tail)
					lowest_slave_head_behind_tail = slave_head;
			}

			// see if we have any slave head in front or aligned with our tail
			if (lowest_slave_head_ahead_of_tail != ~0)
			{
				// ok. there's one in front of our tail.
				if (lowest_slave_head_ahead_of_tail > tail)
				{
					buf->pos[0].tail = tail = lowest_slave_head_ahead_of_tail;
					break;
				}
				
				// there's one aligned with our tail. we have to wait.
				if (wait++ >= MAX_WAIT_CYCLES)
				{
					syscall(__NR_sched_yield);
					wait = 0;
				}
				else
				{
					cpu_relax();
				}
				continue;
			}

			if (lowest_slave_head_behind_tail != ~0)
			{
				// Nothing ahead of us, move the tail to the last slave behind our tail
				buf->pos[0].tail = tail = lowest_slave_head_behind_tail;
				break;
			}

			// we can move if the slaves are just waiting for us
			if (all_aligned)
				break;
		}
	}

	// write element
	*reinterpret_cast<T*>((unsigned long) buf + buf->data_offset + buf->elem_size * head) = elem;

	// barrier needed because the element must be visible before our updated
	// position becomes visible
	__sync_synchronize();

	// handle rollover
	if (head + 1 == buf->elems)
	{
		// flip rollover bit
		SET_WITH_ROLLOVER(buf->pos[0].head, 0, rollover ^ 1);
	}
	else
	{
		SET_WITH_ROLLOVER(buf->pos[0].head, head + 1, rollover);
	}
}

template<typename T>
void rbuf_peek (struct rbuf* buf, int slave_num, T& elem, T& expected)
{
	register unsigned long slave_head, slave_rollover, master_rollover;
	register unsigned long last_seen_master_head = buf->pos[slave_num + 1].tail;
	unsigned wait = 0;

	GET_WITH_ROLLOVER(buf->pos[slave_num + 1].head, 
					  slave_head, 
					  slave_rollover);

	while (last_seen_master_head == slave_head)
	{
		GET_WITH_ROLLOVER(buf->pos[0].head, 
						  buf->pos[slave_num + 1].tail, 
						  master_rollover);

		last_seen_master_head = buf->pos[slave_num + 1].tail;

		// the master might be a full cycle ahead of us
		if (master_rollover != slave_rollover)
			break;
		
		if (wait++ >= MAX_WAIT_CYCLES)
		{
			syscall(__NR_sched_yield);
			wait = 0;
		}
		else
		{
			cpu_relax();
		}
	}

	// if the master and slave heads are not equal, there's data in the buffer
	elem = *reinterpret_cast<T*>((unsigned long) buf + buf->data_offset + buf->elem_size * slave_head);

	// we must have copied the elem before we can update our position
	__sync_synchronize();

	if (elem == expected)
	{
		// handle rollover
		if (slave_head + 1 == buf->elems)		
		{
			SET_WITH_ROLLOVER(buf->pos[slave_num + 1].head, 0, slave_rollover ^ 1);
		}
		else
		{
			SET_WITH_ROLLOVER(buf->pos[slave_num + 1].head, slave_head + 1, slave_rollover);
		}
	}
}
