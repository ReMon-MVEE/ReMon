/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in IPMONLICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Some system calls, particularly the ones that relate to resource management,
    have to complete in the same order in all variants. Possible consequences 
	of not executing these calls in the same order are:
	1) IP-MON's bookkeeping (e.g. the file map) might become inconsistent
	2) There might be situations where syscalls fail in some variants but not
	in others.

	In GHUMVEE, we use a "syslock" mechanism to prevent variants from entering
	certain syscalls while a related syscall is still in flight in other
	variants.

	In IP-MON, we cannot implement such a mechanism due to the decentralized
	nature of the monitor. Instead, we can use logical clocks and assign the
	current clock value to each "order-sensitive" syscall.
-----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <alloca.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <termios.h>
#include <sys/inotify.h>
#include <net/if.h>
#include "MVEE_ipmon.h"
#include "MVEE_ipmon_memory.h"
#include "../MVEE/Inc/MVEE_fake_syscall.h"
#include "../MVEE/Inc/MVEE_build_pku_config.h"
#include "../MVEE/Inc/MVEE_erim.h"

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
//
// Retard check - is the loaded kernel compatible with IP-MON or not?
//
extern "C" unsigned char ipmon_initialized; // MVEE_ipmon_syscall.S
unsigned char            ipmon_kernel_compatible = 0;
unsigned char            ipmon_variant_num       = 0;

//
// Mask of syscalls that may be handled by IP-MON and bypass the ptracer
// Note that mask and kernelmask may differ because we might request
// that certain calls (e.g. sys_futex) be allowed to bypass the ptracer
// even if we want to dispatch them as checked calls in IP-MON.
// 
IPMON_MASK(mask);
IPMON_MASK(kernelmask);

/*-----------------------------------------------------------------------------
    IP-MON shared memory regions
-----------------------------------------------------------------------------*/
// This buffer contains information about the file types for each fd

// TODO: With the full syscalls policy, we might have to invalidate CLOEXEC
// file descriptors ourselves...
long           ipmon_reg_file_map_id          = -1;
char*          ipmon_reg_file_map             = NULL;

/*-----------------------------------------------------------------------------
    Additional Bookkeeping
-----------------------------------------------------------------------------*/
//
// All of the syscalls that allocate new file descriptors return the master's
// fd value, even if the slaves do in fact execute that same syscall.
//
// Thus, for subsequent syscalls, we need a way to map master fds to slave fds.
//
// One situation where this may happen is when the variants load shared libs.
// To load a shared lib, a program has to open the shared lib's file
// using sys_open first. This sys_open call has to be executed by all variants,
// so that the resulting fd is available for subsequent mmap calls.
//
// To simplify fd management, however, we return the master's fd value from
// sys_open. This fd value might differ between variants. Thus, we store a
// mapping in the ipmon_master_fd_to_slave_fd table below.
//
char           ipmon_master_fd_to_slave_fd [4096];

//
// We keep a similar shadow stucture to map fds registered with epoll instances.
// This is explained in the USENIX ATC16 paper.
//
unsigned long ipmon_epoll_map[MAX_FDS][MAX_FDS];
int           ipmon_epoll_map_spinlock = 1;
volatile int* ipmon_epoll_map_lock_ptr = &ipmon_epoll_map_spinlock;

/*-----------------------------------------------------------------------------
    Syscall Ordering Support
-----------------------------------------------------------------------------*/
//
// This is a logical (lamport-style) clock.
//
// NOTE: This mechanism will NOT always work. One situation where it will fail
// is when variants fd spaces but not their address spaces. This can
// happen if you pass weird arguments to sys_clone (i.e. CLONE_FILES but 
// not CLONE_VM). Luckily, I don't think I've ever seen this.
//
int syscall_ordering_clock = 0;

//
// The lock that protects the clock.
//
struct ipmon_mutex syscall_ordering_mutex;

void ipmon_mutex_lock   (struct ipmon_mutex* mut);
void ipmon_mutex_unlock (struct ipmon_mutex* mut);

/*-----------------------------------------------------------------------------
    ipmon_arg_verify_failed - Just crash the variant. It's super user friendly!

	Conventions:
	- For syscall number mismatches:
	=> syscall_no is the master number, arg_no is 0, arg_val is the slave number

	- For argument length mismatches:
	=> arg_no is in the [-6..-1] range, arg_val is the length of the arg in the slave
	=> master arg length can be read from the buffer

	- For argument value mismatches:
	=> arg_no is in the [1..6] range, arg_val is the value of the arg in the slave
	=> master arg value can be read from the buffer

	- Misc IP-MON failures:
	=> syscall_no and arg_no are -1	
-----------------------------------------------------------------------------*/
void ipmon_arg_verify_failed
(
	unsigned long syscall_no, 
	unsigned char arg_no, 
	unsigned long arg_val
)
{
	unsigned long tmp = (syscall_no << 8) | arg_no;

	__asm __volatile ("movq %0, %%rax; movq %1, %%rbx; movq %%rax, (0)"
					  : : "m" (tmp), "m" (arg_val) : "rbx", "rax", "memory");
}

/*-----------------------------------------------------------------------------
    FD mapping support
-----------------------------------------------------------------------------*/
void ipmon_set_slave_fd(int master_fd, int slave_fd)
{
	if (master_fd < 0 || master_fd > 4096)
		ipmon_arg_verify_failed(-1, -1, master_fd);
	ipmon_master_fd_to_slave_fd[master_fd] = slave_fd;
}

int ipmon_get_slave_fd(int master_fd)
{
	if (master_fd < 0 || master_fd > 4096)
		return master_fd;
	return ipmon_master_fd_to_slave_fd[master_fd];
}

/*-----------------------------------------------------------------------------
    IP-MON epoll support
-----------------------------------------------------------------------------*/
#define atomic_decrement_and_test(mem)					\
	({ unsigned char __result;							\
	__asm __volatile ("lock decl %0; sete %1"			\
					  : "=m" (*mem), "=qm" (__result)	\
					  : "m" (*mem));					\
	__result; })

void ipmon_epoll_lock()
{
	while (1)
	{
		if (atomic_decrement_and_test(ipmon_epoll_map_lock_ptr))
			return;

		while (*ipmon_epoll_map_lock_ptr <= 0)
			cpu_relax();
	}
}

void ipmon_epoll_unlock()
{
	gcc_barrier();
	*ipmon_epoll_map_lock_ptr = 1;
}

void ipmon_epoll_set_ptr_for_fd(int epoll_fd, int fd, unsigned long ptr)
{
	ipmon_epoll_map[epoll_fd][fd] = ptr;
}

unsigned long ipmon_epoll_get_ptr_for_fd(int epoll_fd, int fd)
{
	return ipmon_epoll_map[epoll_fd][fd];
}

int ipmon_epoll_get_fd_for_ptr(int epoll_fd, unsigned long ptr)
{
	// optimization
	if (ptr < 4096)
		return ptr;

	for (int i = 0; i < MAX_FDS; ++i)
		if (ipmon_epoll_map[epoll_fd][i] == ptr)
			return i;

	return 0;
}

/*-----------------------------------------------------------------------------
    Keeping track of blocking/non-blocking system calls
-----------------------------------------------------------------------------*/
char ipmon_get_file_type(unsigned long fd)
{
	return 0;
	if (fd >= 4096)
		return 0;

	return ipmon_reg_file_map[fd];
}

/*-----------------------------------------------------------------------------
    ipmon_is_master_file
-----------------------------------------------------------------------------*/
unsigned char ipmon_is_master_file(unsigned long fd)
{
	if (ipmon_get_file_type(fd) & FT_MASTER_FILE)
		return 1;
	return 0;
}

/*-----------------------------------------------------------------------------
    Keeping track of blocking/non-blocking system calls
-----------------------------------------------------------------------------*/
void ipmon_set_file_type(unsigned long fd, char type)
{
	if (fd > 4096)
		return;

	ipmon_reg_file_map[fd] = type;
}


/*-----------------------------------------------------------------------------
    ipmon_can_read
-----------------------------------------------------------------------------*/
bool ipmon_can_read(long fd)
{
#if CURRENT_POLICY >= SOCKET_RO_POLICY
	return true;
#elif CURRENT_POLICY >= NONSOCKET_RO_POLICY
	char type = ipmon_get_file_type(fd) & (~MVEE_BLOCKING_FD);

	if (type != FT_SOCKET_NON_BLOCKING)
		return true;
	return false;
#else
	return false;
#endif
}


/*-----------------------------------------------------------------------------
    ipmon_can_write
-----------------------------------------------------------------------------*/
bool ipmon_can_write(long fd)
{
#if CURRENT_POLICY >= SOCKET_RW_POLICY
	return true;
#elif CURRENT_POLICY >= NONSOCKET_RW_POLICY
	char type = ipmon_get_file_type(fd) & (~MVEE_BLOCKING_FD);

	if (type != FT_SOCKET_NON_BLOCKING)
		return true;
	return false;
#else
	return false;
#endif
}

/*-----------------------------------------------------------------------------
    mmap - (unsigned long addr, unsigned long len, unsigned long prot, 
	unsigned long flags, int fd, unsigned long pgoff)
-----------------------------------------------------------------------------*/
CALCSIZE(mmap)
{
//	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(mmap)
{
	// TODO: Handle that ptmalloc weirdness? This will be tricky

	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKREG(ARG5);

	// pgoff is ignored for anon mappings
	if ((int)ARG5 != -1 && !(ARG4 & MAP_ANONYMOUS))
	{
		CHECKREG(ARG6);
		ARG5 = ipmon_get_slave_fd(ARG5);
	}
	if (ARG3 & PROT_EXEC)
		return IPMON_EXEC_ALL | IPMON_ORDER_CALL | IPMON_LOCKSTEP_CALL;
	return IPMON_EXEC_ALL | IPMON_ORDER_CALL;
}

/*-----------------------------------------------------------------------------
    munmap - (void* addr, size_t len)
-----------------------------------------------------------------------------*/
unsigned char ipmon_handle_munmap_is_unsynced() 
{ 
	return 1; 
}

/*-----------------------------------------------------------------------------
    mprotect - (void* addr, size_t len, int prot)
-----------------------------------------------------------------------------*/
CALCSIZE(mprotect)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(mprotect)
{
	CHECKPOINTER(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	if (ARG3 & PROT_EXEC)
		return IPMON_EXEC_ALL | IPMON_ORDER_CALL | IPMON_LOCKSTEP_CALL;
	return IPMON_EXEC_ALL | IPMON_ORDER_CALL;
}

/*-----------------------------------------------------------------------------
    mremap - (void* old_address, size_t old_size, 
	size_t new_size, int flags, void* new_addr)
-----------------------------------------------------------------------------*/
CALCSIZE(mremap)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(mremap)
{
	CHECKPOINTER(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKPOINTER(ARG5);
	return IPMON_EXEC_ALL | IPMON_ORDER_CALL;
}

/*-----------------------------------------------------------------------------
    brk - (void* addr)
-----------------------------------------------------------------------------*/
CALCSIZE(brk)
{
	COUNTREG(ARG);
}

PRECALL(brk)
{
	CHECKPOINTER(ARG1);
	return IPMON_EXEC_ALL | IPMON_ORDER_CALL;
}

/*-----------------------------------------------------------------------------
    open - (const char* filename, int flags, int mode)
-----------------------------------------------------------------------------*/
CALCSIZE(open)
{
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(open)
{
	// mask out non-existing modes and flags
	long tmp_arg2 = ARG2 & O_FILEFLAGSMASK;
	long tmp_arg3 = ARG3 & S_FILEMODEMASK;

	CHECKPOINTER(ARG1);
	CHECKREG(tmp_arg2);
//	CHECKREG(tmp_arg3); // TODO: stijn: false positives here??
	CHECKSTRING(ARG1);

	bool master = false;

	// Only the master should open /proc/self files (except for the maps and exe files)
	if (strstr((char*)ARG1, "/proc/self/") &&
		!(strstr((char*)ARG1, "/proc/self/maps") || strstr((char*)ARG1, "/proc/self/exe")))
		master = true;

	// Ditto with /dev/
	if (strstr((char*)ARG1, "/dev/"))
		master = true;

	// TODO: Handle O_CREAT | O_EXCL in case we're executing a normal call

	if (master)
		return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER  | IPMON_LOCKSTEP_CALL;
	return IPMON_EXEC_ALL | IPMON_REPLICATE_MASTER | IPMON_LOCKSTEP_CALL | IPMON_ORDER_CALL;
}

POSTCALL(open)
{
	// mark file in fd table
	if (success)
	{		
		if (entry->syscall_type & IPMON_EXEC_MASTER)
		{
			if (ipmon_variant_num == 0)
				ipmon_set_file_type(ret, FT_REGULAR | FT_MASTER_FILE);
		}
		else if (entry->syscall_type & IPMON_EXEC_ALL)
		{
			if (ipmon_variant_num == 0)
				ipmon_set_file_type(ret, FT_REGULAR);
			ipmon_set_slave_fd(ret, realret);
		}
	}
	return order;
}

/*-----------------------------------------------------------------------------
    openat - (int dirfd, const char* filename, int flags, int mode)
-----------------------------------------------------------------------------*/
CALCSIZE(openat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG2);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(openat)
{
	// mask out non-existing modes and flags
	long tmp_arg3 = ARG3 & O_FILEFLAGSMASK;
	long tmp_arg4 = ARG4 & S_FILEMODEMASK;

	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(tmp_arg3);
//	CHECKREG(tmp_arg4); // TODO: stijn: false positives here??
	CHECKSTRING(ARG2);

	bool master = false;

	// Only the master should open /proc/self files (except for the maps and exe files)
	if (strstr((char*)ARG2, "/proc/self/") &&
		!(strstr((char*)ARG2, "/proc/self/maps") || strstr((char*)ARG2, "/proc/self/exe")))
		master = true;

	// Ditto with /dev/
	if (strstr((char*)ARG2, "/dev/"))
		master = true;

	// TODO: Handle O_CREAT | O_EXCL in case we're executing a normal call

	if (master)
		return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER  | IPMON_LOCKSTEP_CALL;
	return IPMON_EXEC_ALL | IPMON_REPLICATE_MASTER | IPMON_LOCKSTEP_CALL | IPMON_ORDER_CALL;
}

POSTCALL(openat)
{
	// mark file in fd table
	if (success)
	{		
		if (entry->syscall_type & IPMON_EXEC_MASTER)
		{
			if (ipmon_variant_num == 0)
				ipmon_set_file_type(ret, FT_REGULAR | FT_MASTER_FILE);
		}
		else if (entry->syscall_type & IPMON_EXEC_ALL)
		{
			if (ipmon_variant_num == 0)
				ipmon_set_file_type(ret, FT_REGULAR);
			ipmon_set_slave_fd(ret, realret);
		}
	}
	return order;
}

/*-----------------------------------------------------------------------------
    socket - (int family, int type, int protocol)
-----------------------------------------------------------------------------*/
CALCSIZE(socket)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(socket)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(socket)
{
	if (success)
	{
		if (ipmon_variant_num == 0)
			ipmon_set_file_type(ret, (ARG2 & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING);
	}
	return order;
}

/*-----------------------------------------------------------------------------
    bind - (int fd, struct sockaddr* addr, int addrlen)
-----------------------------------------------------------------------------*/
CALCSIZE(bind)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, ARG3);
}

PRECALL(bind)
{
	CHECKREG(ARG1);
	CHECKREG(ARG3);
	CHECKPOINTER(ARG2);
	CHECKSOCKADDR(ARG2, ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    connect - (int fd, struct sockaddr* addr, int addrlen)
-----------------------------------------------------------------------------*/
CALCSIZE(connect)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, ARG3);
}

PRECALL(connect)
{
	CHECKREG(ARG1);
	CHECKREG(ARG3);
	CHECKPOINTER(ARG2);
	CHECKSOCKADDR(ARG2, ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    listen - (int fd, int backlog)
-----------------------------------------------------------------------------*/
CALCSIZE(listen)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(listen)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    socketpair - (int family, int type, int protocol, int* sockvec)
-----------------------------------------------------------------------------*/
CALCSIZE(socketpair)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG4, sizeof(int) * 2);
}

PRECALL(socketpair)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKPOINTER(ARG4);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(socketpair)
{
	if (success)
	{
		if (ipmon_variant_num == 0)
		{
			ipmon_set_file_type(((int*)ARG4)[0], (ARG2 & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING);
			ipmon_set_file_type(((int*)ARG4)[1], (ARG2 & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING);
		}

		REPLICATEBUFFER(ARG4, sizeof(int) * 2);
	}
	return order;
}

/*-----------------------------------------------------------------------------
    accept4 - (int fd, struct sockaddr* peer_sockaddr, int* peer_addrlen, int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(accept4)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	if (ARG2 && ARG3)
	{
		COUNTBUFFER(RET, ARG3, sizeof(int));
		COUNTBUFFER(RET, ARG2, *(int*)ARG3); 
	}
}

PRECALL(accept4)
{
	CHECKREG(ARG1);
	CHECKREG(ARG4);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(accept4)
{
	if (success)
	{
		if (ARG2 && ARG3)
		{
			REPLICATEBUFFER(ARG3, sizeof(int));
			REPLICATEBUFFER(ARG2, *(int*)ARG3);
		}

		if (ipmon_variant_num == 0)
			ipmon_set_file_type(ret, (ARG2 & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING);
	}
	return order;
}

/*-----------------------------------------------------------------------------
    accept - (int fd, struct sockaddr* peer_sockaddr, int* peer_addrlen)
-----------------------------------------------------------------------------*/
CALCSIZE(accept)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	if (ARG2 && ARG3)
	{
		COUNTBUFFER(RET, ARG3, sizeof(int));
		COUNTBUFFER(RET, ARG2, *(int*)ARG3);
	}
}

PRECALL(accept)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(accept)
{
	if (success)
	{
		if (ARG2 && ARG3)
		{
			REPLICATEBUFFER(ARG3, sizeof(int));
			REPLICATEBUFFER(ARG2, *(int*)ARG3);
		}

		if (ipmon_variant_num == 0)
			ipmon_set_file_type(ret, (ARG2 & SOCK_NONBLOCK) ? FT_SOCKET_NON_BLOCKING : FT_SOCKET_BLOCKING);
	}
	return order;
}

/*-----------------------------------------------------------------------------
    epoll_create - (int size)
-----------------------------------------------------------------------------*/
CALCSIZE(epoll_create)
{
	COUNTREG(ARG);
}

PRECALL(epoll_create)
{
	CHECKREG(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(epoll_create)
{
	if (success && ipmon_variant_num == 0)
		ipmon_set_file_type(ret, FT_POLL_BLOCKING);
	return order;
}

/*-----------------------------------------------------------------------------
    epoll_create1 - (int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(epoll_create1)
{
	COUNTREG(ARG);
}

PRECALL(epoll_create1)
{
	CHECKREG(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(epoll_create1)
{
	// flags is just used for cloexec. nothing more...
	if (success && ipmon_variant_num == 0)
		ipmon_set_file_type(ret, FT_POLL_BLOCKING);
	return order;
}

/*-----------------------------------------------------------------------------
    close - (int fd)
-----------------------------------------------------------------------------*/
CALCSIZE(close)
{
	COUNTREG(ARG);
}

PRECALL(close)
{
	CHECKREG(ARG1);
	IPMON_MAYBE_DISPATCH_MASTER(ARG1);
}

POSTCALL(close)
{
	if (success && ipmon_variant_num == 0)
		ipmon_set_file_type(ARG1, FT_UNKNOWN);
	return order;
}

/*-----------------------------------------------------------------------------
    fcntl - (int fd, unsigned int cmd, unsigned long arg)
-----------------------------------------------------------------------------*/
CALCSIZE(fcntl)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(fcntl)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	switch(ARG2)
	{
		case F_GETFD:
		case F_GETFL:
		case F_GETOWN:
		case F_GETSIG:
		case F_GETLEASE:
		{
			break;
		}
		default:
		{
			CHECKREG(ARG3);
			break;
		}
	}
	IPMON_MAYBE_DISPATCH_MASTER(ARG1);
}

POSTCALL(fcntl)
{
	if (success && (ARG2 == F_DUPFD || ARG2 == F_DUPFD_CLOEXEC))
		if (ipmon_variant_num == 0)
			ipmon_set_file_type(ret, ipmon_get_file_type(ARG1));
	return order;
}

/*-----------------------------------------------------------------------------
    dup - (unsigned int oldfd)
-----------------------------------------------------------------------------*/
CALCSIZE(dup)
{
	COUNTREG(ARG);
}

PRECALL(dup)
{
	CHECKREG(ARG1);
	IPMON_MAYBE_DISPATCH_MASTER(ARG1);
}

POSTCALL(dup)
{
	if (success && ipmon_variant_num == 0)
		ipmon_set_file_type(ret, ipmon_get_file_type(ARG1));
	return order;
}

/*-----------------------------------------------------------------------------
    dup2 - (unsigned int oldfd, unsigned int newfd)
-----------------------------------------------------------------------------*/
CALCSIZE(dup2)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(dup2)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	IPMON_MAYBE_DISPATCH_MASTER(ARG1);
}

POSTCALL(dup2)
{
	if (success && ipmon_variant_num == 0)
		ipmon_set_file_type(ARG2, ipmon_get_file_type(ARG1));
	return order;
}

/*-----------------------------------------------------------------------------
    dup3 - (unsigned int oldfd, unsigned int newfd, int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(dup3)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(dup3)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	IPMON_MAYBE_DISPATCH_MASTER(ARG1);
}

POSTCALL(dup3)
{
	if (success && ipmon_variant_num == 0)
		ipmon_set_file_type(ARG2, ipmon_get_file_type(ARG1));
	return order;
}

/*-----------------------------------------------------------------------------
    pipe - (int* fds)
-----------------------------------------------------------------------------*/
CALCSIZE(pipe)
{
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(int) * 2);
}

PRECALL(pipe)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(pipe)
{
	if (success)
	{
		if (ipmon_variant_num == 0)
		{
			ipmon_set_file_type(((int*)ARG1)[0], FT_PIPE_BLOCKING);
			ipmon_set_file_type(((int*)ARG1)[1], FT_PIPE_BLOCKING);
		}

		REPLICATEBUFFER(ARG1, sizeof(int) * 2);
	}
	return order;
}

/*-----------------------------------------------------------------------------
    pipe2 - (int* fds, int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(pipe2)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(int) * 2);
}

PRECALL(pipe2)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(pipe2)
{
	if (success)
	{
		if (ipmon_variant_num == 0)
		{
			ipmon_set_file_type(((int*)ARG1)[0], (ARG2 & O_NONBLOCK) ? FT_PIPE_NON_BLOCKING : FT_PIPE_BLOCKING);
			ipmon_set_file_type(((int*)ARG1)[1], (ARG2 & O_NONBLOCK) ? FT_PIPE_NON_BLOCKING : FT_PIPE_BLOCKING);
		}

		REPLICATEBUFFER(ARG1, sizeof(int) * 2);
	}
	return order;
}

/*-----------------------------------------------------------------------------
    inotify_init - (void)
-----------------------------------------------------------------------------*/
PRECALL(inotify_init)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(inotify_init)
{
	if (success && ipmon_variant_num == 0)
		ipmon_set_file_type(ret, FT_POLL_BLOCKING);
	return order;
}

/*-----------------------------------------------------------------------------
    inotify_init1 - (int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(inotify_init1)
{
	COUNTREG(ARG);
}

PRECALL(inotify_init1)
{
	CHECKREG(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(inotify_init1)
{
	if (success && ipmon_variant_num == 0)
		ipmon_set_file_type(ret, (ARG1 & IN_NONBLOCK) ? FT_POLL_NON_BLOCKING : FT_POLL_BLOCKING);
	return order;
}

/*-----------------------------------------------------------------------------
    chdir - (const char* path)
-----------------------------------------------------------------------------*/
CALCSIZE(chdir)
{
	COUNTREG(ARG);
	if (ARG)
		COUNTSTRING(ARG, ARG1);
}

PRECALL(chdir)
{
	CHECKPOINTER(ARG1);
	CHECKSTRING(ARG1);
	return IPMON_EXEC_ALL;
}

/*-----------------------------------------------------------------------------
    fchdir - (int fd)
-----------------------------------------------------------------------------*/
CALCSIZE(fchdir)
{
	COUNTREG(ARG);
}

PRECALL(fchdir)
{
	CHECKREG(ARG1);
	ARG1 = ipmon_get_slave_fd(ARG1);
	return IPMON_EXEC_ALL;
}

/*-----------------------------------------------------------------------------
    ioctl - (unsigned int fd, unsigned int cmd, unsigned long arg)
-----------------------------------------------------------------------------*/
#if CURRENT_POLICY >= FULL_SYSCALLS
CALCSIZE(ioctl)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);

	switch(ARG2)
	{
		// IN: const struct termios*
		case TCSETS:
		case TCSETSW:
		case TCSETSF:
		{
			COUNTBUFFER(ARG, ARG3, sizeof(struct __kernel_termios));
			break;
		}

		// OUT: const struct termios*
		case TCGETS:
		{
			COUNTBUFFER(RET, ARG3, sizeof(struct __kernel_termios));
			break;
		}

		// OUT: pid_t*
		case TIOCGPGRP:
		{
			COUNTBUFFER(RET, ARG3, sizeof(pid_t));
			break;
		}

		// IN: int*
		case FIONBIO:
		case FIOASYNC:
		{
			COUNTBUFFER(ARG, ARG3, sizeof(int));
			break;
		}

		// OUT: int*
		case FIONREAD:
		{
			COUNTBUFFER(RET, ARG3, sizeof(int));
			break;
		}

		// IN: struct winsize*
		case TIOCSWINSZ:
		{
			COUNTBUFFER(ARG, ARG3, sizeof(struct winsize));
			break;
		}

		// OUT: struct winsize*
		case TIOCGWINSZ:
		{
			COUNTBUFFER(RET, ARG3, sizeof(struct winsize));
			break;
		}

		// IN+OUT: struct ifconf*
		case SIOCGIFCONF:
		{
			COUNTBUFFER(ARG, ARG3, sizeof(struct ifconf));
			COUNTBUFFER(RET, ARG3, ((struct ifconf*)ARG3)->ifc_len);
			break;
		}

	    // IN+OUT: struct ifreq*
		case SIOCGIFHWADDR:
		{
			COUNTBUFFER(ARG, ARG3, IFNAMSIZ);
			COUNTBUFFER(RET, ARG3, sizeof(struct ifreq));
			break;
		}
	}
}

PRECALL(ioctl)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
    CHECKPOINTER(ARG3);

    unsigned char is_master = 0;
    switch(ARG2)
    {
        case TCGETS:     // struct termios *
            is_master = ipmon_is_master_file(ARG1);
            break;

        case FIONREAD:   // int*
        case TIOCGWINSZ: // struct winsize *
        case TIOCGPGRP:  // pid_t *
        case TIOCSPGRP:  // const pid_t *
            is_master = 1;
            break;

        case TCSETS:     // const struct termios *
        case TCSETSW:    // const struct termios *
        case TCSETSF:    // const struct termios *
            CHECKBUFFER(ARG3, sizeof(struct __kernel_termios));
            is_master = 1;
            break;

        case FIONBIO:    // int*
        case FIOASYNC:
            is_master = 1;
            CHECKBUFFER(ARG3, sizeof(int));
            break;

        case TIOCSWINSZ:
            CHECKBUFFER(ARG3, sizeof(struct winsize));
            is_master = 1;
            break;

        case FIOCLEX:
        case FIONCLEX:
            break;

		case SIOCGIFCONF: 
			CHECKBUFFER(ARG3, sizeof(int));
			is_master = 1;
			break;

		case SIOCGIFHWADDR:
			CHECKBUFFER(ARG3, IFNAMSIZ);
			is_master = 1;
			break;

        default:
            // Unknown IOCTL
			ipmon_arg_verify_failed(__NR_ioctl, 2, ARG2);
			break;
			
    }

    if (!is_master)
    {
		ARG1 = ipmon_get_slave_fd(ARG1);
        return IPMON_EXEC_ALL | IPMON_REPLICATE_MASTER | IPMON_ORDER_CALL;
    }
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_ORDER_CALL;
}

POSTCALL(ioctl)
{
    switch(ARG2)
    {
        case FIONREAD:
            REPLICATEBUFFER(ARG3, sizeof(int));
            break;
        case TCGETS:
            REPLICATEBUFFER(ARG3, sizeof(struct __kernel_termios));
            break;
        case TIOCGPGRP:
            REPLICATEBUFFER(ARG3, sizeof(pid_t));
            break;
        case TIOCGWINSZ:
            REPLICATEBUFFER(ARG3, sizeof(struct winsize));
            break;
		case SIOCGIFCONF:
			REPLICATEBUFFER(ARG3, sizeof(int));
			REPLICATEBUFFER(&((struct ifconf*)ARG3)->ifc_ifcu.ifcu_req, ((struct ifconf*)ARG3)->ifc_len);
			break;
		case SIOCGIFHWADDR:
			REPLICATEBUFFER(ARG3, sizeof(struct ifreq));
			break;
    }

    return order;
}
#else
# if CURRENT_POLICY < FULL_SYSCALLS
MAYBE_CHECKED(ioctl)
{
	if (ARG2 == FIONREAD)
		return false;
	return true;
}

CALCSIZE(ioctl)
{
	COUNTREG(ARG);
	COUNTREG(ARG);

	switch(ARG2)
	{
	    case FIONREAD:
			COUNTREG(ARG);
			COUNTBUFFER(RET, ARG3, sizeof(int));
			break;
	}
}

PRECALL(ioctl)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);

	switch(ARG2)
	{
    	case FIONREAD:
			CHECKPOINTER(ARG3);
			break;
	}

	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(ioctl)
{
	switch(ARG2)
	{
    	case FIONREAD:
			REPLICATEBUFFER(ARG3, sizeof(int));
			break;
	}

	return order;
}
# endif // CURRENT_POLICY < FULL_SYSCALLS
#endif

/*-----------------------------------------------------------------------------
    exit_group
-----------------------------------------------------------------------------*/
UNSYNCED(exit_group);

/*-----------------------------------------------------------------------------
    uname - (struct utsname* buf)
-----------------------------------------------------------------------------*/
UNSYNCED(uname);

/*-----------------------------------------------------------------------------
    getpriority - (int which, int who)
-----------------------------------------------------------------------------*/
CALCSIZE(getpriority)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(getpriority)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    nanosleep - (const struct timespec* req, struct timespec* rem)
-----------------------------------------------------------------------------*/
CALCSIZE(nanosleep)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG1, sizeof(struct timespec));
	COUNTBUFFER(RET, ARG2, sizeof(struct timespec));
}

PRECALL(nanosleep)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKBUFFER(ARG1, sizeof(struct timespec));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_BLOCKING_CALL;
}

POSTCALL(nanosleep)
{
	REPLICATEBUFFER(ARG2, sizeof(struct timespec));
	return order;
}

/*-----------------------------------------------------------------------------
    getrusage - (int who, struct rusage* usage)
-----------------------------------------------------------------------------*/
CALCSIZE(getrusage)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct rusage));
}

PRECALL(getrusage)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(getrusage)
{
	REPLICATEBUFFER(ARG2, sizeof(struct rusage));
	return order;
}

/*-----------------------------------------------------------------------------
    sysinfo - (struct sysinfo* info)
-----------------------------------------------------------------------------*/
CALCSIZE(sysinfo)
{
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(struct sysinfo));
}

PRECALL(sysinfo)
{
	CHECKPOINTER(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(sysinfo)
{
	REPLICATEBUFFER(ARG1, sizeof(struct sysinfo));
	return order;
}

/*-----------------------------------------------------------------------------
    times - (struct tms* buf)
-----------------------------------------------------------------------------*/
CALCSIZE(times)
{
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(struct tms));
}

PRECALL(times)
{
	CHECKPOINTER(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(times)
{
	REPLICATEBUFFER(ARG1, sizeof(struct tms));
	return order;
}

/*-----------------------------------------------------------------------------
    capget - (cap_user_header_t header, cap_user_data_t dataptr)
-----------------------------------------------------------------------------*/
CALCSIZE(capget)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG1, sizeof(__user_cap_header_struct));
	COUNTBUFFER(RET, ARG1, sizeof(__user_cap_header_struct));
	COUNTBUFFER(RET, ARG2, sizeof(__user_cap_data_struct) * 2);
}

PRECALL(capget)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKBUFFER(ARG1, sizeof(__user_cap_header_struct));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(capget)
{
	REPLICATEBUFFER(ARG1, sizeof(__user_cap_header_struct));
	REPLICATEBUFFER(ARG2, sizeof(__user_cap_data_struct) * 2);
	return order;
}

/*-----------------------------------------------------------------------------
    getitimer - (int which, struct itimerval* curr_value)
-----------------------------------------------------------------------------*/
CALCSIZE(getitimer)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct itimerval));
}

PRECALL(getitimer)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(getitimer)
{
	REPLICATEBUFFER(ARG2, sizeof(struct itimerval));
	return order;
}

/*-----------------------------------------------------------------------------
    int futex(int *uaddr, int op, int val, const struct timespec *timeout,
          int *uaddr2, int val3);
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(futex)
{
	if (ARG2 == MVEE_FUTEX_WAIT_TID)
		return true;
	return false;
}

CALCSIZE(futex)
{
	COUNTREG(ARG);
}

PRECALL(futex)
{
	unsigned short result = IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;

	CHECKREG(ARG2);

	if (!(ARG2 & FUTEX_WAKE))
		result |= IPMON_BLOCKING_CALL;

	return result;
}

/*-----------------------------------------------------------------------------
    gettimeofday -
-----------------------------------------------------------------------------*/
CALCSIZE(gettimeofday)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(struct timeval));
	COUNTBUFFER(RET, ARG2, sizeof(struct timezone));
}

PRECALL(gettimeofday)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(gettimeofday)
{
	REPLICATEBUFFER(ARG1, sizeof(struct timeval));
	REPLICATEBUFFER(ARG2, sizeof(struct timezone));
	return order;
}

/*-----------------------------------------------------------------------------
    time - (time_t*)
-----------------------------------------------------------------------------*/
CALCSIZE(time)
{
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG1, sizeof(time_t));
}

PRECALL(time)
{
	CHECKPOINTER(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(time)
{
	REPLICATEBUFFER(ARG1, sizeof(time_t));
	return order;
}

/*-----------------------------------------------------------------------------
    clock_gettime - int, struct timespec*
-----------------------------------------------------------------------------*/
CALCSIZE(clock_gettime)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct timespec));
}

PRECALL(clock_gettime)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(clock_gettime)
{
	REPLICATEBUFFER(ARG2, sizeof(struct timespec));
	return order;
}

/*-----------------------------------------------------------------------------
    getpid
-----------------------------------------------------------------------------*/
PRECALL(getpid)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    getegid
-----------------------------------------------------------------------------*/
PRECALL(getegid)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    geteuid
-----------------------------------------------------------------------------*/
PRECALL(geteuid)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    getgid
-----------------------------------------------------------------------------*/
PRECALL(getgid)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    getpgrp
-----------------------------------------------------------------------------*/
PRECALL(getpgrp)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    getppid
-----------------------------------------------------------------------------*/
PRECALL(getppid)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    gettid
-----------------------------------------------------------------------------*/
PRECALL(gettid)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    getuid
-----------------------------------------------------------------------------*/
PRECALL(getuid)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    sched_yield - this is never dangerous BUT our synchronization replication
    algorithm heavily depends on this syscall

    => should be super fast!
-----------------------------------------------------------------------------*/
UNSYNCED(sched_yield)

/*-----------------------------------------------------------------------------
    getcwd - char *buffer, unsigned long size
-----------------------------------------------------------------------------*/
CALCSIZE(getcwd)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(getcwd)
{
	CHECKPOINTER(ARG1);
	CHECKREG(ARG2);
	return IPMON_EXEC_ALL | IPMON_REPLICATE_MASTER;
}

POSTCALL(getcwd)
{
	REPLICATEBUFFER(ARG1, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    access - (const char* pathname, int mode)
-----------------------------------------------------------------------------*/
CALCSIZE(access)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
}

PRECALL(access)
{
	CHECKPOINTER(ARG1);
	CHECKREG(ARG2);
	CHECKSTRING(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    faccessat - (int dirfd, const char *pathname, int mode)
-----------------------------------------------------------------------------*/
CALCSIZE(faccessat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG2);
}

PRECALL(faccessat)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKSTRING(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    int stat(const char *path, struct stat *buf);
    int fstat(int fd, struct stat *buf);
    int lstat(const char *path, struct stat *buf); 
-----------------------------------------------------------------------------*/
CALCSIZE(stat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTBUFFER(RET, ARG2, sizeof(struct stat));
}

PRECALL(stat)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKSTRING(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(stat)
{
	REPLICATEBUFFER(ARG2, sizeof(struct stat));
	return order;
}

CALCSIZE(lstat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTBUFFER(RET, ARG2, sizeof(struct stat));
}

PRECALL(lstat)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKSTRING(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(lstat)
{
	REPLICATEBUFFER(ARG2, sizeof(struct stat));
	return order;
}

CALCSIZE(fstat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct stat));
}

PRECALL(fstat)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(fstat)
{
	REPLICATEBUFFER(ARG2, sizeof(struct stat));
	return order;
}

/*-----------------------------------------------------------------------------
    newfstatat - (int dfd, char *filename, struct stat *buf, int flag)
-----------------------------------------------------------------------------*/
CALCSIZE(newfstatat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, sizeof(struct stat));
}

PRECALL(newfstatat)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(newfstatat)
{
	REPLICATEBUFFER(ARG3, sizeof(struct stat));
	return order;
}

/*-----------------------------------------------------------------------------
    getdents - (unsigned int fd, struct linux_dirent* dirp, unsigned int count)
-----------------------------------------------------------------------------*/
CALCSIZE(getdents)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, ARG3);
}

PRECALL(getdents)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(getdents)
{
	REPLICATEBUFFER(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    readlink - (const char *path, char *buf, size_t bufsiz)
-----------------------------------------------------------------------------*/
CALCSIZE(readlink)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTBUFFER(RET, ARG2, ARG3);
}

PRECALL(readlink)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKSTRING(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(readlink)
{
	REPLICATEBUFFER(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    readlinkat - (int dirfd, const char *path, char *buf, size_t bufsiz)
-----------------------------------------------------------------------------*/
CALCSIZE(readlinkat)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, ARG4);
}

PRECALL(readlinkat)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(readlinkat)
{
	REPLICATEBUFFER(ARG3, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    getxattr/lgetxattr - (const char *path, const char *name,
                 void *value, size_t size)
	fgetxattr - (int fd, const char *name,
                 void *value, size_t size)
-----------------------------------------------------------------------------*/
CALCSIZE(getxattr)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, ARG4);
}

PRECALL(getxattr)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG1);
	CHECKSTRING(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(getxattr)
{
	REPLICATEBUFFER(ARG3, ret);
	return order;
}

CALCSIZE(lgetxattr)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTSTRING(ARG, ARG1);
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, ARG4);
}

PRECALL(lgetxattr)
{
	CHECKPOINTER(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG1);
	CHECKSTRING(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(lgetxattr)
{
	REPLICATEBUFFER(ARG3, ret);
	return order;
}

CALCSIZE(fgetxattr)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);	
	COUNTSTRING(ARG, ARG2);
	COUNTBUFFER(RET, ARG3, ARG4);
}

PRECALL(fgetxattr)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKSTRING(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(fgetxattr)
{
	REPLICATEBUFFER(ARG3, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    lseek - (int fd, off_t offset, int whence)
-----------------------------------------------------------------------------*/
CALCSIZE(lseek)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(lseek)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    alarm - (unsigned int seconds)
-----------------------------------------------------------------------------*/
CALCSIZE(alarm)
{
	COUNTREG(ARG);
}

PRECALL(alarm)
{
	CHECKREG(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    setitimer - (int which, const struct itimerval* new_value, struct itimerval* old_value)
-----------------------------------------------------------------------------*/
CALCSIZE(setitimer)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, sizeof(struct itimerval));
	COUNTBUFFER(RET, ARG3, sizeof(struct itimerval));
}

PRECALL(setitimer)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKBUFFER(ARG2, sizeof(struct itimerval));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(setitimer)
{
	REPLICATEBUFFER(ARG3, sizeof(struct itimerval));
	return order;
}

/*-----------------------------------------------------------------------------
    timerfd_gettime - (int ufd, struct itimerspec* otmr)
-----------------------------------------------------------------------------*/
CALCSIZE(timerfd_gettime)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct itimerspec));
}

PRECALL(timerfd_gettime)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(timerfd_gettime)
{
	REPLICATEBUFFER(ARG2, sizeof(struct itimerspec));
	return order;
}

/*-----------------------------------------------------------------------------
    madvise - void* addr, size_t length, int advice

    The only potentially dangerous variant of this call is where
    advice == MADV_REMOVE. That doesn't affect us however since MADV_REMOVE
    only affects MAP_SHARED regions with PROT_WRITE access, which we do not
    allow in GHUMVEE
-----------------------------------------------------------------------------*/
UNSYNCED(madvise)

/*-----------------------------------------------------------------------------
    fadvise64 - (int fd, loff_t offset, loff_t len, int advice)
-----------------------------------------------------------------------------*/
CALCSIZE(fadvise64)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(fadvise64)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    read - int fd, void* buf, size_t count
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(read)
{
	// check whether our current policy allows
	// us to dispatch read calls on this file
	// as unchecked calls
	return !ipmon_can_read(ARG1);
}

CALCSIZE(read)
{
	// reserve space for 3 register arguments
	// one buffer whose maximum size is in argument 3 of this syscall
	COUNTREG(ARG); 
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, ARG3);
}

PRECALL(read)
{
	// compare the system call arguments
	// dispatch this as a call that only
	// the master actually invokes
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(read)
{
	// replicate the results
	REPLICATEBUFFER(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    pread64 - (int fd, void *buf, size_t count, off_t offset)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(pread64)
{
	return !ipmon_can_read(ARG1);
}

CALCSIZE(pread64)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, ARG3);
}

PRECALL(pread64)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(pread64)
{
	REPLICATEBUFFER(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    readv - (int fd, const struct iovec *iov, int iovcnt)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(readv)
{
	return !ipmon_can_read(ARG1);
}

CALCSIZE(readv)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTIOVECLAYOUT(ARG, ARG2, ARG3);
	COUNTIOVEC(RET, ARG2, ARG3);
}

PRECALL(readv)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKIOVECLAYOUT(ARG2, ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(readv)
{
	REPLICATEIOVEC(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    preadv - (int fd, const struct iovec *iov, int iovcnt, off_t offset)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(preadv)
{
	return !ipmon_can_read(ARG1);
}

CALCSIZE(preadv)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTIOVECLAYOUT(ARG, ARG2, ARG3);
	COUNTIOVEC(RET, ARG2, ARG3);
}

PRECALL(preadv)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKIOVECLAYOUT(ARG2, ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(preadv)
{
	REPLICATEIOVEC(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    poll - struct pollfd *fds, nfds_t nfds, int timeout
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(poll)
{
	for (int i = 0; i < ARG2; ++i)
		if (!ipmon_can_read(((struct pollfd*)ARG1)[i].fd))
			return true;

	return false;
}

CALCSIZE(poll)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG1, (sizeof(struct pollfd) * ARG2));
	COUNTBUFFER(RET, ARG1, (sizeof(struct pollfd) * ARG2)); // buffer is input and can be modified by the syscall
}

PRECALL(poll)
{
	CHECKPOINTER(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKBUFFER(ARG1, (sizeof(struct pollfd) * ARG2));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(poll)
{
	REPLICATEBUFFER(ARG1, (sizeof(struct pollfd) * ARG2));
	return order;
}

/*-----------------------------------------------------------------------------
    select - (int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(select)
{
	for (int i = 0; i < ARG1; ++i)
	{
		if ((ARG2 && FD_ISSET(i, (fd_set*)ARG2)) ||
			(ARG3 && FD_ISSET(i, (fd_set*)ARG3)) ||
			(ARG4 && FD_ISSET(i, (fd_set*)ARG4)))
		{
			if (!ipmon_can_read(i))
				return true;
		}
	}

	return false;
}

CALCSIZE(select)
{
	// some bastards don't pass a full fd set to the
	// kernel because they assume that the kernel
	// won't touch the non-interesting bits anyway
	unsigned long set_size = ROUND_UP(ARG1 + 1, sizeof(unsigned long));
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, set_size);
	COUNTBUFFER(RET, ARG2, set_size);
	COUNTBUFFER(ARG, ARG3, set_size);
	COUNTBUFFER(RET, ARG3, set_size);
	COUNTBUFFER(ARG, ARG4, set_size);
	COUNTBUFFER(RET, ARG4, set_size);
	COUNTBUFFER(ARG, ARG5, sizeof(struct timeval));
	COUNTBUFFER(RET, ARG5, sizeof(struct timeval));
}

PRECALL(select)
{
	unsigned long set_size = ROUND_UP(ARG1 + 1, sizeof(unsigned long));
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKPOINTER(ARG4);
	CHECKPOINTER(ARG5);
	CHECKBUFFER(ARG2, set_size);
	CHECKBUFFER(ARG3, set_size);
	CHECKBUFFER(ARG4, set_size);
	CHECKBUFFER(ARG5, sizeof(struct timeval));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_BLOCKING_CALL;	
}

POSTCALL(select)
{
	unsigned long set_size = ROUND_UP(ARG1 + 1, sizeof(unsigned long));
	REPLICATEBUFFER(ARG2, set_size);
	REPLICATEBUFFER(ARG3, set_size);
	REPLICATEBUFFER(ARG4, set_size);
	REPLICATEBUFFER(ARG5, sizeof(struct timeval));
	return order;
}

/*-----------------------------------------------------------------------------
    timerfd_settime - (int fd, int flags,
                    const struct itimerspec *new_value,
                    struct itimerspec *old_value);
-----------------------------------------------------------------------------*/
CALCSIZE(timerfd_settime)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG3, sizeof(struct itimerspec));
	COUNTBUFFER(RET, ARG4, sizeof(struct itimerspec));
}

PRECALL(timerfd_settime)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKPOINTER(ARG3);
	CHECKPOINTER(ARG4);
	CHECKBUFFER(ARG3, sizeof(struct itimerspec));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(timerfd_settime)
{
	REPLICATEBUFFER(ARG4, sizeof(struct itimerspec));
	return order;
}

/*-----------------------------------------------------------------------------
    sync - 
-----------------------------------------------------------------------------*/
PRECALL(sync)
{
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_BLOCKING_CALL;
}

/*-----------------------------------------------------------------------------
    fsync - (int fd)
	fdatasync - (int fd)
	syncfs - (int fd)
-----------------------------------------------------------------------------*/
CALCSIZE(fsync)
{
	COUNTREG(ARG);
}

PRECALL(fsync)
{
	CHECKREG(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_BLOCKING_CALL;
}

CALCSIZE(fdatasync)
{
	COUNTREG(ARG);
}

PRECALL(fdatasync)
{
	CHECKREG(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_BLOCKING_CALL;
}

CALCSIZE(syncfs)
{
	COUNTREG(ARG);
}

PRECALL(syncfs)
{
	CHECKREG(ARG1);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_BLOCKING_CALL;
}

/*-----------------------------------------------------------------------------
    write - int fd, const void* buf, size_t count
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(write)
{
	return !ipmon_can_write(ARG1);
}

CALCSIZE(write)
{
	COUNTREG(ARG); // arg1
	COUNTREG(ARG); // arg2
	COUNTREG(ARG); // arg3
	if ((int)ARG1 >= 0)
		COUNTBUFFER(ARG, ARG2, ARG3);
}

PRECALL(write)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);

	// RAVEN extended syscall support
	unsigned long result = IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
	if ((int)ARG1 >= 0)
	{
		CHECKBUFFER(ARG2, ARG3);
		result |= IPMON_MAYBE_BLOCKING(ARG1);
	}
	else
	{
		result |= IPMON_ORDER_CALL | IPMON_LOCKSTEP_CALL;
	}
	return result;	
}

/*-----------------------------------------------------------------------------
    pwrite - (int fd, const void *buf, size_t count, off_t offset)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(pwrite64)
{
	return !ipmon_can_write(ARG1);
}

CALCSIZE(pwrite64)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, ARG3);
}

PRECALL(pwrite64)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKBUFFER(ARG2, ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    writev - (int fd, const struct iovec *iov, int iovcnt)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(writev)
{
	return !ipmon_can_write(ARG1);
}

CALCSIZE(writev)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTIOVEC(ARG, ARG2, ARG3);
}

PRECALL(writev)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKIOVEC(ARG2, ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    pwritev - (int fd, const struct iovec *iov, int iovcnt,
                off_t offset)
-----------------------------------------------------------------------------*/
MAYBE_CHECKED(pwritev)
{
	return !ipmon_can_write(ARG1);
}

CALCSIZE(pwritev)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTIOVEC(ARG, ARG2, ARG3);
}

PRECALL(pwritev)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKIOVEC(ARG2, ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    recvfrom - (int sockfd, void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen)
-----------------------------------------------------------------------------*/
CALCSIZE(recvfrom)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
    COUNTBUFFER(ARG, ARG6, sizeof(socklen_t));
	COUNTBUFFER(RET, ARG2, ARG3);
	if (ARG6 && *(socklen_t*)ARG6 > 0)
		COUNTBUFFER(RET, ARG5, *(socklen_t*)ARG6);
}

PRECALL(recvfrom)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKPOINTER(ARG5);
	CHECKPOINTER(ARG6);
	CHECKBUFFER(ARG6, sizeof(socklen_t));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(recvfrom)
{
	REPLICATEBUFFER(ARG2, ret);
	REPLICATEBUFFER(ARG6, sizeof(socklen_t));
	REPLICATEBUFFER(ARG5, *(socklen_t*)ARG6);
	return order;
}

/*-----------------------------------------------------------------------------
    recvmsg - (int fd, struct msghdr* msg, int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(recvmsg)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTMSGLAYOUT(ARG, ARG2);
	COUNTMSG(RET, ARG2);
}

PRECALL(recvmsg)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKMSGLAYOUT(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(recvmsg)
{
	REPLICATEMSG(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    recvmmsg - (int fd, struct mmsghdr* msgvec, unsigned int vlen, 
	unsigned int flags, struct timespec* timeout)
-----------------------------------------------------------------------------*/
CALCSIZE(recvmmsg)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTMMSGLAYOUT(ARG, ARG2, ARG3);
	COUNTBUFFER(ARG, ARG5, sizeof(struct timespec));
	COUNTMMSG(RET, ARG2, ARG3);
}

PRECALL(recvmmsg)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKPOINTER(ARG5);
	CHECKMMSGLAYOUT(ARG2, ARG3);
	CHECKBUFFER(ARG5, sizeof(struct timespec));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(recvmmsg)
{
	REPLICATEMMSG(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    getsockname - (int fd, struct sockaddr __user * usockaddr,                                                   
	int __user * usockaddr_len)
-----------------------------------------------------------------------------*/
CALCSIZE(getsockname)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG3, sizeof(int));
	COUNTBUFFER(RET, ARG2, *(int*)ARG3);
	COUNTBUFFER(RET, ARG3, sizeof(int));
}

PRECALL(getsockname)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKBUFFER(ARG3, sizeof(int));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(getsockname)
{
	// tricky business!!! getsockname returns a truncated result
	// if the call was unsucessful
	success = true; // hack
	int oldsize = *(int*)ARG3;
	REPLICATEBUFFER(ARG3, sizeof(int));
	REPLICATEBUFFER(ARG2, MIN(*(int*)ARG3, oldsize));
	return order;
}

/*-----------------------------------------------------------------------------
    getpeername - (int fd, struct sockaddr __user * usockaddr,                                                   
	int __user * usockaddr_len)   
-----------------------------------------------------------------------------*/
CALCSIZE(getpeername)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG3, sizeof(int));
	COUNTBUFFER(RET, ARG2, *(int*)ARG3);
	COUNTBUFFER(RET, ARG3, sizeof(int));
}

PRECALL(getpeername)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKPOINTER(ARG3);
	CHECKBUFFER(ARG3, sizeof(int));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(getpeername)
{
	// same hack as above to deal with truncated results
	success = true; // hack
	int oldsize = *(int*)ARG3;
	REPLICATEBUFFER(ARG3, sizeof(int));
	REPLICATEBUFFER(ARG2, MIN(*(int*)ARG3, oldsize));
	return order;
}

/*-----------------------------------------------------------------------------
    getsockopt - (int fd, int level, int optname,                                                                
	char __user * optval, int __user * optlen) 
-----------------------------------------------------------------------------*/
CALCSIZE(getsockopt)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG5, sizeof(int));
	COUNTBUFFER(RET, ARG4, *(int*)ARG5);
	COUNTBUFFER(RET, ARG5, sizeof(int));
}

PRECALL(getsockopt)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKPOINTER(ARG4);
	CHECKPOINTER(ARG5);
	CHECKBUFFER(ARG5, sizeof(int));
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(getsockopt)
{
	int oldsize = *(int*)ARG5;
	REPLICATEBUFFER(ARG5, sizeof(int));
	REPLICATEBUFFER(ARG4, MIN(oldsize, *(int*)ARG5));
	return order;
}

/*-----------------------------------------------------------------------------
    sendto - (int fd, void __user * buff, size_t len,                                                             
	unsigned int flags, struct sockaddr __user * addr, int addr_len)
-----------------------------------------------------------------------------*/
CALCSIZE(sendto)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG2, ARG3);
	COUNTBUFFER(ARG, ARG5, ARG6);
}

PRECALL(sendto)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	CHECKPOINTER(ARG5);
	CHECKREG(ARG6);
	CHECKBUFFER(ARG2, ARG3);
	CHECKBUFFER(ARG5, ARG6);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    sendmsg - (int fd, struct msghdr __user * msg, unsigned int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(sendmsg)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTMSG(ARG, ARG2);
}

PRECALL(sendmsg)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKMSG(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

/*-----------------------------------------------------------------------------
    sendmmsg - (int fd, struct mmsghdr __user * mmsg,                                                            
	unsigned int vlen, unsigned int flags)
-----------------------------------------------------------------------------*/
CALCSIZE(sendmmsg)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTMMSG(ARG, ARG2, ARG3);
	COUNTBUFFER(RET, ARG2, ARG3 * sizeof(unsigned int));
}

PRECALL(sendmmsg)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);

	// hack set msg_len so we can use the same handlers we're using for recvmmsg
	if (ARG2 && ARG3 > 0)
	{
		struct mmsghdr* hdr = (struct mmsghdr*)ARG2;
		for (int i; i < ARG3; ++i)
		{
			hdr->msg_len = ipmon_iovec_bytes(hdr->msg_hdr.msg_iov, hdr->msg_hdr.msg_iovlen);
			hdr ++;
		}
	}
	
	CHECKMMSG(ARG2, ARG3);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1);
}

POSTCALL(sendmmsg)
{
	// must replicate lens here
	REPLICATEMMSGLENS(ARG2, ret);
	return order;
}

/*-----------------------------------------------------------------------------
    sendfile - (int out_fd, int in_fd, off_t __user * offset, size_t count)
-----------------------------------------------------------------------------*/
CALCSIZE(sendfile)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG3, sizeof(off_t));
}

PRECALL(sendfile)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKPOINTER(ARG3);
	CHECKREG(ARG4);
	CHECKBUFFER(ARG3, sizeof(off_t));

	// tricky business! this may block on in_fd OR out_fd

	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_MAYBE_BLOCKING(ARG1) | IPMON_MAYBE_BLOCKING(ARG2);
}

/*-----------------------------------------------------------------------------
    epoll_wait - (int epfd, struct epoll_event __user* events, int maxevents, int timeout)
-----------------------------------------------------------------------------*/
CALCSIZE(epoll_wait)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(RET, ARG2, sizeof(struct epoll_event) * ARG3);
}

PRECALL(epoll_wait)
{
	CHECKREG(ARG1);
	CHECKPOINTER(ARG2);
	CHECKREG(ARG3);
	CHECKREG(ARG4);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER | IPMON_BLOCKING_CALL;
}

POSTCALL(epoll_wait)
{
	// epoll events contain pointers. Therefore, this will completely break
	// when combined with diversity!!!
	if (success && ret > 0)
	{
		// in the master, map ptrs onto fds before replicating
		if (ipmon_variant_num == 0)
		{
			struct epoll_event* events = (struct epoll_event*)alloca(ret * sizeof(struct epoll_event));
			memcpy(events, (void*)ARG2, ret * sizeof(struct epoll_event));
		
			for (int i = 0; i < ret; ++i)
				events[i].data.u32 = ipmon_epoll_get_fd_for_ptr(ARG1, (unsigned long)events[i].data.ptr);

			REPLICATEBUFFER(events, ret * sizeof(struct epoll_event));
		}
        // in the slaves, map fds onto ptrs after replicating
		else
		{
			struct epoll_event* events = (struct epoll_event*)ARG2;

			REPLICATEBUFFER(ARG2, ret * sizeof(struct epoll_event));

			for (int i = 0; i < ret; ++i)
				events[i].data.ptr = (void*)ipmon_epoll_get_ptr_for_fd(ARG1, (int)events[i].data.u32);
		}	
	}
	return order;
}

/*-----------------------------------------------------------------------------
    epoll_ctl - (int epfd, int op, int fd, struct epoll_event *event)

	See comment above. This won't work when combined with diversity!!!
-----------------------------------------------------------------------------*/
CALCSIZE(epoll_ctl)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(epoll_ctl)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKPOINTER(ARG4);
	ipmon_epoll_lock();
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

POSTCALL(epoll_ctl)
{
	if (success)
	{
		struct epoll_event* event = (struct epoll_event*)ARG4;
		switch(ARG2)
		{
    		case EPOLL_CTL_ADD:
    		case EPOLL_CTL_MOD:
				ipmon_epoll_set_ptr_for_fd(ARG1, ARG3, (unsigned long)event->data.ptr);
				break;
    		case EPOLL_CTL_DEL:
				ipmon_epoll_set_ptr_for_fd(ARG1, ARG3, 0);
				break;
		}
	}
	ipmon_epoll_unlock();
	return order;
}

/*-----------------------------------------------------------------------------
    shutdown - (int sockfd, int how)
-----------------------------------------------------------------------------*/
CALCSIZE(shutdown)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
}

PRECALL(shutdown)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    setsockopt - (int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen)
-----------------------------------------------------------------------------*/
CALCSIZE(setsockopt)
{
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTREG(ARG);
	COUNTBUFFER(ARG, ARG4, ARG5);
}

PRECALL(setsockopt)
{
	CHECKREG(ARG1);
	CHECKREG(ARG2);
	CHECKREG(ARG3);
	CHECKPOINTER(ARG4);
	CHECKREG(ARG5);
	CHECKBUFFER(ARG4, ARG5);
	return IPMON_EXEC_MASTER | IPMON_REPLICATE_MASTER;
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_maybe_checked - allows a system call handler to decide whether
    or not a specific invocation should be reported to the monitor
-----------------------------------------------------------------------------*/
bool ipmon_syscall_maybe_checked(struct ipmon_syscall_args& args, unsigned long syscall_no)
{
	switch(syscall_no)
	{
#include "MVEE_ipmon_maybe_checked.h"
	}
	return false;
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_is_unsynced
-----------------------------------------------------------------------------*/
unsigned char ipmon_syscall_is_unsynced(struct ipmon_syscall_args& args, unsigned long syscall_no)
{
	switch(syscall_no)
	{
#include "MVEE_ipmon_is_unsynced.h"
	}
	return 0;
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_calcsize
-----------------------------------------------------------------------------*/
void ipmon_syscall_calcsize(struct ipmon_syscall_args& args, unsigned long syscall_no, unsigned int* ARG, unsigned int* RET)
{
	switch(syscall_no)
	{
#include "MVEE_ipmon_calcsize.h"
	}
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_precall - does argument logging in the master, argument
    verification in the slaves and determines whether or not the call is a
    mastercall
-----------------------------------------------------------------------------*/
unsigned short ipmon_syscall_precall(struct ipmon_syscall_args& args, struct ipmon_syscall_entry* entry)
{
	switch(entry->syscall_no)
	{
#include "MVEE_ipmon_precall.h"
	}

	return 0;
}

/*-----------------------------------------------------------------------------
    ipmon_syscall_postcall - does return logging in the master and return
    replication in the slaves.  Returns the number of ipmon_syscall_data
    elements used in the buffer for replicating the results
-----------------------------------------------------------------------------*/
int ipmon_syscall_postcall(struct ipmon_syscall_args& args, struct ipmon_syscall_entry* entry, long realret)
{
	long ret = entry->syscall_return_value;
	bool success = (ret >= 0 || ret < -4096);
	int nr_elements = 0;

	switch(entry->syscall_no)
	{
#include "MVEE_ipmon_postcall.h"
	}

	return nr_elements;
}

/*-----------------------------------------------------------------------------
    ipmon_mutex_lock - based on locklessinc implementation
-----------------------------------------------------------------------------*/
void ipmon_mutex_lock(struct ipmon_mutex* mut)
{
	// We still assume low contention
	for (int i = 0; i < 100; ++i)
	{
		// Set locked to 1. If the old value of locked was 0, we can return right away
		if(!__atomic_exchange_n(&mut->locked, 1, __ATOMIC_ACQUIRE))
			return;

		cpu_relax();
	}

	// Set locked and contended using one xchg op. If the locked flag was
	// set to 1, wait on the mutex using a private futex call
	while (__atomic_exchange_n(&mut->hack, 0x101, __ATOMIC_ACQUIRE) & 1)
		ipmon_unchecked_syscall(__NR_futex, &mut->hack, FUTEX_WAIT_PRIVATE, 0x101, NULL, NULL, 0);
}

/*-----------------------------------------------------------------------------
    ipmon_mutex_unlock - 
-----------------------------------------------------------------------------*/
void ipmon_mutex_unlock(struct ipmon_mutex* mut)
{
	// test if the mutex is contended
	if (mut->hack == 1 && 
		// don't do the cmpxchg if it's definitely contended
		// The cmpxchg succeeds only if there's no lock contention
		__sync_bool_compare_and_swap(&mut->hack, 1, 0))
		return;

	mut->locked = 0;
	__sync_synchronize();

	// If someone takes the lock immediately, we can avoid the futex wake call
	for (int i = 0; i < 200; ++i)
	{
		if (mut->locked)
			return;
		cpu_relax();
	}

	// Noone took the lock but there was contention
	// => At least one other thread is waiting in a futex_wait op
	mut->contended = 0;
	ipmon_unchecked_syscall(__NR_futex, &mut->hack, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
}

/*-----------------------------------------------------------------------------
    ipmon_spin_lock - Used to order syscalls. We don't expect much contention
	so this is not a super duper optimized lock
-----------------------------------------------------------------------------*/
void ipmon_spin_lock(volatile long* lock)
{
	while (1)
	{
		if (__sync_bool_compare_and_swap(lock, 0, 1))
			break;
//		cpu_relax();
		ipmon_unchecked_syscall(__NR_sched_yield);
	}
}

/*-----------------------------------------------------------------------------
    ipmon_spin_unlock - 
-----------------------------------------------------------------------------*/
void ipmon_spin_unlock(volatile long* lock)
{
	// TODO: can we drop the barrier for intel?
	__sync_synchronize();
	*lock = 0;
}

/*-----------------------------------------------------------------------------
    ipmon_barrier_wait - Super optimized spin-futex barrier. 
	
	NOTE: This is a slightly altered version of pool_barrier_wait2 on 
	locklessinc.com.

	TODO: Check License?

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
void ipmon_barrier_wait(struct ipmon_buffer* RB, struct ipmon_barrier* barrier)
{
	// the upper byte of the sequence number represents the actual sequence number
	// the lower byte is just used as a waiter flag
	// if the lower byte is 1 => threads are waiting to be waked up at the barrier
	unsigned short old_seq = __atomic_load_n(&barrier->seq, __ATOMIC_SEQ_CST);
	unsigned short count   = __atomic_add_fetch(&barrier->count, 1, __ATOMIC_SEQ_CST);

	// we're not the last thread to reach the barrier
	if (count < RB->numvariants)
	{
		old_seq |= 1;

		// We optimize for the case where the variants are in sync
		// (i.e. we don't have to wait too long at the barrier)
		for (int i = 0; i < 1000; ++i)
		{
			// The sequence number can only change after all threads have
			// reached the barrier
			if ((__atomic_load_n(&barrier->seq, __ATOMIC_SEQ_CST) | 1) != old_seq)
				return;	
		
			cpu_relax();
		}

		while ((__atomic_load_n(&barrier->seq, __ATOMIC_SEQ_CST) | 1) == old_seq)
		{
			// set the waiter flag
			*(volatile char*)&barrier->seq = 1;
			// and wait for the sequence number to change
			ipmon_unchecked_syscall(__NR_futex, &barrier->hack, FUTEX_WAIT, old_seq, NULL, NULL, 0);
		}
	}
	// last thread, wake everyone
	else 
	{
		unsigned short old_seq = __atomic_load_n(&barrier->seq, __ATOMIC_SEQ_CST);
		
		if (__atomic_exchange_n(&barrier->hack, (unsigned short)((old_seq | 1) + 0xFF), __ATOMIC_SEQ_CST) & 1)
			ipmon_unchecked_syscall(__NR_futex, &barrier->hack, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
	}
}

/*-----------------------------------------------------------------------------
    ipmon_cond_wait - super optimized cv that can only be used once!

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
void ipmon_cond_wait(struct ipmon_condvar* cv, bool expect_long_wait = false)
{
#ifndef IPMON_USE_FUTEXES_FOR_CONDVAR
	int i = 0;
	while (!__atomic_load_n(&cv->signaled, __ATOMIC_SEQ_CST))
	{
		cpu_relax();
						
		if (i++ > IPMON_YIELD_THRESHOLD)
		{
			i = 0;
			ipmon_unchecked_syscall(__NR_sched_yield);
		}
	}
#else
	// We expect to see 1
	if (!expect_long_wait)
	{
		for (int i = 0; i < 10000; ++i)
		{
			if (__atomic_load_n(&cv->signaled, __ATOMIC_SEQ_CST))
				return;

			cpu_relax();
		}
	}

	// futex_wait while not signaled
	while ((__atomic_load_n(&cv->hack, __ATOMIC_SEQ_CST) | 1) == 1)
	{
		__atomic_store_n(&cv->have_waiters, 1, __ATOMIC_SEQ_CST);

		// and wait for everything to change
		ipmon_unchecked_syscall(__NR_futex, &cv->hack, FUTEX_WAIT, 1, NULL, NULL, 0);
	}
#endif
}

/*-----------------------------------------------------------------------------
    ipmon_cond_broadcast - 

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
void ipmon_cond_broadcast(struct ipmon_condvar* cv)
{
#ifndef IPMON_USE_FUTEXES_FOR_CONDVAR
	__atomic_store_n(&cv->signaled, 1, __ATOMIC_SEQ_CST);
#else
	// atomically set signaled to 1 and clear the have_waiters flag
	if (__atomic_exchange_n(&cv->hack, 0x00000100, __ATOMIC_SEQ_CST) & 1)
	{
		// have_waiters was set. We must wake some threads
		ipmon_unchecked_syscall(__NR_futex, &cv->hack, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
	}
#endif
}

/*-----------------------------------------------------------------------------
    ipmon_sync_on_syscall_entrance - Called just before we invoke the original
	syscall. This would be the place where we implement lock-stepping.

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
void ipmon_sync_on_syscall_entrance(struct ipmon_buffer* rb, struct ipmon_syscall_entry* entry)
{
	if (entry->syscall_type & IPMON_LOCKSTEP_CALL)
		ipmon_barrier_wait(rb, &entry->syscall_lockstep_barrier);

	if (entry->syscall_type & IPMON_ORDER_CALL)
	{
		if (ipmon_variant_num == 0)
		{
			ipmon_mutex_lock(&syscall_ordering_mutex);
			entry->syscall_order = syscall_ordering_clock;
		}
		else
		{			
            // wait for preceding operations to complete
			while (1)
			{
				if (syscall_ordering_clock == entry->syscall_order)
				{
					ipmon_mutex_lock(&syscall_ordering_mutex);
					break;
				}
				ipmon_unchecked_syscall(__NR_sched_yield);
			}			
		}
	}
}

/*-----------------------------------------------------------------------------
    ipmon_sync_on_syscall_exit - This is called AFTER the results have been
    copied into the local slave memory!

	TODO: Rewrite in ASM to get rid of explicit pointer
-----------------------------------------------------------------------------*/
void ipmon_sync_on_syscall_exit(struct ipmon_buffer* rb, struct ipmon_syscall_entry* entry)
{
	if (entry->syscall_type & IPMON_ORDER_CALL)
	{
		syscall_ordering_clock++;
		ipmon_mutex_unlock(&syscall_ordering_mutex);
	}
}

/*-----------------------------------------------------------------------------
    ipmon_do_syscall_wake - Called by the master to inform the slaves about
	the availability of the syscall results. 
-----------------------------------------------------------------------------*/
void ipmon_do_syscall_wake(struct ipmon_syscall_entry* entry)
{
	ipmon_cond_broadcast(&entry->syscall_results_available);
}

/*-----------------------------------------------------------------------------
    ipmon_do_syscall_wait - Called by the slaves to wait for the syscall results
    to become available. 
-----------------------------------------------------------------------------*/
void ipmon_do_syscall_wait(struct ipmon_syscall_entry* entry)
{
	ipmon_cond_wait(&entry->syscall_results_available, entry->syscall_type & IPMON_BLOCKING_CALL);
}

/*-----------------------------------------------------------------------------
    ipmon_should_restart_call - We might see the ERESTART errors (which are
	normally never returned to user space) because GHUMVEE explicitly 
	forced an interrupted unchecked call to return to user space.
	
	Normally, interrupted calls would automatically restart after the signal
	that interrupts them has been handled by the ptracer.

	In our case, however, we want to restart the unchecked call as a checked
	call. This gives GHUMVEE the opportunity to deliver the interrupting signal
-----------------------------------------------------------------------------*/
bool ipmon_should_restart_call(long ret)
{
	// check for ERESTART* errors
	if (ret <= -512	&& ret >= -516)
		return true;
	return false;
}

/*-----------------------------------------------------------------------------
    ipmon_flush_buffer - called at a syscall entry when there's not enough
    room to log the next syscall info
-----------------------------------------------------------------------------*/
void ipmon_flush_buffer(struct ipmon_buffer* RB)
{
	RB->variant_info[ipmon_variant_num].status = IPMON_STATUS_FLUSHING;
#ifndef IPMON_FLUSH_LOCAL
	ipmon_checked_syscall(MVEE_FLUSH_SHARED_BUFFER, MVEE_IPMON_BUFFER);
#else
	ipmon_barrier_wait(RB, &RB->pre_flush_barrier);
	if (ipmon_variant_num == 0)
	{
		memset((void*)((unsigned long)RB + 64), 0, RB->numvariants * 64 + RB->usable_size);
		RB->flush_count++;
	}
	ipmon_barrier_wait(RB, &RB->post_flush_barrier);
#endif
}

/*-----------------------------------------------------------------------------
    ipmon_wait_for_next_syscall - called only by slaves. Spins on the master's
	pos variable until it is bigger than the local variant's pos
-----------------------------------------------------------------------------*/
unsigned char ipmon_wait_for_next_syscall(struct ipmon_buffer* RB)
{
	unsigned int i = 0;
	unsigned char result = 0;

	while (1)
	{
		unsigned int master_pos = *(volatile unsigned int*)&RB->variant_info[0].pos;
		unsigned int our_pos    = RB->variant_info[ipmon_variant_num].pos;

		if (master_pos > our_pos)
			return result;

		// Maybe the master is just flushing the buffer?
		if (master_pos == our_pos && 
			(RB->variant_info[0].status & IPMON_STATUS_FLUSHING))
		{
			// The above check is racy. We need to check again if we really
			// caught up with the master the master might indeed be flushing
			// right now but it might have changed its offset since the time we
			// read it!!!
			master_pos = *(volatile unsigned int*)&RB->variant_info[0].pos;
			if (master_pos == our_pos)
			{
				ipmon_flush_buffer(RB);
				result = 1;
				continue;
			}
		}

		if (i++ > IPMON_YIELD_THRESHOLD)
		{
			i = 0;
			ipmon_unchecked_syscall(__NR_sched_yield);
		}
		else
		{
			cpu_relax();
		}
	}

	return result;
}

/*-----------------------------------------------------------------------------
    ipmon_pos_to_pointer - the pos we store in RB->variant_info is relative to
	the start of the syscall_entry array.
-----------------------------------------------------------------------------*/
void* ipmon_pos_to_pointer(struct ipmon_buffer* RB)
{
	return (void*)((unsigned long)RB +
				   64 * (RB->numvariants + 1) +
				   RB->variant_info[ipmon_variant_num].pos);
}

/*-----------------------------------------------------------------------------
    ipmon_prepare_syscall - 

    Determines how a syscall should be handled. There are several scenarios:

    1) if syscall is not in the list of possibly unchecked syscalls,
    this function will just return straight away

    2) if the syscall is in the list, then the master replica will determine
    whether or not the syscall metadata will fit in the IPMON buffer.

    If not, we will just store minimal info about the syscall and tell
    the caller that the syscall SHOULD be checked.

    If the metadata fits in the buffer, then the policy will be applied
-----------------------------------------------------------------------------*/
unsigned short ipmon_prepare_syscall (struct ipmon_buffer* RB, struct ipmon_syscall_args& args, unsigned long syscall_no)
{
	// Prepare the syscall here. The master needs to ensure that there's room to
	// write the syscall info

	// The structure we'll be writing/reading
	struct ipmon_syscall_entry* entry = 
		(struct ipmon_syscall_entry*)ipmon_pos_to_pointer(RB);

	// Remember this so ipmon_finish_syscall can use it too
	args.entry = entry;

	// Check whether we're the master or slave
	if (ipmon_variant_num == 0)
	{
		unsigned int args_size = 0, ret_size = 0, entry_size;
		unsigned short syscall_type;

		ipmon_syscall_calcsize(args, syscall_no, &args_size, &ret_size);

		entry_size = ROUND_UP(sizeof(struct ipmon_syscall_entry) + args_size + ret_size, ENTRY_ALIGNMENT);

		if (RB->have_pending_signals & 1)
			syscall_type = IPMON_WAIT_FOR_SIGNAL_CALL;
		else if (entry_size > RB->usable_size)
			syscall_type = IPMON_EXEC_NO_IPMON;
		else
			syscall_type = 0;

		// If the call is not actually going to get replicated by IP-MON, then
		// don't reserve space for the arguments or return values
		if (syscall_type)
		{
			args_size = ret_size = 0;
			entry_size = ROUND_UP(sizeof(struct ipmon_syscall_entry), ENTRY_ALIGNMENT);
		}

		// If the entry size (which can be just sizeof(ipmon_syscall_entry) when
		// it is a checked call, would exceed the buffer, flush
		if (entry_size > RB->usable_size - RB->variant_info[ipmon_variant_num].pos)
		{
			ipmon_flush_buffer(RB); 
			entry = (struct ipmon_syscall_entry*)ipmon_pos_to_pointer(RB);
			args.entry = entry;
		}

		// OK. We have room to write the entry now
		entry->syscall_no         = (unsigned short)syscall_no;
		entry->syscall_entry_size = entry_size;
		entry->syscall_args_size  = args_size;
		entry->syscall_type       = syscall_type;

		if (!entry->syscall_type)
			entry->syscall_type = ipmon_syscall_precall(args, entry);

		// Update the variant's current in-buffer position here.  NOTE: We will
		// adjust this later, once we know the real size occupied by the return
		// values.
		//
		// We update the position here already to ease debugging in GHUMVEE
		RB->variant_info[0].pos += 
			((entry->syscall_type & IPMON_REPLICATE_MASTER) ? sizeof(struct ipmon_syscall_entry) : entry->syscall_entry_size);

		// Skip sync if we're not going to execute the original call
		if ((entry->syscall_type & IPMON_EXEC_NO_IPMON) ||
			(entry->syscall_type & IPMON_WAIT_FOR_SIGNAL_CALL))
			return entry->syscall_type;

		// All relevant pre-syscall information has been logged into the buffer
		// This is where we could sync with the slave variants to implement
		// lock-stepping
		ipmon_sync_on_syscall_entrance(RB, entry);
	} 
	else 
	{ 
        // wait until we see a valid syscall entry that we haven't replicated
        // yet
		if (ipmon_wait_for_next_syscall(RB))
		{
			entry = (struct ipmon_syscall_entry*)ipmon_pos_to_pointer(RB);
			args.entry = entry;
		}

		// Update our position in the replication buffer
		RB->variant_info[ipmon_variant_num].pos +=
			((entry->syscall_type & IPMON_REPLICATE_MASTER) ? sizeof(struct ipmon_syscall_entry) : entry->syscall_entry_size);

		// See if we're actually going to execute the call
		// If not, skip all the checking and syncing
		if ((entry->syscall_type & IPMON_EXEC_NO_IPMON) ||
			(entry->syscall_type & IPMON_WAIT_FOR_SIGNAL_CALL))
			return entry->syscall_type;

		// Sanity Check 1: Compare the master's syscall number with ours
		if ((unsigned short)syscall_no != entry->syscall_no)
			ipmon_arg_verify_failed(entry->syscall_no, 0, syscall_no);

		// Sanity Check 2: Compare all syscall arguments
		ipmon_syscall_precall(args, entry);

		// We could sync with the master here to implement lock-stepping
		ipmon_sync_on_syscall_entrance(RB, entry);
	}

	return entry->syscall_type;
}

/*-----------------------------------------------------------------------------
    ipmon_finish_syscall - this gets called in the following contexts:

    * by the master if the call was unchecked
    * by the slave if the call was unchecked
    * by the slave if the call was noexec
-----------------------------------------------------------------------------*/
long ipmon_finish_syscall (struct ipmon_buffer* RB, struct ipmon_syscall_args& args, long ret)
{
	struct ipmon_syscall_entry* entry = args.entry;
	long realret = ret;

	// This will happen for unsynced calls!
	if (!entry)
		return ret;

	// Skip all of the replication logic if REPLICATE_MASTER is not set
	if (!(entry->syscall_type & IPMON_REPLICATE_MASTER))
	{
		ipmon_sync_on_syscall_exit(RB, entry);
		return ret;
	}

	if (ipmon_variant_num == 0)
	{
		unsigned int nr_ret_elements = 0;
		unsigned long true_ret_size  = 0;

		entry->syscall_return_value = ret;
		gcc_barrier();

		// We might have to restart the call if it was interrupted by a signal
		// Don't replicate the return values in this case...
		if (!ipmon_should_restart_call(ret))
		{
			nr_ret_elements = ipmon_syscall_postcall(args, entry, realret);

			// Recalculate the size of the return values			
			for (unsigned int i = 0; i < nr_ret_elements; i++)				
			{
				// our current position is the start of the return values
				true_ret_size += ((struct ipmon_syscall_data*)((unsigned long)ipmon_pos_to_pointer(RB) + 
															   entry->syscall_args_size + 
															   true_ret_size))->len;
			}
		}

		// we need word-size alignment on all ipmon_syscall_entries
		// because they contain variables that must be updated atomically
		entry->syscall_entry_size = 
			ROUND_UP(sizeof(struct ipmon_syscall_entry) + entry->syscall_args_size + true_ret_size, ENTRY_ALIGNMENT);

		// Update our position in the buffer once more
		RB->variant_info[0].pos += 
			entry->syscall_entry_size - sizeof(struct ipmon_syscall_entry);

		// Tell the slaves that the syscall results are available
		ipmon_do_syscall_wake(entry);

		// We could sync with the slaves here to implement full lock-stepping
		ipmon_sync_on_syscall_exit(RB, entry);
	}
	else
	{
		// Wait until the master has written the results
		ipmon_do_syscall_wait(entry);

		ret = entry->syscall_return_value;

		// Replicate the results
		if (!ipmon_should_restart_call(ret))
			ipmon_syscall_postcall(args, entry, realret);

		// And update our position in the buffer because the master might have
		// changed the entry size.
		RB->variant_info[ipmon_variant_num].pos += 
			entry->syscall_entry_size - sizeof(struct ipmon_syscall_entry);

		// We could sync with the master here
		ipmon_sync_on_syscall_exit(RB, entry);
	}

	return ret;
}

/*-----------------------------------------------------------------------------
    ipmon_is_unchecked_syscall
-----------------------------------------------------------------------------*/
unsigned char ipmon_is_unchecked_syscall(unsigned char* mask, unsigned long syscall_no)
{
	unsigned long no_to_byte, bit_in_byte;

	/* This is not very concise but the compiler will optimize it anyway... */
	if (syscall_no > ROUND_UP(__NR_syscalls, 8))
		return 0;

	no_to_byte  = syscall_no / 8;
	bit_in_byte = syscall_no % 8;

	if (mask[no_to_byte] & (1 << (7 - bit_in_byte)))
		return 1;
	return 0;
}

/*-----------------------------------------------------------------------------
    ipmon_set_unchecked_syscall
-----------------------------------------------------------------------------*/
void ipmon_set_unchecked_syscall(unsigned char* mask, unsigned long syscall_no, unsigned char unchecked)
{
	unsigned long no_to_byte, bit_in_byte;

	if (syscall_no > ROUND_UP(__NR_syscalls, 8))
		return;

	no_to_byte  = syscall_no / 8;
	bit_in_byte = syscall_no % 8;

	if (unchecked)
		mask[no_to_byte] |= (1 << (7 - bit_in_byte));
	else
		mask[no_to_byte] &= ~(1 << (7 - bit_in_byte));
}

/*-----------------------------------------------------------------------------
    ipmon_enclave_entrypoint - defined in MVEE_ipmon_syscall.S. This is where
	the kernel will land when the app executes a syscall on the IP-MON whitelist
-----------------------------------------------------------------------------*/
extern "C" void ipmon_enclave_entrypoint();
extern "C" void ipmon_enclave_entrypoint_alternative();
extern "C" void* ipmon_register_thread();

ipmon_buffer* secret_ipmon_buffer_pointer = NULL;

/*-----------------------------------------------------------------------------
    ipmon_enclave - This is where we land after the enclave entrypoint has
	set up our arguments for us.
-----------------------------------------------------------------------------*/
extern "C" long ipmon_enclave
(
#ifdef IPMON_PASS_RB_POINTER_EXPLICITLY
	ipmon_buffer* RB,
#endif
	unsigned long syscall_no,
	unsigned long arg1,
	unsigned long arg2,
	unsigned long arg3,
	unsigned long arg4,
	unsigned long arg5,
	unsigned long arg6
)
{
	long result;
	struct ipmon_syscall_args args;
	args.arg1 = arg1;
	args.arg2 = arg2;
	args.arg3 = arg3;
	args.arg4 = arg4;
	args.arg5 = arg5;
	args.arg6 = arg6;
	args.entry = NULL;

#ifdef MVEE_IP_PKU_ENABLED
	// erim_switch_to_trusted is moved inside the kernel (sys_ipmon_invoke)
	// otherwise we open the following attack window:
	//     1) attacker jumps before the domain switch
	//     2) changes the domain and possibly corrupts the memory protected by MPK
	//     Note that 2) can happen even without the use of system calls by using
	//     a bug inside IP-MON.
	// erim_switch_to_trusted;

	// Remove this comment to check that MPK protection works
	// !!! For testing purposes only !!!
	// erim_switch_to_untrusted;
#endif

	// check if we need to reinitialize
	// The kernel resets the RB pointer after every fork/clone
	if (!RB)
		RB = (ipmon_buffer*)ipmon_register_thread();

	// In signal handler
	if (RB->have_pending_signals & 2) {
		long ret = ipmon_checked_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
#ifdef MVEE_IP_PKU_ENABLED
		erim_switch_to_untrusted;
#endif
		return ret;
	}

	// If the syscall is not registered as a possibly unchecked syscall,
	// then we can skip the policy checks and replication logic altogether.
	//
	// Do note that even if we did decide to let the call through,
	// the kernel would refuse to dispatch it as an unchecked call anyway!
	if (!ipmon_is_unchecked_syscall(mask, syscall_no)
		|| ipmon_syscall_maybe_checked(args, syscall_no)) {
		long ret = ipmon_checked_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5, arg6);
#ifdef MVEE_IP_PKU_ENABLED
		erim_switch_to_untrusted;
#endif
		return ret;
	}

	// Certain syscalls are always harmless and should bypass both the ptracer
	// and the IP-MON's replication logic. Examples of such calls are
	// sys_sched_yield and sys_madvise
	if (ipmon_syscall_is_unsynced(args, syscall_no)) {
		long ret = ipmon_unchecked_syscall(syscall_no, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5, args.arg6);
#ifdef MVEE_IP_PKU_ENABLED
		erim_switch_to_untrusted;
#endif
		return ret;
	}

	// OK. At this point we know that the syscall could possibly bypass
	// the ptracer and that it does have to go through the policy and
	// replication manager.
	//
	// We invoke the policy manager here first through ipmon_prepare_syscall.
	// The policy manager will then tell us what to do with it.
	while (true)
	{
		unsigned short syscall_type = ipmon_prepare_syscall(RB, args, syscall_no);

		// Only the master should invoke the original syscall
		if (syscall_type & IPMON_EXEC_MASTER)
		{
			// Execute and replicate in the master
			if (ipmon_variant_num == 0)
			{
				result = ipmon_unchecked_syscall(syscall_no, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5, args.arg6);

				long ret = ipmon_finish_syscall(RB, args, result);

				if (ipmon_should_restart_call(result))
					continue;

#ifdef MVEE_IP_PKU_ENABLED
				erim_switch_to_untrusted;
#endif
				return ret;
			}
			// Skip execution but do try replicating in the slaves
			else
			{
				long ret = ipmon_finish_syscall(RB, args, 0);

				if (ipmon_should_restart_call(ret))
					continue;

#ifdef MVEE_IP_PKU_ENABLED
				erim_switch_to_untrusted;
#endif
				return ret;
			}
		}
		// Execute and possibly replicate in all variants
		else if (syscall_type & IPMON_EXEC_ALL)
		{
			result = ipmon_unchecked_syscall(syscall_no, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5, args.arg6);

			long ret = ipmon_finish_syscall(RB, args, result);

			if (ipmon_should_restart_call(result))
				continue;

#ifdef MVEE_IP_PKU_ENABLED
			erim_switch_to_untrusted;
#endif
			return ret;
		}
		else if (syscall_type & IPMON_EXEC_NOEXEC)
		{
			// Skip execution but do try replicating in all variants
			long ret = ipmon_finish_syscall(RB, args, 0);
		
			if (ipmon_should_restart_call(ret))
				continue;

#ifdef MVEE_IP_PKU_ENABLED
			erim_switch_to_untrusted;
#endif
			return ret;
		}
		else if (syscall_type & IPMON_WAIT_FOR_SIGNAL_CALL)
		{
			// The master decided we shouldn't execute the call because a signal is pending
			// Do a checked sys_getpid instead, then restart the original call
			ipmon_checked_syscall(__NR_getpid);
			continue;
		}
		else
		{	long ret = ipmon_checked_syscall(syscall_no, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5, args.arg6);
#ifdef MVEE_IP_PKU_ENABLED
			erim_switch_to_untrusted;
#endif
			return ret;
		}
	}
}

/*-----------------------------------------------------------------------------
    ipmon_rb_probe - 
-----------------------------------------------------------------------------*/
/*
void ipmon_rb_probe()
{
	// Test if we can access the replication buffer
	RB->padding[0] = 0;
}
*/

/*-----------------------------------------------------------------------------
    ipmon_register_thread - IP-MON registration is thread-local now!
-----------------------------------------------------------------------------*/
extern "C" void* ipmon_register_thread()
{
	int rb_size;
	void* RB = (void*)ipmon_checked_syscall(__NR_shmat,
											ipmon_checked_syscall(MVEE_GET_SHARED_BUFFER, 0, MVEE_IPMON_BUFFER, &rb_size, NULL, NULL, 0 /*rb_already_initialized*/),
											NULL, 0);

	if (!RB)
	{
		printf("ERROR: IP-MON registration failed. Could not attach to Replication Buffer\n");
		exit(-1);
		return NULL;
	}

	// printf("Replication buffer mapped @ 0x%016lx\n", RB);

	// Attach to the regfile map. This one is process-wide but might still be mapped after forking! 
	long mvee_regfile_id = ipmon_checked_syscall(MVEE_GET_SHARED_BUFFER, 0, MVEE_IPMON_REG_FILE_MAP, NULL, NULL, NULL, NULL);
	if (mvee_regfile_id != ipmon_reg_file_map_id)
	{
		ipmon_reg_file_map_id = mvee_regfile_id;
		ipmon_reg_file_map    = (char*)ipmon_checked_syscall(__NR_shmat, mvee_regfile_id, NULL, 0);

		if (!ipmon_reg_file_map)
		{
			printf("ERROR: IP-MON registration failed. Could not attach to File Map\n");
			exit(-1);
			return NULL;
		}
	}

	// This syscall returns the thread number within the variant set and can
	// optonally also set the variant number
	ipmon_checked_syscall(MVEE_GET_THREAD_NUM, &ipmon_variant_num);

	// Register IP-MON
	long ret = ipmon_checked_syscall(__NR_prctl, 
									 PR_REGISTER_IPMON, 
									 kernelmask, 
									 ROUND_UP(__NR_syscalls, 8) / 8, 
									 RB, 
#ifdef IPMON_PASS_RB_POINTER_EXPLICITLY
									 ipmon_enclave_entrypoint_alternative
#else
									 ipmon_enclave_entrypoint
#endif
		);

///	RB = NULL;

	if (ret < 0 && ret > -4096)
	{
		printf("ERROR: IP-MON registration failed. sys_prctl(PR_REGISTER_IPMON) returned: %ld (%s)\n", ret, strerror(-ret));
//		exit(-1);
		return NULL;
	}

#ifdef MVEE_IP_PKU_ENABLED
	// erim_switch_to_trusted is moved inside the kernel (sys_prctl with PR_REGISTER_IPMON as argument)
	// otherwise we open the following attack window:
	//     1) attacker jumps before the domain switch
	//     2) changes the domain and possibly corrupts the memory protected by MPK
	//     Note that 2) can happen even without the use of system calls by using
	//     a bug inside IP-MON.
	// erim_switch_to_trusted;

	int status;
	int pkey;

	int flags = ERIM_FLAG_ISOLATE_TRUSTED;

	/*
	* Allocate a protection key:
	*/
	pkey = pkey_alloc(0, 0);
	if (pkey == -1)
		printf("ERROR: IP-MON registration failed. sys_pkey_alloc returned -1.");

	// this check is important when the buffer has already been initialized
	// this can happen after a fork in a child since the child inherits parent's
	// permissions, mappings and the allocated keys. If we have an execve exactly
	// after the fork we do not experience this behavior since variant's state is cleared
	if (pkey == 2) {
		pkey_free(2);
	}

	/*
	* Set the protection key on ipmon_reg_file_map.
	* Note that it is still read/write as far as mprotect() is
	* concerned and the previous pkey_set() overrides it. !!! We changed that though !!!
	*/
	status = pkey_mprotect(ipmon_reg_file_map, 4096/* TODO this number may change at some point */, PROT_READ | PROT_WRITE, ERIM_TRUSTED_DOMAIN_ID(flags));
	if (status == -1)
		printf("ERROR: IP-MON File-Map registration failed. pkey_mprotect returned -1.");

	/*
	* Set the protection key on RB.
	* Note that it is still read/write as far as mprotect() is
	* concerned and the previous pkey_set() overrides it. !!! We changed that though !!!
	*/
	status = pkey_mprotect(RB, rb_size, PROT_READ | PROT_WRITE, ERIM_TRUSTED_DOMAIN_ID(flags));
	if (status == -1)
		printf("ERROR: IP-MON RB registration failed. pkey_mprotect returned -1.");
#endif

	return RB;
}

/*-----------------------------------------------------------------------------
    is_ipmon_kernel_compatible - Check if the currently loaded kernel supports
	the sys_ipmon_return syscall
-----------------------------------------------------------------------------*/
unsigned char is_ipmon_kernel_compatible()
{
	if (!ipmon_initialized)
	{
		// this call returns -EFAULT if called from outside the 
		// enclave
		if (ipmon_checked_syscall(__NR_ipmon_invoke) == -ENOIPMON)
			ipmon_kernel_compatible = 1;
	}
	return ipmon_kernel_compatible;
}

/*-----------------------------------------------------------------------------
    init - Initialize IP-MON and check for compatible glibc
-----------------------------------------------------------------------------*/
void __attribute__((constructor)) init()
{
	// We don't want to recalculate the syscall mask if we've already registered
	// an IP-MON for this process.
	if (ipmon_initialized && 
		is_ipmon_kernel_compatible())
	{
		ipmon_register_thread();
		return;
	}

	if (!is_ipmon_kernel_compatible())
	{
		printf("WARNING: IP-MON has been activated through the use_ipmon setting in MVEE.ini,\n");
		printf("WARNING: but we could not detect an IP-MON-compatible kernel.\n");
		printf("WARNING:\n");
		printf("WARNING: Please refer to MVEE/README.txt for instruction on how to build an\n");
		printf("WARNING: IP-MON compatible kernel.\n");
		return;
	}

	ipmon_initialized = true;
	syscall_ordering_mutex.hack = 0;
	IPMON_MASK_CLEAR(mask);
//	IPMON_MASK_SET(mask, __NR_ipmon_invoke);
#if CURRENT_POLICY >= BASE_POLICY
	IPMON_MASK_SET(mask, __NR_getegid);
	IPMON_MASK_SET(mask, __NR_geteuid);
	IPMON_MASK_SET(mask, __NR_getgid);
	IPMON_MASK_SET(mask, __NR_getpgrp);
	IPMON_MASK_SET(mask, __NR_getppid);
	IPMON_MASK_SET(mask, __NR_gettid);
	IPMON_MASK_SET(mask, __NR_getuid);
	IPMON_MASK_SET(mask, __NR_getpid);
	IPMON_MASK_SET(mask, __NR_gettimeofday);
	IPMON_MASK_SET(mask, __NR_time);
	IPMON_MASK_SET(mask, __NR_clock_gettime);
	IPMON_MASK_SET(mask, __NR_sched_yield);
	IPMON_MASK_SET(mask, __NR_getcwd);
	IPMON_MASK_SET(mask, __NR_uname);
	IPMON_MASK_SET(mask, __NR_getpriority);
	IPMON_MASK_SET(mask, __NR_nanosleep);
	IPMON_MASK_SET(mask, __NR_getrusage);
	IPMON_MASK_SET(mask, __NR_sysinfo);
    IPMON_MASK_SET(mask, __NR_times);
	IPMON_MASK_SET(mask, __NR_capget);
	IPMON_MASK_SET(mask, __NR_getitimer);

# if CURRENT_POLICY >= NONSOCKET_RO_POLICY
	// unconditionally allow
	IPMON_MASK_SET(mask, __NR_access);
	IPMON_MASK_SET(mask, __NR_faccessat);
	IPMON_MASK_SET(mask, __NR_stat);
	IPMON_MASK_SET(mask, __NR_lstat);
	IPMON_MASK_SET(mask, __NR_fstat);
	IPMON_MASK_SET(mask, __NR_newfstatat);
	IPMON_MASK_SET(mask, __NR_getdents);
	IPMON_MASK_SET(mask, __NR_readlink);
	IPMON_MASK_SET(mask, __NR_readlinkat);
	IPMON_MASK_SET(mask, __NR_getxattr);
	IPMON_MASK_SET(mask, __NR_lgetxattr);
	IPMON_MASK_SET(mask, __NR_fgetxattr);
	IPMON_MASK_SET(mask, __NR_lseek);
	IPMON_MASK_SET(mask, __NR_alarm);
	IPMON_MASK_SET(mask, __NR_setitimer);
	IPMON_MASK_SET(mask, __NR_timerfd_gettime);
	IPMON_MASK_SET(mask, __NR_madvise);
	IPMON_MASK_SET(mask, __NR_fadvise64);

	// conditionally allow
	IPMON_MASK_SET(mask, __NR_read);
	IPMON_MASK_SET(mask, __NR_readv);
	IPMON_MASK_SET(mask, __NR_pread64);
	IPMON_MASK_SET(mask, __NR_preadv);
	IPMON_MASK_SET(mask, __NR_select);
	IPMON_MASK_SET(mask, __NR_poll); 
	IPMON_MASK_SET(mask, __NR_ioctl);
# if defined(IPMON_SUPPORT_FUTEX) || defined(IPMON_USE_FUTEXES_FOR_BLOCKING_CALLS)
	IPMON_MASK_SET(mask, __NR_futex);
# endif

#  if CURRENT_POLICY >= NONSOCKET_RW_POLICY
    // unconditionally allow
	IPMON_MASK_SET(mask, __NR_timerfd_settime);
	IPMON_MASK_SET(mask, __NR_sync);
	IPMON_MASK_SET(mask, __NR_fsync);
	IPMON_MASK_SET(mask, __NR_fdatasync);
	IPMON_MASK_SET(mask, __NR_syncfs);

	// conditionally allow
	IPMON_MASK_SET(mask, __NR_write);
	IPMON_MASK_SET(mask, __NR_writev);
	IPMON_MASK_SET(mask, __NR_pwrite64); 
	IPMON_MASK_SET(mask, __NR_pwritev); 

#   if CURRENT_POLICY >= SOCKET_RO_POLICY
	// unconditionally allow
#    ifdef IPMON_SUPPORT_EPOLL
	IPMON_MASK_SET(mask, __NR_epoll_wait);
#    endif
	IPMON_MASK_SET(mask, __NR_recvfrom);
	IPMON_MASK_SET(mask, __NR_recvmsg);
	IPMON_MASK_SET(mask, __NR_recvmmsg);
	IPMON_MASK_SET(mask, __NR_getsockname);
	IPMON_MASK_SET(mask, __NR_getpeername);
	IPMON_MASK_SET(mask, __NR_getsockopt);

#    if CURRENT_POLICY >= SOCKET_RW_POLICY
	// unconditionally allow
	IPMON_MASK_SET(mask, __NR_sendto);
	IPMON_MASK_SET(mask, __NR_sendmsg);
	IPMON_MASK_SET(mask, __NR_sendmmsg);
	IPMON_MASK_SET(mask, __NR_sendfile);
	IPMON_MASK_SET(mask, __NR_shutdown);
	IPMON_MASK_SET(mask, __NR_setsockopt);
#     ifdef IPMON_SUPPORT_EPOLL
	IPMON_MASK_SET(mask, __NR_epoll_ctl);
#     endif

#     if CURRENT_POLICY >= FULL_SYSCALLS

	// Memory Management
	IPMON_MASK_SET(mask, __NR_mmap);
	IPMON_MASK_SET(mask, __NR_munmap);
	IPMON_MASK_SET(mask, __NR_mremap);
	IPMON_MASK_SET(mask, __NR_mprotect);
	IPMON_MASK_SET(mask, __NR_brk);

	// File Management
	IPMON_MASK_SET(mask, __NR_open);
	IPMON_MASK_SET(mask, __NR_openat);
	IPMON_MASK_SET(mask, __NR_close);
	IPMON_MASK_SET(mask, __NR_fcntl);
	IPMON_MASK_SET(mask, __NR_dup);
	IPMON_MASK_SET(mask, __NR_dup2);
	IPMON_MASK_SET(mask, __NR_dup3);
	IPMON_MASK_SET(mask, __NR_pipe);
	IPMON_MASK_SET(mask, __NR_pipe2);
	IPMON_MASK_SET(mask, __NR_inotify_init);
	IPMON_MASK_SET(mask, __NR_inotify_init1);

	// Directory management
	IPMON_MASK_SET(mask, __NR_chdir);
	IPMON_MASK_SET(mask, __NR_fchdir);
	IPMON_MASK_SET(mask, __NR_mkdir);

	// Socket Management
	IPMON_MASK_SET(mask, __NR_socket);
	IPMON_MASK_SET(mask, __NR_socketpair);
	IPMON_MASK_SET(mask, __NR_bind);
	IPMON_MASK_SET(mask, __NR_connect);
	IPMON_MASK_SET(mask, __NR_listen);
	IPMON_MASK_SET(mask, __NR_accept4);
	IPMON_MASK_SET(mask, __NR_accept);
#      ifdef IPMON_SUPPORT_EPOLL
	IPMON_MASK_SET(mask, __NR_epoll_create);
	IPMON_MASK_SET(mask, __NR_epoll_create1);
#      endif

	// Process Management
//	IPMON_MASK_SET(mask, __NR_exit_group);

#     endif // >= FULL_SYSCALLS
#    endif  // >= SOCKET_RW
#   endif   // >= SOCKET_RO
#  endif    // >= NONSOCKET_RW
# endif     // >= NONSOCKET_RO
#endif      // >= BASE

	memcpy(&kernelmask, &mask, sizeof(mask));

// explicitly disable it here because we might have enabled it
// during registration if we're using futexes internally
// for blocking calls
#ifndef IPMON_SUPPORT_FUTEX
    IPMON_MASK_UNSET(mask, __NR_futex);
#endif

	ipmon_register_thread();
#ifdef MVEE_IP_PKU_ENABLED
	erim_switch_to_untrusted;
#endif
}
