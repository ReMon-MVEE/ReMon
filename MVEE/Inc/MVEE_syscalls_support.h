/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_SYSCALLS_SUPPORT_H_
#define MVEE_SYSCALLS_SUPPORT_H_

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include "MVEE_build_config.h"

/*-----------------------------------------------------------------------------
  System Call Handling Macros - Important note: All CHECKxxx and REPLICATExxx
  macros assume that you've checked whether or not their pointer arguments are
  valid using the CHECKPOINTER macro.

  CHECKPOINTER ensures that either all pointers are NULL or all pointers are
  non-NULL.  It could be interesting to also check whether all pointers point to
  mapped regions.

  The CHECKxxx and REPLICATExxx macros therefore only check whether the
  specified argument is non-NULL in the master variant.
-----------------------------------------------------------------------------*/
//
// Fill an array with the values of a syscall argument in all variants
//
#define FILLARGARRAY(numarg, argarray) do {						\
        for (int i = 0; i < mvee::numvariants; ++i)				\
            *(unsigned long*)&argarray[i] = ARG ## numarg(i);	\
} while (0)

//
// Check whether the arguments are null or valid pointers
//
#define CHECKPOINTER(numarg)                                                                 \
    {                                                                                        \
        std::vector<void*> pointers(mvee::numvariants);					                     \
        FILLARGARRAY(numarg, pointers);                                                      \
        if (call_compare_pointers(pointers) == 1)                                            \
        {                                                                                    \
            cache_mismatch_info("argument %d mismatch - pointer null-nonnull - syscall: %ld (%s)\n", \
                        numarg, variants[0].callnum,                                           \
                        getTextualSyscall(variants[0].callnum));                               \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY; \
        }                                                                                    \
    }

//
// Compare the values of the specified argument
//
#define CHECKARG(numarg)                                                               \
    for (int i = 1; i < mvee::numvariants; ++i)                                        \
    {                                                                                  \
        if (ARG ## numarg(i) != ARG ## numarg(i-1))                                    \
        {                                                                              \
            cache_mismatch_info("argument %d mismatch - syscall: %ld (%s)\n",                  \
                        numarg, variants[0].callnum,                                     \
                        getTextualSyscall(variants[0].callnum));                         \
            cache_mismatch_info("ARG%d(%d) = 0x" PTRSTR " - ARG%d(%d) = 0x" PTRSTR "\n",       \
                        numarg, i, ARG ## numarg(i), numarg, i-1, ARG ## numarg(i-1)); \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;	\
        }                                                                              \
    }

//
// Compare the values of the specified argument
//
#define CHECKARG64(basearg, alignedarg)									\
    for (int i = 1; i < mvee::numvariants; ++i)							\
    {																	\
		if (arg64<basearg, alignedarg>(i) != arg64<basearg, alignedarg>(i-1)) \
        {																\
            cache_mismatch_info("argument %d mismatch - syscall: %ld (%s)\n", \
								basearg, variants[0].callnum,			\
								getTextualSyscall(variants[0].callnum)); \
            cache_mismatch_info("ARG%d(%d) = 0x%016llx - ARG%d(%d) = 0x%016llx\n", \
								basearg, i, arg64<basearg, alignedarg>(i), \
								basearg, i-1, arg64<basearg, alignedarg>(i-1)); \
            return MVEE_PRECALL_ARGS_MISMATCH(basearg) | MVEE_PRECALL_CALL_DENY;	\
        }																\
    }

//
// Compare the values of the specified argument
//
#define CHECKALIGNEDARG(basearg, alignedarg)									\
    for (int i = 1; i < mvee::numvariants; ++i)							\
    {																	\
		if (aligned_arg<basearg, alignedarg>(i) != aligned_arg<basearg, alignedarg>(i-1)) \
        {																\
            cache_mismatch_info("argument %d mismatch - syscall: %ld (%s)\n", \
								basearg, variants[0].callnum,			\
								getTextualSyscall(variants[0].callnum)); \
            cache_mismatch_info("ARG%d(%d) = 0x%016llx - ARG%d(%d) = 0x%016llx\n", \
								basearg, i, aligned_arg<basearg, alignedarg>(i), \
								basearg, i-1, aligned_arg<basearg, alignedarg>(i-1)); \
            return MVEE_PRECALL_ARGS_MISMATCH(basearg) | MVEE_PRECALL_CALL_DENY;	\
        }																\
    }


//
// Compare the values of the specified sockaddr - POINTER ARGUMENT!!!
//
#define CHECKSOCKADDR(numarg, addrlen)                                               \
    if (ARG ## numarg(0))                                                            \
    {                                                                                \
        GETTEXTADDRDIRECT(0, master_addr, numarg, addrlen);                          \
        for (int i = 1; i < mvee::numvariants; ++i)                                  \
        {                                                                            \
            GETTEXTADDRDIRECT(i, slave_addr, numarg, addrlen);                       \
            if (master_addr != slave_addr)                                           \
            {                                                                        \
                cache_mismatch_info("argument %d mismatch - sockaddr - syscall: %ld (%s)\n", \
                            numarg, variants[0].callnum,                               \
                            getTextualSyscall(variants[0].callnum));                   \
                cache_mismatch_info("master sockaddr: %s - slave %d sockaddr: %s\n",         \
                            master_addr.c_str(), i, slave_addr.c_str());             \
                return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;          \
            }                                                                        \
        }                                                                            \
    }

//
// Compare the values of the specified argument
//
#define CHECKFLAGS(numarg, mask)                                              \
    for (int i = 1; i < mvee::numvariants; ++i)                               \
    {                                                                         \
        if ((ARG ## numarg(i) & (mask)) != (ARG ## numarg(i-1) & (mask)))     \
        {                                                                     \
            cache_mismatch_info("argument %d mismatch - flags - syscall: %ld (%s)\n", \
                        numarg, variants[0].callnum,                            \
                        getTextualSyscall(variants[0].callnum));                \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;       \
        }                                                                     \
    }

//
// Compare file descriptors - Well this is easy now. In the current implementation, the FDs should be equal
//
#define CHECKFD(numarg) \
    CHECKARG(numarg);

//
// Compare file descriptor sets - POINTER ARGUMENT!!!
//
#define CHECKFDSET(numarg, nfds)										\
	if (ARG ## numarg(0))												\
	{																	\
		std::vector<fd_set*> pointers(mvee::numvariants);			\
		FILLARGARRAY(numarg, pointers);									\
		if (!call_compare_fd_sets(pointers, nfds))						\
		{																\
			cache_mismatch_info("argument %d mismatch - fd_sets - syscall: %ld (%s)\n",	\
						numarg, variants[0].callnum,						\
                        getTextualSyscall(variants[0].callnum));			\
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;	\
        }																\
    }

//
// Compare buffer contents - POINTER ARGUMENT!!!
//
#define CHECKBUFFER(numarg, len)                                                        \
    if (ARG ## numarg(0) && len > 0)                                                    \
    {                                                                                   \
        std::vector<const unsigned char*> argarray(mvee::numvariants);                         \
        FILLARGARRAY(numarg, argarray);                                                 \
        if (!call_compare_variant_buffers(argarray, len))				\
        {                                                                               \
            cache_mismatch_info("buffer contents mismatch - argument %d - syscall: %ld (%s)\n", \
                        numarg, variants[0].callnum,                                      \
                        getTextualSyscall(variants[0].callnum));                          \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;                 \
        }                                                                               \
    }

//
// Compare strings - POINTER ARGUMENT!!!
//
#define CHECKSTRING(numarg)                                                     \
    if (ARG ## numarg(0))                                                       \
    {                                                                           \
        std::vector<const char*> argarray(mvee::numvariants);                 \
        FILLARGARRAY(numarg, argarray);                                         \
        if (!call_compare_variant_strings(argarray, 0))                           \
        {                                                                       \
            cache_mismatch_info("strings mismatch - argument %d - syscall: %ld (%s)\n", \
                        numarg, variants[0].callnum,                              \
                        getTextualSyscall(variants[0].callnum));                  \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;         \
        }                                                                       \
    }

//
// Compare signal handlers
//
#define CHECKSIGHAND(numarg)                                                    \
    {                                                                           \
        std::vector<unsigned long> argarray(mvee::numvariants);                 \
        FILLARGARRAY(numarg, argarray);                                         \
        if (!call_compare_signal_handlers(argarray))                            \
        {                                                                       \
            cache_mismatch_info("sighand mismatch - argument %d - syscall: %ld (%s)\n", \
                        numarg, variants[0].callnum,                              \
                        getTextualSyscall(variants[0].callnum));                  \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;         \
        }                                                                       \
    }

//
// Compare memory regions
//
#define CHECKREGION(numarg, len)                                                      \
    {                                                                                 \
        std::vector<unsigned long> addresses(mvee::numvariants);                      \
        FILLARGARRAY(numarg, addresses);                                              \
        if (!set_mmap_table->compare_ranges(addresses, len))                          \
        {                                                                             \
            cache_mismatch_info("memory region mismatch - argument %d - syscall: %ld (%s)\n", \
                        numarg, variants[0].callnum,                                    \
                        getTextualSyscall(variants[0].callnum));                        \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;               \
        }                                                                             \
    }

//
// Compare I/O vectors - POINTER ARGUMENT!!!
//
#define CHECKVECTOR(numarg, len)                                        \
    if (ARG ## numarg(0) && len > 0)                                    \
    {                                                                   \
        std::vector<struct iovec*> addresses(mvee::numvariants);        \
        FILLARGARRAY(numarg, addresses);                                \
        if (!call_compare_io_vectors(addresses, len))                   \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY; \
    }

//
// Compare I/O vectors (layout only) - POINTER ARGUMENT!!!
//
#define CHECKVECTORLAYOUT(numarg, len)                                  \
    if (ARG ## numarg(0) && len > 0)                                    \
    {                                                                   \
        std::vector<struct iovec*> addresses(mvee::numvariants);        \
        FILLARGARRAY(numarg, addresses);                                \
        if (!call_compare_io_vectors(addresses, len, 1))                \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY; \
    }

//
// Compare socket msg vectors - POINTER ARGUMENT!!!
//
#define CHECKMSGVECTOR(numarg)                                          \
    if (ARG ## numarg(0))                                               \
    {                                                                   \
        std::vector<struct msghdr*> addresses(mvee::numvariants);        \
        FILLARGARRAY(numarg, addresses);                                \
        if (!call_compare_msgvectors(addresses))                        \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY; \
    }

//
// Compare socket msg vectors - POINTER ARGUMENT!!!
//
#define CHECKMSGVECTORLAYOUT(numarg)                                    \
    if (ARG ## numarg(0))                                               \
    {                                                                   \
        std::vector<struct msghdr*> addresses(mvee::numvariants);        \
        FILLARGARRAY(numarg, addresses);                                \
        if (!call_compare_msgvectors(addresses, true))                  \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY; \
    }

//
// Compare socket msg vector vectors - POINTER ARGUMENT!!!
//
#define CHECKMMSGVECTOR(numarg, len)                                        \
    if (ARG ## numarg(0) && len > 0)                                        \
    {                                                                       \
        std::vector<struct mmsghdr*> addresses(mvee::numvariants);            \
        FILLARGARRAY(numarg, addresses);                                    \
		if (!call_compare_mmsgvectors(addresses, len))					\
			return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY; \
    }

//
// Compare socket msg vector vectors - POINTER ARGUMENT!!!
//
#define CHECKMMSGVECTORLAYOUT(numarg, len)                                  \
    if (ARG ## numarg(0) && len > 0)                                        \
    {                                                                       \
        std::vector<struct mmsghdr*> addresses(mvee::numvariants);            \
        FILLARGARRAY(numarg, addresses);                                    \
		if (!call_compare_mmsgvectors(addresses, len, true))				\
			return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY; \
    }

//
// Compare sigactions - must be non-RT signal handling aware! - POINTER ARGUMENT!!!
//
#define CHECKSIGACTION(numarg, is_old_call)                                               \
    if (ARG ## numarg(0))                                                                 \
    {                                                                                     \
        std::vector<void*> argarray(mvee::numvariants);                           \
        FILLARGARRAY(numarg, argarray);                                                   \
        struct sigaction master_action = call_get_sigaction(0, argarray[0], is_old_call); \
        for (int i = 1; i < mvee::numvariants; ++i)                                       \
        {                                                                                 \
            struct sigaction action = call_get_sigaction(i, argarray[i], is_old_call);    \
            if (action.sa_flags != master_action.sa_flags                                 \
                || !call_compare_sigsets(&action.sa_mask, &master_action.sa_mask)         \
                || (action.sa_handler == SIG_IGN && master_action.sa_handler != SIG_IGN)  \
                || (action.sa_handler == SIG_DFL && master_action.sa_handler != SIG_DFL)  \
                || (action.sa_handler && !master_action.sa_handler)                       \
                || (!action.sa_handler && master_action.sa_handler))                      \
            {                                                                             \
                cache_mismatch_info("sigaction mismatch - argument %d - syscall: %ld (%s)\n",     \
                            numarg, variants[0].callnum,                                    \
                            getTextualSyscall(variants[0].callnum));                        \
                return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;               \
            }                                                                             \
        }                                                                                 \
    }

//
// Compare sigsets - must be non-RT signal handling aware! - POINTER ARGUMENT!!!
//
#define CHECKSIGSET(numarg, is_old_call)                                           \
    if (ARG ## numarg(0))                                                          \
    {                                                                              \
        std::vector<void*> argarray(mvee::numvariants);                    \
        FILLARGARRAY(numarg, argarray);                                            \
        sigset_t master_set = call_get_sigset(0, argarray[0], is_old_call);        \
        for (int i = 1; i < mvee::numvariants; ++i)                                \
        {                                                                          \
            sigset_t set = call_get_sigset(i, argarray[i], is_old_call);           \
            if (!call_compare_sigsets(&master_set, &set))                          \
            {                                                                      \
                cache_mismatch_info("sigset mismatch - argument %d - syscall: %ld (%s)\n", \
                            numarg, variants[0].callnum,                             \
                            getTextualSyscall(variants[0].callnum));                 \
                return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;        \
            }                                                                      \
        }                                                                          \
    }

//
// Compare epoll events - POINTER ARGUMENT!!!
//
#define CHECKEPOLLEVENT(numarg)                                                                                \
    if (ARG ## numarg(0))                                                                                      \
    {                                                                                                          \
        std::vector<void*> events(mvee::numvariants);                                                  \
        FILLARGARRAY(numarg, events);                                                                          \
        struct epoll_event master_event, slave_event;                                                          \
        if (!rw::read_struct(variants[0].variantpid, events[0], sizeof(struct epoll_event), &master_event))    \
        {                                                                                                      \
            cache_mismatch_info("couldn't read epoll_event\n");                                                        \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;                                        \
        }                                                                                                      \
        for (int i = 1; i < mvee::numvariants; ++i)                                                            \
        {                                                                                                      \
            if (!rw::read_struct(variants[i].variantpid, events[i], sizeof(struct epoll_event), &slave_event)) \
            {                                                                                                  \
                cache_mismatch_info("couldn't read epoll_event\n");                                                    \
                return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;                                    \
            }                                                                                                  \
            if (slave_event.events != master_event.events)                                                     \
            {                                                                                                  \
                cache_mismatch_info("epoll event mismatch in argument %d - syscall: %ld (%s)\n",                       \
                            numarg, variants[0].callnum,                                                         \
                            getTextualSyscall(variants[0].callnum));                                             \
                return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;                                    \
            }                                                                                                  \
        }                                                                                                      \
    }

//
// Compare pollfds - POINTER ARGUMENT!!!
//
#define CHECKPOLLFD(numarg, len)                                                                               \
    if (ARG ## numarg(0) && len > 0)                                                                           \
    {                                                                                                          \
        std::vector<void*> pollfds(mvee::numvariants);                                                         \
        FILLARGARRAY(numarg, pollfds);                                                                         \
        struct pollfd master_pollfd, slave_pollfd;                                                             \
        if (!rw::read_struct(variants[0].variantpid, pollfds[0], sizeof(struct pollfd), &master_pollfd))       \
        {                                                                                                      \
            cache_mismatch_info("couldn't read pollfd\n");                                                     \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;                                \
        }                                                                                                      \
        for (int i = 1; i < mvee::numvariants; ++i)                                                            \
        {                                                                                                      \
            if (!rw::read_struct(variants[i].variantpid, pollfds[i], sizeof(struct pollfd), &slave_pollfd))    \
            {                                                                                                  \
                cache_mismatch_info("couldn't read pollfd\n");                                                 \
                return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;                            \
            }                                                                                                  \
            if (slave_pollfd.fd     != master_pollfd.fd ||                                                     \
                slave_pollfd.events != master_pollfd.events)                                                   \
            {                                                                                                  \
                cache_mismatch_info("pollfd mismatch in argument %d - syscall: %ld (%s)\n",                    \
                            numarg, variants[0].callnum,                                                       \
                            getTextualSyscall(variants[0].callnum));                                           \
                return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;                            \
            }                                                                                                  \
        }                                                                                                      \
    }

//
// Replicate buffer contents. Use this only for mastercalls that return
// a fixed length buffer - POINTER ARGUMENT!!!
//
#define REPLICATEBUFFERFIXEDLEN(numarg, len)                        \
    {                                                               \
        if (call_succeeded &&                                       \
            state == STATE_IN_MASTERCALL &&                         \
            ARG ## numarg(0))                                       \
        {                                                           \
            std::vector<const unsigned char*> argarray(mvee::numvariants); \
            FILLARGARRAY(numarg, argarray);                         \
            call_replicate_buffer(argarray, len);                   \
        }                                                           \
    }

//
// Replicate buffer contents. Use this only for mastercalls that return the
// length of the buffer as the return value of the syscall - POINTER ARGUMENT!!!
//
#define REPLICATEBUFFER(numarg)                                     \
    {                                                               \
        if (call_succeeded &&                                       \
            state == STATE_IN_MASTERCALL &&                         \
            ARG ## numarg(0))                                       \
        {                                                           \
            long len = call_postcall_get_variant_result(0);           \
            std::vector<const unsigned char*> argarray(mvee::numvariants); \
            FILLARGARRAY(numarg, argarray);                         \
            call_replicate_buffer(argarray, len);                   \
        }                                                           \
    }

//
// Replicate buffer contents. Use this only for mastercalls that return the
// length of the buffer in an argument - TWO POINTER ARGUMENTS!!!
//
#define REPLICATEBUFFERANDLEN(bufferarg, lenarg, lenarg_type)			\
    {																	\
        if (call_succeeded &&											\
            state == STATE_IN_MASTERCALL &&								\
            ARG ## bufferarg(0) &&										\
            ARG ## lenarg(0))											\
        {																\
			lenarg_type len = 0;										\
			if (!rw::read_primitive<lenarg_type>(variants[0].variantpid, (void*) ARG ## lenarg(0), len)) \
			{															\
				warnf("%s - couldn't read length\n", call_get_variant_pidstr(0).c_str()); \
				shutdown(false);										\
			}															\
            std::vector<const unsigned char*> argarray(mvee::numvariants); \
            FILLARGARRAY(bufferarg, argarray);							\
            call_replicate_buffer(argarray, len);						\
            for (int j = 1; j < mvee::numvariants; ++j)					\
            {															\
				if (!rw::write_primitive<lenarg_type>(variants[j].variantpid, (void*) ARG ## lenarg(j), len)) \
				{														\
					warnf("%s - couldn't write length\n", call_get_variant_pidstr(j).c_str()); \
					shutdown(false);									\
				}														\
            }															\
        }																\
    }

//
// Replicate I/O vector contents. Use only for mastercalls that return the
// number of bytes copied through the syscall return value - POINTER ARGUMENT!!!
//
#define REPLICATEVECTOR(numarg)                                     \
    {                                                               \
        if (call_succeeded &&                                       \
            state == STATE_IN_MASTERCALL &&                         \
            ARG ## numarg(0))                                       \
        {                                                           \
            long len = call_postcall_get_variant_result(0);           \
            std::vector<struct iovec*> argarray(mvee::numvariants); \
            FILLARGARRAY(numarg, argarray);                         \
            call_replicate_io_vector(argarray, len);                \
        }                                                           \
    }

//
// Replicate socket MSG vector contents. Use only for mastercalls that return the
// number of bytes sent through the syscall return value - POINTER ARGUMENT!!!
//
#define REPLICATEMSGVECTOR(numarg)                                  \
    {                                                               \
        if (call_succeeded &&                                       \
            state == STATE_IN_MASTERCALL &&                         \
            ARG ## numarg(0))                                       \
        {                                                           \
            long len = call_postcall_get_variant_result(0);           \
            std::vector<struct msghdr*> argarray(mvee::numvariants); \
            FILLARGARRAY(numarg, argarray);                         \
            call_replicate_msgvector(argarray, len);                \
        }                                                           \
    }

//
// Replicate socket MSG vector vector contents.
// This is quite tricky!!! Calls like recvmmsg don't return the number
// of bytes that you've received. Instead, they return the number of vectors that were filled.
//
#define REPLICATEMMSGVECTOR(numarg)                                 \
    {                                                               \
        if (call_succeeded &&                                       \
            state == STATE_IN_MASTERCALL &&                         \
            ARG ## numarg(0))                                       \
        {                                                           \
            long len = call_postcall_get_variant_result(0);           \
            std::vector<struct mmsghdr*> argarray(mvee::numvariants); \
            FILLARGARRAY(numarg, argarray);                         \
            call_replicate_mmsgvector(argarray, len);               \
        }                                                           \
    }

//
//
#define REPLICATEMMSGVECTORLENS(numarg, attempted)                   \
    {                                                                \
        if (call_succeeded &&                                        \
            state == STATE_IN_MASTERCALL &&                          \
            ARG ## numarg(0))                                        \
        {                                                            \
            long len = call_postcall_get_variant_result(0);            \
            std::vector<struct mmsghdr*> argarray(mvee::numvariants);  \
            FILLARGARRAY(numarg, argarray);                          \
            call_replicate_mmsgvectorlens(argarray, len, attempted); \
        }                                                            \
    }

//
// Replicate struct ifconf
//
#define REPLICATEIFCONF(numarg)										\
	{																\
	if (call_succeeded &&											\
		state == STATE_IN_MASTERCALL &&								\
		ARG ## numarg(0))											\
	{																\
		std::vector<struct ifconf*> argarray(mvee::numvariants);	\
		FILLARGARRAY(numarg, argarray);								\
		call_replicate_ifconfs(argarray);							\
	}																\
	}

//
// Get sockaddr from arg sockarg with length from arg lenarg
// and convert to textual form
//
#define GETTEXTADDR(variantnum, text_addr, sockarg, lenarg)				\
    std::string text_addr;												\
    if (ARG ## sockarg(variantnum) && ARG ## lenarg(variantnum))		\
    {																	\
		socklen_t len = 0;												\
		if (!rw::read_primitive<socklen_t>(variants[variantnum].variantpid, \
										   (void*) ARG ## lenarg(variantnum), len)) \
		{																\
			warnf("%s - Failed to read socket text address\n",			\
				  call_get_variant_pidstr(variantnum).c_str());			\
			shutdown(false);											\
		}																\
		struct sockaddr* addr = call_get_sockaddr(variantnum, (struct sockaddr*) ARG ## sockarg(variantnum), len); \
		text_addr = addr ? getTextualSocketAddr(addr) : "";				\
		SAFEDELETEARRAY(addr);											\
    }

//
// Get sockaddr from arg sockarg with length len
// and convert to textual form
//
#define GETTEXTADDRDIRECT(variantnum, text_addr, sockarg, len)                                \
    std::string text_addr;                                                                  \
    if (ARG ## sockarg(variantnum) && len)                                                    \
    {                                                                                       \
        struct sockaddr* addr = call_get_sockaddr(variantnum, (struct sockaddr*) ARG ## sockarg(variantnum), len); \
        text_addr = addr ? getTextualSocketAddr(addr) : "";                                 \
        SAFEDELETEARRAY(addr);                                                              \
    }

#define OLDCALLIFNOT(newcallnum) \
    ((variants[0].callnum == newcallnum) ? false : true)

//
// Map master fds onto slave fds - used at the system call site
//
#define MAPFDS(numarg)													\
    if ((unsigned int)ARG ## numarg(0) != (unsigned int)-1)				\
    {																	\
        fd_info* info = set_fd_table->get_fd_info(ARG ## numarg(0));	\
        if (info && !info->master_file)									\
        {																\
            for (int i = 1; i < mvee::numvariants; ++i)					\
            {															\
				if (ARG ## numarg(0) != info->fds[i])					\
				{														\
					debugf("%s - mapped fd %lu to fd %lu\n", call_get_variant_pidstr(i).c_str(), (unsigned long) ARG ## numarg(0), info->fds[i]); \
					call_overwrite_arg_value(i, numarg, info->fds[i], true); \
				}														\
            }															\
        }																\
        else if (!info || info->master_file)							\
        {																\
            for (int i = 1; i < mvee::numvariants; ++i)					\
            {															\
				unsigned long new_fd = set_fd_table->get_free_fd(i, ARG ## numarg(i)); \
				call_overwrite_arg_value(i, numarg, new_fd, true);		\
            }															\
        }																\
    }

//
// Replicate a system call result from master to slave variants even
// if we're not in state STATE_IN_MASTERCALL
//
#define REPLICATEFDRESULT()                                              \
    {                                                                    \
        unsigned long master_result = call_postcall_get_variant_result(0); \
        for (int i = 1; i < mvee::numvariants; ++i)                      \
            call_postcall_set_variant_result(i, master_result);            \
    }

//
// We use this for all system calls that take PID arguments. Therefore it must take into account
// that the 0 and -1 values have special meanings and do not need to be mapped and that
// negative values indicate process group values
//
#define MAPPIDS(numarg)													\
    if (ARG ## numarg(0) != 0 && ARG ## numarg(0) != 1)					\
    {																	\
        pid_t master_pid = (pid_t) ARG ## numarg(0);					\
			std::vector<pid_t> mapped_pids(mvee::numvariants);			\
			if (mvee::map_master_to_slave_pids((master_pid < -1) ? -master_pid : master_pid, mapped_pids)) \
			{															\
				for (int i = 1; i < mvee::numvariants; ++i)				\
				{														\
					if ((pid_t)ARG ## numarg(i) != mapped_pids[i])		\
						call_overwrite_arg_value(i, numarg, mapped_pids[i], true); \
				}														\
			}															\
    }

#endif /* MVEE_SYSCALLS_SUPPORT_H_ */
