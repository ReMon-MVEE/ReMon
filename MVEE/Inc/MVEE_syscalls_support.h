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
#include "MVEE_config.h"

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
#define STRINGARG(variantnum, numarg) \
    variants[variantnum].args[numarg].str

#define CSTRINGARG(variantnum, numarg) \
    variants[variantnum].args[numarg].cstr

#define BUFARG(variantnum, numarg) \
    variants[variantnum].args[numarg].buf

//
// Fill an array with the values of a syscall argument in all variants
//
#define FILLARGARRAY(numarg, argarray) do {         \
        for (int i = 0; i < mvee::numvariants; ++i) \
            argarray[i] = ARG ## numarg(i);         \
} while (0)

//
// Change the values of a syscall argument in all variants, given an array
//
#define SETARGARRAY(numarg, argarray)  do {         \
        for (int i = 0; i < mvee::numvariants; ++i) \
            SETARG ## numarg(i, argarray[i]);       \
} while (0)


//
// Check whether the arguments are null or valid pointers
//
#define CHECKPOINTER(numarg)                                                                 \
    {                                                                                        \
        std::vector<unsigned long> pointers(mvee::numvariants);                              \
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
// The shm ids must either all be equal OR they must 
// be equal to the variant's hidden buffer array id
//
#define CHECKSHMID(numarg)												\
	for (int i = 1; i < mvee::numvariants; ++i)							\
	{																	\
		if (ARG ## numarg(i) != ARG ## numarg(i-1)						\
			&& (int)ARG ## numarg(i) != variants[i].hidden_buffer_array_id) \
		{																\
			cache_mismatch_info("argument %d mismatch - syscall: %ld (%s)\n",	\
						numarg, variants[0].callnum,						\
						getTextualSyscall(variants[0].callnum));			\
			cache_mismatch_info("ARG%d(%d) = 0x" PTRSTR " - ARG%d(%d) = 0x" PTRSTR "\n", \
						numarg, i, ARG ## numarg(i), numarg, i-1, ARG ## numarg(i-1)); \
			return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;	\
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
		std::vector<unsigned long> pointers(mvee::numvariants);			\
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
        std::vector<unsigned long> argarray(mvee::numvariants);                         \
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
        std::vector<unsigned long> argarray(mvee::numvariants);                 \
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
        std::vector<unsigned long> addresses(mvee::numvariants);        \
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
        std::vector<unsigned long> addresses(mvee::numvariants);        \
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
        std::vector<unsigned long> addresses(mvee::numvariants);        \
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
        std::vector<unsigned long> addresses(mvee::numvariants);        \
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
        std::vector<unsigned long> addresses(mvee::numvariants);            \
        FILLARGARRAY(numarg, addresses);                                    \
        for (unsigned int i = 0; i < (unsigned int)len; ++i)                \
        {                                                                   \
            if (!call_compare_msgvectors(addresses))                        \
                return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY; \
            for (int j = 0; j < mvee::numvariants; ++j)                     \
                addresses[j] += sizeof(struct mmsghdr);                     \
        }                                                                   \
    }

//
// Compare socket msg vector vectors - POINTER ARGUMENT!!!
//
#define CHECKMMSGVECTORLAYOUT(numarg, len)                                  \
    if (ARG ## numarg(0) && len > 0)                                        \
    {                                                                       \
        std::vector<unsigned long> addresses(mvee::numvariants);            \
        FILLARGARRAY(numarg, addresses);                                    \
        for (unsigned int i = 0; i < (unsigned int)len; ++i)                \
        {                                                                   \
            if (!call_compare_msgvectors(addresses, true))                  \
                return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY; \
            for (int j = 0; j < mvee::numvariants; ++j)                     \
                addresses[j] += sizeof(mmsghdr);                            \
        }                                                                   \
    }

//
// Compare sigactions - must be non-RT signal handling aware! - POINTER ARGUMENT!!!
//
#define CHECKSIGACTION(numarg, is_old_call)                                               \
    if (ARG ## numarg(0))                                                                 \
    {                                                                                     \
        std::vector<unsigned long> argarray(mvee::numvariants);                           \
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
        std::vector<unsigned long> argarray(mvee::numvariants);                    \
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
        std::vector<unsigned long> events(mvee::numvariants);                                                  \
        FILLARGARRAY(numarg, events);                                                                          \
        struct epoll_event master_event, slave_event;                                                          \
        if (!mvee_rw_read_struct(variants[0].variantpid, events[0], sizeof(struct epoll_event), &master_event))    \
        {                                                                                                      \
            cache_mismatch_info("couldn't read epoll_event\n");                                                        \
            return MVEE_PRECALL_ARGS_MISMATCH(numarg) | MVEE_PRECALL_CALL_DENY;                                        \
        }                                                                                                      \
        for (int i = 1; i < mvee::numvariants; ++i)                                                            \
        {                                                                                                      \
            if (!mvee_rw_read_struct(variants[i].variantpid, events[i], sizeof(struct epoll_event), &slave_event)) \
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
// Replicate buffer contents. Use this only for mastercalls that return
// a fixed length buffer - POINTER ARGUMENT!!!
//
#define REPLICATEBUFFERFIXEDLEN(numarg, len)                        \
    {                                                               \
        if (call_succeeded &&                                       \
            state == STATE_IN_MASTERCALL &&                         \
            ARG ## numarg(0))                                       \
        {                                                           \
            std::vector<unsigned long> argarray(mvee::numvariants); \
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
            std::vector<unsigned long> argarray(mvee::numvariants); \
            FILLARGARRAY(numarg, argarray);                         \
            call_replicate_buffer(argarray, len);                   \
        }                                                           \
    }

//
// Replicate buffer contents. Use this only for mastercalls that return the
// length of the buffer in an argument - TWO POINTER ARGUMENTS!!!
//
#define REPLICATEBUFFERANDLEN(bufferarg, lenarg, lenarg_size)                                        \
    {                                                                                                \
        if (call_succeeded &&                                                                        \
            state == STATE_IN_MASTERCALL &&                                                          \
            ARG ## bufferarg(0) &&                                                                   \
            ARG ## lenarg(0))                                                                        \
        {                                                                                            \
            mvee_word master_word, slave_word;                                                       \
            long      len = 0;                                                                       \
            master_word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA,                                    \
                                                 variants[0].variantpid, ARG ## lenarg(0), NULL);        \
            switch(lenarg_size)                                                                      \
            {                                                                                        \
                case 8: len = master_word._long; break;                                              \
                case 4: len = master_word._int; break;                                               \
                case 2: len = master_word._short; break;                                             \
                case 1: len = master_word._char; break;                                              \
            }                                                                                        \
            std::vector<unsigned long> argarray(mvee::numvariants);                                  \
            FILLARGARRAY(bufferarg, argarray);                                                       \
            call_replicate_buffer(argarray, len);                                                    \
            for (int j = 1; j < mvee::numvariants; ++j)                                              \
            {                                                                                        \
                if (lenarg_size < sizeof(long))                                                      \
                    slave_word._long = mvee_wrap_ptrace(PTRACE_PEEKDATA,                             \
                                                        variants[j].variantpid, ARG ## lenarg(j), NULL); \
                else                                                                                 \
                    slave_word._long = master_word._long;                                            \
                                                                                                     \
                switch(lenarg_size)                                                                  \
                {                                                                                    \
                    case 4: slave_word._int   = master_word._int; break;                             \
                    case 2: slave_word._short = master_word._short; break;                           \
                    case 1: slave_word._char  = master_word._char; break;                            \
                }                                                                                    \
                mvee_wrap_ptrace(PTRACE_POKEDATA,                                                    \
                                 variants[j].variantpid, ARG ## lenarg(j), (void*)slave_word._long);     \
            }                                                                                        \
        }                                                                                            \
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
            std::vector<unsigned long> argarray(mvee::numvariants); \
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
            std::vector<unsigned long> argarray(mvee::numvariants); \
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
            std::vector<unsigned long> argarray(mvee::numvariants); \
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
            std::vector<unsigned long> argarray(mvee::numvariants);  \
            FILLARGARRAY(numarg, argarray);                          \
            call_replicate_mmsgvectorlens(argarray, len, attempted); \
        }                                                            \
    }

//
// Get sockaddr from arg sockarg with length from arg lenarg
// and convert to textual form
//
#define GETTEXTADDR(variantnum, text_addr, sockarg, lenarg)                                                              \
    std::string text_addr;                                                                                             \
    if (ARG ## sockarg(variantnum) && ARG ## lenarg(variantnum))                                                           \
    {                                                                                                                  \
        socklen_t        len  = (socklen_t)mvee_wrap_ptrace(PTRACE_PEEKDATA,                                           \
                                                            variants[variantnum].variantpid, ARG ## lenarg(variantnum), NULL); \
        struct sockaddr* addr = call_get_sockaddr(variantnum, ARG ## sockarg(variantnum), len);                            \
        text_addr = addr ? getTextualSocketAddr(addr) : "";                                                            \
        SAFEDELETEARRAY(addr);                                                                                         \
    }

//
// Get sockaddr from arg sockarg with length len
// and convert to textual form
//
#define GETTEXTADDRDIRECT(variantnum, text_addr, sockarg, len)                                \
    std::string text_addr;                                                                  \
    if (ARG ## sockarg(variantnum) && len)                                                    \
    {                                                                                       \
        struct sockaddr* addr = call_get_sockaddr(variantnum, ARG ## sockarg(variantnum), len); \
        text_addr = addr ? getTextualSocketAddr(addr) : "";                                 \
        SAFEDELETEARRAY(addr);                                                              \
    }

#define OLDCALLIFNOT(newcallnum) \
    ((variants[0].callnum == newcallnum) ? false : true)

//
// Map master fds onto slave fds - used at the system call site
//
#define MAPFDS(numarg)                                                               \
    if ((unsigned int)ARG ## numarg(0) != (unsigned int)-1)                          \
    {                                                                                \
        fd_info* info = set_fd_table->get_fd_info(ARG ## numarg(0));                 \
        if (info && !info->master_file)                                              \
        {                                                                            \
            for (int i = 1; i < mvee::numvariants; ++i)                              \
            {                                                                        \
                debugf("> variant %d - mapped to fd %lu\n", i, info->fds[i]);      \
                SETARG ## numarg(i, info->fds[i]);                                   \
            }                                                                        \
        }                                                                            \
        else if (!info || info->master_file)                                         \
        {                                                                            \
            for (int i = 1; i < mvee::numvariants; ++i)                              \
            {                                                                        \
                SETARG ## numarg(i, set_fd_table->get_free_fd(i, ARG ## numarg(i))); \
            }                                                                        \
        }                                                                            \
    }

//
// Maps them back as we're not allowed to clobber argument registers
//
#define UNMAPFDS(numarg)                        \
    for (int i = 1; i < mvee::numvariants; ++i) \
    {                                           \
        SETARG ## numarg(i, ARG ## numarg(0));  \
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
#define MAPPIDS(numarg)                                                                                \
    if (ARG ## numarg(0) != 0 && ARG ## numarg(0) != 1)                                                \
    {                                                                                                  \
        pid_t master_pid = (pid_t) ARG ## numarg(0);                                                   \
        std::vector<pid_t> mapped_pids(mvee::numvariants);                                             \
        if (mvee::map_master_to_slave_pids((master_pid < -1) ? -master_pid : master_pid, mapped_pids)) \
        {                                                                                              \
            for (int i = 1; i < mvee::numvariants; ++i)                                                \
                SETARG ## numarg(i, mapped_pids[i]);                                                   \
        }                                                                                              \
    }

#define UNMAPPIDS(numarg)                               \
    if (ARG ## numarg(0) != 0 && ARG ## numarg(0) != 1) \
    {                                                   \
        for (int i = 1; i < mvee::numvariants; ++i)     \
        {                                               \
            SETARG ## numarg(i, ARG ## numarg(0));      \
        }                                               \
    }





#endif /* MVEE_SYSCALLS_SUPPORT_H_ */
