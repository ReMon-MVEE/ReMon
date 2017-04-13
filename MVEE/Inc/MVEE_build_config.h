/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_BUILD_CONFIG_H_
#define MVEE_BUILD_CONFIG_H_

/*-----------------------------------------------------------------------------
  Monitor Definitions
-----------------------------------------------------------------------------*/
//
// MVEE_BENCHMARK: When this is defined, no messages are logged to the logfile
// and the monitor won't keep track of the number of syscalls made.
// #define MVEE_BENCHMARK

//
// MVEE_FORCE_ENABLE_BACKTRACING: if this is defined, you can also request a monitor
// backtrace in benchmark mode. In benchmark mode, the backtrace will be logged to
// stdout.
// #define MVEE_FORCE_ENABLE_BACKTRACING

//
// MVEE_DISABLE_SYNCHRONIZATION_REPLICATION: if defined, no user-space sync will
// be replicated from master to slave
// #define MVEE_DISABLE_SYNCHRONIZATION_REPLICATION

// MVEE_FILTER_LOGGING: when defined, we will log only for the spec/parsec binaries.
// this filter applies to regular logging (logf), warnings (warnf) and EXTRA_STATS
// and LOCKSTATS logging
// #define MVEE_FILTER_LOGGING

// MVEE_GENERATE_EXTRA_STATS: when defined, the monitor will generate extra statistics
// e.g.: number of memcpy operations
// #define MVEE_GENERATE_EXTRA_STATS

// MVEE_GENERATE_LOCKSTATS: when defined, the monitor will log locking statistics
// #define MVEE_GENERATE_LOCKSTATS

// MVEE_LOG_HEX_DUMPS: when defined, the monitor will log syscall data in hex format
// rather than trying to print them as strings
// #define MVEE_LOG_HEX_DUMPS

// MVEE_NO_RW_LOGGING: when defined, the monitor will not log argument and
// return buffers for read/write system calls
// not defined: full logging
// defined and set to 1: 80 chars max
// defined and set to 2: no logging
#define MVEE_NO_RW_LOGGING 1

// MVEE_CHECK_SYNC_PRIMITIVES: the MVEE will keep track of which high-level synchronization
// primitives the variants are using. Requires libc-support. NO LONGER WORKS. FIXME
// #define MVEE_CHECK_SYNC_PRIMITIVES

// MVEE_ALLOW_MONITOR_SCHEDULING: if defined, the monitor might pin variant threads
// and their respective thread monitors onto the same physical cpu
// We have predefined scheduling rules in Src/MVEE_variant_launch.cpp
// #define MVEE_ALLOW_MONITOR_SCHEDULING

// MVEE_DUMP_MEM_STATS: When defined, the MVEE will calculate an estimate of the
// memory footprint overhead due to Multi-Variant Execution
// #define MVEE_DUMP_MEM_STATS

// MVEE_CALCULATE_CLOCK_SPREAD: when used with the wall of clocks agents, this
// will calculate the number of clocks used as well as the mean/variance for
// the time on each clock
// #define MVEE_CALCULATE_CLOCK_SPREAD

// MVEE_ALLOW_SHM: When defined, the variants are permitted to attach to sysv shared
// memory segments even though it is clearly a bad idea to allow them to do so!!!!
#define MVEE_ALLOW_SHM

// MVEE_DUMP_IPMON_BUFFER_ON_FLUSH: If defined, GHUMVEE will log the contents of
// the IP-MON/UTCB buffer whenever it is being flushed 
// #define MVEE_DUMP_IPMON_BUFFER_ON_FLUSH

/*-----------------------------------------------------------------------------
  Self-Debugging Support
-----------------------------------------------------------------------------*/
// MVEE_ENABLE_VALGRIND_HACKS: alters the behavior of certain I/O related syscalls
// so the MVEE can get through the valgrind initialization without any mismatches
// #define MVEE_ENABLE_VALGRIND_HACKS

// MVEE_FD_DEBUG: when defined, the monitor will log the /proc/pid/fd directory every
// time a file descriptor is opened/closed
// #define MVEE_FD_DEBUG

// MVEE_MMAN_DEBUG: adds debugging messages to the memory management code
// also checks whether or internal mman bookkeeping matches /proc/pid/maps
// every time we add, remove or modify a memory region
// #define MVEE_MMAN_DEBUG

// MVEE_DWARF_DEBUG: adds debugging messages to the DWARF debugging support code
// #define MVEE_DWARF_DEBUG

// MVEE_DUMP_JIT_CACHES: disassembles, compares, and dumps the contents of JIT
// caches every time they get marked PROT_EXEC
// #define MVEE_DUMP_JIT_CACHES

/*-----------------------------------------------------------------------------
  Constants
-----------------------------------------------------------------------------*/
// This is the number of slots we allocate for every buffer requested through
// the MVEE_GET_SHARED_BUFFER syscall
#define SHARED_QUEUE_SLOTS    4 * 1024 * 1024

// Size (in bytes) of the IP-MON replication buffers we allocate for each thread
#define MVEE_IPMON_BUFFER_SIZE 16 * 1024 * 1024

// The number of counters we use in the Wall Of Clocks synchronization agent
// This must match the MVEE_TOTAL_CLOCK_COUNT value in glibc/csu/libc-start.c
#define MVEE_COUNTERS         2048

#endif /* MVEE_BUILD_CONFIG_H_ */
