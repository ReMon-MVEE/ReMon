/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_MEMORY_H_INCLUDED
#define MVEE_MEMORY_H_INCLUDED

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <unistd.h>
#include "MVEE_config.h"

/*-----------------------------------------------------------------------------
    Constants
-----------------------------------------------------------------------------*/
#define PTRACE_EXT_COPYMEM    0x4220
#define PTRACE_EXT_COPYSTRING 0x4221
#define PROCESS_VM_WRITEV     0x4222
#define PROCESS_VM_READV      0x4223

/*-----------------------------------------------------------------------------
    Function prototypes
-----------------------------------------------------------------------------*/

//
// Functions for direct copying from 1 process to another
//
long mvee_rw_copy_data                     (pid_t source_pid, unsigned long source_addr, pid_t dest_pid, unsigned long dest_addr, ssize_t len);
bool mvee_rw_copy_string                   (pid_t source_pid, unsigned long source_addr, pid_t dest_pid, unsigned long dest_addr);

//
// Functions for reading from/writing to a child's VA
//
bool           mvee_rw_write_data           (pid_t variantpid, unsigned long addr, ssize_t datalength, unsigned char* databuf);
unsigned char* mvee_rw_read_data            (pid_t variantpid, unsigned long addr, ssize_t datalength, int append_zero_byte=0);
char*          mvee_rw_read_string          (pid_t variantpid, unsigned long addr, ssize_t maxlength=0);
bool           mvee_rw_read_struct          (pid_t variantpid, unsigned long addr, ssize_t datalength, void* buf);

void           mvee_rw_write_uchar          (pid_t pid, unsigned long addr, unsigned char val);
void           mvee_rw_write_ushort         (pid_t pid, unsigned long addr, unsigned short val);
void           mvee_rw_write_uint           (pid_t pid, unsigned long addr, unsigned int val);
void           mvee_rw_write_pid            (pid_t pid, unsigned long addr, pid_t val);
unsigned char* mvee_rw_safe_alloc           (long int alloc_size);

#endif // MVEE_MEMORY_H_INCLUDED
