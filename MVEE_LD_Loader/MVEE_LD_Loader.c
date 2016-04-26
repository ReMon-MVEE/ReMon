/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#define _GNU_SOURCE 1
#define __USE_MISC
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef _LP64
# include "amd64/MVEE_LD_Loader.h"
#else
# include "i386/MVEE_LD_Loader.h"
#endif

//#define MVEE_DEBUG

// we initialize everything to 1 to avoid the generation of a bss segment
// bss segments are in the initial heap!!!
unsigned char  interp_buf[256*1024] = {1};
unsigned char* interp_mapped[256] = {(unsigned char*)1};
char           initial_stack[8192] = { 1 };
unsigned long  initial_stack_depth = 0;
unsigned long  new_sp              = 1;
unsigned long  new_entry           = 1;
unsigned short __variant_num       = 1;

#ifdef MVEE_USE_MVEE_LD
#undef INTERP
unsigned char  found_mvee_root = 0;
char           mvee_root[4096] = {1};
char           INTERP[4096] = {1};
#endif

unsigned long  mvee_write_stack_data(const void* data, int datalen, int padbytes)
{    
    memcpy((void*)((unsigned long)initial_stack + 8192 - initial_stack_depth - datalen - padbytes), data, datalen);
    initial_stack_depth += datalen + padbytes;
    return (unsigned long)initial_stack + 8192 - initial_stack_depth;
}

unsigned long  mvee_write_stack_string(const char* string, int padbytes)
{
#ifdef MVEE_DEBUG
  fprintf(stderr, "writing string: %s @ %x (initial_stack_depth: %d) (padbytes: %d)\n", string, (unsigned long)initial_stack + 8192 - initial_stack_depth, initial_stack_depth, padbytes);
#endif
    return mvee_write_stack_data(string, strlen(string) + 1, padbytes);
}

unsigned long  mvee_calc_initial_stack_address(unsigned long stack_base, unsigned long temp_stack_ptr)
{
    if (!temp_stack_ptr)
        return 0;
    unsigned long temp_stack_offset = (unsigned long)initial_stack + 8192 - temp_stack_ptr;
    return stack_base - temp_stack_offset;
}

#ifdef MVEE_DEBUG
const char* getTextualAuxType(uint64_t type)
{
#define DEF_TYPE(a) case a: return #a;
    switch(type)
    {
        DEF_TYPE(AT_NULL);
        DEF_TYPE(AT_IGNORE);
        DEF_TYPE(AT_EXECFD);
        DEF_TYPE(AT_PHDR);
        DEF_TYPE(AT_PHENT);
        DEF_TYPE(AT_PHNUM);
        DEF_TYPE(AT_PAGESZ);
        DEF_TYPE(AT_BASE);
        DEF_TYPE(AT_FLAGS);
        DEF_TYPE(AT_ENTRY);
        DEF_TYPE(AT_NOTELF);
        DEF_TYPE(AT_UID);
        DEF_TYPE(AT_EUID);
        DEF_TYPE(AT_GID);
        DEF_TYPE(AT_EGID);
        DEF_TYPE(AT_CLKTCK);
        DEF_TYPE(AT_PLATFORM);
        DEF_TYPE(AT_HWCAP);
        DEF_TYPE(AT_FPUCW);
        DEF_TYPE(AT_DCACHEBSIZE);
        DEF_TYPE(AT_ICACHEBSIZE);
        DEF_TYPE(AT_UCACHEBSIZE);
        DEF_TYPE(AT_IGNOREPPC);
        DEF_TYPE(AT_SECURE);
        DEF_TYPE(AT_BASE_PLATFORM);
        DEF_TYPE(AT_RANDOM);
        DEF_TYPE(AT_HWCAP2);
        DEF_TYPE(AT_EXECFN);
        DEF_TYPE(AT_SYSINFO);
        DEF_TYPE(AT_SYSINFO_EHDR);
        DEF_TYPE(AT_L1I_CACHESHAPE);
        DEF_TYPE(AT_L1D_CACHESHAPE);
        DEF_TYPE(AT_L2_CACHESHAPE);
        DEF_TYPE(AT_L3_CACHESHAPE);
    }

    return "???";
}
#endif

//
// this function builds an initial stack in the following format:
//
// <========== stack base ==========>
// AT_EXECFN string (always padded with 4 NULL bytes?)
// envp[n] string
// ...
// envp[0] string
// argv[argc-1] string
// ...
// argv[0] string
// AT_PLATFORM string ("i686\0")
// AT_RANDOM seed (16 bytes?)
// NULL
// Elf_auxv_t vector
// NULL
// envp vector
// NULL
// argv vector
// argc <= new sp
//
void  mvee_build_initial_stack(unsigned long* new_sp, unsigned long stack_base, Elf_Ehdr* interp_hdr, Elf_Addr actual_load_addr)
{
#ifdef MVEE_DEBUG
    fprintf(stderr, "building initial stack...\n");
#endif

    // we use a very long name for this binary so that our new stack will be smaller
    // with a smaller stack, we can insert padding to place both the envp string and argv string array
    // at their original positions
    syscall(0x6FFFFFFF + 10, (unsigned long)&__variant_num);
    char          new_proc_name[40];
    sprintf(new_proc_name, INTERP_SHORT, __variant_num);

    // look for envp
    int           argc          = *(unsigned long*)(*new_sp);
    char**        argv          = (char**)(*new_sp + sizeof(long));
    char**        envp          = (char**)(*new_sp + (argc + 2) * sizeof(long));
    int           j             = 0;
    while (envp[j++]) ;
    j--;
    Elf_auxv_t*   auxv          = (Elf_auxv_t*) ((unsigned long) envp + (j+1) * sizeof(unsigned long));
    Elf_auxv_t*   orig_auxv     = auxv;
#ifdef MVEE_DEBUG
    fprintf(stderr, "reading argv0 at %x\n", argv[0]);
#endif
    unsigned long orig_argv0len = strlen(argv[0]) + 1;
    unsigned long orig_argv0    = (unsigned long)argv[0];
    unsigned long orig_execfn   = 0;

#ifdef MVEE_DEBUG
    fprintf(stderr, "checking auxv\n");
#endif

    // first, we must calculate the length of the original AT_EXECFN string
    while (auxv && auxv->a_type)
    {
        if (auxv->a_type == AT_EXECFN)
        {
            orig_execfn = auxv->a_un.a_val;
            break;
        }
        auxv++;
    }
    auxv = orig_auxv;


    // AT_EXECFN string
    // now we ensure that this execfn is in the exact same position
#ifdef MVEE_DEBUG
    fprintf(stderr, "writing execfn - stack base: 0x%016x - orig_execfn: 0x%016x\n", stack_base, orig_execfn);
#endif
    unsigned long auxv_execfn = mvee_write_stack_string(INTERP, stack_base - orig_execfn - strlen(INTERP) - 1);

    // backwards traversal through envp
    // envp doesn't change so we can just write the array as is
#ifdef MVEE_DEBUG
    fprintf(stderr, "> checking envp\n");
#endif
    while (j >= 0)
    {
        //	  fprintf(stderr, "found envp[%d] = %s\n", j, envp[j]);
        if (envp[j])
            envp[j] = (char*)mvee_write_stack_string(envp[j], 0);
        j--;
    }

    // backwards traversal through argv
    // the last argv must be appended with nul bytes to force argv[0] into its original position
#ifdef MVEE_DEBUG
    fprintf(stderr, "> checking argv - argc: %d\n", argc);
#endif
    for (int i = 0; i < argc; ++i)
    {
#ifdef MVEE_DEBUG
        fprintf(stderr, "> %d...\n", i);
#endif
        if (argc-1-i == 0)
            argv[0] = (char*)mvee_write_stack_string(new_proc_name, 0);
        else if (i == 0)
            argv[argc-1-i] = (char*)mvee_write_stack_string(argv[argc-1-i], orig_argv0len - strlen(new_proc_name) - 1);
        else
            argv[argc-1-i] = (char*)mvee_write_stack_string(argv[argc-1-i], 0);
    }

    //	fprintf(stderr, "orig argv[0] offset: %ld - new argv[0] offset: %ld\n", stack_base - orig_argv0, initial_stack + 8192 - argv[0]);

    // identify AT_PLATFORM
#ifdef MVEE_DEBUG
    fprintf(stderr, "> checking auxv\n");
#endif
    while (auxv && auxv->a_type)
    {
        if (auxv->a_type == AT_PLATFORM)
        {
            auxv->a_un.a_val = mvee_write_stack_string((char*)auxv->a_un.a_val, 0);
            break;
        }
        auxv++;
    }
    auxv = orig_auxv;

    // identify AT_RANDOM
    while (auxv && auxv->a_type)
    {
        if (auxv->a_type == AT_RANDOM)
        {
            auxv->a_un.a_val = mvee_write_stack_data((void*)auxv->a_un.a_val, 16, 0);
            break;
        }
        auxv++;
    }
    auxv = orig_auxv;

    // write and relocate auxv vectors
    // seek to the end first
    while (auxv && auxv->a_type)
        auxv++;

    for (; auxv != orig_auxv-1; --auxv)
    {
#ifdef MVEE_DEBUG
        fprintf(stderr, "found %s => " LONGINTSTR " - " PTRSTR "\n",
               getTextualAuxType(auxv->a_type), auxv->a_un.a_val, auxv->a_un.a_val);
#endif
        switch (auxv->a_type)
        {
        case AT_PHDR:
            auxv->a_un.a_val = actual_load_addr + REAL_AT_PHDR_OFFSET;
            break;
        case AT_PHENT:
            auxv->a_un.a_val = REAL_AT_PHENT;
            break;
        case AT_PHNUM:
            auxv->a_un.a_val = interp_hdr->e_phnum;
            break;
        case AT_BASE:
        case AT_FLAGS:
            auxv->a_un.a_val = 0;
            auxv->a_un.a_val = 0;
            break;
        case AT_ENTRY:
            auxv->a_un.a_val = actual_load_addr + interp_hdr->e_entry;
            break;
        // the following addresses point to our temporary initial stack but
        // need to be relocated
        case AT_EXECFN:
            auxv->a_un.a_val = mvee_calc_initial_stack_address(stack_base, auxv_execfn);
            break;
        case AT_PLATFORM:
        case AT_RANDOM:
            auxv->a_un.a_val = mvee_calc_initial_stack_address(stack_base, auxv->a_un.a_val);
            break;
#ifdef MVEE_HIDE_DSO
        case AT_SYSINFO:
        case AT_SYSINFO_EHDR:
            auxv->a_un.a_val = 0;
            break;
#endif
        }
        mvee_write_stack_data(auxv, sizeof(Elf_auxv_t), 0);
    }

    // write envp pointers
    j = 0;
    while (envp[j])
        j++;
    while (j >= 0)
    {
        unsigned long relocated_envp = mvee_calc_initial_stack_address(stack_base, (unsigned long)envp[j]);
        mvee_write_stack_data(&relocated_envp, sizeof(unsigned long), 0);
        j--;
    }

    // write argv pointers
    for (int i = 0; i <= argc; ++i)
    {
        unsigned long relocated_argv = mvee_calc_initial_stack_address(stack_base, (unsigned long)argv[argc-i]);
        mvee_write_stack_data(&relocated_argv, sizeof(unsigned long), 0);
    }

    // write argc
    mvee_write_stack_data(&argc, sizeof(unsigned long), 0);
    *new_sp = mvee_calc_initial_stack_address(stack_base, (unsigned long)initial_stack + 8192 - initial_stack_depth);
}

void  mvee_write_stack_and_transfer()
{
#ifdef MVEE_DEBUG
    fprintf(stderr, "attempting to write stack...\n");
#endif

    // this stupid hack enforces a stack frame enlargement so we can safely
    // smash our own stack and give ld-linux.so.2 the initial stack it expects...
    char* bla = alloca(16834);
    bla[1] = 'c';
    syscall(__NR_gettid, bla);

#ifdef MVEE_DEBUG
    fprintf(stderr, "writing stack at 0x" PTRSTR "-0x" PTRSTR " (" LONGINTSTR " bytes) - bla at: 0x" PTRSTR " - then jumping to entry at 0x" PTRSTR "\n",
           new_sp, initial_stack_depth + new_sp, initial_stack_depth, (unsigned long)bla, new_entry);
#endif
    memcpy((void*)new_sp, (void*)((unsigned long)initial_stack + 8192 - initial_stack_depth), initial_stack_depth);

#ifdef MVEE_DEBUG
    fprintf(stderr, "stack written\n");
#endif
    // the monitor can now restore esp so it points to argc, delete the loader program from memory
    // and then transfer control to ld-linux's start routine
    syscall(0x6FFFFFFF + 16, new_sp, new_entry);

    // we should never get to this point unless we're running natively!!!
    ARCH_JMP_TO_LD(new_sp, new_entry);
    exit(0);
}

int  main(int argc, char** argv, char** envp)
{
    int           interp_fd = 0;
    struct stat   statbuf;

#ifdef MVEE_DEBUG
    fprintf(stderr, "MVEE LD Loader v1.0\n");
    //  fprintf(stderr, "> argc: %d\n", argc);
    fprintf(stderr, "> Manually loading program: ");
    for (int i = 1; i < argc; ++i)
        fprintf(stderr, "%s ", argv[i]);
    fprintf(stderr, "\n");
#endif

	new_sp    = (unsigned long) argv - sizeof(unsigned long);
    unsigned long stack_base;

    // step 0: look for stack base and the name of the interpreter we should load
    if (envp[0] == NULL)
	{
#ifdef MVEE_DEBUG
		fprintf(stderr, "no environment pointers! wtf!\n");
#endif
		stack_base = ((unsigned long)argv[argc-1] + 4095) & ~4095;
	}
    else
	{
		int j = 0;

		while (envp[j])
		{
#ifdef MVEE_USE_MVEE_LD
			if (!found_mvee_root)
			{
				if (strstr(envp[j], "MVEEROOT=") == envp[j])
				{
					strcpy(mvee_root, envp[j] + strlen("MVEEROOT="));
					found_mvee_root = 1;
				}
			}
#endif

			j++;
		}

#ifdef MVEE_USE_MVEE_LD
		if (!found_mvee_root)
		{
			fprintf(stderr, "MVEE_LD_Loader is configured with MVEE_USE_MVEE_LD but we could not find the MVEE root folder!\n");
			return -1;			
		}

		// Build <MVEE Root>/patched_binaries/ld-linux/<arch>/ld-linux.so
		strcpy(INTERP, mvee_root);
		strcat(INTERP, "/patched_binaries/ld-linux/");
		strcat(INTERP, INTERP_ARCH);
		strcat(INTERP, "/ld-linux.so");

// 		fprintf(stderr, "INTERP is %s\n", INTERP);
#endif

		stack_base = ((unsigned long)envp[j-2] + 4095) & ~4095;
	}


    // step 1: read ld-linux.so.2
    interp_fd = syscall(__NR_open, INTERP, O_RDONLY);
    if (interp_fd < 0)
    {
#ifdef MVEE_DEBUG
        fprintf(stderr, "could not open ld-linux for reading\n");
#endif
        return -1;
    }

    int           err        = syscall(FSTAT_NO, interp_fd, &statbuf);
    if (err < 0 && err > -4095)
    {
#ifdef MVEE_DEBUG
        fprintf(stderr, "could not get size for ld-linux\n");
#endif
        return -1;
    }

#ifdef MVEE_DEBUG
    fprintf(stderr, "loaded interp - fd: %d - size: %d\n", interp_fd, statbuf.st_size);
#endif

    int           read       = syscall(__NR_read, interp_fd, interp_buf, statbuf.st_size);
    if (statbuf.st_size != read)
    {
#ifdef MVEE_DEBUG
        fprintf(stderr, "could not read interpreter - tried to read: %ld bytes - bytes actually read: %d\n", statbuf.st_size, read);
#endif
        return -1;
    }

    // step 2: parse headers, manually map every segment
    Elf_Ehdr*     interp_hdr = (Elf_Ehdr*) interp_buf;
    // sanity check
    if (memcmp(interp_hdr->e_ident + 1, "ELF", 3))
    {
#ifdef MVEE_DEBUG
        fprintf(stderr, "invalid elf file\n");
#endif
        return -1;
    }

#ifdef MVEE_DEBUG
    fprintf(stderr, "Loading %d Segments...\n", interp_hdr->e_phnum);
#endif

    //	interp_mapped = (unsigned char**) malloc(interp_hdr->e_phnum * sizeof(unsigned char*));
    memset(interp_mapped, 0, sizeof(unsigned char*) * interp_hdr->e_phnum);
    // expected load addr = lowest vaddr seen in PT_LOAD segments
    Elf_Addr      expected_load_addr = 0;
    // actual load addr = where the above segment was actually mapped
    Elf_Addr      actual_load_addr   = 0;

    // check how much we need to map in total
    Elf_Addr      init_mapping_len   = 0;

    for (int i = 0; i < interp_hdr->e_phnum; ++i)
    {
        Elf_Phdr* segment_hdr = (Elf_Phdr*) ((Elf_Off) interp_buf + interp_hdr->e_phoff + i * sizeof(Elf_Phdr));

        if (segment_hdr->p_type == PT_LOAD)
        {
            if (i == 0)
                expected_load_addr = segment_hdr->p_vaddr;
            init_mapping_len = segment_hdr->p_vaddr + segment_hdr->p_memsz - expected_load_addr;
        }
    }

    // expected_load_addr = 0x80000000;

    unsigned char exec_mapped        = 0;
    for (int i = 0; i < interp_hdr->e_phnum; ++i)
    {
        Elf_Phdr* segment_hdr = (Elf_Phdr*) ((Elf_Off) interp_buf + interp_hdr->e_phoff + i * sizeof(Elf_Phdr));

        if (segment_hdr->p_type == PT_LOAD)
        {
            if (!exec_mapped)
            {
                exec_mapped      = 1;
                interp_mapped[i] = (unsigned char*) mmap(
                    (void*) (expected_load_addr & ~4095),                                                    // rounded down to page boundary
                    (init_mapping_len + 4095) & ~4095,                                                       // rounded up to page boundary
                    PROT_EXEC | PROT_READ,
                    MAP_PRIVATE | MAP_DENYWRITE,
                    interp_fd,
                    segment_hdr->p_offset & ~4095);
                actual_load_addr = (Elf_Addr) interp_mapped[i];
                //expected_load_addr = segment_hdr->p_vaddr;
            }
            else
            {
                unsigned long prot_flags = 0;
                unsigned long map_flags  = MAP_PRIVATE;

                if (segment_hdr->p_flags & PF_R)
                    prot_flags |= PROT_READ;
                if (segment_hdr->p_flags & PF_W)
                    prot_flags |= PROT_WRITE;
                if (segment_hdr->p_flags & PF_X)
                {
                    prot_flags &= ~PROT_WRITE;
                    prot_flags |= PROT_EXEC;
                    map_flags  |= MAP_DENYWRITE;
                }
                if (actual_load_addr)
                    map_flags |= MAP_FIXED;

                // actual start of the region is at segment_hdr->p_memsz & 4095 within the mapped region
                // total bytes mapped = rounded up to page boundary
                unsigned long actual_start_offset = (segment_hdr->p_vaddr & 4095);
                unsigned long total_bytes_mapped  = (actual_start_offset + (segment_hdr->p_memsz) + 4095) & ~4095;

                if (segment_hdr->p_memsz)
                {
                    interp_mapped[i] = (unsigned char*) mmap(
                        (void*) ((segment_hdr->p_vaddr & ~4095)  + (actual_load_addr - expected_load_addr)), // rounded down to page boundary
                        total_bytes_mapped,
                        prot_flags,
                        map_flags,
                        interp_fd,
                        segment_hdr->p_offset & ~4095);
                }

                // must be .bss
                if (segment_hdr->p_memsz > segment_hdr->p_filesz)
                    memset((void*) ((unsigned long) interp_mapped[i]  + actual_start_offset + segment_hdr->p_filesz), 0,
                           total_bytes_mapped - actual_start_offset - segment_hdr->p_filesz);
            }

#ifdef MVEE_DEBUG
            fprintf(stderr, "> Found loadable segment. idx: %d - vaddr: 0x" PTRSTR "-0x" PTRSTR " - faddr: 0x" PTRSTR "-0x" PTRSTR "\n",
                   i, segment_hdr->p_vaddr, segment_hdr->p_vaddr + segment_hdr->p_memsz,
                   segment_hdr->p_offset, segment_hdr->p_offset + segment_hdr->p_filesz);
#endif
        }
    }

#ifdef MVEE_DEBUG
    fprintf(stderr, "> Expected Load Address was: 0x" PTRSTR " - Actual Load Address was: 0x" PTRSTR "\n",
           expected_load_addr, actual_load_addr);
#endif

    syscall(__NR_close, interp_fd);

#ifdef MVEE_DEBUG
    fprintf(stderr, "attempting to transfer control to entrypoint: " PTRSTR "\n", actual_load_addr + interp_hdr->e_entry);
#endif

    mvee_build_initial_stack(&new_sp, stack_base, interp_hdr, actual_load_addr);

    new_entry = actual_load_addr + interp_hdr->e_entry;
    mvee_write_stack_and_transfer();
}

