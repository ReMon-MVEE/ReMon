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

/* musl-gcc doesn't allow us to import the correct header */
#define ARCH_GET_CPUID		0x1011
#define ARCH_SET_CPUID		0x1012

#include "MVEE_LD_Loader.h"

//#define MVEE_DEBUG

// we initialize everything to 1 to avoid the generation of a bss segment
// bss segments are in the initial heap!!!
unsigned char  interp_buf[2*1024*1024] = {1};
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
  fprintf(stderr, "writing string: %s @ %x (initial_stack_depth: %d) (padbytes: %d)\n",
		  string, (unsigned long)initial_stack + 8192 - initial_stack_depth, initial_stack_depth, padbytes);
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
// this function builds a new stack in the following format:
//
// <========== stack base ==========>
// AT_EXECFN string (always padded with 4 NULL bytes?)
// envp[envc-1] string
// ...
// envp[0] string
// argv[argc-1] string
// ...
// argv[0] string
// AT_PLATFORM string ("i686\0" for i386, "v7l\0" for ARM)
// AT_RANDOM seed (16 bytes?)
// NULL padding (haven't seen this on x86 but ARM has it)
// NULL
// Elf_auxv_t vector
// NULL
// envp vector
// NULL
// argv vector
// argc <= new sp
//
// We do not copy the original stack because we have to modify several data
// structures on the stack.  Some of our modifications also affect the sizes of
// certain stack data structures.
//
// NOTE: The kernel assumes that the positions of certain elements on the
// original program stack don't change. One example is the AT_EXECFN string,
// which contains the name of the running program. When we start the LD Loader,
// this AT_EXECFN string will be "MVEE_LD_Loader_this_name_must_be....", but we
// want to change this to the name of the actual program interpreter.  We insert
// padding to make sure that the new AT_EXECFN starts at the same position as
// the original string.
//
// Besides AT_EXECFN, we also want to keep the argv[0] string and the argv
// pointer array in place.
//
void  mvee_build_initial_stack
(
	unsigned long* original_sp,
	unsigned long stack_base, 
	Elf_Ehdr* interp_hdr, 
	Elf_Addr actual_load_addr
)
{
#ifdef MVEE_DEBUG
    fprintf(stderr, "building new stack...\n");
#endif

	// =====================================================================
	// STEP 1: Identify interesting data structures on the original stack
	// =====================================================================
	size_t argv_size = 0, envp_size = 0, auxv_size = 0;

    // find argv, count args, calculate size of argv pointer array
	char** argv = (char**)((unsigned long)original_sp + sizeof(long));
	int argc = 0;
	while (argv[argc++]) ;
	argc--;	
	argv_size = (argc + 1) * sizeof(long);
	
#ifdef MVEE_DEBUG
	fprintf(stderr, "Found %d args\n", argc);
#endif

	// find envp, count env vars, calculate size of envp pointer array
    char** envp = (char**)((unsigned long)original_sp + (argc + 2) * sizeof(long));
    int envc = 0;
    while (envp[envc++]) ;
    envc--;
	envp_size = (envc + 1) * sizeof(long);

	// find auxv, count aux vars, calculate size of auxv array
    Elf_auxv_t* auxv = (Elf_auxv_t*) ((unsigned long) envp + (envc + 1) * sizeof(long));
    Elf_auxv_t* orig_auxv = auxv;
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
		auxv_size += sizeof(Elf_auxv_t);
    }
    auxv = orig_auxv;
	auxv_size += sizeof(Elf_auxv_t);

	// =====================================================================
	// STEP 2: Write new AT_EXECFN at the same position as the old AT_EXECFN
	// =====================================================================

#ifdef MVEE_DEBUG
    fprintf(stderr, "writing execfn - stack base: 0x%016x - orig_execfn: 0x%016x\n", stack_base, orig_execfn);
#endif
    unsigned long auxv_execfn = mvee_write_stack_string(INTERP, stack_base - orig_execfn - strlen(INTERP) - 1);

	// =====================================================================
	// STEP 3: Write new envp strings
	// =====================================================================

    // envp doesn't change so we can just write the array as is
#ifdef MVEE_DEBUG
    fprintf(stderr, "> writing new envp\n");
#endif
	for (int j = envc - 1; j >= 0; --j)
		envp[j] = (char*)mvee_write_stack_string(envp[j], 0);

	// =====================================================================
	// STEP 4: Write new argv strings
	// =====================================================================

	// The original value of argv[0] is the basename of the LD Loader. We
	// need to change this to the name of the interpreter. We also need to
	// make sure that the new argv[0] starts at the same place as the old one.
	// This is why we need to make the basename of the LD Loader really big.
	char          new_proc_name[40];
    syscall(MVEE_FAKE_SYSCALL_BASE + 10, (unsigned long)&__variant_num);
    sprintf(new_proc_name, INTERP_SHORT, __variant_num);

    // backwards traversal through argv
    // the last argv must be appended with nul bytes to force argv[0] into its original position
#ifdef MVEE_DEBUG
    fprintf(stderr, "> writing new argv\n");
#endif
    for (int i = argc - 1; i >= 0; --i)
    {
        if (i == 0)
            argv[0] = (char*)mvee_write_stack_string(new_proc_name, 0);
        else if (i == argc - 1)
            argv[i] = (char*)mvee_write_stack_string(argv[i], orig_argv0len - strlen(new_proc_name) - 1);
        else
            argv[i] = (char*)mvee_write_stack_string(argv[i], 0);
    }

	// =====================================================================
	// STEP 5: Write AT_PLATFORM and AT_RANDOM
	// =====================================================================

    // identify AT_PLATFORM
#ifdef MVEE_DEBUG
    fprintf(stderr, "> writing AT_PLATFORM\n");
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
#ifdef MVEE_DEBUG
    fprintf(stderr, "> writing AT_RANDOM\n");
#endif
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

	// =====================================================================
	// STEP 6: Insert padding to make sure the stack is 16-byte aligned
	// =====================================================================

	size_t original_stack_size = stack_base - (unsigned long) original_sp;
	size_t new_stack_size = initial_stack_depth + // nr of bytes written so far
		auxv_size + envp_size + argv_size +       // nr of bytes required for auxv/envp/argv arrays
		sizeof(long);                             // nr of bytes for argc

#ifdef MVEE_DEBUG
    fprintf(stderr, "> original stack size was: %d - new stack size will be: %d\n",
			original_stack_size, new_stack_size);
#endif

	if (original_stack_size > new_stack_size)
	{		
		size_t padding_bytes = original_stack_size - new_stack_size;
		mvee_write_stack_string("", padding_bytes - 1);
	}

	// =====================================================================
	// STEP 7: Write ELF auxiliary vector. NOTE: auxv elements may be
	// pointers that might have to be relocated
	// =====================================================================
#ifdef MVEE_DEBUG
    fprintf(stderr, "> Writing auxv\n");
#endif

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
#ifdef MVEE_DEBUG
        fprintf(stderr, "writing %s => " LONGINTSTR " - " PTRSTR "\n",
				getTextualAuxType(auxv->a_type), auxv->a_un.a_val, auxv->a_un.a_val);
#endif

        mvee_write_stack_data(auxv, sizeof(Elf_auxv_t), 0);
    }

	// =====================================================================
	// STEP 8: Relocate and write environment pointers
	// =====================================================================
#ifdef MVEE_DEBUG
    fprintf(stderr, "> Writing envp pointers\n");
#endif

    for (int j = envc; j >= 0; --j)
    {
        unsigned long relocated_envp = mvee_calc_initial_stack_address(stack_base, (unsigned long)envp[j]);
        mvee_write_stack_data(&relocated_envp, sizeof(unsigned long), 0);
    }

	// =====================================================================
	// STEP 9: Relocate and write argument pointers
	// =====================================================================
#ifdef MVEE_DEBUG
    fprintf(stderr, "> Writing argv pointers\n");
#endif

    for (int i = argc; i >= 0; --i)
    {
        unsigned long relocated_argv = mvee_calc_initial_stack_address(stack_base, (unsigned long)argv[i]);
        mvee_write_stack_data(&relocated_argv, sizeof(unsigned long), 0);
    }

	// =====================================================================
	// STEP 10: Write argc
	// =====================================================================
#ifdef MVEE_DEBUG
    fprintf(stderr, "> Writing argc\n");
#endif

    mvee_write_stack_data(&argc, sizeof(unsigned long), 0);

	// =====================================================================
	// FINAL STEP: Calculate new stack pointer
	// =====================================================================	
    new_sp = mvee_calc_initial_stack_address(stack_base,
											 (unsigned long)initial_stack + 8192 - initial_stack_depth);
	
#ifdef MVEE_DEBUG
    fprintf(stderr, "> New stack built. Calculated new stack pointer: %x\n",
		new_sp);
#endif
}

volatile unsigned long old_sp;
volatile unsigned long old_entry;

void  mvee_write_stack_and_transfer()
{
#ifdef MVEE_DEBUG
    fprintf(stderr, "Preparing to copy stack...\n");
#endif

    // this stupid hack enforces a stack frame enlargement so we can safely
    // smash our own stack and give ld-linux.so.2 the initial stack it expects...
    char* bla = alloca(16834);
    bla[1] = 'c';
    syscall(__NR_gettid, bla);

#ifdef MVEE_DEBUG
    fprintf(stderr, "copying stack to 0x" PTRSTR "-0x" PTRSTR " (" LONGINTSTR " bytes) - then jumping to entry at 0x" PTRSTR "\n",
           new_sp, initial_stack_depth + new_sp, initial_stack_depth, new_entry);
#endif
    memcpy((void*)new_sp,
		   (void*)((unsigned long)initial_stack + 8192 - initial_stack_depth),
		   initial_stack_depth);


#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
    // map some extra easy syscall code, should only be used to log instructions
    void* syscall_pointer = mmap(0, 2, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall_pointer == MAP_FAILED)
    {
        printf("problem setting up syscall instruction for instruction logging\n");
        exit(-1);
    }


    // load syscall instruction
    ((char*) syscall_pointer)[0] = 0x0f;
    ((char*) syscall_pointer)[1] = 0x05;

    // set syscall instruction to executable
    mprotect(syscall_pointer, 2, PROT_EXEC);

    // printf("set up syscall instruction at %p\n", syscall_pointer);
#endif


#ifdef MVEE_DEBUG
    fprintf(stderr, "stack copied\n");
#endif
    // the monitor can now restore esp so it points to argc, delete the loader program from memory
    // and then transfer control to ld-linux's start routine
	old_sp = new_sp;
	old_entry = new_entry;
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
    syscall(MVEE_FAKE_SYSCALL_BASE + 16, new_sp, new_entry, syscall_pointer);
#else
    syscall(MVEE_FAKE_SYSCALL_BASE + 16, new_sp, new_entry);
#endif
	new_sp = old_sp;
	new_entry = old_entry;


    // we should never get to this point unless we're running natively!!!
	ARCH_JMP_TO_LD(new_sp, new_entry);
    exit(0);
}

int main (int argc, char** argv, char** envp)
{
#ifdef MVEE_EMULATE_CPUID
    // disable CPUID execution for this process
    syscall(__NR_arch_prctl, ARCH_SET_CPUID, 0);
#endif

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

	unsigned long* original_sp = (unsigned long*)((unsigned long) argv - sizeof(unsigned long));
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

		// Build <MVEE Root>/patched_binaries/libc/<arch>/ld-linux.so
		strcpy(INTERP, mvee_root);
		strcat(INTERP, "/patched_binaries/libc/");
		strcat(INTERP, INTERP_ARCH);
		strcat(INTERP, "/ld-linux.so");

// 		fprintf(stderr, "INTERP is %s\n", INTERP);
#endif

		stack_base = ((unsigned long)envp[j-2] + 4095) & ~4095;

#ifdef MVEE_DEBUG
		fprintf(stderr, "stack base is %p\n", stack_base);
#endif		
	}


    // step 1: read ld-linux.so.2
	interp_fd = open(INTERP, O_RDONLY);
    if (interp_fd < 0)
    {
        fprintf(stderr, "could not open ld-linux for reading\n");
        return -1;
    }

	int err = fstat(interp_fd, &statbuf);
	if (err)
    {
        fprintf(stderr, "could not get size for ld-linux\n");
        return -1;
    }

#ifdef MVEE_DEBUG
    fprintf(stderr, "loaded interp - fd: %d - size: %d\n", interp_fd, statbuf.st_size);
#endif

	if (statbuf.st_size > sizeof(interp_buf))
	{
		fprintf(stderr, "cannot read interpreter - interp_buf size is too small\n");
		return -1;
	}

	int bytes_read = read(interp_fd, interp_buf, statbuf.st_size);
    if (statbuf.st_size != bytes_read)
    {
        fprintf(stderr, "could not read interpreter - tried to read: %ld bytes - bytes actually read: %d\n",
				statbuf.st_size, bytes_read);
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

    close(interp_fd);

#ifdef MVEE_DEBUG
    fprintf(stderr, "attempting to transfer control to entrypoint: " PTRSTR "\n", actual_load_addr + interp_hdr->e_entry);
#endif

    mvee_build_initial_stack(original_sp, stack_base, interp_hdr, actual_load_addr);

    new_entry = actual_load_addr + interp_hdr->e_entry;
    mvee_write_stack_and_transfer();
}

