/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string>
#include <libdwarf.h>
#include <libelf.h>
#include <dwarf.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sstream>
#include <stack>
#include <iomanip>
#include <signal.h>
#include "MVEE.h"
#include "MVEE_filedesc.h"
#include "MVEE_macros.h"
#include "MVEE_mman.h"
#include "MVEE_memory.h"
#include "MVEE_logging.h"
#include "MVEE_private_arch.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    mmap_addr2line_proc class
-----------------------------------------------------------------------------*/
mmap_addr2line_proc::mmap_addr2line_proc(std::string& file, int variantnum, pid_t variantpid, unsigned long region_address, unsigned long region_size)
    : addr2line_file(file),
    addr2line_pid(0),
    addr2line_status(ADDR2LINE_FILE_STATUS_UNKNOWN)
{
    addr2line_fds[0] = addr2line_fds[1] = 0;
    pthread_mutex_init(&addr2line_lock, NULL);

    if (file == "[vdso]" || file == "[vsyscall]")
    {
		std::string dump_name = "/tmp/" + file.substr(1, file.length() - 2) + "-dump.so";

        // possibly dump the vdso
        struct stat _stat;
        if (stat(dump_name.c_str(), &_stat))
        {
            FILE*          vdso      = fopen(dump_name.c_str(), "wb+");
            if (!vdso)
            {
                warnf("couldn't open vdso dump file - err: %s\n", getTextualErrno(errno));

                addr2line_status = ADDR2LINE_FILE_NO_DEBUG_SYMS;
                return;
            }
            unsigned char* vdso_data = rw::read_data(variantpid, (void*)region_address,
                                                         region_size, 0);
            if (!vdso_data)
            {
                warnf("couldn't read vdso binary from master variant\n");

                addr2line_status = ADDR2LINE_FILE_NO_DEBUG_SYMS;
                return;
            }
            if (fwrite(vdso_data, 1, region_size, vdso) != region_size)
            {
                warnf("couldn't write vdso dump to file\n");

                SAFEDELETEARRAY(vdso_data);
                addr2line_status = ADDR2LINE_FILE_NO_DEBUG_SYMS;
                return;
            }
            SAFEDELETEARRAY(vdso_data);
            fclose(vdso);
        }

        pipe_create(dump_name.c_str());
    }
	else
    {
		// test if file exists
		if (access(file.c_str(), R_OK) != 0)
			addr2line_status = ADDR2LINE_FILE_NO_DEBUG_SYMS;
		else
			pipe_create(file.c_str());
    }
}

mmap_addr2line_proc::~mmap_addr2line_proc()
{
    close_proc();
}

/*-----------------------------------------------------------------------------
    mmap_addr2line_proc::close_proc
-----------------------------------------------------------------------------*/
void mmap_addr2line_proc::close_proc()
{
    if (addr2line_fds[0])
        close(addr2line_fds[0]);
    if (addr2line_fds[1])
        close(addr2line_fds[1]);
    if (addr2line_pid)
        kill(addr2line_pid, SIGKILL);
}

/*-----------------------------------------------------------------------------
    mmap_addr2line_proc::read_internal
-----------------------------------------------------------------------------*/
std::string mmap_addr2line_proc::read_internal(const std::string& cmd)
{
	std::stringstream ss;
	std::string tmp;
    int         read_bytes = -1;
    char        tmp_buf[4096];

    if (cmd.back() != '\n')
        tmp = cmd + '\n';
    else
        tmp = cmd;

    if (write(addr2line_fds[1], tmp.c_str(), tmp.length()) == -1)
    {
        warnf("can't write cmd to addr2line pipe: %s (err: %s)\n", cmd.c_str(), getTextualErrno(errno));
        return "";
    }

    while (true)
	{
		read_bytes = read(addr2line_fds[0], tmp_buf, 4096);

		if (read_bytes > 1)
		{
			tmp_buf[read_bytes-1] = '\0';
			ss << tmp_buf;

			if (read_bytes < 4096)
				break;
		}
		else if (read_bytes == -1)
		{
			debugf("couldn't read from proc pipe! - command was: %s\n", cmd.c_str());
			addr2line_status = ADDR2LINE_PROC_TERMINATED;
			return "";
		}
		else
		{
			break;
		}
	}

	size_t inlined = ss.str().rfind("(inlined by) ");
	if (inlined != std::string::npos)
		return ss.str().substr(inlined + strlen("(inlined by) "));

	return ss.str();
}

/*-----------------------------------------------------------------------------
    mmap_addr2line_proc::read_from_addr2line_pipe
-----------------------------------------------------------------------------*/
std::string mmap_addr2line_proc::read_from_addr2line_pipe(const std::string& cmd, int variantnum)
{
    std::stringstream ss;

    MutexLock         lock(&addr2line_lock);

    while (true)
    {
        // Pipe closed unexpectedly. Don't bother resolving
        if (addr2line_status == ADDR2LINE_PROC_TERMINATED ||
            addr2line_status == ADDR2LINE_FILE_NO_DEBUG_SYMS)
        {
            ss << "couldn't get caller info - debugging symbols: NOT FOUND - file name: " << addr2line_file << " - file address: " << cmd;
            break;
        }

        // we can get to this point if we either KNOW that we have debugging syms
        // OR if we don't know anything about the lib
        std::string caller_info = read_internal(cmd);

        if (caller_info.length() > 0 &&
            (caller_info.find("??") != 0 || caller_info.find(" at ") != std::string::npos))
        {
            // debug syms found
            ss << cmd << ": " << caller_info << " (" << addr2line_file << ")";
            addr2line_status = ADDR2LINE_FILE_HAS_DEBUG_SYMS;
            break;
        }
        else
        {
            // Failed to resolve the caller. Maybe we're looking in the wrong library
            if (addr2line_status == ADDR2LINE_FILE_STATUS_UNKNOWN)
            {
				auto unstripped_file = mvee::os_get_unstripped_binary(addr2line_file);

				if (unstripped_file != "")
				{
					addr2line_file   = unstripped_file;
					close_proc();
					pipe_create(addr2line_file.c_str());
					addr2line_status = ADDR2LINE_FILE_HAS_DEBUG_SYMS;

					// retry
					continue;
				}
				else
				{
                    // no debug syms and no unstripped binary found...
                    addr2line_status = ADDR2LINE_FILE_NO_DEBUG_SYMS;
                    continue;
				}				
            }
            else
            {
                ss << "couldn't get caller info - debugging symbols: FOUND - file name: " << addr2line_file << " - file address: " << cmd;
                break;
            }
        }
    }

    return ss.str();
}

/*-----------------------------------------------------------------------------
    mvee_mman_addr2line_pipe_func - simple func to be executed in a forked off
    process. rfd to stdin and stdout to wfd. This way we can set up a 2-way
    communication channel between addr2line and the main monitor process.
-----------------------------------------------------------------------------*/
void mmap_addr2line_proc::pipe_func (unsigned int rfd, unsigned int wfd, const std::string& lib_name)
{
    dup2(rfd, STDIN_FILENO);
    dup2(wfd, STDOUT_FILENO);
    close(STDERR_FILENO);        // equivalent to 2>/dev/null
    execl("/usr/bin/addr2line", "addr2line", "-e", lib_name.c_str(), "-f", "-p", "-C", "-i", NULL);
}

/*-----------------------------------------------------------------------------
    pcreate - ripped from http://stackoverflow.com/questions/3884103/
    can-popen-make-bidirectional-pipes-like-pipe-fork/3884402#3884402
-----------------------------------------------------------------------------*/
void mmap_addr2line_proc::pipe_create(const std::string& lib_name)
{
    /* Spawn a process from pfunc, returning it's pid. The fds array passed will
     * be filled with two descriptors: fds[0] will read from the variant process,
     * and fds[1] will write to it.
     * Similarly, the variant process will receive a reading/writing fd set (in
     * that same order) as arguments.
    */
    int pipes[4];

    /* Parent read/variant write pipe */
    if (pipe(&pipes[0]))
    {
        warnf("failed to create parent read/variant write pipe - %s\n", getTextualErrno(errno));
        return;
    }
    /* Child read/parent write pipe */
    if (pipe(&pipes[2]))
    {
        warnf("failed to create variant read/parent write pipe - %s\n", getTextualErrno(errno));
        return;
    }

    if ((addr2line_pid = fork()) > 0)
    {
        /* Parent process */
        addr2line_fds[0] = pipes[0];
        addr2line_fds[1] = pipes[3];

        close(pipes[1]);
        close(pipes[2]);

        return;
    }
    else
    {
        close(pipes[0]);
        close(pipes[3]);

        pipe_func(pipes[2], pipes[1], lib_name);

        exit(0);
    }

    return;
}

/*-----------------------------------------------------------------------------
    mvee_mman_dwarf_context_init
-----------------------------------------------------------------------------*/
mvee_dwarf_context::mvee_dwarf_context (pid_t variantpid)
{
    // get initial context
	(void) interaction::read_all_regs(variantpid, &regs);
    cfa = 0;
}

/*-----------------------------------------------------------------------------
    resolved_instruction
-----------------------------------------------------------------------------*/
resolved_instruction::resolved_instruction()
    : instruction_address(0),
    instruction_file_offset(0)
{
}

/*-----------------------------------------------------------------------------
    dwarf_info class -

    libdwarf thread safety: calls that modify Dwarf_Debug must be serialized
    Since we only touch Dwarf_Debug in the constructor, we don't need locking
    for a dwarf_info object
-----------------------------------------------------------------------------*/
dwarf_info::dwarf_info(std::string& file, int variantnum, pid_t variantpid, mmap_region_info* region_info)
    : dwarf_in_memory(false),
    info_valid(true),
    dwarf_elf(NULL),
    dwarf_debug(NULL),
    cie_list(NULL),
    fde_list(NULL),
    cie_count(0),
    fde_count(0)
{
	auto try_file = region_info->region_backing_file_path;

	// Try twice. Once for the original file and once for the debug version of
	// the file (if such a debug version exists on the system)
	for (int i = 0; i < 2; ++i)
	{
		dwarf_data.dwarf_fd = 0;

		if (file == "[vdso]")
			dwarf_in_memory = true;

		// In memory file => try to copy the image into a buffer
		if (dwarf_in_memory)
		{
			dwarf_data.dwarf_buffer =
				rw::read_data(variantpid, (void*)region_info->region_base_address, region_info->region_size, true);

			if (dwarf_data.dwarf_buffer)
				dwarf_elf = elf_memory((char*)dwarf_data.dwarf_buffer, region_info->region_size);

			if (!dwarf_data.dwarf_buffer || !dwarf_elf)
			{
				warnf("libelf error: trying to open in-memory file: %s\n", try_file.c_str());

				info_valid = false;
				return;
			}
		}
		// not in memory but it is a vdso-style region => we can't handle this so we'll bail out here
		else if (region_info->region_backing_file_path[0] == '[')
		{
			info_valid = false;
			return;
		}
		// regular on-disk ELF file
		else
		{
			elf_version(EV_CURRENT);

			int fd = open(try_file.c_str(), O_RDONLY, 0);

			if (fd >= 0)
			{
				dwarf_data.dwarf_fd = fd;
				dwarf_elf = elf_begin(dwarf_data.dwarf_fd, ELF_C_READ, NULL);
			}

			if (dwarf_data.dwarf_fd <= 0 || !dwarf_elf)
			{
				warnf("libelf error: trying to open file: %s (%d 0x" PTRSTR ") - err: %s\n",
					  try_file.c_str(), dwarf_data.dwarf_fd, (unsigned long)dwarf_elf, elf_errmsg(elf_errno()));

				info_valid = false;
				return;
			}
		}

		Dwarf_Error err;
		if (dwarf_elf_init(dwarf_elf, DW_DLC_READ, NULL, NULL, &dwarf_debug, &err) != DW_DLV_OK)
		{
			warnf("libdwarf error: trying to open file: %s %s\n",
				  try_file.c_str(),
				  dwarf_in_memory ? "(in-memory)" : "");

			info_valid = false;
			return;
		}

#ifndef MVEE_ARCH_USE_LIBUNWIND
		// try to get the fde list from the DWARF debug frame
		int debug_frame_err, eh_frame_err;
		Dwarf_Error de;
		if ((debug_frame_err = dwarf_get_fde_list(dwarf_debug, &cie_list,
												  &cie_count, &fde_list, &fde_count, &de)) != DW_DLV_OK)
		{
			// try again but use the GCC EH frame instead
			if ((eh_frame_err = dwarf_get_fde_list_eh(dwarf_debug, &cie_list,
													  &cie_count, &fde_list, &fde_count, &de)) != DW_DLV_OK)
			{
				if (debug_frame_err == DW_DLV_NO_ENTRY &&
					eh_frame_err == DW_DLV_NO_ENTRY)
				{
					auto unstripped_file = mvee::os_get_unstripped_binary(file);

					if (unstripped_file != "")
					{
						reset();
						try_file = unstripped_file;
						continue;
					}
				}
				
				warnf("DWARF: Could not find valid unwind info for file: %s\n",
					  try_file.c_str());
				
				info_valid = false;
				return;				
			}
		}
#endif
	}
}

/*-----------------------------------------------------------------------------
  reset
-----------------------------------------------------------------------------*/
void dwarf_info::reset()
{
    Dwarf_Error err;

//	warnf("destroying dwarf info: 0x" PTRSTR "\n", this);

    if (cie_count > 0 || fde_count > 0)
	{
        dwarf_fde_cie_list_dealloc(dwarf_debug, cie_list, cie_count, fde_list, fde_count);
		cie_count = fde_count = 0;
		cie_list = NULL;
		fde_list = NULL;
	}

    if (dwarf_debug)
	{
        dwarf_finish(dwarf_debug, &err);
		dwarf_debug = NULL;
	}
    elf_end(dwarf_elf);
	dwarf_elf = NULL;

    if (dwarf_in_memory)
    {
        SAFEDELETEARRAY(dwarf_data.dwarf_buffer);
		dwarf_in_memory = false;
    }
    else
    {
        close(dwarf_data.dwarf_fd);
		dwarf_data.dwarf_fd = 0;
    }
}

/*-----------------------------------------------------------------------------

-----------------------------------------------------------------------------*/
dwarf_info::~dwarf_info()
{
	reset();
}

/*-----------------------------------------------------------------------------
    map_memory_pc_to_file_pc - calculates the value the pc would've
    had, had the library been loaded at its preferred address
-----------------------------------------------------------------------------*/
unsigned long mmap_region_info::map_memory_pc_to_file_pc (int variantnum, pid_t variantpid, unsigned long rva)
{
    dwarf_info*   dwarf_info        = get_dwarf_info(variantnum, variantpid);
    if (!dwarf_info || !dwarf_info->info_valid)
        return 0;

    unsigned char elf_class         = ELFCLASSNONE;
    unsigned long file_base_address = (unsigned long)-1;
    size_t        phdr_cnt          = 0;

    if (elf_getphdrnum(dwarf_info->dwarf_elf, &phdr_cnt) == -1)
    {
        warnf("ERROR: couldn't get program header count for file: %s\n",
                    region_backing_file_path.c_str());
        return 0;
    }

    size_t        nbytes;
    char*         ident             = elf_getident(dwarf_info->dwarf_elf, &nbytes);
    if (ident == NULL)
    {
        warnf("ERROR: couldn't get ELF class for file: %s\n",
                    region_backing_file_path.c_str());
        return 0;
    }

    elf_class = ident[EI_CLASS];

    if (elf_class == ELFCLASS32)
    {
        Elf32_Phdr* phdr = elf32_getphdr(dwarf_info->dwarf_elf);
        if (!phdr)
        {
            warnf("ERROR: couldn't get program header table for file: %s\n",
                        region_backing_file_path.c_str());
            return 0;
        }

        for (unsigned int i = 0; i < phdr_cnt; ++i)
        {
            if (phdr[i].p_type == PT_LOAD)
            {
                //warnf("found PT_LOAD header: 0x%08x\n", phdr[i].p_vaddr);
                if (phdr[i].p_vaddr < file_base_address)
                    file_base_address = phdr[i].p_vaddr;
            }
        }
    }
    else
    {
        Elf64_Phdr* phdr = elf64_getphdr(dwarf_info->dwarf_elf);
        if (!phdr)
        {
            warnf("ERROR: couldn't get program header table for file: %s\n",
                        region_backing_file_path.c_str());
            return 0;
        }

        for (unsigned int i = 0; i < phdr_cnt; ++i)
        {
            if (phdr[i].p_type == PT_LOAD)
            {
                //warnf("found PT_LOAD header: 0x" PTRSTR "\n", phdr[i].p_vaddr);
                if (phdr[i].p_vaddr < file_base_address)
                    file_base_address = phdr[i].p_vaddr;
            }
        }
    }

    if (file_base_address != (unsigned long)-1)
        return rva + file_base_address + region_backing_file_offset;

    return 0;
}

/*-----------------------------------------------------------------------------
  mvee_read_sleb128
-----------------------------------------------------------------------------*/
unsigned long long mmap_table::read_sleb128(unsigned char** ptr, unsigned char* ptr_max)
{
    unsigned long long result = 0;
    unsigned int       shift  = 0;

    while (*ptr < ptr_max)
    {
        unsigned char byte = *(unsigned char*)((*ptr)++);

        result |= (unsigned long long)(byte & 0x7f) << shift;
        shift  += 7;

        if ((byte & 0x80) == 0)
        {
            if (shift < sizeof(result) * 8 && (byte & 0x40))
                result |= -((unsigned long long)1 << shift);
            return result;
        }
    }

    return 0;
}

/*-----------------------------------------------------------------------------
  mvee_read_uleb128
-----------------------------------------------------------------------------*/
unsigned long long mmap_table::read_uleb128(unsigned char** ptr, unsigned char* ptr_max)
{
    unsigned long long result = 0;
    unsigned int       shift  = 0;

    while (*ptr < ptr_max)
    {
        unsigned char byte = *(unsigned char*)((*ptr)++);

        result |= (unsigned long long)(byte & 0x7f) << shift;
        shift  += 7;

        if ((byte & 0x80) == 0)
            return result;
    }

    return 0;
}

/*-----------------------------------------------------------------------------
    dwarf_step
-----------------------------------------------------------------------------*/
int mmap_table::dwarf_step (int variantnum, pid_t variantpid, mvee_dwarf_context* context)
{
    int               success      = 0;
    mmap_region_info* found_region = NULL;
    dwarf_info*       info         = NULL;
    long int*         regptr       = NULL;
    Dwarf_Regtable3   regtable;
    Dwarf_Cie         cie;
    Dwarf_Fde         fde;
    Dwarf_Addr        row_pc, pc, low_pc, high_pc;
    Dwarf_Error       de;

#ifdef MVEE_DWARF_DEBUG
	unsigned long old_cfa;
    debugf("DWARF: stepping to the previous frame - variantnum: %d\n", variantnum);
#endif

    regtable.rt3_rules = NULL;

    // map EIP to a region
    found_region       = get_region_info(variantnum, IP_IN_REGS(context->regs));
    if (!found_region)
    {
        warnf("DWARF: couldn't map EIP " PTRSTR " to a known region for variant: %d (pid: %d)\n",
			  (unsigned long)IP_IN_REGS(context->regs), variantnum, variantpid);
        goto out;
    }

    // fetch the FDE that describes the frame at the specified address
    pc                 = found_region->map_memory_pc_to_file_pc(variantnum, variantpid, IP_IN_REGS(context->regs) - found_region->region_base_address);

    // now make sure that we get a valid dwarf info
    info               = found_region->get_dwarf_info(variantnum, variantpid);

    if (!info)
    {
#ifdef MVEE_DWARF_DEBUG
        found_region->print_region_info("DWARF: couldn't get DWARF info for region:", mvee::warnf);
#endif
        goto out;
    }

    if (dwarf_get_fde_at_pc(info->fde_list, pc, &fde, &low_pc, &high_pc, &de) != DW_DLV_OK)
    {
#ifdef MVEE_DWARF_DEBUG
        warnf("DWARF: couldn't find an FDE that covers the specified address: %08llx\n", pc);
#endif
        goto out;
    }

    if (dwarf_get_cie_of_fde(fde, &cie, &de) != DW_DLV_OK)
    {
        warnf("DWARF: couldn't find CIE\n");
        goto out;
    }

    // allocate regtable - we allocate enough space for all GP registers up till EIP
    regtable.rt3_reg_table_size = DWARF_RAR + 1;
    regtable.rt3_rules          = new Dwarf_Regtable_Entry3[regtable.rt3_reg_table_size];

    // get the entire table
    if (dwarf_get_fde_info_for_all_regs3(fde, pc, &regtable, &row_pc, &de) != DW_DLV_OK)
    {
        warnf("DWARF: Couldn't get regtable\n");
        goto out;
    }

#ifdef MVEE_DWARF_DEBUG
    debugf("DWARF: Calculated regtable at pc: %08llx\n", pc);
    mvee::log_dwarf_rule(DW_FRAME_CFA_COL3, &regtable.rt3_cfa_rule);
    for (int i = 0; i <= DWARF_RAR; ++i)
        mvee::log_dwarf_rule(i, &regtable.rt3_rules[i]);
#endif

    // calculate the Canonical Frame Address (CFA) first
    if (regtable.rt3_cfa_rule.dw_value_type != DW_EXPR_OFFSET || !regtable.rt3_cfa_rule.dw_offset_relevant)
    {
        warnf("DWARF: Unrecognized CFA Rule\n");
        mvee::log_dwarf_rule(DW_FRAME_CFA_COL3, &regtable.rt3_cfa_rule);
        goto out;
    }

    regptr       = select_dwarf_reg(context, regtable.rt3_cfa_rule.dw_regnum);
    if (!regptr)
    {
        warnf("DWARF: invalid rule - couldn't get reg ptr\n");
        goto out;
    }

#ifdef MVEE_DWARF_DEBUG
	old_cfa = context->cfa;
#endif

    context->cfa = *regptr
                   + (long)regtable.rt3_cfa_rule.dw_offset_or_block_len;

#ifdef MVEE_DWARF_DEBUG
	debugf("DWARF: updated canonical frame address: " PTRSTR " => " PTRSTR "\n", old_cfa, context->cfa);
#endif

    for (int i = 0; i <= DWARF_RAR; ++i)
    {
        if (regtable.rt3_rules[i].dw_value_type == DW_EXPR_OFFSET)
        {
            if (regtable.rt3_rules[i].dw_regnum != DW_FRAME_SAME_VAL && regtable.rt3_rules[i].dw_offset_relevant)
            {
#ifdef MVEE_DWARF_DEBUG
                debugf("DWARF: updating val for reg: %s - DW_EXPR_OFFSET with offset: %ld - CFA: " PTRSTR "\n",
                           getTextualDWARFReg(i), (long)regtable.rt3_rules[i].dw_offset_or_block_len,
                           context->cfa);
#endif
                long*         reg     = select_dwarf_reg(context, i);
#ifdef MVEE_DWARF_DEBUG
                long          old_val = *reg;
#endif
                unsigned long addr    = (unsigned long)(context->cfa + (long)regtable.rt3_rules[i].dw_offset_or_block_len);
                long tmp;
				if (!rw::read_primitive<long>(variantpid, (void*) addr, tmp))				
					warnf("DWARF: Couldn't read DWARF reg at addr 0x" PTRSTR "\n", addr);
				*reg = tmp;
#ifdef MVEE_DWARF_DEBUG
                long          new_val = *reg;
                debugf("DWARF: updated val: %s - " PTRSTR " => " PTRSTR " -- val was at addr: " PTRSTR "\n", getTextualDWARFReg(i), old_val, new_val, addr);
#endif
            }
        }
        else if (regtable.rt3_rules[i].dw_value_type == DW_EXPR_VAL_EXPRESSION)
        {
            Dwarf_Small      opcode;
            Dwarf_Small      instr;
            Dwarf_Ptr        cur_ptr = regtable.rt3_rules[i].dw_block_ptr;
            Dwarf_Ptr        max_ptr = (Dwarf_Ptr)((Dwarf_Unsigned)regtable.rt3_rules[i].dw_block_ptr + regtable.rt3_rules[i].dw_offset_or_block_len);
            std::stack<long> dwarf_stack;

#ifdef MVEE_DWARF_DEBUG
            debugf("DWARF: found DW_EXPR_VAL_EXPRESSION. Debugging libpthreads are we?\n");
            debugf("DWARF: block_ptr = " PTRSTR "\n", (unsigned long) regtable.rt3_rules[i].dw_block_ptr);
            debugf("DWARF: block_len = %llu\n",       regtable.rt3_rules[i].dw_offset_or_block_len);
#endif

            while (cur_ptr < max_ptr)
            {
                instr   = *(Dwarf_Small*)cur_ptr;
                cur_ptr = (Dwarf_Ptr)((Dwarf_Unsigned)cur_ptr + sizeof(Dwarf_Small));
                opcode  = instr;
#ifdef MVEE_DWARF_DEBUG
                debugf("DWARF: op: %d (%s)\n", opcode, getTextualDWARFOp(opcode));
#endif

                if (opcode >= DW_OP_lit0 && opcode <= DW_OP_lit31)
                {
                    dwarf_stack.push(opcode - DW_OP_lit0);
                }
                else if (opcode >= DW_OP_breg0 && opcode <= DW_OP_breg11)
                {
                    int reg = opcode - DW_OP_breg0;
                    dwarf_stack.push(*select_dwarf_reg(context, reg)
                                     + read_sleb128((unsigned char**)&cur_ptr, (unsigned char*)max_ptr));
                }
                else if (opcode == DW_OP_const4s)
                {
                    dwarf_stack.push(*(int*)(cur_ptr));
                    cur_ptr = (Dwarf_Ptr)((Dwarf_Unsigned)cur_ptr + sizeof(long));
                }
                else if (opcode == DW_OP_minus)
                {
                    long top    = dwarf_stack.top(); dwarf_stack.pop();
                    long second = dwarf_stack.top(); dwarf_stack.pop();
                    dwarf_stack.push(second - top);
                }
                else if (opcode == DW_OP_plus)
                {
                    long top    = dwarf_stack.top(); dwarf_stack.pop();
                    long second = dwarf_stack.top(); dwarf_stack.pop();
                    dwarf_stack.push(second + top);
                }
                else
                {
                    warnf("DWARF: this op is not yet implemented in the stack machine. BAILING!\n");
                    warnf("DWARF: op is: %d (%s)\n", opcode, getTextualDWARFOp(opcode));
                    goto out;
                }
            }

            long int* reg     = select_dwarf_reg(context, i);
#ifdef MVEE_DWARF_DEBUG
            long int  old_val = *reg;
#endif
            *reg = dwarf_stack.top();
            dwarf_stack.pop();

#ifdef MVEE_DWARF_DEBUG
            debugf("DWARF: updated val: %s - " PTRSTR " => " PTRSTR "\n", getTextualDWARFReg(i), old_val, *reg);
#endif
        }
        else
        {
            warnf("DWARF: unknown register rule\n");
            mvee::log_dwarf_rule(i, &regtable.rt3_rules[i]);
        }
    }


    SP_IN_REGS(context->regs) = context->cfa;
    success           = 1;

out:
    SAFEDELETEARRAY(regtable.rt3_rules);
    return success;
}

/*-----------------------------------------------------------------------------
    get_numerical_prot_flags - converts "rwxp" to PROT_READ
    | PROT_WRITE | ...
-----------------------------------------------------------------------------*/
unsigned int mmap_table::get_numerical_prot_flags(const char* textual_prot_flags)
{
    int result = 0;
    if (textual_prot_flags[0] == 'r')
        result |= PROT_READ;
    if (textual_prot_flags[1] == 'w')
        result |= PROT_WRITE;
    if (textual_prot_flags[2] == 'x')
        result |= PROT_EXEC;
    return result;
}

/*-----------------------------------------------------------------------------
    get_textual_prot_flags - converts PROT_READ | PROT_WRITE | ... to "rw..."
-----------------------------------------------------------------------------*/
std::string mmap_table::get_textual_prot_flags(unsigned int prot_flags)
{
    std::string s = "---";

    if (prot_flags & PROT_READ)
        s[0] = 'r';
    if (prot_flags & PROT_WRITE)
        s[1] = 'w';
    if (prot_flags & PROT_EXEC)
        s[2] = 'x';

    return s;
}

/*-----------------------------------------------------------------------------
    refresh_variant_maps - refreshes the cached_map table - this
    function is slow!
-----------------------------------------------------------------------------*/
#ifdef MVEE_CONNECTED_MMAP_REGIONS
void mmap_table::refresh_variant_maps(int variantnum, pid_t variantpid,
                                      std::shared_ptr<mmap_region_info*[]> &stack_regions)
#else
void mmap_table::refresh_variant_maps(int variantnum, pid_t variantpid)
#endif
{
    char              str[100];
    size_t            size;
    sprintf(str, "cat /proc/%d/maps", variantpid);

    std::string       ln;
    std::stringstream buf(mvee::log_read_from_proc_pipe(str, &size));

#ifdef MVEE_MMAN_DEBUG
    debugf("Refreshed maps for pid: %d using cmdline process: %s\n>>> RESULT:\n%s\n",
               variantpid, str, buf.str().c_str());
#endif


    unsigned long     region_start, region_end;
    unsigned int      region_file_offset;
    char              name[500];
    char              flags[10];
    fd_info           info;
    unsigned int      region_map_flags;

    while (std::getline(buf, ln, '\n'))
    {
        name[0] = '\0';
        int matched = sscanf(ln.c_str(), "" LONGPTRSTR "-" LONGPTRSTR " %s %08x %*s %*s %s\n", &region_start, &region_end, flags, &region_file_offset, name);

        if (matched == 4 && name[0] == '\0')
        {
            map_range(variantnum, region_start, region_end-region_start, MAP_ANONYMOUS, get_numerical_prot_flags(flags), NULL, region_file_offset);
        }
        else if (matched != 5 || strstr(name, "/SYSV000"))
        {
            continue;
        }
        else
        {
            info.paths[variantnum]  = name;
            info.access_flags       = 0; // unknown access flags
            info.fds[variantnum]    = MVEE_UNKNOWN_FD;
            info.original_file_size = 0;
            region_map_flags        = 0;

            if (strstr(name, "[stack") == name)
                region_map_flags |= MAP_STACK | MAP_GROWSDOWN;

            if (flags[3] == 'p')
                region_map_flags |= MAP_PRIVATE;
            else
                region_map_flags |= MAP_SHARED;

#ifdef MVEE_CONNECTED_MMAP_REGIONS
            if (region_map_flags & MAP_STACK)
            {
                mmap_region_info *region_info = map_range(variantnum, region_start, region_end - region_start,
                        region_map_flags, get_numerical_prot_flags(flags), &info, region_file_offset);
                region_info->connected_regions = stack_regions;
                stack_regions[variantnum] = region_info;
            }
            else
#endif
                map_range(variantnum, region_start, region_end - region_start, region_map_flags,
                          get_numerical_prot_flags(flags), &info, region_file_offset);
        }
    }
}

/*-----------------------------------------------------------------------------
    get_stack_base
-----------------------------------------------------------------------------*/
unsigned long mmap_table::get_stack_base(int variantnum)
{
    for (auto it = full_map[variantnum].begin(); it != full_map[variantnum].end(); ++it)
        if ((*it)->region_backing_file_path == "[stack]")
            return (*it)->region_size + (*it)->region_base_address;

    return 0;
}

/*-----------------------------------------------------------------------------
    mvee_mman_get_caller_info
-----------------------------------------------------------------------------*/
std::string mmap_table::get_caller_info
(
    int           variantnum,
    pid_t         variantpid,
    unsigned long address,
    int           calculate_file_offsets
)
{
    std::stringstream                                       ss;
    std::string                                             caller_info;
    unsigned char                                           update_instr_cache = 0;
    resolved_instruction                                    instr;
    mmap_addr2line_proc*                                    addr2line_proc;
    mmap_region_info*                                       found_region       = NULL;


    if (!address)
    {
        ss << "couldn't find code address: " << STDPTRSTR(address);
        return ss.str();
    }

    // see if we've already cached this lookup...
    // need the fd lock here because we might refresh variant maps
    grab_lock();
    std::map<unsigned long, resolved_instruction>::iterator instrs_iterator
        = cached_instrs[variantnum].find(address);
    if (instrs_iterator != cached_instrs[variantnum].end())
        instr = instrs_iterator->second;

    // couldn't find the lookup...
    // we'll have to perform a new lookup then.
    // Map the address onto a region first...
    if (!instr.instruction_address)
    {
        update_instr_cache            = 1;
        instr.instruction_address     = address;

        found_region                  = get_region_info(variantnum, address, 0);

        if (!found_region)
        {
            ss << "couldn't find code address: " << STDPTRSTR(address);
            release_lock();
            return ss.str();
        }

        // Now perform the lookup. We don't need to calculate the offsets yet
        unsigned long lib_start_address = found_region->region_base_address;
        unsigned long file_pc           = found_region->map_memory_pc_to_file_pc(variantnum, variantpid, address - found_region->region_base_address);

        //warnf("found region => %s => 0x%08x\n", found_region->region_backing_file_path, found_region->region_base_address);

        addr2line_proc                = found_region->get_addr2line_proc(variantnum, variantpid);
        ss << STDPTRSTR(file_pc);
        caller_info                   = addr2line_proc->read_from_addr2line_pipe(ss.str(), variantnum);

        ss.str(std::string());
        ss.clear();

        if (caller_info.find("couldn't get") == 0)
        {
			if (found_region->region_backing_file_path == "[vdso]")
			{
				unsigned long syscall_no;
				if (!interaction::fetch_syscall_no(variantpid, syscall_no))
					ss << "in vdso - couldn't read syscall no";
				else
					ss << "vdso - syscall: " << syscall_no << " (" << getTextualSyscall(syscall_no) << ") - addr: " << STDPTRSTR(address - lib_start_address);

				update_instr_cache = 0;
				caller_info = "";
			}
			else if (found_region->region_backing_file_path == "[anonymous]" &&
					 (found_region->region_prot_flags & PROT_EXEC))
			{
				ss << STDPTRSTR(address) << ": JIT cache @ " << STDPTRSTR(found_region->region_base_address) << "-" << STDPTRSTR(found_region->region_base_address + found_region->region_size);
				update_instr_cache = 0;
				calculate_file_offsets = 0;
				caller_info = "";
			}
        }

        // lookup complete... update the resolved instruction info
        // but don't insert it yet. We might need to resolve offsets as well...
        ss << caller_info;
        instr.instruction_info        = ss.str();
        instr.instruction_file_offset = 0;
    }
    else
    {
        // the lookup WAS cached
        if (calculate_file_offsets && !instr.instruction_file_offset)
            update_instr_cache = 1;
        ss << instr.instruction_info;
    }

    // we need to append offset info to the result
    if (calculate_file_offsets)
    {
        // see if we've already cached it...
        unsigned long file_offset = instr.instruction_file_offset;

        if (!file_offset)
        {
            // try to resolve the region again...
            found_region = get_region_info(variantnum, instr.instruction_address, 0);
            if (found_region && found_region->region_backing_file_path[0] != '[')
            {
                file_offset                   = found_region->map_memory_pc_to_file_pc(variantnum, variantpid, address - found_region->region_base_address);
                instr.instruction_file_offset = file_offset;
            }
        }

        if (file_offset)
            ss << " - file offset: " << STDPTRSTR(file_offset);
    }

    if (update_instr_cache)
    {
        cached_instrs[variantnum].insert(
            std::pair<unsigned long, resolved_instruction>(address, instr));
    }

    release_lock();
    return ss.str();
}

/*-----------------------------------------------------------------------------
    resolve_symbol
-----------------------------------------------------------------------------*/
unsigned long mmap_table::resolve_symbol (int variantnum, const char* sym, const char* lib_name)
{
    std::set<mmap_region_info*, region_sort>::iterator                     region_iterator;

    // map lib_name to a resolved region
    // we need this for 2 reasons:
    // 1) the region_file_path is the index into the cached symbol table
    // 2) every variant might have a different base address for the specified region

    grab_lock();
    for (region_iterator = full_map[variantnum].begin();
         region_iterator != full_map[variantnum].end();
         region_iterator++)
    {
        if ((*region_iterator)->region_backing_file_path == lib_name)
        {
            break;
        }
    }

    if (region_iterator == full_map[variantnum].end())
    {
        release_lock();
        return 0;
    }

    // OK... we have the full path now.
    // Next, let's map it to the symbol table for this region
    std::map<std::string, unsigned long>*                                  symbol_table;
    std::map<std::string, std::map<std::string, unsigned long> >::iterator it
        = cached_syms.find(std::string(lib_name));

    if (it == cached_syms.end())
    {
        symbol_table = &(cached_syms.insert(std::pair<std::string, std::map<std::string, unsigned long> >(
                                                std::string(lib_name), std::map<std::string, unsigned long>())).first->second);
    }
    else
    {
        symbol_table = &it->second;
    }

    // we have a symbol table for this region. Check if we need to fill it in...
    if (symbol_table->size() == 0)
    {
        char              proc[500];
        size_t            len;

        sprintf(proc, "readelf -s -W %s | sed 's/  */ /g'", (*region_iterator)->region_backing_file_path.c_str());
        std::stringstream syms(mvee::log_read_from_proc_pipe(proc, &len));
        std::string       ln;

        while (std::getline(syms, ln, '\n'))
        {
            char          symbol[1024];
            unsigned long addr;

            if (sscanf(ln.c_str(), " %*d: " LONGPTRSTR " %*d %*s %*s %*s %*d %s", &addr, symbol) == 2)
                symbol_table->insert(std::pair<std::string, unsigned long>(std::string(symbol), addr));
        }
    }

    std::map<std::string, unsigned long>::const_iterator                   resolved_sym
        = symbol_table->find(std::string(sym));
    if (resolved_sym != symbol_table->end())
    {
        unsigned long result = (*resolved_sym).second + ((*region_iterator)->region_is_so ?
                                                         (*region_iterator)->region_base_address : 0);

        release_lock();
        return result;
    }

    release_lock();
    return 0;
}

/*-----------------------------------------------------------------------------
    get_normalized_map_dump - this generates a /proc/maps style dump of
    the memory map and merges adjacent regions where possible
-----------------------------------------------------------------------------*/
std::string mmap_table::get_normalized_map_dump (int variantnum)
{
    mmap_region_info* merged_region = NULL;
    std::stringstream ss;

    // make a /proc/maps style dump of the memory map for this variant
    for (auto it = full_map[variantnum].begin();; it++)
    {
        // check if we can merge this region with merged_region
        if ((it == full_map[variantnum].end() || !merge_regions(variantnum, merged_region, *it, true))
            && merged_region)
        {
            // we're at the end of the table OR we have encountered a new region

            // add range
            ss << STDPTRSTR(merged_region->region_base_address) << "-" << STDPTRSTR(merged_region->region_base_address + merged_region->region_size) << " ";

            // add flags
            ss << get_textual_prot_flags(merged_region->region_prot_flags) << " ";

            // add offset
            ss << STDHEXSTR(8, merged_region->region_backing_file_offset) << " ";

            // add backing file for non-anonymous regions
            if (merged_region->region_backing_file_path.length() > 1 && (merged_region->region_backing_file_fd != MVEE_ANONYMOUS_FD || merged_region->region_backing_file_path[1] == 's'))
                ss << merged_region->region_backing_file_path;

            ss << "\n";

            SAFEDELETE(merged_region);

        }

        if (!merged_region && it != full_map[variantnum].end())
            merged_region = new mmap_region_info(**it);

        if (it == full_map[variantnum].end())
            break;
    }

    SAFEDELETE(merged_region);
    return ss.str();
}

/*-----------------------------------------------------------------------------
    get_normalized_maps_output - reads the memory map from
    /proc/<variantpid>/maps but merges adjacent regions where possible.
    The kernel won't always do this...

    This function discards deleted regions, inode numbers, device numbers
    the private/shared flag and it will treat /dev/zero as a regular anonymous
    region
-----------------------------------------------------------------------------*/
char* mmap_table::get_normalized_maps_output (int variantnum, pid_t variantpid)
{
    char              cmd[512];
    size_t            orig_size;
    char*             result = NULL;
    unsigned long     region_start, region_end;
    unsigned long     prev_region_start, prev_region_end;
    unsigned int      region_file_offset, prev_region_file_offset;
    char              flags[10], prev_flags[10];
    char              name[500], prev_name[500];

    sprintf(cmd, "cat /proc/%d/maps | sed 's/\\([0-F]*-[0-F]* .... [0-F]* \\)[0-F]*:[0-F]* [0-F]* *\\(.*\\)/\\1\\2/' | grep -v /SYSV | sed 's/\\/dev\\/zero//' | sed 's/(deleted)//' | sed 's/   *$/ /'",
            variantpid);

    std::stringstream maps(mvee::log_read_from_proc_pipe(cmd, &orig_size));

    if (maps.str() == "")
        return NULL;

    std::string       ln;
    result            = new char[orig_size*2];
    result[0]         = '\0';

    prev_region_start = prev_region_end = prev_region_file_offset = 0;
    memset(flags,      0, 10);
    memset(prev_flags, 0, 10);
    prev_name[0]      = '\0';

    while (std::getline(maps, ln, '\n'))
    {
        name[0]  = '\0';
        int matched = sscanf(ln.c_str(), LONGPTRSTR "-" LONGPTRSTR " %s %08x %s\n", &region_start, &region_end, flags, &region_file_offset, name);
        if (!((matched == 4 && name[0] == '\0') || matched == 5))
            continue;

        flags[3] = 'p';

        // check if we can merge with the previous region
        if (region_start == prev_region_end
            && memcmp(flags, prev_flags, 4) == 0
            && (!strcmp(name, prev_name) || (name[0] == '\0' && prev_name[0] == '[' && prev_name[1] == 's'))
            && ((name[0] == '\0') || !strcmp(name, "[heap]") || (name[0] != '\0' && region_file_offset == prev_region_file_offset + prev_region_end - prev_region_start)))
        {
            // we can merge...
            prev_region_end = region_end;
        }
        else
        {
            // can't merge. write the prev region if any
            if (prev_region_start)
            {
                char new_line[600];
                sprintf(new_line, LONGPTRSTR "-" LONGPTRSTR " %c%c%c %08x %s\n", prev_region_start, prev_region_end, prev_flags[0], prev_flags[1], prev_flags[2], prev_region_file_offset, prev_name);
                strcat(result, new_line);
            }
            prev_region_start       = region_start;
            prev_region_end         = region_end;
            prev_region_file_offset = region_file_offset;
            strcpy(prev_name, name);
            memcpy(prev_flags, flags, 4);
        }
    }

    char new_line[600];
    sprintf(new_line, LONGPTRSTR "-" LONGPTRSTR " %c%c%c %08x %s\n", prev_region_start, prev_region_end, prev_flags[0], prev_flags[1], prev_flags[2], prev_region_file_offset, prev_name);
    strcat(result, new_line);
    return result;
}

/*-----------------------------------------------------------------------------
    mvee_mman_verify_mman_table - compares the mman table with the info
    read from /proc/<pid>/maps
-----------------------------------------------------------------------------*/
void mmap_table::verify_mman_table (int variantnum, pid_t variantpid)
{
    if (mmap_startup_info[0].image.length() == 0)
        return;

#if 0
    char*       maps            = get_normalized_maps_output(variantnum, variantpid);
    std::string normalized_dump = get_normalized_map_dump(variantnum);

    if (normalized_dump != maps)
    {
        warnf("MMAN TABLE MISMATCH - VARIANT: %d!!!\n",      variantnum);
        warnf("maps output:\n%s\n\n\nour output:\n%s\n\n", maps, normalized_dump.c_str());

        char        cmd[100];
        sprintf(cmd, "cat /proc/%d/smaps",
                variantpid);
        std::string smaps = mvee::log_read_from_proc_pipe(cmd, NULL);
        warnf("smaps output:\n%s\n", smaps.c_str());
    }

    SAFEDELETEARRAY(maps);
#endif
}

