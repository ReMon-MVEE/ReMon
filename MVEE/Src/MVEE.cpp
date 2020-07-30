/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <elf.h>
#include <libelf.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <libgen.h>
#include <stdarg.h>
#include <iostream>
#include <ctype.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_memory.h"
#include "MVEE_logging.h"
#include "MVEE_syscalls.h"
#include "MVEE_private_arch.h"
#include "MVEE_macros.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
    Static Member Initialization
-----------------------------------------------------------------------------*/
std::vector<
	std::map<std::string,
			 std::string>>             mvee::aliases;
std::vector<
	std::map<std::string,
			 std::string>>             mvee::reverse_aliases;
int                                    mvee::numvariants                         = 0;
std::vector<std::string>               mvee::variant_ids;
__thread monitor*                      mvee::active_monitor                      = NULL;
__thread int                           mvee::active_monitorid                    = 0;
int                                    mvee::shutdown_signal                     = 0;
std::map<unsigned long, unsigned char> mvee::syslocks_table;
__thread bool                          mvee::in_logging_handler                  = false;
pthread_mutex_t                        mvee::global_lock                         = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
pthread_cond_t                         mvee::global_cond                         = PTHREAD_COND_INITIALIZER;
std::map<std::string, std::weak_ptr<mmap_addr2line_proc> >
                                       mvee::addr2line_cache;
std::map<std::string, std::weak_ptr<dwarf_info> >
                                       mvee::dwarf_cache;
std::map<std::string, std::string>     mvee::unstripped_binaries_cache;
bool                                   mvee::should_garbage_collect              = false;
std::vector<monitor*>                  mvee::dead_monitors;
std::vector<monitor*>                  mvee::active_monitors;
std::vector<monitor*>                  mvee::inactive_monitors;
std::map<pid_t, std::vector<pid_t> >   mvee::variant_pid_mapping;
std::map<int, monitor*>                mvee::monitor_id_mapping;
int                                    mvee::next_monitorid                      = 0;
std::vector<detachedvariant*>          mvee::detachlist;
std::string                            mvee::orig_working_dir;
std::string                            mvee::mvee_root_dir;
unsigned int                           mvee::stack_limit                         = 0;
int                                    mvee::num_cores                           = 0;
int                                    mvee::num_physical_cpus                   = 0;
pid_t                                  mvee::process_pid                         = 0;
__thread pid_t                         mvee::thread_pid                          = 0;
std::map<std::string, std::string>     mvee::interp_map;
bool                                   mvee::should_generate_backtraces          = false;
volatile unsigned long                 mvee::can_run                             = 0;
std::string                            mvee::config_file_name                    = "";
bool                                   mvee::config_show                         = false;
std::string                            mvee::config_variant_set                  = "default";
Json::Value                            mvee::config;
Json::Value*                           mvee::config_monitor                      = NULL;
Json::Value*                           mvee::config_variant_global               = NULL;
Json::Value*                           mvee::config_variant_exec                 = NULL;
std::string                            mvee::synctrace_logfile                   = "";

/*-----------------------------------------------------------------------------
    Prototypes
-----------------------------------------------------------------------------*/
void                    mvee_mon_external_termination_request(int sig);

/*-----------------------------------------------------------------------------
  strsplit
------------------------------------------------------------------------------*/
std::deque<std::string> mvee::strsplit(const std::string &s, char delim)
{
    std::stringstream       ss(s);
    std::string             item;
    std::deque<std::string> elems;

    while (std::getline(ss, item, delim))
        elems.push_back(item);

    return elems;
}
/*-----------------------------------------------------------------------------
  str_ends_with
------------------------------------------------------------------------------*/
bool mvee::str_ends_with(std::string& search_in_str, const char* suffix)
{
    std::string search_for_str(suffix);
    return search_in_str.size() >= search_for_str.size() && 
		search_in_str.rfind(search_for_str) == (search_in_str.size()-search_for_str.size());
}

/*-----------------------------------------------------------------------------
    mvee_strdup - returns a string copy allocated with new[] instead of
    malloc... This is just here to keep valgrind happy
-----------------------------------------------------------------------------*/
char* mvee::strdup(const char* orig)
{
    if (!orig)
        return NULL;

    int   orig_len   = strlen(orig);
    char* new_string = new char[orig_len+1];
    memcpy(new_string, orig, strlen(orig)+1);
    return new_string;
}

/*-----------------------------------------------------------------------------
    mvee_is_printable_string
-----------------------------------------------------------------------------*/
bool mvee::is_printable_string(char* str, int len)
{
    for (int i = 0; i < len; ++i)
    {
        char c = str[i];
        if (c < 32 || c > 126)
            return false;
    }
    return true;
}

/*-----------------------------------------------------------------------------
    upcase
-----------------------------------------------------------------------------*/
std::string mvee::upcase(const char* lower_case_string)
{
	std::string out(lower_case_string);
	std::transform(out.begin(), out.end(), out.begin(), ::toupper);
	return out;
}

/*-----------------------------------------------------------------------------
    mask_is_unchecked_syscall
-----------------------------------------------------------------------------*/
unsigned char mvee::mask_is_unchecked_syscall(unsigned char* mask, unsigned long syscall_no)
{
	unsigned long no_to_byte, bit_in_byte;

	if (syscall_no > ROUND_UP(MAX_CALLS, 8))
		return 0;

	no_to_byte  = syscall_no / 8;
	bit_in_byte = syscall_no % 8;

	if (mask[no_to_byte] & (1 << (7 - bit_in_byte)))
		return 1;
	return 0;
}

/*-----------------------------------------------------------------------------
    mask_set_unchecked_syscall
-----------------------------------------------------------------------------*/
void mvee::mask_set_unchecked_syscall(unsigned char* mask, unsigned long syscall_no, unsigned char unchecked)
{
	unsigned long no_to_byte, bit_in_byte;

	if (syscall_no > ROUND_UP(MAX_CALLS, 8))
		return;

	no_to_byte  = syscall_no / 8;
	bit_in_byte = syscall_no % 8;

	if (unchecked)
		mask[no_to_byte] |= (1 << (7 - bit_in_byte));
	else
		mask[no_to_byte] &= ~(1 << (7 - bit_in_byte));
}


/*-----------------------------------------------------------------------------
    mvee_old_sigset_to_new_sigset
-----------------------------------------------------------------------------*/
sigset_t mvee::old_sigset_to_new_sigset(unsigned long old_sigset)
{
    sigset_t set;
    sigemptyset(&set);

    for (int i = 1; i < 32; ++i)
    {
        if ((old_sigset >> i) & 0x1)
            sigaddset(&set, i);
    }

    return set;
}

/*-----------------------------------------------------------------------------
    get_alias - RAVEN-style aliasing
-----------------------------------------------------------------------------*/
std::string mvee::get_alias(int variantnum, std::string path)
{
//	warnf("Looking for alias of %s in variant %d\n", path.c_str(), variantnum);
	auto alias = aliases[variantnum].find(path);
	if (alias != aliases[variantnum].end())
		return alias->second;

	// built-in aliases
	if (path.find("/dev/shm/") == 0 ||
		path.find("/run/shm/") == 0)
	{
		std::stringstream ss;
		ss << path << "_variant" << variantnum;
		return ss.str();
	}
	else if (path.find("/home/stijn/glibc-build/etc/") == 0)
	{
		return path.replace(0, strlen("/home/stijn/glibc-build/etc/"), "/etc/");
	}
	else if (path.find("/home/stijn/glibc-build/") == 0)
	{
		return path.replace(0, strlen("/home/stijn/glibc-build/"), "/usr/");
	}

	return "";
}

/*-----------------------------------------------------------------------------
    init_aliases
-----------------------------------------------------------------------------*/
void mvee::init_aliases()
{
	aliases.resize(mvee::numvariants);
	reverse_aliases.resize(mvee::numvariants);

	for (int i = 0; i < mvee::numvariants; ++i)
	{
		Json::Value& variant_config =
			mvee::config["variant"]["specs"][mvee::variant_ids[i]]["exec"];

		if (!variant_config["alias"])
			continue;

		for (auto alias : variant_config["alias"])
		{
			auto str = alias.asString();
			size_t pos = str.find("=");
			if (pos != std::string::npos)
			{
				std::string pattern     = str.substr(0, pos);
				std::string replacement = str.substr(pos + 1);

				aliases[i].insert(std::make_pair(pattern, replacement));
				reverse_aliases[i].insert(std::make_pair(pattern, replacement));
			}	
		}
	}
}

/*-----------------------------------------------------------------------------
    are_aliases - check if all of these paths are aliases of the same source path
-----------------------------------------------------------------------------*/
bool mvee::are_aliases(std::vector<std::string> paths)
{
	std::string cmp;
	
	for (int i = 0; i < mvee::numvariants; ++i)
	{
		auto source = reverse_aliases[i].find(paths[i]);
		if (source == reverse_aliases[i].end())
			return false;

		if (cmp == "")
		{
			cmp = source->second;
			continue;
		}
		else
		{
			if (cmp != source->second)
				return false;
		}			 
	}

	return true;
}

/*-----------------------------------------------------------------------------
    map_master_to_slave_pids
-----------------------------------------------------------------------------*/
bool mvee::map_master_to_slave_pids(pid_t master_pid, std::vector<pid_t>& slave_pids)
{
    MutexLock                                      lock(&mvee::global_lock);

    std::map<pid_t, std::vector<pid_t> >::iterator it
        = mvee::variant_pid_mapping.find(master_pid);
    if (it == mvee::variant_pid_mapping.end())
    {
        debugf("no suitable mapping found for pid %d\n", master_pid);
        return false;
    }

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        debugf("mapped master_pid %d to pid %d for variant %d\n", master_pid, it->second[i], i);
        slave_pids[i] = it->second[i];
    }

    return true;
}

/*-----------------------------------------------------------------------------
    is_monitored_variant
-----------------------------------------------------------------------------*/
bool mvee::is_monitored_variant(pid_t variant_pid)
{
	MutexLock lock(&mvee::global_lock);
	return mvee::variant_pid_mapping.find(variant_pid) !=
		mvee::variant_pid_mapping.end();
}

/*-----------------------------------------------------------------------------
    get_addr2line_proc - global lock must be locked when calling this function
-----------------------------------------------------------------------------*/
std::shared_ptr<mmap_addr2line_proc> mvee::get_addr2line_proc(const std::string& input_file_name)
{
    std::shared_ptr<mmap_addr2line_proc>                                 result;

    std::map<std::string, std::weak_ptr<mmap_addr2line_proc> >::iterator it =
        mvee::addr2line_cache.find(input_file_name);
    if (it != mvee::addr2line_cache.end())
    {
        result = it->second.lock();
        if (!result)
            mvee::addr2line_cache.erase(it);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    get_dwarf_info - we store weak pointers in the dwarf cache so
    there's always a chance that a dwarf_info we find in the cache has been
    invalidated

    global lock must be locked when calling this function!!!
-----------------------------------------------------------------------------*/
std::shared_ptr<dwarf_info> mvee::get_dwarf_info(const std::string& file)
{
    std::shared_ptr<dwarf_info>                                 result;

    std::map<std::string, std::weak_ptr<dwarf_info> >::iterator it =
        mvee::dwarf_cache.find(file);
    if (it != mvee::dwarf_cache.end())
    {
        result = it->second.lock();
        if (!result)
            mvee::dwarf_cache.erase(it);
    }

    return result;
}

/*-----------------------------------------------------------------------------
    os_get_build_id - get the GNU build ID from the ELF notes section
-----------------------------------------------------------------------------*/
std::string mvee::os_get_build_id(const std::string& file)
{
	std::stringstream cmd;
	cmd << "readelf -n " << file << " | grep \"Build ID:\" | cut -d':' -f2 | tr -d ' '";
	return mvee::log_read_from_proc_pipe(cmd.str().c_str(), NULL);
}

/*-----------------------------------------------------------------------------
    os_get_unstripped_binary - look for the unstripped version of the specified
	ELF binary. Return "" if no such binary can be found in /usr/lib/debug
-----------------------------------------------------------------------------*/
std::string mvee::os_get_unstripped_binary(const std::string& file)
{
	// First, see if we've already done this lookup before
	{
		MutexLock lock(&mvee::global_lock);

		auto it = mvee::unstripped_binaries_cache.find(file);
		if (it != mvee::unstripped_binaries_cache.end())
			return it->second;
	}

	// Not in the cache. Let's fetch the build ID and see if we
	// can find a binary with a matching build ID and name in /usr/lib/debug
	auto orig_build_id = mvee::os_get_build_id(file);

	// Look for other unstripped versions of the binary now...
	auto basename = file.substr(file.find_last_of('/'));
	std::stringstream cmd;
	cmd << "find /usr/lib/debug/* | grep " << basename;
	std::stringstream binaries(mvee::log_read_from_proc_pipe(cmd.str().c_str(), NULL));
	std::string binary;

	while(std::getline(binaries, binary))
	{
		auto build_id = mvee::os_get_build_id(binary);

		if (orig_build_id == build_id)
		{
			MutexLock lock(&mvee::global_lock);

			auto it = mvee::unstripped_binaries_cache.find(file);
			if (it == mvee::unstripped_binaries_cache.end())
			{
				debugf("Found unstripped version of ELF file\n");
				debugf("> Original (stripped) file: %s\n", file.c_str());
				debugf("> Unstripped file: %s\n", binary.c_str());
				mvee::unstripped_binaries_cache.insert(std::make_pair(file, binary));
			}
			return binary;
		}
	}

	return "";	
}

/*-----------------------------------------------------------------------------
    os_has_noninstrumented_atomics
-----------------------------------------------------------------------------*/
bool mvee::os_has_noninstrumented_atomics (const std::string& file)
{
	static std::map<std::string, bool> has_noninstrumented_atomics;
   
	// check if it's already in the map
	{
		MutexLock lock(&mvee::global_lock);
		auto it = has_noninstrumented_atomics.find(file);

		if (it != has_noninstrumented_atomics.end())
			return it->second;
	}

	if (file.find("/patched_binaries/") == std::string::npos)
	{
		// not in the map yet, disassemble and check
		std::stringstream cmd;
		cmd << "objdump --disassemble " << file << " | " << MVEE_ARCH_FIND_ATOMIC_OPS_STRING;
		std::stringstream instructions(mvee::log_read_from_proc_pipe(cmd.str().c_str(), NULL));
		std::string instruction, prev_instruction;

		while (std::getline(instructions, instruction))
		{
			// the filtered disassembly includes only atomic operations and calls to the sync agent
			// Thus, if this line is nog a call to the sync agent, it must be an atomic op
			if (instruction.find("mvee_atomic") == std::string::npos)
			{
				// check if the previous instruction was a call to the preop function
				// if it was, then this atomic op is wrapped
				if (prev_instruction.find("mvee_atomic_preop") == std::string::npos)
				{
					MutexLock lock(&mvee::global_lock);
					auto it = has_noninstrumented_atomics.find(file);
				
					if (it == has_noninstrumented_atomics.end())
						has_noninstrumented_atomics.insert(std::make_pair(file, true));
					return true;				
				}
			}

			prev_instruction = instruction;
		}
	}

	// no non-instrumented ops found
	{
		MutexLock lock(&mvee::global_lock);
		auto it = has_noninstrumented_atomics.find(file);
		
		if (it == has_noninstrumented_atomics.end())
			has_noninstrumented_atomics.insert(std::make_pair(file, false));
	}

	return false;	
}

/*-----------------------------------------------------------------------------
    os_get_orig_working_dir
-----------------------------------------------------------------------------*/
std::string mvee::os_get_orig_working_dir()
{
    if (mvee::orig_working_dir == "")
    {
        char* cwd = getcwd(NULL, 0);
        mvee::orig_working_dir = std::string(cwd);
        free(cwd);
    }
    return mvee::orig_working_dir;
}

/*-----------------------------------------------------------------------------
    os_get_mvee_root_dir
-----------------------------------------------------------------------------*/
std::string mvee::os_get_mvee_root_dir()
{
    if ((*mvee::config_monitor)["root_path"].isNull() ||
		strlen((*mvee::config_monitor)["root_path"].asCString()) == 0)
    {
		char cmd[500];
		sprintf(cmd, "readlink -f /proc/%d/exe | sed 's/\\(.*\\)\\/.*/\\1\\/..\\/..\\/..\\//' | xargs readlink -f | tr -d '\\n'", getpid());
        std::string out = mvee::log_read_from_proc_pipe(cmd, NULL);

        if (out != "")
        {
            if (out.length() < 2)
            {
                warnf("root path does not make sense. the mvee is possibly running under valgrind/gdb\n");
                warnf("using /home/stijn/MVEE as the root dir instead\n");
                (*mvee::config_monitor)["root_path"] = "/home/stijn/MVEE";
            }
            else
            {
                (*mvee::config_monitor)["root_path"] = out;
            }
        }
    }

    return (*mvee::config_monitor)["root_path"].asString();
}

/*-----------------------------------------------------------------------------
    mvee_env_get_stack_limit
-----------------------------------------------------------------------------*/
unsigned long mvee::os_get_stack_limit()
{
    if (!mvee::stack_limit)
    {
        std::string out = mvee::log_read_from_proc_pipe("ulimit -s", NULL);

        if (out != "")
        {
            int tmp = 0;
            sscanf(out.c_str(), "%d\n", &tmp);
            mvee::stack_limit = tmp * 1024;
        }
    }

    return mvee::stack_limit;
}

/*-----------------------------------------------------------------------------
    os_get_num_cores - fastest way to get the number of cpu cores!
-----------------------------------------------------------------------------*/
int mvee::os_get_num_cores()
{
    if (!mvee::num_cores)
        mvee::num_cores = sysconf(_SC_NPROCESSORS_ONLN);

    return mvee::num_cores;
}

/*-----------------------------------------------------------------------------
  mvee_env_get_num_physical_cpus
-----------------------------------------------------------------------------*/
int mvee::os_get_num_physical_cpus()
{
    if (!mvee::num_physical_cpus)
        mvee::num_physical_cpus = std::stol(mvee::log_read_from_proc_pipe("cat /proc/cpuinfo | grep \"physical id\" | tr -d ' ' | cut -d':' -f2 | uniq | wc -l", NULL));

    return mvee::num_physical_cpus;
}

/*-----------------------------------------------------------------------------
    os_check_ptrace_scope - Ubuntu's Yama LSM is currently broken w.r.t.
    ptracing. I've reported the bug here but afaik it hasn't been fixed yet:
    https://lkml.org/lkml/2014/12/24/196

    As a temporary fix, this function will attempt to disable Yama's ptrace
    checking.
-----------------------------------------------------------------------------*/
void mvee::os_check_ptrace_scope()
{
#ifdef MVEE_ARCH_HAS_YAMA_LSM
    std::string yama = mvee::log_read_from_proc_pipe("/sbin/sysctl kernel.yama.ptrace_scope", NULL);

    // If we're not running on ubuntu, we won't get any feedback through stdout
    if (yama == "")
        return;

    if (yama.find("kernel.yama.ptrace_scope = 1") == 0)
    {
        printf("============================================================================================================================\n");
        printf("It seems that you are running Ubuntu with the Yama Linux Security Module and Yama's ptrace scope set to SCOPE_RELATIONAL.\n");
        printf("In the current Yama implementation, SCOPE_RELATIONAL causes problems for multi-process variants.\n");
        printf("GHUMVEE will therefore try to disable yama's ptrace introspection using:\n\n");
        printf("sudo sysctl -w kernel.yama.ptrace_scope=0\n\n");
        printf("You can read more about this bug on the Linux Kernel Mailing list in the following thread:\n");
        printf("https://lkml.org/lkml/2014/12/24/196\n\n");

        yama = mvee::log_read_from_proc_pipe("sudo sysctl -w kernel.yama.ptrace_scope=0", NULL);

        if (yama.find("kernel.yama.ptrace_scope = 0") != 0)
            printf("Failed to disable yama's ptrace introspection. You probably don't have sudo rights. Please have your administrator fix this!\n");
        else
            printf("Disabled yama!\n");
        printf("============================================================================================================================\n");
    }
#endif
}

/*-----------------------------------------------------------------------------
    mvee_env_check_kernel_cmdline - if we're running on AMD64, we need
    vsyscall=native in the kernel commandline
-----------------------------------------------------------------------------*/
void mvee::os_check_kernel_cmdline()
{
#ifdef MVEE_ARCH_HAS_VSYSCALL
    std::string cmdline = mvee::log_read_from_proc_pipe("cat /proc/cmdline", NULL);

    if (cmdline == "")
        return;

    if (cmdline.find("vsyscall=native") == std::string::npos)
    {
        printf("============================================================================================================================\n");
        printf("It seems that you are running a 64-bit kernel with vsyscall set to emulate.\n");
        printf("GHUMVEE requires that vsyscall be set to native, so it can intercept calls to\n");
        printf("timing related functions such as sys_gettimeofday.\n\n");
        printf("If you are using the GRUB bootloader, you can fix this by running the following commands:\n");
        printf("\n");
        printf("sudo sed -i 's/GRUB\\_CMDLINE\\_LINUX\\_DEFAULT=\"/GRUB\\_CMDLINE\\_LINUX\\_DEFAULT=\"vsyscall=native /' /etc/default/grub\n");
        printf("sudo update-grub\n");
        printf("sudo reboot\n");
        printf("\n");
        printf("GHUMVEE will now continue running but keep in mind that you will probably see mismatches until you fix the vsyscall setting!\n");
        printf("============================================================================================================================\n");
    }
#endif
}

/*-----------------------------------------------------------------------------
    mvee_env_try_update_shmmax - we can try this if we fail to allocate a new SYSV ipc
    shared buffer through shmget. This updates the kernel shmmax (= system-wide
    total number of bytes allowed in shared mem) and shmall (= system-wide total
    number of pages allowed in shared mem) variables
-----------------------------------------------------------------------------*/
bool mvee::os_try_update_shmmax()
{
    unsigned long desired_size   = 0xFFFFFFFF;
    unsigned long desired_pages  = 0x100000;

#ifndef MVEE_BENCHMARK
    unsigned long shmmax         = std::stoul(mvee::log_read_from_proc_pipe("sysctl kernel.shmmax | cut -d' ' -f3 | tr -d '\\n'", NULL));
    debugf("current kernel.shmmax = %lu\n", shmmax);
    debugf("===> trying to adjust kernel.shmmax\n");
#endif

    char          cmd[200];
    sprintf(cmd, "sudo -n sysctl -w kernel.shmmax=%ld", desired_size);
    std::string   _shmmax_update = mvee::log_read_from_proc_pipe(cmd, NULL);
    if (_shmmax_update.find("kernel.shmmax") != 0)
    {
        warnf("failed to adjust kernel.shmmax. do you have sudo NOPASSWD rights?\n");
        return false;
    }

    sprintf(cmd, "sudo -n sysctl -w kernel.shmall=%ld", desired_pages);
    std::string   _shmall_update = mvee::log_read_from_proc_pipe(cmd, NULL);
    if (_shmall_update.find("kernel.shmall") != 0)
    {
        warnf("failed to adjust kernel.shmall. do you have sudo NOPASSWD rights?\n");
        return false;
    }

    return true;
}

/*-----------------------------------------------------------------------------
    mvee_getpid
-----------------------------------------------------------------------------*/
int mvee::os_getpid()
{
    if (!mvee::process_pid)
        mvee::process_pid = syscall(__NR_getpid);

    return mvee::process_pid;
}

/*-----------------------------------------------------------------------------
    mvee_gettid
-----------------------------------------------------------------------------*/
int mvee::os_gettid()
{
    if (!mvee::thread_pid)
        mvee::thread_pid = syscall(__NR_gettid);

    return mvee::thread_pid;
}

/*-----------------------------------------------------------------------------
    os_get_interp - get the full path to the program interpreter for this
    architecture.
-----------------------------------------------------------------------------*/
std::string mvee::os_get_interp()
{
    std::stringstream ss;
    ss << MVEE_ARCH_INTERP_PATH << MVEE_ARCH_INTERP_NAME;
    return ss.str();
}

/*-----------------------------------------------------------------------------
    os_can_load_indirect - TODO: Add cache here
-----------------------------------------------------------------------------*/
bool mvee::os_can_load_indirect(std::string& file)
{	
    std::string cmd = "/usr/bin/readelf -d " + file + " 2>&1";
    std::string dyn = mvee::log_read_from_proc_pipe(cmd.c_str(), NULL);

	// invalid ELF file
	if (dyn.find("Error") != std::string::npos)
		return true;

	// dynamic section found => We can use the LD_Loader
	if (dyn.find("There is no dynamic section in this file.") == std::string::npos)
		return true;

	cmd = "/usr/bin/readelf -h " + file + " | grep Type 2>&1";
	std::string header = mvee::log_read_from_proc_pipe(cmd.c_str(), NULL);

	// statically linked, but PIE compiled
	if (header.find("DYN") != std::string::npos)
		return true;

	// statically linked and position dependent => can't use LD_Loader
	return false;
}

/*-----------------------------------------------------------------------------
    os_get_interp_for_file - if file is a script, return the interpreter for
    that script
-----------------------------------------------------------------------------*/
void mvee::os_register_interp(std::string& file, const char* interp)
{
    MutexLock lock(&mvee::global_lock);
    if (interp_map.find(file) != interp_map.end())
        interp_map.insert(std::pair<std::string, std::string>(file, interp));
}

bool mvee::os_add_interp_for_file(std::deque<char*>& add_to_queue, std::string& file)
{
    {   MutexLock lock(&mvee::global_lock);
        auto      it = interp_map.find(file);

        if (it != interp_map.end())
        {
            if (it->second.length() != 0)
                add_to_queue.push_front(mvee::strdup(it->second.c_str()));
            return true;
        }
	}

    std::string cmd       = "/usr/bin/file -L " + file + " | grep -v ERROR";
    std::string file_type = mvee::log_read_from_proc_pipe(cmd.c_str(), NULL);

    if (file_type == "")
        return false;

    if (file_type.find("ELF") != std::string::npos)
    {
        os_register_interp(file, "");
        return true;
    }

    // the file exists but is not ELF
    cmd = "/usr/bin/head -n1 " + file;
    std::string interp    = mvee::log_read_from_proc_pipe(cmd.c_str(), NULL);
    if (interp.find("#!") == 0)
    {
        interp.erase(interp.begin(),                                  interp.begin()+1);
        interp.erase(interp.begin(),                                  interp.begin()+interp.find("/"));
        interp.erase(std::remove(interp.begin(), interp.end(), '\n'), interp.end());
        std::deque<std::string> tokens = mvee::strsplit(interp, ' ');
        while (tokens.size() > 0)
        {
            add_to_queue.push_front(mvee::strdup(tokens.back().c_str()));
            tokens.pop_back();
        }
        return true;
    }

    // can find an interpreter there. Try a set of known extensions
    if (mvee::str_ends_with(file, ".sh"))
    {
        add_to_queue.push_front(mvee::strdup("/bin/bash"));
        os_register_interp(file, "/bin/bash");
        return true;
    }
    else if (mvee::str_ends_with(file, ".rb"))
    {
        add_to_queue.push_front(mvee::strdup("/usr/bin/ruby"));
        os_register_interp(file, "/usr/bin/ruby");
        return true;
    }

    warnf("Can't determine the appropriate interpreter for file: %s\n", file.c_str());
    return false;
}

/*-----------------------------------------------------------------------------
    os_get_mvee_ld_loader - get the full path to the MVEE_LD_Loader for this
    architecture.
-----------------------------------------------------------------------------*/
std::string mvee::os_get_mvee_ld_loader()
{
    std::stringstream ss;
    ss << (*mvee::config_monitor)["root_path"].asString() << MVEE_LD_LOADER_PATH << MVEE_LD_LOADER_NAME;
    return ss.str();
}

/*-----------------------------------------------------------------------------
    os_reset_envp
-----------------------------------------------------------------------------*/
void mvee::os_reset_envp()
{
    // Dirty hack to force initialization of the environment.
    // Without this we'll get allocation behavior mismatches everywhere!
    // Even in GCC!!
    putenv((char*)"THIS=SILLY");
    putenv((char*)"LD_PRELOAD");
    putenv((char*)"SPEC");
    putenv((char*)"SPECPERLLIB");
    putenv((char*)"LD_LIBRARY_PATH");
    //    putenv((char*)"SPECPATH");
    //    putenv((char*)"SPECLIBPATH");
    //    putenv((char*)"SPECPROFILE");
    //    putenv((char*)"SPECEXT");
}

/*-----------------------------------------------------------------------------
    os_alloc_sysv_sharedmem - allocates a sysv shared memory block of the 
	specified size.
-----------------------------------------------------------------------------*/
bool mvee::os_alloc_sysv_sharedmem(unsigned long alloc_size, int* id_ptr, int* size_ptr, void** ptr_ptr)
{
	struct shmid_ds shared_buffer_ds;
	int id = shmget(IPC_PRIVATE, alloc_size, IPC_CREAT | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	// this might fail because we're trying to allocate too many
	// shared memory segments or because the shared memory segment
	// we're trying to allocate is too big.
	//
	// attempt to increase it here and retry!
	if (id == -1)
	{
		if (!mvee::os_try_update_shmmax())
			return false;

		id = shmget(IPC_PRIVATE, alloc_size, IPC_CREAT | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	}

	if (id == -1)
	{
		warnf("Failed to allocate shared memory block! Are the IPC slots full? - alloc_size = %ld\n",
			alloc_size);
		return false;
	}

	if (shmctl(id, IPC_STAT, &shared_buffer_ds))
	{
		warnf("Failed to retrieve size of the shared memory block!\n");
		return false;
	}

	if (id_ptr)
		*id_ptr = id;

	if (size_ptr)
		*size_ptr = shared_buffer_ds.shm_segsz;

	if (ptr_ptr)
	{
		*ptr_ptr  = shmat(id, NULL, 0);

		if (*ptr_ptr == (void*)-1)
		{
			warnf("Failed to attach to shared memory block! err = %d (%s)\n", errno, getTextualErrno(errno));
			return false;
		}
	}

	// Make sure that the buffer gets deleted when we detach from it
	shmctl(id, IPC_RMID, &shared_buffer_ds);


	return true;
}

/*-----------------------------------------------------------------------------
    os_get_entry_point_address - get the relative entry point address for the
	specified ELF binary
-----------------------------------------------------------------------------*/
unsigned long mvee::os_get_entry_point_address(std::string& binary)
{
	unsigned long result = 0;
	Elf* elf = NULL;
	bool is_pie = false;
	int fd = open(binary.c_str(), O_RDONLY, 0);
	char* ident = NULL;

	elf_version(EV_CURRENT);

	if (fd > 0)
		elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);

	if (fd < 0 || !elf)
	{
		warnf("Can't open file: %s - fd is %d\n", binary.c_str(), fd);
		goto error;
	}

	// Identify the architecture
	ident = elf_getident(elf, NULL);
	if (!ident)
		goto error;

	if (ident[4] == ELFCLASS64)
	{
		Elf64_Ehdr* ehdr = elf64_getehdr(elf);
		if (ehdr && ehdr->e_type == ET_DYN)
			is_pie = true;

		result = ehdr->e_entry;

        // find in-memory base address for this binary
		if (!is_pie)
		{
			Elf64_Phdr* phdr = elf64_getphdr(elf);
			size_t phdr_cnt;
			unsigned long long image_base = 0xFFFFFFFFFFFFFFFF;
			
			if (!phdr || elf_getphdrnum(elf, &phdr_cnt) == -1)
				goto error;

			for (size_t i = 0; i < phdr_cnt; ++i)
				if (phdr[i].p_type == PT_LOAD)
					if (phdr[i].p_vaddr < image_base)
						image_base = phdr[i].p_vaddr;

			result -= image_base;
		}
	}
	else
	{
		Elf32_Ehdr* ehdr = elf32_getehdr(elf);
		if (ehdr && ehdr->e_type == ET_DYN)
			is_pie = true;

		result = ehdr->e_entry;

        // find in-memory base address for this binary
		if (!is_pie)
		{
			Elf32_Phdr* phdr = elf32_getphdr(elf);
			size_t phdr_cnt;
			unsigned long long image_base = 0x00000000FFFFFFFF;
			
			if (!phdr || elf_getphdrnum(elf, &phdr_cnt) == -1)
				goto error;

			for (size_t i = 0; i < phdr_cnt; ++i)
				if (phdr[i].p_type == PT_LOAD)
					if (phdr[i].p_vaddr < image_base)
						image_base = phdr[i].p_vaddr;

			result -= image_base;
		}
	}

error:	
	if (elf)
		elf_end(elf);
	if (fd > 0)
		close(fd);
	return result;
}

/*-----------------------------------------------------------------------------
    os_get_rpath - get the relative library path for the specified binary
-----------------------------------------------------------------------------*/
std::string mvee::os_get_rpath(std::string& binary)
{
	std::string cmd = "objdump -p " + binary + "| grep RPATH | tr -d ' ' | sed 's/RPATH//'";
	std::string rpath = mvee::log_read_from_proc_pipe(cmd.c_str(), NULL);

	if (rpath.size() > 0)
	{
		if (rpath.find("$ORIGIN") != std::string::npos)
		{
			char* dir = dirname(mvee::strdup(binary.c_str()));

			rpath.replace(rpath.find("$ORIGIN"), strlen("$ORIGIN"), dir);

			if (dir)
				free(dir);
		}

		char* path = realpath(rpath.c_str(), NULL);
		mvee::warnf("realpath = %s (errno: %s)\n", path, getTextualErrno(errno));
		if (path)
		{
			rpath = std::string(path);
			free(path);
		}
	}

	mvee::warnf("execve rpath = %s\n", rpath.c_str());

	return rpath;
}

/*-----------------------------------------------------------------------------
    os_normalize_path_name
-----------------------------------------------------------------------------*/
std::string mvee::os_normalize_path_name(std::string path)
{
	char* tmp = realpath(path.c_str(), NULL);

	if (!tmp)
	{
		if (errno == ENOENT)
		{
			auto slash = path.rfind('/');
			if (slash != std::string::npos)
			{
				auto dir_only = path.substr(0, slash);
				auto file = path.substr(slash);
				auto normalized_dir = os_normalize_path_name(dir_only);
				return normalized_dir + file;
			}

			return path;
		}
		else
			return path;
	}
	{
		std::string result(tmp);
		free(tmp);
		return result;
	}
}

/*-----------------------------------------------------------------------------
    lock
-----------------------------------------------------------------------------*/
void mvee::lock()
{
    pthread_mutex_lock(&mvee::global_lock);
}

/*-----------------------------------------------------------------------------
    unlock
-----------------------------------------------------------------------------*/
void mvee::unlock()
{
    pthread_mutex_unlock(&mvee::global_lock);
}

/*-----------------------------------------------------------------------------
    request_shutdown -
-----------------------------------------------------------------------------*/
void mvee::request_shutdown(bool should_backtrace)
{
    mvee::lock();
    mvee::shutdown_signal            = SIGINT;
    mvee::should_generate_backtraces = should_backtrace;
    mvee::unlock();
    pthread_cond_broadcast(&mvee::global_cond);
}

/*-----------------------------------------------------------------------------
    shutdown - Safely shuts down the MVEE

    @param shutdown_sig     signal that triggered the shutdown. This can only
    be non-zero for monitor 0 (== the monitor to which all signals are
    delivered) and this will be ignored if it's a normal shutdown

    @param should_backtrace if 1, every monitorthread will log a callstack for
    all of the variants it's tracing, prior to shutting down
-----------------------------------------------------------------------------*/
void mvee::shutdown(int sig, int should_backtrace)
{
    /*
    retarded hack here. We have no way
    to unblock monitors that are waitpid'ing UNLESS we trigger an event that
    causes the waitpid to return

    => we send a SIGALRM to one of the variants
     */
    mvee::lock();
    for (auto it : mvee::active_monitors)
	{
        it->signal_shutdown();
	}
    for (auto it : mvee::inactive_monitors)
	{
        // no need to send SIGUSR1. This monitor is already waiting to be shut down
		it->monitor_tid = 0; 
        it->signal_shutdown();
	}
    mvee::unlock();

    // wait for all monitors to terminate
    while (1)
    {
        mvee::lock();
        if (mvee::active_monitors.size() == 0 &&
			mvee::inactive_monitors.size() == 0)
        {
            mvee::unlock();
            break;
        }
        mvee::unlock();
        sched_yield();
    }

    printf("all monitors terminated\n");
    mvee::log_fini(true);
    exit(0);
}

/*-----------------------------------------------------------------------------
    garbage_collect -
-----------------------------------------------------------------------------*/
void mvee::garbage_collect()
{
    std::vector<monitor*> local_gclist;

    {   MutexLock lock(&mvee::global_lock);

        mvee::should_garbage_collect = false;

        // copy all dead monitors to a local gclist first and then clean them up
        // without locking the global state...
        while (mvee::dead_monitors.size() > 0)
        {
            auto mon = mvee::dead_monitors.back();
            local_gclist.push_back(mon);
            mvee::dead_monitors.pop_back();
        }
	}

    while (local_gclist.size() > 0)
    {
        auto mon = local_gclist.back();

        if (mvee::shutdown_signal == 0)
            mon->join_thread();

        logf("garbage collected monitor: %d\n", 
			 mon->monitorid);
        SAFEDELETE(mon);
        local_gclist.pop_back();
    }
}

/*-----------------------------------------------------------------------------
    is_multiprocess
-----------------------------------------------------------------------------*/
bool mvee::is_multiprocess()
{
    pid_t     prev_tgid = 0;
    int       num_tgids = 0;

    MutexLock lock(&mvee::global_lock);
    for (auto it : mvee::active_monitors)
    {
        pid_t tgid;
        if ((tgid = it->get_mastertgid()) != prev_tgid)
        {
            if (num_tgids++)
                return true;

            prev_tgid = tgid;
        }
    }

    return false;
}

/*-----------------------------------------------------------------------------
    get_unavailable_cores
-----------------------------------------------------------------------------*/
std::set<int> mvee::get_unavailable_cores(int* most_recent_core)
{
	std::set<int> result;

    MutexLock lock(&mvee::global_lock);

    for (auto it : mvee::monitor_id_mapping)
	{
		int core = it.second->get_master_core();

		if (core != -1)
		{
			debugf("cores [%d, %d] are currently in use by monitor %d\n",
						core,
						core + mvee::numvariants - 1,
						it.second->monitorid);

			result.insert(core);

			if (it.first == mvee::active_monitorid - 1
				&& most_recent_core)
				*most_recent_core = core;
		}
	}

	return result;
}

/*-----------------------------------------------------------------------------
    get_next_monitorid
-----------------------------------------------------------------------------*/
int mvee::get_next_monitorid()
{
    MutexLock lock(&mvee::global_lock);
    return mvee::next_monitorid++;
}

/*-----------------------------------------------------------------------------
    get_should_generate_backtraces
-----------------------------------------------------------------------------*/
bool mvee::get_should_generate_backtraces()
{
    MutexLock lock(&mvee::global_lock);
    return mvee::should_generate_backtraces;
}

/*-----------------------------------------------------------------------------
    set_should_generate_backtraces
-----------------------------------------------------------------------------*/
void mvee::set_should_generate_backtraces()
{
    mvee::should_generate_backtraces = true;
	__sync_synchronize();
}

/*-----------------------------------------------------------------------------
    add_detached_variant
-----------------------------------------------------------------------------*/
void mvee::add_detached_variant(detachedvariant* variant)
{
    MutexLock lock(&mvee::global_lock);
    mvee::detachlist.push_back(variant);
}

/*-----------------------------------------------------------------------------
    remove_detached_variant - returns the variant that was removed
-----------------------------------------------------------------------------*/
detachedvariant* mvee::remove_detached_variant(pid_t variantpid)
{
    MutexLock lock(&mvee::global_lock);

    for (std::vector<detachedvariant*>::iterator it = mvee::detachlist.begin();
         it != mvee::detachlist.end(); ++it)
    {
        if ((*it)->variantpid == variantpid)
        {
            detachedvariant* variant = *it;
            mvee::detachlist.erase(it);
			pthread_cond_broadcast(&mvee::global_cond);
            return variant;
        }
    }

    return NULL;
}

/*-----------------------------------------------------------------------------
    have_detached_variants - checks whether the specified monitor has detached
    from processes that have not been attached to another monitor yet
-----------------------------------------------------------------------------*/
bool mvee::have_detached_variants(monitor* mon)
{
    MutexLock lock(&mvee::global_lock);

    for (std::vector<detachedvariant*>::iterator it = mvee::detachlist.begin();
         it != mvee::detachlist.end(); ++it)
    {
        if ((*it)->parentmonitorid == mon->monitorid)
            return true;
    }

    return false;
}

/*-----------------------------------------------------------------------------
    have_pending_variants - counts the number of variants that are waiting to
    be attached to the specified monitor
-----------------------------------------------------------------------------*/
int mvee::have_pending_variants(monitor* mon)
{
    int       cnt = 0;

    MutexLock lock(&mvee::global_lock);

    for (std::vector<detachedvariant*>::iterator it = mvee::detachlist.begin();
         it != mvee::detachlist.end(); ++it)
    {
        if ((*it)->parent_has_detached && (*it)->new_monitor == mon)
            cnt++;
    }

    return cnt;
}

/*-----------------------------------------------------------------------------
    set_should_check_multithread_state
-----------------------------------------------------------------------------*/
void mvee::set_should_check_multithread_state(int monitorid)
{
    MutexLock lock(&mvee::global_lock);
    auto it = mvee::monitor_id_mapping.find(monitorid);
    if (it != mvee::monitor_id_mapping.end())
        it->second->set_should_check_multithread_state();
}

/*-----------------------------------------------------------------------------
    register_variants
-----------------------------------------------------------------------------*/
void mvee::register_variants(std::vector<pid_t>& pids)
{
    MutexLock lock(&mvee::global_lock);

    for (int i = 0; i < mvee::numvariants; ++i)
    {
        mvee::variant_pid_mapping.erase(pids[i]);
        mvee::variant_pid_mapping.insert(std::pair<pid_t, std::vector<pid_t> >(pids[i], pids));
    }
}

/*-----------------------------------------------------------------------------
    register_monitor
-----------------------------------------------------------------------------*/
void mvee::register_monitor(monitor* mon)
{
    {
		MutexLock lock(&mvee::global_lock);
        mvee::monitor_id_mapping.insert(std::pair<int, monitor*>(mon->monitorid, mon));
		mvee::active_monitors.push_back(mon);
	}

    mon->signal_registration();
}

/*-----------------------------------------------------------------------------
    unregister_monitor
-----------------------------------------------------------------------------*/
void mvee::unregister_monitor(monitor* mon, bool move_to_dead_monitors)
{
    bool should_shutdown = false;

    {
		MutexLock lock(&mvee::global_lock);
        auto it = monitor_id_mapping.find(mon->monitorid);
        if (it != monitor_id_mapping.end())
            monitor_id_mapping.erase(it);
		auto it2 = std::find(active_monitors.begin(), active_monitors.end(), mon);
		if (it2 != active_monitors.end())
			active_monitors.erase(it2);

		if (move_to_dead_monitors)
		{
			auto it3 = std::find(inactive_monitors.begin(), inactive_monitors.end(), mon);
			if (it3 != inactive_monitors.end())
				inactive_monitors.erase(it3);

			dead_monitors.push_back(mon);
			should_garbage_collect = true;
		}
		else
		{
			inactive_monitors.push_back(mon);
		}

        if (active_monitors.size() <= 0)
            should_shutdown = true;

        pthread_cond_broadcast(&mvee::global_cond);

        if (mon == mvee::active_monitor)
            mvee::active_monitor = NULL;
	}

    if (should_shutdown)
        mvee::request_shutdown(mvee::should_generate_backtraces);
}

/*-----------------------------------------------------------------------------
    is_monitored_tgid - caller needs the global lock!
-----------------------------------------------------------------------------*/
bool mvee::is_monitored_tgid(pid_t tgid)
{
	// never shut down if we still have detached variants
	if (detachlist.size() > 0)
		return true;

	for (auto it : active_monitors)
	{
		for (int i = 0; i < mvee::numvariants; ++i)
		{
			if (it->variants[i].varianttgid == tgid &&
				!it->variants[i].variant_terminated)
				return true;
		}
	}

	return false;
}


/*-----------------------------------------------------------------------------
    mvee_mon_external_backtrace_request - request backtraces when we shut down
    the monitor
-----------------------------------------------------------------------------*/
void mvee_mon_external_backtrace_request(int sig)
{
	mvee::set_should_generate_backtraces();
	mvee_mon_external_termination_request(sig);
}

/*-----------------------------------------------------------------------------
    mvee_mon_external_termination_request - signal handler for the primary thread
-----------------------------------------------------------------------------*/
void mvee_mon_external_termination_request(int sig)
{
    if (mvee::active_monitorid == -1)
    {
        printf("EXTERNAL TERMINATION REQUEST - MONITORID: %d\n", mvee::active_monitorid);
        if (!mvee::shutdown_signal)
			mvee::request_shutdown(mvee::should_generate_backtraces);
        else
            exit(0);
    }
    else
    {
        // do nothing. We just use a signal to unblock any blocking calls
        // mvee_mon_return(true);
        printf("TERMINATION REQUEST - MONITORID: %d\n", mvee::active_monitorid);
        mvee::active_monitor->signal_shutdown();
    }
}

/*-----------------------------------------------------------------------------
    start_unmonitored - Just forks off <mvee::numvariants> variants, starts them
    and immediately stops them with SIGSTOP. The monitor then starts the timer
    and immediately resumes all variants
-----------------------------------------------------------------------------*/
void mvee::start_unmonitored()
{
    std::vector<int>   resumed(mvee::numvariants);
    std::vector<int>   terminated(mvee::numvariants);
    std::vector<pid_t> pids(mvee::numvariants);
    int                i;

    for (i = 0; i < mvee::numvariants; ++i)
    {
        resumed[i]    = 0;
        terminated[i] = 0;
        pids[i]       = fork();
        if (pids[i] == 0)
            break;
    }

    if (i < mvee::numvariants)
    {
        mvee::setup_env(i);
		// raise SIGSTOP so the monitor process can attach before we exec
        kill(getpid(), SIGSTOP);
		start_variant(i);
    }
    else
    {
        bool all_resumed    = false;
        bool all_terminated = false;

        // In benchmark mode, initlogging just starts the timer...
        mvee::log_init();

        // Resume all variants
        while (!all_resumed)
        {
			interaction::mvee_wait_status status;

			if (!interaction::wait(-1, status, false, false) ||
				status.reason != STOP_SIGNAL ||
				status.data != SIGSTOP)
			{
				warnf("Failed to wait for children - error: %s - status: %s\n",
					  getTextualErrno(errno), getTextualMVEEWaitStatus(status).c_str());
				exit(-1);
				return;
			}
           
			kill(status.pid, SIGCONT);

			for (i = 0; i < mvee::numvariants; ++i)
				if (status.pid == pids[i])
					resumed[i] = 1;

			for (i = 0; i < mvee::numvariants; ++i)
				if (!resumed[i])
					break;

			if (i >= mvee::numvariants)
				all_resumed = true;
        }

        for (i = 0; i < mvee::numvariants; ++i)
            resumed[i] = 0;
        all_resumed = false;

        // Now wait for all variants to terminate...
        while (!all_terminated)
        {
			interaction::mvee_wait_status status;

			if (!interaction::wait(-1, status, false, false) ||
				(status.reason != STOP_EXIT && 
				 status.reason != STOP_SIGNAL))
			{
				warnf("Failed to wait for children - error: %s - status: %s\n",
					  getTextualErrno(errno), 
					  getTextualMVEEWaitStatus(status).c_str());
				exit(-1);
				return;
			}

            if (status.reason == STOP_EXIT)
            {
                for (i = 0; i < mvee::numvariants; ++i)
                    if (status.pid == pids[i])
                        terminated[i] = 1;

                for (i = 0; i < mvee::numvariants; ++i)
                    if (!terminated[i])
                        break;

                if (i >= mvee::numvariants)
                    all_terminated = true;
            }
            else if (status.reason == STOP_SIGNAL && 
					 status.data == SIGSTOP)
            {
                for (i = 0; i < mvee::numvariants; ++i)
                    if (status.pid == pids[i])
                        resumed[i] = 1;

                for (i = 0; i < mvee::numvariants; ++i)
                    if (!resumed[i])
                        break;

                if (i >= mvee::numvariants)
                    all_resumed = true;

                if (all_resumed)
                {
                    for (i = 0; i < mvee::numvariants; ++i)
                    {
                        kill(pids[i], SIGCONT);
                        resumed[i] = 0;
                    }
                    all_resumed = false;
                }
            }
        }

        // Just prints the time in benchmark mode
        mvee::log_fini(true);
        return;
    }
}

/*-----------------------------------------------------------------------------
    start_monitored - forks off <mvee::numvariants> variants, prepares them
    for tracing, starts them, ... Then the monitor sets up signal handlers,
    starts the timer and immediately resumes all variants.
-----------------------------------------------------------------------------*/
void mvee::start_monitored()
{
    int                i;
    std::vector<pid_t> procs(mvee::numvariants);
    sigset_t           set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    for (i = 0; i < mvee::numvariants; ++i)
    {
        procs[i] = fork();
        if (!procs[i])
            break;
    }

    if (i >= mvee::numvariants)
    {
        mvee::log_init();
        logf("======================================================\n");
        logf("   Ghent University Computer Systems Lab MVEE v4.0    \n");
        logf("                 aka \"GHUMVEE\"                      \n");
        logf("======================================================\n");
        logf("\nTracing %d semantically equivalent variant processes...\n\n", mvee::numvariants);

        sigset_t  set;
        sigemptyset(&set);
        sigaddset(&set, SIGINT);
        pthread_sigmask(SIG_UNBLOCK, &set, NULL);

        mvee::active_monitor = new monitor(procs);

        // Install signal handlers for SIGINT and SIGQUIT so we can shut down safely after CTRL+C
		struct sigaction sigact;
		sigact.sa_handler = mvee_mon_external_termination_request;
		sigemptyset(&set);
		sigact.sa_mask    = set;
		sigact.sa_flags   = 0;
		
		sigaction(SIGINT, &sigact, nullptr);
		sigaction(SIGQUIT, &sigact, nullptr);
		
		// Same thing but with backtraces
		sigact.sa_handler = mvee_mon_external_backtrace_request;
		sigaction(SIGUSR2, &sigact, nullptr);

        for (int i = 0; i < mvee::numvariants; ++i)
        {
			interaction::mvee_wait_status status;

			if (!interaction::wait(procs[i], status, false, false, false))
			{
				warnf("Failed to wait for children - errno: %s - status: %s\n",
					  getTextualErrno(errno), getTextualMVEEWaitStatus(status).c_str());
				exit(-1);
				return;
			}

            if (status.reason == STOP_SIGNAL)
				if (!interaction::detach(procs[i]))
					warnf("Failed to detach from variant %d\n", i);
        }

        mvee::register_monitor(mvee::active_monitor);

#ifdef MVEE_FD_DEBUG
        char      cmd[500];
        for (i = 0; i < mvee::numvariants; ++i)
        {
            sprintf(cmd, "ls -al /proc/%d/fd", procs[i]);
            logf("fd list for variant %d: \n", procs[i]);
            std::string str = mvee::log_read_from_proc_pipe(cmd, NULL);
            logf("%s\n",                     str.c_str());
        }
#endif


#ifdef MVEE_TASKSWITCH_OVERHEAD_BENCHMARK
        cpu_set_t cpu;
        CPU_ZERO(&cpu);
        CPU_SET(5*2, &cpu);
        if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu))
            warnf("couldn't set affinity\n");
#endif

        // everything is set up and ready to go...
        mvee::active_monitor   = NULL;
        mvee::active_monitorid = -1;
        while (true)
        {
            bool should_gc = false;

            mvee::lock();
            if (mvee::shutdown_signal)
            {
                mvee::unlock();
                mvee::shutdown(mvee::shutdown_signal,
                               mvee::should_generate_backtraces ? 1 : 0);
                return;
            }

            pthread_cond_wait(&mvee::global_cond, &mvee::global_lock);
            should_gc = mvee::should_garbage_collect;
            mvee::unlock();

            if (should_gc)
                mvee::garbage_collect();
        }
    }
    // If the process is a variant, prepare it for tracing
    else
    {
        mvee::setup_env(i);

        // We can disable the TSC right away
        // the tsc disable flag is inherited across forks, clones and execves...
        if ((*mvee::config_variant_global)["intercept_tsc"].asBool())
            prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0);

#ifdef MVEE_TASKSWITCH_OVERHEAD_BENCHMARK
        cpu_set_t cpu;
        CPU_ZERO(&cpu);
        CPU_SET(i*2, &cpu);
        if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu))
            warnf("couldn't set affinity\n");
#endif


        // Place the new variant under supervision of the main thread of the
		// monitor process.
        if (!interaction::accept_tracing())
			fprintf(stderr, "Couldn't accept tracing\n");

        // Stop the variant so we can detach the main monitor thread.
        kill(getpid(), SIGSTOP);

		// Wait in a busy loop while we wait for the designated monitor
		// thread to attach
        while (!mvee::can_run)
            ;

		// The monitor thread is now attached. It is now safe to execve
		start_variant(i);
    }
}

/*-----------------------------------------------------------------------------
    usage
-----------------------------------------------------------------------------*/
static void usage()
{
	printf("======================================================\n");
	printf("   Ghent University Computer Systems Lab MVEE v4.0    \n");
	printf("                 aka \"GHUMVEE\"                      \n");
	printf("======================================================\n\n");
	printf("Legacy Mode Syntax:\n");
	printf("./MVEE [Builtin Configuration Number (see MVEE_config.cpp)] [MVEE Options]\n\n");
	printf("RAVEN Mode Syntax:\n");
	printf("./MVEE -s <variant set> -f <config file> [MVEE Options] -- [Program Args]\n\n");
	printf("MVEE Options:\n");
	printf("> -s <variant set> : run the specified variant set. If this option is omitted, GHUMVEE will launch variant set \"default\". NOTE: This option is ignored in legacy mode.\n");
	printf("> -f <file name>   : use the monitor config in the specified file. If this option is omitted, the config will be read from MVEE.ini. NOTE: If the MVEE is run in legacy mode, then any options in the builtin config take precedence over the settings in the config file.\n");
	printf("> -N <number of variants> : sets the number of variants. In RAVEN mode, this option can override the number of variants specified in the config file.\n");
	printf("> -S <SyncTrace logfile name> : use SyncTrace to find uninstrumented accesses to synchronization variables. NOTE: monitoring is disabled and only a single variant is run.\n");
	printf("> -n : no monitoring. Variant processes are executed without supervision. Useful for benchmarking.\n");
	printf("> -p : use performance counters to track cache and synchronization behavior of the variants.\n");
	printf("> -o : log everything to stdout, as well as the log files. This flag is ignored if the MVEE is compiled with MVEE_BENCHMARK defined in MVEE_build_config.h\n");
	printf("> -c : show the contents of the json config file after command line processing.\n");
	printf("> In legacy mode, all arguments including and following the first non-option are passed as program arguments to the variants\n");
}

/*-----------------------------------------------------------------------------
    add_argv
-----------------------------------------------------------------------------*/
void mvee::add_argv(const char* arg, bool first_extra_arg)
{
	bool merge_extra_args = 
		!(*mvee::config_variant_global)["merge_extra_args"].isNull() &&
		(*mvee::config_variant_global)["merge_extra_args"].asBool();

	// Add to global exec arguments
	if (!(*mvee::config_variant_exec)["argv"])
		(*mvee::config_variant_exec)["argv"][0] = std::string(arg);
	else if (!merge_extra_args || first_extra_arg)
		(*mvee::config_variant_exec)["argv"].append(std::string(arg));
	else
	{
		auto str = (*mvee::config_variant_exec)["argv"][(*mvee::config_variant_exec)["argv"].size() - 1].asCString();
		std::stringstream ss;
		ss << str << " " << arg;
		(*mvee::config_variant_exec)["argv"][(*mvee::config_variant_exec)["argv"].size() - 1] = ss.str();
	}

	for (auto variant_spec : mvee::config["variant"]["specs"])
	{
		if (!variant_spec["argv"])
			variant_spec["argv"][0] = std::string(arg);
		else if (!merge_extra_args || first_extra_arg)
			variant_spec["argv"].append(std::string(arg));
		else
		{
			auto str = (variant_spec)["argv"][(variant_spec)["argv"].size() - 1].asCString();
			std::stringstream ss;
			ss << str << " " << arg;
			(variant_spec)["argv"][(variant_spec)["argv"].size() - 1] = ss.str();
		}
	}
}

/*-----------------------------------------------------------------------------
    process_opts
-----------------------------------------------------------------------------*/
bool mvee::process_opts(int argc, char** argv, bool add_args)
{
	int opt;
	bool stop = false;
	while ((opt = getopt(argc, argv, ":s:f:N:npocS:")) != -1 && !stop)
	{
		switch(opt)
		{
			case ':': // missing arg
				if (!strcmp(argv[optind+1], "--"))
				{
					stop = true;
					break;
				}
				else
				{
					usage();
					return false;
				}
			case 'S':
#ifndef SYNCTRACE_LIB
                printf("No SyncTrace support available! Install DynamoRIO.\n");
                usage();
                return false;
#else
				mvee::synctrace_logfile = std::string(optarg);
				mvee::numvariants = 1;
				(*mvee::config_variant_global)["disable_syscall_checks"] = true;
				break;
#endif
			case 's':
				mvee::config_variant_set = std::string(optarg);
				break;
			case 'o':
				(*mvee::config_monitor)["log_to_stdout"] = true;
				break;
			case 'N':
#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
                printf("shared memory logging option only available when running single variant, "
                       "-N should be omitted.\n");
                return false;
#else
                mvee::numvariants = strtoll(optarg, NULL, 10);
                break;
#endif
			case 'n':
				(*mvee::config_variant_global)["disable_syscall_checks"] = true;
				break;
			case 'p':
				(*mvee::config_variant_global)["performance_counting_enabled"] = true;
				break;
			case 'f': // we've already parsed the config file name
				break;
			case 'c':
				mvee::config_show = true;
				break;
			default:
				stop = true;
				break;				
		}
	}

	if (add_args)
	{
		bool first_extra_arg = true;

		for (int i = optind; i < argc; ++i)
		{			
			add_argv(argv[i], first_extra_arg);
			first_extra_arg = false;
		}
	}

	return true;
}

/*-----------------------------------------------------------------------------
    isnumeric
-----------------------------------------------------------------------------*/
static bool isnumeric(const char* str)
{
	while(*str)
	{
		char c = *str;
		if (c < '0' || c > '9')
			return false;
		str++;
	}
	return true;
}

/*-----------------------------------------------------------------------------
    Main - parse command line opts and launch monitor/variants
-----------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	bool legacy_mode = true;

    if (argc <= 2)
    {
		usage();
		return 0;
    }
    else
    {

#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
        mvee::numvariants = 1;
#endif

		mvee::os_check_ptrace_scope();
		mvee::os_check_kernel_cmdline();
		mvee::init_syslocks();
		
        int dash_pos, i = 1, builtin = 0;

		// Determine the mode we're launching in
        for (dash_pos = 0; dash_pos < argc; ++dash_pos)
        {
            if (!strcmp(argv[dash_pos], "--"))
            {
				legacy_mode = false;
                break;
            }
        }

		// look for -f first and initialize the config
		i = legacy_mode ? 2 : 1;
		for (; i < argc; ++i)
		{
			if (!strcmp(argv[i], "-f"))
			{
				if (i + 1 < argc)
					mvee::config_file_name = std::string(argv[i + 1]);
				else
					warnf("You must pass a filename after -f! Using MVEE.ini instead.\n");
				break;
			}
		}
	   
		// Use default MVEE.ini if needed
		if (mvee::config_file_name.size() == 0)
		{
			char path[1024];
			memset(path, 0, 1024);

			if (readlink("/proc/self/exe", path, 1024) > 0)
			{
				std::string str(path);
				if (str.rfind("/") != std::string::npos)
					mvee::config_file_name = str.substr(0, str.rfind("/") + 1) + "MVEE.ini";
				else
					mvee::config_file_name = "MVEE.ini";
			}
		}		

		// Initialize the config before processing further cmdline options
		mvee::init_config();
		mvee::os_get_orig_working_dir();
		mvee::os_get_mvee_root_dir();
		mvee::os_reset_envp();

        if (!legacy_mode)
        {
			// process all options before the --
			if (!mvee::process_opts(argc, argv, false))
				return -1;
			
			bool first_extra_arg = true;
#ifdef SYNCTRACE_LIB
			if (!mvee::synctrace_logfile.empty())
			{
				mvee::add_argv(DYNAMORIO_DIR "/bin64/drrun", true);
				mvee::add_argv("-c", false);
				mvee::add_argv(SYNCTRACE_LIB, false);
				mvee::add_argv("--log_file", false);
				mvee::add_argv(mvee::synctrace_logfile.c_str(), false);
				mvee::add_argv("--", false);
				first_extra_arg = false;
			}
#endif
			// Process everything after the "--" as program arguments
            for (i = dash_pos + 1; i < argc; ++i)
			{
				mvee::add_argv(argv[i], first_extra_arg);
				first_extra_arg = false;
			}
        }
        else
        {
			if (!isnumeric(argv[1]))
			{
				usage();
				return -1;
			}

			// discard any conflicting args we may have read from the config
			mvee::config["variant"]["sets"].clear();
			mvee::config["variant"]["specs"].clear();
			if (!(*mvee::config_variant_exec)["path"].isNull() &&
				(*mvee::config_variant_exec)["path"].isArray()) // it shouldn't be, but who knows...
				(*mvee::config_variant_exec)["path"];
			if (!(*mvee::config_variant_exec)["argv"].isNull() &&
				(*mvee::config_variant_exec)["argv"].isArray())
				(*mvee::config_variant_exec)["argv"].clear();
			if (!(*mvee::config_variant_exec)["env"].isNull() &&
				(*mvee::config_variant_exec)["env"].isArray())
				(*mvee::config_variant_exec)["env"].clear();
			
			builtin = atoi(argv[1]);

			// Pretend that argv[1] is the new argv[0]
			if (!mvee::process_opts(argc - 1, &argv[1], true))
				return -1;

			mvee::set_builtin_config(builtin);
        }
    }

	// select variants
	if (!legacy_mode)
	{
		if (!mvee::config["variant"]["sets"][mvee::config_variant_set])
		{
			printf("Couldn't find variant set %s\n", mvee::config_variant_set.c_str());
			return -1;
		}

		int limit = mvee::numvariants ? mvee::numvariants : mvee::config["variant"]["sets"][mvee::config_variant_set].size(), i = 0;
		auto it = mvee::config["variant"]["sets"][mvee::config_variant_set].begin();
		for (; i < limit; ++i)
		{
			if (it == mvee::config["variant"]["sets"][mvee::config_variant_set].end())
				it = mvee::config["variant"]["sets"][mvee::config_variant_set].begin();

			if (it == mvee::config["variant"]["sets"][mvee::config_variant_set].end())
				break;

			auto variant = *it;

			// check if a variant.specs config exists for the specified variant
			if (!mvee::config["variant"]["specs"][variant.asString()])
			{
				printf("Couldn't find config for variant %s in set %s\n",
					   variant.asString().c_str(), mvee::config_variant_set.c_str());
				return -1;
			}
			mvee::variant_ids.push_back(variant.asString());

			it++;
		}

		mvee::numvariants = mvee::variant_ids.size();
	}
	else
	{
		// initialize variant ids
		if (mvee::numvariants != 0)
		{
			mvee::variant_ids.resize(mvee::numvariants);
			std::fill(mvee::variant_ids.begin(), mvee::variant_ids.end(), "null");
		}
	}

	if (mvee::numvariants <= 0)
	{
		printf("Can't run GHUMVEE with %d variants!\n", mvee::numvariants);
		usage();
		return -1;
	}

#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
	if (mvee::numvariants != 1)
    {
	    printf("to run instruction tracing it is required to run only 1 variant.\n");
	    usage();
        return -1;
    }
#endif

	// Everything is set up so we can initialize the alias maps now
	mvee::init_aliases();
	
	if (mvee::config_show)
	{
		Json::StyledWriter writer;
		std::cout << "Using config: " << writer.write(mvee::config) << "\n";
	}

    if ((*mvee::config_variant_global)["disable_syscall_checks"].asBool())
        mvee::start_unmonitored();
    else
        mvee::start_monitored();

    return 0;
}

#ifdef MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
// =====================================================================================================================
// static init
// =====================================================================================================================
pthread_mutex_t mvee::tracing_lock           = PTHREAD_MUTEX_INITIALIZER;
tracing_data_t* mvee::instruction_log_result = nullptr;
tracing_lost_t* mvee::instruction_log_lost   = nullptr;
FILE*           mvee::instruction_log        = nullptr;

void            mvee::tracing_cleanup                 ()
{
    tracing_data_t* temp_data;
    tracing_data_t::prefixes_t* data_prefixes;
    tracing_data_t::prefixes_t* temp_data_prefixes;
    tracing_data_t::modrm_t* data_modrm;
    tracing_data_t::modrm_t* temp_data_modrm;
    tracing_data_t::immediate_t* data_immediate;
    tracing_data_t::immediate_t* temp_data_immediate;
    tracing_data_t::files_t* data_files;
    tracing_data_t::files_t* temp_data_files;

    while (instruction_log_result)
    {
        data_prefixes = instruction_log_result->prefixes.next;
        while (data_prefixes) {
            temp_data_prefixes = data_prefixes;
            data_prefixes = data_prefixes->next;
            free(temp_data_prefixes);
        }

        data_modrm = instruction_log_result->modrm.next;
        while (data_modrm) {
            temp_data_modrm = data_modrm;
            data_modrm = data_modrm->next;
            free(temp_data_modrm);
        }

        data_immediate = instruction_log_result->immediate.next;
        while (data_immediate) {
            temp_data_immediate = data_immediate;
            data_immediate = data_immediate->next;
            free(temp_data_immediate);
        }

        data_files = instruction_log_result->files_accessed.next;
        while (data_files) {
            temp_data_files = data_files;
            data_files = data_files->next;
            free(temp_data_files);
        }


        temp_data = instruction_log_result;
        instruction_log_result = instruction_log_result->next;
        free(temp_data);
    }


    tracing_lost_t* temp_lost;
    tracing_lost_t::files_t* lost_files;
    tracing_lost_t::files_t* temp_lost_files;

    while (instruction_log_lost)
    {
        lost_files = instruction_log_lost->files_accessed.next;
        while (lost_files) {
            temp_lost_files = lost_files;
            lost_files = lost_files->next;
            free(temp_lost_files);
        }


        temp_lost = instruction_log_lost;
        instruction_log_lost = instruction_log_lost->next;
        free(temp_lost);
    }

    instruction_log_result = nullptr;
    instruction_log_lost = nullptr;
}
#endif