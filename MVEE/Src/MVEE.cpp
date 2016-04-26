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
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <libconfig.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <libgen.h>
#include <stdarg.h>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_memory.h"
#include "MVEE_logging.h"
#include "MVEE_syscalls.h"
#include "MVEE_private_arch.h"
#include "MVEE_macros.h"

/*-----------------------------------------------------------------------------
    Static Member Initialization
-----------------------------------------------------------------------------*/
bool                                   mvee::no_monitoring  = false;
std::vector<std::string>               mvee::demo_args;
int                                    mvee::demo_num       = 0;
#ifdef MVEE_ALLOW_PERF
bool                                   mvee::use_perf       = false;
#endif
int                                    mvee::numvariants    = 0;
std::string                            mvee::custom_library_path;
struct mvee_config                     mvee::config         =
{
	0,                                      // use_ipmon
    1,                                      // hide_vdso
    1,                                      // intercept_tsc
    0,                                      // use_dcl
    0,                                      // allow_setaffinity
    0,                                      // use_system_libc
    0,                                      // use_system_libgomp
    0,                                      // use_system_libstdcpp
    0,                                      // use_system_libgfortran
    0,                                      // use_system_gnomelibs
    "",                                     // root_path
    "/patched_binaries/libc/",              // libc_path
    "/patched_binaries/libgomp/",           // libgomp_path
    "/patched_binaries/libstdc++/",         // libstdcpp_path
    "/patched_binaries/libgfortran/",       // libgfortran_path
    "/patched_binaries/gnomelibs/",         // gnomelibs_path
	"/ext/spec2006/",                       // spec2006_path
	"/ext/parsec-2.1/",                     // parsec2_path
	"/ext/parsec-3.0/",                     // parsec3_path
    NULL
};
unsigned int                           mvee::demo_schedule_type                  = 0;
bool                                   mvee::demo_has_many_threads               = false;
__thread monitor*                      mvee::active_monitor                      = NULL;
__thread int                           mvee::active_monitorid                    = 0;
int                                    mvee::shutdown_signal                     = 0;
std::map<unsigned long, unsigned char> mvee::syslocks_table;
#ifdef MVEE_GENERATE_EXTRA_STATS
__thread bool                          mvee::in_logging_handler                  = false;
#endif
pthread_mutex_t                        mvee::global_lock                         = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
pthread_cond_t                         mvee::global_cond                         = PTHREAD_COND_INITIALIZER;
std::map<std::string, std::weak_ptr<mmap_addr2line_proc> >
                                       mvee::addr2line_cache;
std::map<std::string, std::weak_ptr<dwarf_info> >
                                       mvee::dwarf_cache;
bool                                   mvee::should_garbage_collect              = false;
std::vector<monitor*>                  mvee::monitor_gclist;
std::map<pid_t, std::vector<pid_t> >   mvee::variant_pid_mapping;
std::map<int, monitor*>                mvee::monitor_id_mapping;
int                                    mvee::next_monitorid                      = 0;
std::vector<detachedvariant*>            mvee::detachlist;
std::string                            mvee::orig_working_dir;
std::string                            mvee::mvee_root_dir;
unsigned int                           mvee::stack_limit                         = 0;
int                                    mvee::num_cores                           = 0;
int                                    mvee::num_physical_cpus                   = 0;
pid_t                                  mvee::process_pid                         = 0;
__thread pid_t                         mvee::thread_pid                          = 0;
std::map<std::string, std::string>     mvee::interp_map;
std::vector<pid_t>                     mvee::shutdown_kill_list;
bool                                   mvee::shutdown_should_generate_backtraces = false;

FILE*                                  mvee::logfile                             = NULL;
FILE*                                  mvee::ptrace_logfile                      = NULL;
FILE*                                  mvee::datatransfer_logfile                = NULL;
FILE*                                  mvee::lockstats_logfile                   = NULL;
double                                 mvee::initialtime                         = 0.0;
pthread_mutex_t                        mvee::loglock                             = PTHREAD_MUTEX_INITIALIZER;
bool                                   mvee::print_to_stdout                     = false;
volatile unsigned long                 mvee::can_run                             = 0;

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
    return search_in_str.size() >= search_for_str.size() && search_in_str.rfind(search_for_str) == (search_in_str.size()-search_for_str.size());
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
    mvee_mon_prepare_argv - serializes the program arguments
-----------------------------------------------------------------------------*/
std::string mvee::prepare_argv()
{
    assert(mvee::demo_args.size() > 0);
    std::stringstream ss;

    for (unsigned i = 0; i < mvee::demo_args.size(); ++i)
    {
        if (i) ss << " ";
        ss << mvee::demo_args[i];
    }

    return ss.str();
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
    mvee_mman_dwarf_find_info - we store weak pointers in the dwarf cache so
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
    if (!mvee::config.mvee_root_path || strlen(mvee::config.mvee_root_path) == 0)
    {
        char        command[500];
        sprintf(command, "readlink -f /proc/%d/exe | sed 's/\\(.*\\)\\/.*/\\1\\/..\\/..\\/..\\//' | xargs readlink -f | tr -d '\\n'", getpid());

        std::string out = mvee::log_read_from_proc_pipe(command, NULL);

        if (out != "")
        {
            if (out.length() < 2)
            {
                warnf("root path does not make sense. the mvee is possibly running under valgrind/gdb\n");
                warnf("using /home/stijn/MVEE as the root dir instead\n");
                mvee::config.mvee_root_path = mvee::strdup("/home/stijn/MVEE");
            }
            else
            {
                mvee::config.mvee_root_path = mvee::strdup(out.c_str());
            }
        }
    }

    return std::string(mvee::config.mvee_root_path);
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
    std::string yama = mvee::log_read_from_proc_pipe("sysctl kernel.yama.ptrace_scope", NULL);

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
}

/*-----------------------------------------------------------------------------
    mvee_env_check_kernel_cmdline - if we're running on AMD64, we need
    vsyscall=native in the kernel commandline
-----------------------------------------------------------------------------*/
void mvee::os_check_kernel_cmdline()
{
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
    debugf("current kernel.shmmax = %d\n", shmmax);
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
    ss << mvee::config.mvee_root_path << MVEE_LD_LOADER_PATH << MVEE_LD_LOADER_NAME;
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
			warnf("Failed to attach to shared memory block! err = %d (%s)\n", errno, strerror(errno));
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
			unsigned long image_base = 0xFFFFFFFFFFFFFFFF;
			
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
			unsigned long image_base = 0x00000000FFFFFFFF;
			
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
		mvee::warnf("realpath = %s (errno: %s)\n", path, strerror(errno));
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
			return path;
		else
			return std::string("");
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
    open_signal_file - we open a file in tmp. An external
    process can write to this file to communicate with the monitor and request
    backtraces
-----------------------------------------------------------------------------*/
char* mvee::open_signal_file()
{
    char*       signal_file = NULL;

#if !defined(MVEE_BENCHMARK) || defined(MVEE_FORCE_ENABLE_BACKTRACING)
    int         fd          = open("/tmp/MVEE_signal_file.tmp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);

    if (fd == -1)
    {
        warnf("couldn't open signal file. Error = %d (%s)\n", errno, strerror(errno));
        return NULL;
    }

    const char* init_buf    = "000";
    int         numwritten  = write(fd, init_buf, 3);
    if (numwritten != 3)
    {
        warnf("couldn't write to signal file. Error = %d (%s)\n", errno, strerror(errno));
        return NULL;
    }
    signal_file = (char*)mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (signal_file == (char*)-1)
    {
        warnf("couldn't map signal file. Error = %d (%s)\n", errno, strerror(errno));
        return signal_file;
    }

    memset(signal_file, 48, 4096);
    close(fd);
#endif

    return signal_file;
}

/*-----------------------------------------------------------------------------
    request_shutdown -
-----------------------------------------------------------------------------*/
void mvee::request_shutdown(bool should_backtrace)
{
//	warnf("Shutdown requested - should backtrace: %d\n", should_backtrace);
    mvee::lock();
    mvee::shutdown_signal                     = SIGINT;
    mvee::shutdown_should_generate_backtraces = should_backtrace;
    mvee::unlock();
    pthread_cond_signal(&mvee::global_cond);
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
      warnf("monitor closing.\n");
      warnf("shutdown sig: %d (%s)\n", sig, getTextualSig(sig));
      warnf("should backtrace: %d\n",  should_backtrace);
    */

    /*
    retarded hack here. We have no way
    to unblock monitors that are waitpid'ing UNLESS we trigger an event that
    causes the waitpid to return

    => we send a SIGALRM to one of the variants
     */
    mvee::lock();
    for (std::map<int, monitor*>::iterator it
             = mvee::monitor_id_mapping.begin(); it != mvee::monitor_id_mapping.end(); ++it)
        it->second->signal_shutdown();
    mvee::unlock();

    // wait for all monitors to terminate
    while (1)
    {
        //        mvee::garbage_collect();
        mvee::lock();
        if (mvee::monitor_id_mapping.size() <= 0)
        {
            //            warnf("all monitors have unregistered. Closing!\n");
            mvee::unlock();
            break;
        }
        mvee::unlock();
        sched_yield();
    }

    printf("all monitors terminated\n");
    mvee::log_fini(true);

    mvee::lock();
    while (!mvee::shutdown_kill_list.empty())
    {
        //printf("killing proc: %d\n", mvee_shutdown_kill_list.back());
        kill(mvee::shutdown_kill_list.back(), SIGKILL);
        mvee::shutdown_kill_list.pop_back();
    }
    mvee::unlock();

    exit(0);
}

/*-----------------------------------------------------------------------------
    shutdown_add_to_kill_list -
-----------------------------------------------------------------------------*/
void mvee::shutdown_add_to_kill_list   (pid_t kill_pid)
{
    MutexLock lock(&mvee::global_lock);
    mvee::shutdown_kill_list.push_back(kill_pid);
}

/*-----------------------------------------------------------------------------
    garbage_collect -
-----------------------------------------------------------------------------*/
void mvee::garbage_collect()
{
    std::vector<monitor*> local_gclist;

    {   MutexLock lock(&mvee::global_lock);

        mvee::should_garbage_collect = false;

        // copy all dead monitors to a local gclist first and then clean
        // them up without locking the global state...
        while (mvee::monitor_gclist.size() > 0)
        {
            monitor* mon = mvee::monitor_gclist.back();
            local_gclist.push_back(mon);
            mvee::monitor_gclist.pop_back();
        }}

    while (local_gclist.size() > 0)
    {
        monitor* mon = local_gclist.back();

        if (mvee::shutdown_signal == 0)
            mon->join_thread();

        logf("garbage collected monitor: %d\n", mon->monitorid);
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
    for (std::map<int, monitor*>::iterator it
             = mvee::monitor_id_mapping.begin(); it != mvee::monitor_id_mapping.end(); ++it)
    {
        pid_t tgid;
        if ((tgid = it->second->get_mastertgid()) != prev_tgid)
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

    for (std::map<int, monitor*>::iterator it
             = mvee::monitor_id_mapping.begin(); it != mvee::monitor_id_mapping.end(); ++it)
	{
		int core = it->second->get_master_core();

		if (core != -1)
		{
			debugf("cores [%d, %d] are currently in use by monitor %d\n",
						core,
						core + mvee::numvariants - 1,
						it->second->monitorid);

			result.insert(core);

			if (it->first == mvee::active_monitorid - 1
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
    get_next_monitorid
-----------------------------------------------------------------------------*/
bool mvee::get_should_generate_backtraces()
{
    MutexLock lock(&mvee::global_lock);
    return mvee::shutdown_should_generate_backtraces;
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
    MutexLock                         lock(&mvee::global_lock);
    std::map<int, monitor*>::iterator it
        = mvee::monitor_id_mapping.find(monitorid);
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
//    std::vector<pid_t> pids = mon->getpids();

    {   MutexLock lock(&mvee::global_lock);
        mvee::monitor_id_mapping.insert(std::pair<int, monitor*>(mon->monitorid, mon)); }

    mon->signal_registration();
}

/*-----------------------------------------------------------------------------
    unregister_monitor
-----------------------------------------------------------------------------*/
void mvee::unregister_monitor(monitor* mon)
{
    std::map<int, monitor*>::iterator it;
    bool                              should_shutdown = false;

    {   MutexLock lock(&mvee::global_lock);
        it                           = monitor_id_mapping.find(mon->monitorid);
        if (it != monitor_id_mapping.end())
            monitor_id_mapping.erase(it);

        monitor_gclist.push_back(mon);

        if (mvee::monitor_id_mapping.size() <= 0)
            should_shutdown = true;

        mvee::should_garbage_collect = true;
        pthread_cond_signal(&mvee::global_cond);

        if (mon == mvee::active_monitor)
            mvee::active_monitor = NULL; }

    if (should_shutdown)
        mvee::request_shutdown(false);
}

/*-----------------------------------------------------------------------------
    mvee_config_to_config_t - stores the values from our own mvee_config
    struct into libconfig's config_t struct, which can then be written to a file
-----------------------------------------------------------------------------*/
config_setting_t* mvee::config_setting_lookup_or_create(config_t* config, const char* path, int type)
{
    config_setting_t* setting = ::config_lookup(config, path);
    if (!setting)
        setting = config_setting_add(config_root_setting(config), path, type);
    assert(setting);
    return setting;
}

void mvee::config_store_uchar (config_t* config, const char* path, unsigned char value)
{
    config_setting_set_int(mvee::config_setting_lookup_or_create(config, path, CONFIG_TYPE_INT), value);
}

void mvee::config_store_string (config_t* config, const char* path, const char* value)
{
    config_setting_set_string(mvee::config_setting_lookup_or_create(config, path, CONFIG_TYPE_STRING), value);
}

void mvee::config_store(unsigned char config_type, config_t* config, const char* path, void* value)
{
    switch(config_type)
    {
        case CONFIG_TYPE_STRING:
            mvee::config_store_string(config, path, *(const char**)value);
            break;
        case CONFIG_TYPE_NONE:
            mvee::config_store_uchar(config, path, *(unsigned char*)value);
            break;
    }
}

void mvee::mvee_config_to_config_t (config_t* config)
{
    mvee::config_store(CONFIG_TYPE_NONE,   config, "use_ipmon",              &mvee::config.mvee_use_ipmon);
    mvee::config_store(CONFIG_TYPE_NONE,   config, "hide_vdso",              &mvee::config.mvee_hide_vdso);
    mvee::config_store(CONFIG_TYPE_NONE,   config, "intercept_tsc",          &mvee::config.mvee_intercept_tsc);
    mvee::config_store(CONFIG_TYPE_NONE,   config, "use_dcl",                &mvee::config.mvee_use_dcl);
    mvee::config_store(CONFIG_TYPE_NONE,   config, "allow_setaffinity",      &mvee::config.mvee_allow_setaffinity);
    mvee::config_store(CONFIG_TYPE_NONE,   config, "use_system_libc",        &mvee::config.mvee_use_system_libc);
    mvee::config_store(CONFIG_TYPE_NONE,   config, "use_system_libgomp",     &mvee::config.mvee_use_system_libgomp);
    mvee::config_store(CONFIG_TYPE_NONE,   config, "use_system_libstdcpp",   &mvee::config.mvee_use_system_libstdcpp);
    mvee::config_store(CONFIG_TYPE_NONE,   config, "use_system_libgfortran", &mvee::config.mvee_use_system_libgfortran);
    mvee::config_store(CONFIG_TYPE_NONE,   config, "use_system_gnomelibs",   &mvee::config.mvee_use_system_gnomelibs);
    mvee::config_store(CONFIG_TYPE_STRING, config, "root_path",              &mvee::config.mvee_root_path);
    mvee::config_store(CONFIG_TYPE_STRING, config, "libc_path",              &mvee::config.mvee_libc_path);
    mvee::config_store(CONFIG_TYPE_STRING, config, "libgomp_path",           &mvee::config.mvee_libgomp_path);
    mvee::config_store(CONFIG_TYPE_STRING, config, "libstdcpp_path",         &mvee::config.mvee_libstdcpp_path);
    mvee::config_store(CONFIG_TYPE_STRING, config, "libgfortran_path",       &mvee::config.mvee_libgfortran_path);
    mvee::config_store(CONFIG_TYPE_STRING, config, "gnomelibs_path",         &mvee::config.mvee_gnomelibs_path);
    mvee::config_store(CONFIG_TYPE_STRING, config, "spec2006_path",          &mvee::config.mvee_spec2006_path);
    mvee::config_store(CONFIG_TYPE_STRING, config, "parsec2_path",           &mvee::config.mvee_parsec2_path);
    mvee::config_store(CONFIG_TYPE_STRING, config, "parsec3_path",           &mvee::config.mvee_parsec3_path);
}

/*-----------------------------------------------------------------------------
    config_t_to_mvee_config - loads the values from libconfig's config_t
    into our own mvee_config struct
-----------------------------------------------------------------------------*/
void mvee::config_lookup_uchar (config_t* config, const char* path, unsigned char* value)
{
    int tmp;
    if (config_lookup_int(config, path, &tmp) == CONFIG_TRUE)
        *value = tmp ? 1 : 0;
}

void mvee::config_lookup (unsigned char config_type, config_t* config, const char* path, void* value)
{
    switch(config_type)
    {
        case CONFIG_TYPE_STRING:
            config_lookup_string(config, path, (const char**)value);
            break;
        case CONFIG_TYPE_NONE:
            mvee::config_lookup_uchar(config, path, (unsigned char*)value);
            break;
    }
}

void mvee::config_t_to_mvee_config (config_t* config)
{
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "use_ipmon",              &mvee::config.mvee_use_ipmon);
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "hide_vdso",              &mvee::config.mvee_hide_vdso);
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "intercept_tsc",          &mvee::config.mvee_intercept_tsc);
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "use_dcl",                &mvee::config.mvee_use_dcl);
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "allow_setaffinity",      &mvee::config.mvee_allow_setaffinity);
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "use_system_libc",        &mvee::config.mvee_use_system_libc);
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "use_system_libgomp",     &mvee::config.mvee_use_system_libgomp);
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "use_system_libstdcpp",   &mvee::config.mvee_use_system_libstdcpp);
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "use_system_libgfortran", &mvee::config.mvee_use_system_libgfortran);
    mvee::config_lookup(CONFIG_TYPE_NONE,   config, "use_system_gnomelibs",   &mvee::config.mvee_use_system_gnomelibs);
    mvee::config_lookup(CONFIG_TYPE_STRING, config, "root_path",              &mvee::config.mvee_root_path);
    mvee::config_lookup(CONFIG_TYPE_STRING, config, "libc_path",              &mvee::config.mvee_libc_path);
    mvee::config_lookup(CONFIG_TYPE_STRING, config, "libgomp_path",           &mvee::config.mvee_libgomp_path);
    mvee::config_lookup(CONFIG_TYPE_STRING, config, "libstdcpp_path",         &mvee::config.mvee_libstdcpp_path);
    mvee::config_lookup(CONFIG_TYPE_STRING, config, "libgfortran_path",       &mvee::config.mvee_libgfortran_path);
    mvee::config_lookup(CONFIG_TYPE_STRING, config, "gnomelibs_path",         &mvee::config.mvee_gnomelibs_path);
    mvee::config_lookup(CONFIG_TYPE_STRING, config, "spec2006_path",          &mvee::config.mvee_spec2006_path);
    mvee::config_lookup(CONFIG_TYPE_STRING, config, "parsec2_path",           &mvee::config.mvee_parsec2_path);
    mvee::config_lookup(CONFIG_TYPE_STRING, config, "parsec3_path",           &mvee::config.mvee_parsec3_path);
}

/*-----------------------------------------------------------------------------
    init_config - reads MVEE.ini or initializes this file with default
    values if it doesn't exist yet.
-----------------------------------------------------------------------------*/
void mvee::init_config()
{
    if (mvee::config.config)
    {
        config_destroy(mvee::config.config);
        delete mvee::config.config;
    }

    mvee::config.config = new config_t;
    config_init(mvee::config.config);

    if (config_read_file(mvee::config.config, "MVEE.ini") != CONFIG_TRUE)
    {
        fprintf(stderr, "Couldn't read the MVEE config file (MVEE.ini) - we will try to write a new one!\n");

        mvee::mvee_config_to_config_t(mvee::config.config);
        if (config_write_file(mvee::config.config, "MVEE.ini") != CONFIG_TRUE)
            fprintf(stderr, "Couldn't write the MVEE config (MVEE.ini)\n");
        else
            fprintf(stderr, "Wrote the default MVEE config to MVEE.ini\n");
        return;
    }

    mvee::config_t_to_mvee_config(mvee::config.config);
}

/*-----------------------------------------------------------------------------
    process_opt
-----------------------------------------------------------------------------*/
void mvee::process_opt(char* opt)
{
    if (!strcasecmp(opt, "-s"))
        mvee::print_to_stdout = true;
    else if (!strcasecmp(opt, "-n"))
        mvee::no_monitoring = true;
#ifdef MVEE_ALLOW_PERF
    else if (!strcasecmp(opt, "-p"))
        mvee::use_perf = true;
#endif
    // all other arguments are passed to the demo
    else if (mvee::demo_num != -1)
        mvee::demo_args.push_back(std::string(opt));
}

/*-----------------------------------------------------------------------------
    add_library_path -
-----------------------------------------------------------------------------*/
void mvee::add_library_path(const char* library_path, bool append_arch_suffix, bool prepend_mvee_root)
{
    if (mvee::custom_library_path.size() > 0)
        mvee::custom_library_path += ":";

    if (prepend_mvee_root)
    {
        mvee::custom_library_path += mvee::config.mvee_root_path;
        mvee::custom_library_path += "/";
    }
    mvee::custom_library_path += library_path;
    if (append_arch_suffix)
    {
        mvee::custom_library_path += MVEE_ARCH_SUFFIX;
        mvee::custom_library_path += "/";
    }
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
        {
            mvee::shutdown_signal = sig;
            pthread_cond_signal(&mvee::global_cond);
        }
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
    start_variant_direct - We use this in MVEE_demos.cpp to start programs
	directly (i.e. without interpreting the startup command line using a shell
-----------------------------------------------------------------------------*/
void mvee::start_variant_direct(const char* binary, ...)
{
	std::deque<const char*> args;
	va_list va;
	const char* arg;

	args.push_back(binary);
	va_start(va, binary);
	do
	{
		arg = va_arg(va, const char*);
		args.push_back(arg);
	} while (arg);
	va_end(va);
	args.push_back(NULL);

	const char** _args = new const char*[args.size()];
	int i = 0;
	for (auto _arg : args)
		_args[i++] = _arg;

	// this should not return
	execv(binary, (char* const*)_args);

	printf("ERROR: Failed to start variant directly\n");
}

/*-----------------------------------------------------------------------------
    start_variant_indirect - This is called if the MVEE is invoked using:
	./MVEE <number of variants> -- <cmd>

	We pass the cmd to /bin/bash because it is really clever and knows how
	to interpret whatever the cmd is.
-----------------------------------------------------------------------------*/
void mvee::start_variant_indirect(const char* cmd)
{
	execl("/bin/bash", "bash", "-c", cmd, NULL);
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
    int                status;

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
        mvee::setup_env(mvee::demo_num, true);

		// raise SIGSTOP so the monitor process can attach before we exec
        kill(getpid(), SIGSTOP);

		// demo_num will be != 1 if we invoke the MVEE using ./MVEE <demo num> <number of variants>
        if (mvee::demo_num != -1)
            mvee::start_demo(mvee::demo_num, i, true);
        else
			mvee::start_variant_indirect(mvee::prepare_argv().c_str());
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
            int tmp = wait4(-1, &status, WUNTRACED, NULL);
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
            {
                kill(tmp, SIGCONT);

                for (i = 0; i < mvee::numvariants; ++i)
                    if (tmp == pids[i])
                        resumed[i] = 1;

                for (i = 0; i < mvee::numvariants; ++i)
                    if (!resumed[i])
                        break;

                if (i >= mvee::numvariants)
                    all_resumed = true;
            }
        }

        for (i = 0; i < mvee::numvariants; ++i)
            resumed[i] = 0;
        all_resumed = false;

        // Now wait for all variants to terminate...
        while (!all_terminated)
        {
            int tmp = wait4(-1, &status, WUNTRACED, NULL);
            if (WIFEXITED(status))
            {
                for (i = 0; i < mvee::numvariants; ++i)
                    if (tmp == pids[i])
                        terminated[i] = 1;

                for (i = 0; i < mvee::numvariants; ++i)
                    if (!terminated[i])
                        break;

                if (i >= mvee::numvariants)
                    all_terminated = true;
            }
            else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
            {
                for (i = 0; i < mvee::numvariants; ++i)
                    if (tmp == pids[i])
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
    int                i, res, status;
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
        mvee::set_demo_options(mvee::demo_num);

        // Install signal handlers for SIGINT and SIGQUIT so we can shut down safely after CTRL+C
        signal(SIGINT,  mvee_mon_external_termination_request);
        signal(SIGQUIT, mvee_mon_external_termination_request);

        for (int i = 0; i < mvee::numvariants; ++i)
        {
            res = wait4(procs[i], &status, 0, NULL);

            if (WIFSTOPPED(status) && res > 0)
                mvee_wrap_ptrace(PTRACE_DETACH, procs[i], 0, NULL);
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
        char*     signal_file = mvee::open_signal_file();
        while (true)
        {
            bool should_gc = false;

            mvee::lock();
            if (mvee::shutdown_signal)
            {
                if (signal_file && signal_file[0] == '1')
                    mvee::shutdown_should_generate_backtraces = true;
                mvee::unlock();
                mvee::shutdown(mvee::shutdown_signal,
                               mvee::shutdown_should_generate_backtraces ? 1 : 0);
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
        mvee::setup_env(mvee::demo_num, false);

        // We can disable the TSC right away
        // the tsc disable flag is inherited across forks, clones and execves...
        if (mvee::config.mvee_intercept_tsc)
            prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0);

#ifdef MVEE_TASKSWITCH_OVERHEAD_BENCHMARK
        cpu_set_t cpu;
        CPU_ZERO(&cpu);
        CPU_SET(i*2, &cpu);
        if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu))
            warnf("couldn't set affinity\n");
#endif


        // Place the new variant under supervision
        // Not that this does not stop the variant.
        // We will raise a SIGSTOP so the parent can set ptrace options
        // and can issue a PTRACE_SYSCALL request
        mvee_wrap_ptrace(PTRACE_TRACEME, 0, 0, NULL);

        // stop the process so we can detach from it
        raise(SIGSTOP);

        while (!mvee::can_run)
            ;

        if (mvee::demo_num != -1)
            mvee::start_demo(mvee::demo_num, i, false);
        else
			mvee::start_variant_indirect(mvee::prepare_argv().c_str());
    }
}

/*-----------------------------------------------------------------------------
    Main
-----------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    mvee::init_config();
    mvee::os_check_ptrace_scope();
    mvee::os_check_kernel_cmdline();
    mvee::os_get_orig_working_dir();
    mvee::os_get_mvee_root_dir();
    mvee::os_reset_envp();
    mvee::init_syslocks();

    //
    // Parse commandline options
    //
    if (argc <= 2)
    {
        printf("======================================================\n");
        printf("   Ghent University Computer Systems Lab MVEE v4.0    \n");
        printf("                 aka \"GHUMVEE\"                      \n");
        printf("======================================================\n");
        printf("> Syntax:\n\n");
        printf("> ./MVEE [Demonum] [Number of Variants] [MVEE Options]\n");
        printf("> OR\n");
        printf("> ./MVEE [Number of Variants] [MVEE Options] -- [Program] [Program Args]\n");
        printf("\n");
        printf("> MVEE Options:\n");
        printf("> -s : log to stdout. All logfile output is also printed to stdout.\n");
        printf("> -n : no monitoring. Variant processes are executed without supervision. Useful for benchmarking.\n");
#ifdef MVEE_ALLOW_PERF
        printf("> -p : use performance counters to track cache and synchronization behavior of the variants.\n");
#endif
        return 0;
    }
    else
    {
        int i = 1, j;

        mvee::demo_num = atoi(argv[1]);

        for (; i < argc; ++i)
        {
            if (!strcmp(argv[i], "--"))
            {
                mvee::numvariants = mvee::demo_num;
                mvee::demo_num    = -1;
                break;
            }
        }

        if (mvee::demo_num == -1)
        {
            for (j = 2; j < i; ++j)
                mvee::process_opt(argv[j]);
            for (i = i + 1; i < argc; ++i)
                mvee::demo_args.push_back(std::string(argv[i]));
        }
        else
        {
            mvee::numvariants = atoi(argv[2]);
            for (i = 3; i < argc; ++i)
                mvee::process_opt(argv[i]);
        }
    }

	if (mvee::numvariants <= 0)
	{
		printf("Can't run GHUMVEE with %d variants!\n", mvee::numvariants);
		return -1;
	}

    if (mvee::no_monitoring)
        mvee::start_unmonitored();
    else
        mvee::start_monitored();

    return 0;
}
