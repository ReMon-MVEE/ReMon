/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_FILEDESC_H_
#define MVEE_FILEDESC_H_

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <vector>
#include <string>
#include <map>
#include <pthread.h>
#include "MVEE_build_config.h"
#include "MVEE_shm.h"

/*-----------------------------------------------------------------------------
    Constants
-----------------------------------------------------------------------------*/
#define MVEE_UNKNOWN_FD   ((unsigned int)-1)
#define MVEE_ANONYMOUS_FD ((unsigned int)-2)
#define MVEE_DELETE_FD    ((unsigned int)-3)
#define MVEE_BLOCKING_FD  (16)

enum FileType
{
	FT_UNKNOWN = 0,
	FT_REGULAR = 1,
	FT_PIPE_NON_BLOCKING = 2,
	FT_SOCKET_NON_BLOCKING = 3,
	FT_POLL_NON_BLOCKING = 4,
	FT_SPECIAL = 5,

	FT_PIPE_BLOCKING = 18,    // 16 | 2
	FT_SOCKET_BLOCKING = 19,  // 16 | 3
	FT_POLL_BLOCKING = 20,    // 16 | 4
};

/*-----------------------------------------------------------------------------
    Class Definitions
-----------------------------------------------------------------------------*/
//
// File Descriptor Info
// NOTE: The kernel uses unsigned ints to store fds internally
//
class fd_info
{
public:
    std::vector<unsigned long> fds;                   // file descriptor values in all variants - note: if master_file == true, these fds will be virtual fds for all slave variants
	std::vector<std::string>   paths;                 // For a filesystem file descriptor, the full path to the corresponding file
    unsigned long              access_flags;          // e.g. O_RDONLY
    bool                       master_file;           // if set to true, this file is only actually opened by the master variant
    bool                       close_on_exec;         // fds are duplicated across forks but if O_CLOEXEC is set, they will be closed if the new fork executes execve
    bool                       unsynced_access;       // if set to true, all file ops on this file are dispatched as NORMAL calls instead of mastercalls
	bool                       unlinked;              // set to true when the file has been unlinked from the file system
    ssize_t                    original_file_size;    // for shared mappings that we changed to private, we need to know the original file size!!!
	FileType                   file_type;

    void print_fd_info();
    fd_info();
    fd_info(
		FileType type, 
		std::vector<unsigned long>& fds, 
		std::vector<std::string>& path, 
		unsigned long access_flags, 
		bool close_on_exec, 
		bool master_file, 
		bool unsynced_access = false, 
		bool unlinked = false, 
		ssize_t original_file_size = 0);

	// 
	// get_path_string returns:
	// * "<path 0>" if the file is a master file or does not have the unsynced access flag set
	// * "[<path 0>, ..., <path N>]" if the file is not a master file and it does have the unsynced access flag set
	//
	std::string get_path_string();
};

//
// File Descriptor Table. File operations are generally synchronized. All
// variants therefore (try to) open the same files. Consequently, we can store
// file information in a map and use the master's fd as the key.
//
// File operations are NOT synchronized while fast forwarding to the program
// entry point, however. Thus, the variants might open different files.
// We store the information about files used during fast forwarding in the
// temporary_files vector.
//
class fd_table
{
public:
	//
    // Current working directory. 
	//
	std::vector<std::string> fd_cwds;

	//
    // Thread-safety: We want the locking to go through these functions for
    // debugging purposes
	// 
    void          grab_lock           ();
    void          release_lock        ();
    void          full_release_lock   ();
    bool          have_unlocked       ();

	//
    // Creating/Deleting file descriptors. These are the functions we use for
    // synchronized file operations.
	//
    void          create_fd_info      (
		FileType type, 
		std::vector<unsigned long>& fds, 
		std::vector<std::string>& path, 
		unsigned long access_flags,
		bool close_on_exec,
		bool master_file,
		bool unsynced_access=false,
		bool unlinked=false,
		ssize_t original_file_size=0);
	void          create_master_fd_info_from_proc (int fd, pid_t master_pid);
	std::map<unsigned long, fd_info>::iterator
                  free_fd_info        (unsigned long fd);
    void          free_cloexec_fds    ();

	//
	//
	//
	bool          should_open_in_all_variants (std::string& master_path, pid_t master_pid);

	//
	// Wipe the fd table and repopulate it using /proc/<pid>/fd
    //
    bool          add_missing_fds     (std::vector<pid_t> variant_pids);
	void          refresh_fd_table    (std::vector<pid_t> variant_pids);

    //
	// Temporary files management. These functions are used for unsynchronized
	// file operations that happen during fast forwarding
	// 
	void          create_temporary_fd_info (int variantnum, unsigned long fd, std::string path, unsigned long access_flags, bool close_on_exec, ssize_t original_file_size=0, FileType type=FT_REGULAR);
	void          free_temporary_fd_info   (int variantnum, unsigned long fd);
	void          flush_temporary_files    (int variantnum);
	void          dup_temporary_fd         (int variantnum, unsigned long oldfd, unsigned long newfd, bool close_on_exec);

	//
    // Getters. These are temporary file-aware. All of these functions
	// first search through the "regular" fd @table and will search
	// through the @temporary_files table if nothing is found.
	// 
    fd_info*      get_fd_info         (unsigned long fd, int variantnum=0);
    std::string   get_full_path       (int variantnum, pid_t variant_pid, unsigned long dirfd, void* path_ptr);
    unsigned long get_free_fd         (int variantnum, unsigned long bias=(unsigned long)-1);

    bool          is_fd_unsynced      (unsigned long fd, int variantnum=0);
    bool          is_fd_master_file   (unsigned long fd, int variantnum=0);

	//
    // Epoll support. We assume that sys_epoll_* calls are synchronized.
	// Thus, these functions are not temporary file-aware
	//
    void          epoll_id_register   (unsigned long epfd, unsigned long fd, std::vector<unsigned long> ids);
    void          epoll_id_remove     (unsigned long epfd, unsigned long fd);
    std::vector<unsigned long>
                  epoll_id_map        (unsigned long epfd, unsigned long master_id);

	//
	// Support for select-style syscalls
	// 
    void          master_fd_set_to_non_master_fd_sets
                                      (fd_set *master_fd_set, int nfds, std::vector<fd_set>& variant_fd_sets);

	//
	// Unlink support
	//
	void          set_fd_unlinked   (unsigned long fd, int variantnum=0);
	void          set_file_unlinked (const char* path);
	bool          is_fd_unlinked    (unsigned long fd, int variantnum=0);

	//
    // Debugging goodies
	//
    void          print_fd_table      ();
    void          print_fd_table_proc (pid_t pid);
    bool          verify_path         (std::string& mvee_path, const char* proc_path);
    void          verify_fd_table     (std::vector<pid_t> pids);

	//
	// Changes the current working directory. Supports relative @path names
	// 
    void          chdir               (int variantnum, const char* path);

	//
    // IP-MON file mapping. We assume that IP-MON is only used for synchronized
    // calls so these functions are not @temporary_files aware.
	//
	_shm_info*    file_map_get        ();
	bool          file_map_exists     ();
	int           file_map_id         ();
	void          file_map_set        (int fd, FileType type);
	void          set_blocking        (int fd);
	void          set_non_blocking    (int fd);

	//
    // Constructors/Destructors
	//
    fd_table();
    fd_table(const fd_table& parent);
	~fd_table();

private:
    pthread_mutex_t lock;
    std::map<unsigned long, fd_info>
                    table;                         // maps fds onto fd info, key = fd in the master variant

    std::map<unsigned long,
             std::map<unsigned long,
                      std::vector<unsigned long> > >
                    epoll_map;                     // maps epoll fd -> fd registered on the epoll fd -> ids for the registered fd

	std::vector<std::map<unsigned long, fd_info>>
                    temporary_files;               // temporary files tracked during fast forwarding

    //
    // This is a page sized sysv shared mem segment that can be mapped
    // into a variant's address space as a hidden buffer
    // It keeps track of file types
    //
	_shm_info* file_map;

    void init();
};

#endif /* MVEE_FILEDESC_H_ */
