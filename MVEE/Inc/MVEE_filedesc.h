/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
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
#include "MVEE_config.h"
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
    std::string                path;                  // For a filesystem file descriptor, the full path to the corresponding file
    unsigned long              access_flags;          // e.g. O_RDONLY
    bool                       master_file;           // if set to true, this file is only actually opened by the master child
    bool                       close_on_exec;         // fds are duplicated across forks but if O_CLOEXEC is set, they will be closed if the new fork executes execve
    bool                       unsynced_reads;        // if set to true, sys_read* calls from this fd are dispatched as normal calls rather than mastercalls
    ssize_t                    original_file_size;    // for shared mappings that we changed to private, we need to know the original file size!!!
	FileType                   file_type;

    void print_fd_info();
    fd_info();
    fd_info(FileType type, std::vector<unsigned long>& fds, std::string path, unsigned long access_flags, bool close_on_exec, bool master_file, bool unsynced_reads = false, ssize_t original_file_size = 0);
};

//
// File Descriptor Table. Since ALL file operations
// are synchronized, we only need one of these tables per set
// of equivalent childs.
//
class fd_table
{
public:
    std::string fd_cwd;                               // current working directory

    // We want the locking to go through these functions for debugging purposes
    void          grab_lock           ();
    void          release_lock        ();
    void          full_release_lock   ();

    // Creating/Deleting file descriptors
    void          create_fd_info      (FileType type, std::vector<unsigned long>& fds, std::string path, unsigned long access_flags, bool close_on_exec, bool master_file, bool unsynced_reads=false, ssize_t original_file_size=0);
    void          free_fd_info        (unsigned long fd);
    void          free_cloexec_fds    ();

    // Getters
    fd_info*      get_fd_info         (unsigned long fd, int childnum=0);
    fd_info*      get_fd_info_by_path (const char* path);
    std::string   get_full_path       (pid_t master_pid, unsigned long master_dirfd, void* master_path_ptr);
    unsigned long get_free_fd         (int childnum, unsigned long bias=(unsigned long)-1);

    bool          is_fd_unsynced      (unsigned long fd, int childnum=0);
    bool          is_fd_master_file   (unsigned long fd, int childnum=0);

    // Epoll support
    void          epoll_id_register   (unsigned long epfd, unsigned long fd, std::vector<unsigned long> ids);
    void          epoll_id_remove     (unsigned long epfd, unsigned long fd);
    std::vector<unsigned long>
                  epoll_id_map        (unsigned long epfd, unsigned long master_id);


    void          master_fd_set_to_non_master_fd_sets
        (fd_set *master_fd_set, int nfds, std::vector<fd_set>& child_fd_sets);

    //
    void          print_fd_table ();
    void          print_fd_table_proc(pid_t pid);
    bool          verify_path(std::string& mvee_path, const char* proc_path);
    void          verify_fd_table(std::vector<pid_t> pids);

    void          chdir (const char* path);

    // IP-MON file mapping
	_shm_info*    file_map_get();
	bool          file_map_exists();
	int           file_map_id();
	void          file_map_set(int fd, FileType type);

	void          set_blocking(int fd);
	void          set_non_blocking(int fd);

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

    //
    // This is a page sized sysv shared mem segment that can be mapped
    // into a variant's address space as a hidden buffer
    // It keeps track of file types
    //
	_shm_info* file_map;

    void init();
};

#endif /* MVEE_FILEDESC_H_ */
