
/*=============================================================================
    This shared library instruments all the usermode stat-related functions in
    glibc. When the stat struct buffer is passed uninitialized to a
    stat-related function and then sent to output, the padding in this struct
    stays initialized, which can cause mismatches in the MVEE.

    This library prevents that by intercepting the stat-related functions and
    filling the stat struct buffer with nullbytes before calling the original
    stat function.

    This library also cancels out glibc's setuid et al functions, because these
    functions send a signal to all threads of the current process. This causes
    deadlocks during multivariant execution of Firefox. As a workaround, the
    functions are cancelled out to prevent this.

    TODO: Block Read/Write mmap with backing file
=============================================================================*/

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#define _GNU_SOURCE 1
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <asm/unistd_32.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <errno.h>
#ifndef __set_errno
# define __set_errno(Val) errno = (Val)
#endif

#include <stdio.h>
#ifndef P_tmpdir
# define P_tmpdir "/tmp"
#endif
#ifndef TMP_MAX
# define TMP_MAX 238328
#endif
#ifndef __GT_FILE
# define __GT_FILE	0
# define __GT_DIR	1
# define __GT_NOCREATE	2
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/stat.h>
#if STAT_MACROS_BROKEN
# undef S_ISDIR
#endif
#if !defined S_ISDIR && defined S_IFDIR
# define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif
#if !S_IRUSR && S_IREAD
# define S_IRUSR S_IREAD
#endif
#if !S_IRUSR
# define S_IRUSR 00400
#endif
#if !S_IWUSR && S_IWRITE
# define S_IWUSR S_IWRITE
#endif
#if !S_IWUSR
# define S_IWUSR 00200
#endif
#if !S_IXUSR && S_IEXEC
# define S_IXUSR S_IEXEC
#endif
#if !S_IXUSR
# define S_IXUSR 00100
#endif

#if ! (HAVE___SECURE_GETENV || _LIBC)
# define __secure_getenv getenv
#endif

#  define RANDOM_BITS(Var) 					\
  if (value == 0)			      			\
    {							      	\
      struct timeval tv;					\
      __gettimeofday (&tv, NULL);				\
      value = ((uint64_t) tv.tv_usec << 16) ^ tv.tv_sec;	\
    }								\
  __asm__ __volatile__ ("rdtsc" : "=A" (Var));			\

/*int putenv(char* string)
{
  static int (*orig_putenv)(char*) = NULL;
  if (!orig_putenv)
    orig_putenv = dlsym(RTLD_NEXT, "putenv");
  printf("PUTENV => %s\n", string);
  return orig_putenv(string);
  }*/

/*-----------------------------------------------------------------------------
    mmap
-----------------------------------------------------------------------------*/
/*void *mmap(void *addr, size_t length, int prot, int flags,
	   int fd, off_t offset)
{

}*/

/*-----------------------------------------------------------------------------
    mmap64
-----------------------------------------------------------------------------*/




/*static void* (*orig_malloc)(size_t) = NULL;

void* malloc(size_t size)
{
  if (!orig_malloc)
    orig_malloc = (void* (*)(size_t))dlsym(RTLD_NEXT, "malloc");
  printf("malloc: %d\n", size);
  return orig_malloc(size);
  }*/

/*-----------------------------------------------------------------------------
    shmget
-----------------------------------------------------------------------------*/
/*int shmget(key_t key, size_t size, int shmflg)
{
	errno = EPERM;
	return -1;
	}*/

/*-----------------------------------------------------------------------------
    These need to be interposed. __getpid seems to know the real pid without
    executing sys_getpid. Need to figure this out sometime...
-----------------------------------------------------------------------------*/
static int pid = 0;

int getpid()
{
    if (!pid)
        pid = syscall(__NR_getpid);
    return pid;
}

int __getpid()
{
    return getpid();
}

/*-----------------------------------------------------------------------------
    ZERO_BUF_FUNCTION - Traps a usermode functions and fills the argbuf argument
    with nullbytes before calling the original function.
-----------------------------------------------------------------------------*/
#define ZERO_BUF_FUNCTION(funcname, type, fullargs, argtypes, argnames, argbuf)\
type funcname fullargs\
{\
    static type (*orig_##funcname) argtypes;\
    if (!orig_##funcname)\
        orig_##funcname = (type (*)argtypes)dlsym(RTLD_NEXT, #funcname);\
    memset(argbuf, 0, sizeof(*argbuf));\
    return orig_##funcname argnames;\
}

/*-----------------------------------------------------------------------------
    Function definitions
-----------------------------------------------------------------------------*/
ZERO_BUF_FUNCTION(__xstat, int,
                  (int vers, const char *name, struct stat *buf),
                  (int, const char*, struct stat*),
                  (vers, name, buf),
                  buf);
ZERO_BUF_FUNCTION(__lxstat, int,
                  (int vers, const char *name, struct stat *buf),
                  (int, const char*, struct stat*),
                  (vers, name, buf),
                  buf);
ZERO_BUF_FUNCTION(__fxstat, int,
                  (int vers, int fd, struct stat *buf),
                  (int, int, struct stat*),
                  (vers, fd, buf),
                  buf);
ZERO_BUF_FUNCTION(__fxstatat, int,
                  (int vers, int fd, const char *name, struct stat *buf, int flag),
                  (int, int, const char*, struct stat*, int),
                  (vers, fd, name, buf, flag),
                  buf);

/*-----------------------------------------------------------------------------
    ZERO_FUNCTION - Effectively cancels out a usermode function, by doing
    nothing but returning 0 (without calling the original function).
-----------------------------------------------------------------------------*/
#define ZERO_FUNCTION(funcname, fullargs)\
int funcname fullargs\
{\
    return 0;\
}

/*-----------------------------------------------------------------------------
    Function definitions
-----------------------------------------------------------------------------*/
ZERO_FUNCTION(seteuid, (uid_t euid));
ZERO_FUNCTION(setegid, (gid_t egid));

ZERO_FUNCTION(setuid, (uid_t uid));
ZERO_FUNCTION(setgid, (gid_t gid));

ZERO_FUNCTION(setreuid, (uid_t ruid, uid_t euid));
ZERO_FUNCTION(setregid, (gid_t rgid, gid_t egid));

ZERO_FUNCTION(setresuid, (uid_t ruid, uid_t euid, uid_t suid));
ZERO_FUNCTION(setresgid, (gid_t rgid, gid_t egid, gid_t sgid));

/*-----------------------------------------------------------------------------
    path_search - stripped down version
-----------------------------------------------------------------------------*/
int ____path_search (char *tmpl, size_t tmpl_len, const char *dir, const char *pfx, int try_tmpdir)
{
  const char *d;
  size_t dlen, plen;

  if (!pfx || !pfx[0])
    {
      pfx = "file";
      plen = 4;
    }
  else
    {
      plen = strlen (pfx);
      if (plen > 5)
	plen = 5;
    }

  dir = "/tmp";

  dlen = strlen (dir);
  while (dlen > 1 && dir[dlen - 1] == '/')
    dlen--;			/* remove trailing slashes */

  /* check we have room for "${dir}/${pfx}XXXXXX\0" */
  if (tmpl_len < dlen + 1 + plen + 6 + 1)
    {
      __set_errno (EINVAL);
      return -1;
    }

  sprintf (tmpl, "%.*s/%.*sXXXXXX", (int) dlen, dir, (int) plen, pfx);
  return 0;
}

/*-----------------------------------------------------------------------------
    gen_tempname - the original implementation of gen_tempname does not 
    initialize value and (unintentionally) uses its non-initialized value as a 
    source of randomness.
-----------------------------------------------------------------------------*/
/* These are the characters used in temporary filenames.  */
static const char letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

int
____gen_tempname (char *tmpl, int suffixlen, int flags, int kind)
{
  int len;
  char *XXXXXX;
  static uint64_t value = 0;
  uint64_t random_time_bits;
  unsigned int count;
  int fd = -1;
  int save_errno = errno;
  struct stat64 st;

  /* A lower bound on the number of temporary files to attempt to
     generate.  The maximum total number of temporary file names that
     can exist for a given template is 62**6.  It should never be
     necessary to try all these combinations.  Instead if a reasonable
     number of names is tried (we define reasonable as 62**3) fail to
     give the system administrator the chance to remove the problems.  */
#define ATTEMPTS_MIN (62 * 62 * 62)

  /* The number of times to attempt to generate a temporary file.  To
     conform to POSIX, this must be no smaller than TMP_MAX.  */
#if ATTEMPTS_MIN < TMP_MAX
  unsigned int attempts = TMP_MAX;
#else
  unsigned int attempts = ATTEMPTS_MIN;
#endif

  len = strlen (tmpl);
  if (len < 6 + suffixlen || memcmp (&tmpl[len - 6 - suffixlen], "XXXXXX", 6))
    {
      __set_errno (EINVAL);
      return -1;
    }

  /* This is where the Xs start.  */
  XXXXXX = &tmpl[len - 6 - suffixlen];

  /* Get some more or less random data.  */
  RANDOM_BITS (random_time_bits);
  value += random_time_bits ^ __getpid ();

  for (count = 0; count < attempts; value += 7777, ++count)
    {
      uint64_t v = value;

      /* Fill in the random bits.  */
      XXXXXX[0] = letters[v % 62];
      v /= 62;
      XXXXXX[1] = letters[v % 62];
      v /= 62;
      XXXXXX[2] = letters[v % 62];
      v /= 62;
      XXXXXX[3] = letters[v % 62];
      v /= 62;
      XXXXXX[4] = letters[v % 62];
      v /= 62;
      XXXXXX[5] = letters[v % 62];

      switch (kind)
	{
	case __GT_FILE:
	  fd = __open (tmpl,
		       (flags & ~O_ACCMODE)
		       | O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	  break;

	case __GT_DIR:
	  fd = __mkdir (tmpl, S_IRUSR | S_IWUSR | S_IXUSR);
	  break;

	case __GT_NOCREATE:
	  /* This case is backward from the other three.  __gen_tempname
	     succeeds if __xstat fails because the name does not exist.
	     Note the continue to bypass the common logic at the bottom
	     of the loop.  */
	  if (__lxstat64 (_STAT_VER, tmpl, &st) < 0)
	    {
	      if (errno == ENOENT)
		{
		  __set_errno (save_errno);
		  return 0;
		}
	      else
		/* Give up now. */
		return -1;
	    }
	  continue;

	default:
	  assert (! "invalid KIND in __gen_tempname");
	}

      if (fd >= 0)
	{
	  __set_errno (save_errno);
	  return fd;
	}
      else if (errno != EEXIST)
	return -1;
    }

  /* We got out of the loop because we ran out of combinations to try.  */
  __set_errno (EEXIST);
  return -1;
}

/*-----------------------------------------------------------------------------
    tmpnam - one of the functions that calls __gen_tempname. We have to
    interpose this because __gen_tempname is not exported
-----------------------------------------------------------------------------*/
static char tmpnam_buffer[L_tmpnam];

char *
tmpnam (char *s)
{
  /* By using two buffers we manage to be thread safe in the case
     where S != NULL.  */
  char tmpbufmem[L_tmpnam];
  char *tmpbuf = s ?: tmpbufmem;

  /* In the following call we use the buffer pointed to by S if
     non-NULL although we don't know the size.  But we limit the size
     to L_tmpnam characters in any case.  */
  if (____path_search (tmpbuf, L_tmpnam, NULL, NULL, 0))
    return NULL;

  if (____gen_tempname (tmpbuf, 0, 0, __GT_NOCREATE))
    return NULL;

  if (s == NULL)
    return (char *) memcpy (tmpnam_buffer, tmpbuf, L_tmpnam);

  return s;
}

/*-----------------------------------------------------------------------------
    tmpnam_r - see tmpnam
-----------------------------------------------------------------------------*/
char *
tmpnam_r (char *s)
{
  if (s == NULL)
    return NULL;

  if (____path_search (s, L_tmpnam, NULL, NULL, 0))
    return NULL;
  if (____gen_tempname (s, 0, 0, __GT_NOCREATE))
    return NULL;

  return s;
}

/*-----------------------------------------------------------------------------
    tempnam - see tmpnam
-----------------------------------------------------------------------------*/
char *
tempnam (const char *dir, const char *pfx)
{
  char buf[FILENAME_MAX];

  if (____path_search (buf, FILENAME_MAX, dir, pfx, 1))
    return NULL;

  if (____gen_tempname (buf, 0, 0, __GT_NOCREATE))
    return NULL;

  return __strdup (buf);
}

/*-----------------------------------------------------------------------------
    tmpfile - see tmpnam
-----------------------------------------------------------------------------*/
FILE *
tmpfile (void)
{
  char buf[FILENAME_MAX];
  int fd;
  FILE *f;

  if (____path_search (buf, FILENAME_MAX, NULL, "tmpf", 0))
    return NULL;
  int flags = 0;
#ifdef FLAGS
  flags = FLAGS;
#endif
  fd = ____gen_tempname (buf, 0, flags, __GT_FILE);
  if (fd < 0)
    return NULL;

  /* Note that this relies on the Unix semantics that
     a file is not really removed until it is closed.  */
  (void) unlink (buf);

  if ((f = fdopen (fd, "w+b")) == NULL)
    close (fd);

  return f;
}

/*-----------------------------------------------------------------------------
    mkstemp - see tmpnam
-----------------------------------------------------------------------------*/
int
mkstemp (template)
     char *template;
{
  return ____gen_tempname (template, 0, 0, __GT_FILE);
}

/*-----------------------------------------------------------------------------
    mkostemps - see tmpnam
-----------------------------------------------------------------------------*/
int
mkostemps (template, suffixlen, flags)
     char *template;
     int suffixlen;
     int flags;
{
  if (suffixlen < 0)
    {
      __set_errno (EINVAL);
      return -1;
    }

  return ____gen_tempname (template, suffixlen, flags, __GT_FILE);
}

/*-----------------------------------------------------------------------------
    mkostemp - see tmpnam
-----------------------------------------------------------------------------*/
int
mkostemp (template, flags)
     char *template;
     int flags;
{
  return ____gen_tempname (template, 0, flags, __GT_FILE);
}


/*-----------------------------------------------------------------------------
    mkostemps64 - see tmpnam
-----------------------------------------------------------------------------*/
int
mkostemps64 (template, suffixlen, flags)
     char *template;
     int suffixlen;
     int flags;
{
  if (suffixlen < 0)
    {
      __set_errno (EINVAL);
      return -1;
    }

  return ____gen_tempname (template, suffixlen, flags | O_LARGEFILE, __GT_FILE);
}

/*-----------------------------------------------------------------------------
    mkostemp64 - see tmpnam
-----------------------------------------------------------------------------*/
int
mkostemp64 (template, flags)
     char *template;
     int flags;
{
  return ____gen_tempname (template, 0, flags | O_LARGEFILE, __GT_FILE);
}

/*-----------------------------------------------------------------------------
    mkstemp64 - see tmpnam
-----------------------------------------------------------------------------*/
int
mkstemp64 (template)
     char *template;
{
  return ____gen_tempname (template, 0, O_LARGEFILE, __GT_FILE);
}

/*-----------------------------------------------------------------------------
    mkstemps64 - see tmpnam
-----------------------------------------------------------------------------*/
int
mkstemps64 (template, suffixlen)
     char *template;
     int suffixlen;
{
  if (suffixlen < 0)
    {
      __set_errno (EINVAL);
      return -1;
    }

  return ____gen_tempname (template, suffixlen, O_LARGEFILE, __GT_FILE);
}

/*-----------------------------------------------------------------------------
    mkstemps - see tmpnam
-----------------------------------------------------------------------------*/
int
mkstemps (template, suffixlen)
     char *template;
     int suffixlen;
{
  if (suffixlen < 0)
    {
      __set_errno (EINVAL);
      return -1;
    }

  return ____gen_tempname (template, suffixlen, 0, __GT_FILE);
}

/*-----------------------------------------------------------------------------
    mkdtemp - see tmpnam
-----------------------------------------------------------------------------*/
char *
mkdtemp (template)
     char *template;
{
  if (____gen_tempname (template, 0, 0, __GT_DIR))
    return NULL;
  else
    return template;
}

/*-----------------------------------------------------------------------------
    mktemp - see tmpnam
-----------------------------------------------------------------------------*/
char *
mktemp (template)
     char *template;
{
  if (____gen_tempname (template, 0, 0, __GT_NOCREATE) < 0)
    /* We return the null string if we can't find a unique file name.  */
    template[0] = '\0';

  return template;
}
