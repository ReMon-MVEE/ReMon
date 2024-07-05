/*
 * Based on Anjo Vahldiek-Oberwagner's code from https://github.com/vahldiek/erim
 */

#ifndef _MVEE_PKEYS_HELPER_H
#define _MVEE_PKEYS_HELPER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>


#define NR_PKEYS 16

/*
 * pkru intrinsics
 */

#define __rdpkru()                              \
  ({                                            \
    unsigned int eax, edx;                      \
    unsigned int ecx = 0;                       \
    unsigned int pkru;                          \
    asm volatile(".byte 0x0f,0x01,0xee\n\t"     \
                 : "=a" (eax), "=d" (edx)       \
                 : "c" (ecx));                  \
    pkru = eax;                                 \
    pkru;                                       \
  })

#if defined(__clang__)
#define __wrpkrucheck(PKRU_ARG)						\
  do {									\
    asm volatile ("1:\n\txor %%ecx, %%ecx\n\txor %%edx, %%edx\n\tmov %0,%%eax\n\t.byte 0x0f,0x01,0xef\n\tcmp %0, %%eax\n\tjne 1b\n\t" \
		  : : "n" (PKRU_ARG)					\
		  :"eax", "ecx", "edx");				\
  } while (0)
#define __wrpkrucheckmem(PKRU_ARG)					\
  do {									\
    asm volatile ("1:\n\txor %%ecx, %%ecx\n\txor %%edx, %%edx\n\tmov %0,%%eax\n\t.byte 0x0f,0x01,0xef\n\tcmp %0, %%eax\n\tjne 1b\n\t" \
		  : : "m" (PKRU_ARG)					\
		  :"eax", "ecx", "edx");				\
  } while (0)

#elif defined(__GNUC__) || defined(__GNUG__)
#define __wrpkrucheck(PKRU_ARG)						\
  do {									\
    __label__ erim_start;						\
  erim_start:								\
    asm goto ("xor %%ecx, %%ecx\n\txor %%edx, %%edx\n\tmov %0,%%eax\n\t.byte 0x0f,0x01,0xef\n\tcmp %0, %%eax\n\tjne %l1\n\t" \
	      : : "n" (PKRU_ARG)					\
	      :"eax", "ecx", "edx" : erim_start);			\
  } while (0)
#define __wrpkrucheckmem(PKRU_ARG)					\
  do {									\
    __label__ erim_start;						\
  erim_start:								\
    asm goto ("xor %%ecx, %%ecx\n\txor %%edx, %%edx\n\tmov %0,%%eax\n\t.byte 0x0f,0x01,0xef\n\tcmp %0, %%eax\n\tjne %l1\n\t" \
	      : : "m" (PKRU_ARG)			\
	      :"eax", "ecx", "edx" : erim_start);			\
  } while (0)
#else
#error "ERIM only supports clang or gcc"
#endif

#define __wrpkru(PKRU_ARG)			    \
  do {									\
    asm volatile ("xor %%ecx, %%ecx\n\txor %%edx, %%edx\n\tmov %0,%%eax\n\t.byte 0x0f,0x01,0xef\n\t" \
	      : : "n" (PKRU_ARG)					\
	      :"eax", "ecx", "edx");			\
  } while (0)

#define __wrpkrumem(PKRU_ARG)			    \
  do {									\
    asm volatile ("xor %%ecx, %%ecx\n\txor %%edx, %%edx\n\tmov %0,%%eax\n\t.byte 0x0f,0x01,0xef\n\t" \
	      : : "m" (PKRU_ARG)					\
	      :"eax", "ecx", "edx");			\
  } while (0)

/*
 * Function to check if machine has pku
 */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#endif /* _MVEE_PKEYS_HELPER_H */
