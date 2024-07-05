/*
 * MVEE_erim_api_inlined.h
 * 
 * Provides interface for switching and initialization of ERIM to be
 * used directly in functions.
 *
 * Based on Anjo Vahldiek-Oberwagner's code from https://github.com/vahldiek/erim
 */

#ifndef MVEE_ERIM_API_INLINED_H_
#define MVEE_ERIM_API_INLINED_H_

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Debug prints
 */
#ifdef ERIM_DBG
  #define ERIM_DBM(...)				\
    do {					\
      fprintf(stderr, __VA_ARGS__);		\
      fprintf(stderr, "\n");			\
    } while(0)
#else // disable debug
   #define ERIM_DBM(...)
#endif

/*
 * Error prints
 */
#define ERIM_ERR(...)				\
    do {					\
      fprintf(stderr, __VA_ARGS__);		\
      fprintf(stderr, "\n");			\
    } while(0)
  
#include <stdint.h>
#include "MVEE_pkeys.h"

// TODO if we change anything here, we should also change and recompile the kernel
// TODO we need to change a bit the macros here if we want 3 domains (one for trusted code, one for untrusted and one for the in-process monitor)

#define ERIM_ISOLATED_DOMAIN 1

#define ERIM_PKRU_ISOTRS_UNTRUSTED_CI (0x5555555C)
#define ERIM_PKRU_ISOTRS_UNTRUSTED_IO (0x55555558)
#define ERIM_PKRU_ISOUTS_UNTRUSTED_CI (0x55555553)
#define ERIM_PKRU_ISOUTS_UNTRUSTED_IO (0x55555552)

#ifndef ERIM_ISOLATE_UNTRUSTED
  // trusted -> domain 1, untrusted -> domain 0
  #define ERIM_TRUSTED_DOMAIN 1
   #ifdef ERIM_INTEGRITY_ONLY
  // read(trusted) = allowed, write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOTRS_UNTRUSTED_IO
   #else
      // read(trusted) = write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOTRS_UNTRUSTED_CI
   #endif
#else
// trusted -> domain 0, untrusted -> domain 1
  #define ERIM_TRUSTED_DOMAIN 0
   #ifdef ERIM_INTEGRITY_ONLY
      // read(trusted) = allowed, write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOUTS_UNTRUSTED_IO
   #else
      // read(trusted) = write(trusted) = disallowed
      #define ERIM_UNTRUSTED_PKRU ERIM_PKRU_ISOUTS_UNTRUSTED_CI
   #endif
#endif

// PKRU when running trusted (access to both domain 0 and 1)
#define ERIM_TRUSTED_PKRU (0x55555550)

// Switching between isolated and application
#define erim_switch_to_trusted						\
  do {                                                                  \
    __wrpkru(ERIM_TRUSTED_PKRU);					\
    ERIM_DBM("pkru: %x", __rdpkru());					\
  } while(0)
  
#define erim_switch_to_untrusted					\
  do {                                                                  \
    __wrpkrucheck(ERIM_UNTRUSTED_PKRU);					\
    ERIM_DBM("pkru: %x", __rdpkru());					\
  } while(0)

#define uint8ptr(ptr) ((uint8_t *)ptr)
  
#define erim_isWRPKRU(ptr)				\
  ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0x01	\
   && uint8ptr(ptr)[2] == 0xef)?			\
  1 : 0)

#define erim_isXRSTOR(ptr) \
   ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0xae \
    && (uint8ptr(ptr)[2] & 0xC0) != 0xC0 \
    && (uint8ptr(ptr)[2] & 0x38) == 0x28) ? 1 : 0)
  
#ifdef __cplusplus
}
#endif
 
#endif
