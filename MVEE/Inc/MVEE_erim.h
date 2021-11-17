/*
 * Based on Anjo Vahldiek-Oberwagner's code from https://github.com/vahldiek/erim
 * MVEE_erim.h
 *
 * Defines interface to isolate secrets using ERIM. Applications are
 * split into a trusted component (tc) and an untrusted application
 * (app). To transfer between the two compartments, one has to
 * explicitly call a switch. The interface offers ways to insert
 * these switches. Inlined provides the interface to inline the switches
 * using erim_switch_to_trusted and erim_switch_to_untrusted.
 *
 * Lifecycle of ERIMized Application:
 *   During compilation:
 *     - Insert where necessary switches between application and
 *       tc
 *     - Insert initialization code somewhere before application start
 *       -> e.g. via DL_PRELOAD
 *
 * Arguments to this header file:
 * ERIM_DBG -> 0, 1 (default 0)
 *  Adds print statements to switch calls and initialization code
 *
 * ERIM_INTEGRITY_ONLY -> defined, undefined (default undefined)
 *  If defined, assures that untrusted application may read the memory
 *  of the tc.
 *  If undefined, assures that the untrusted application may never
 *  read or write the tc.
 *  (providing confidentiality and integrity)
 *
 * ERIM_ISOLATE_UNTRUSTED -> defined, undefined (default undefined) 
 *  If defined, trusted runs in domain 0. (application runs in domain 1)
 *  If undefined, trusted runs in domain 1. (application runs in
 *  domain 0) Without changes everything runs in domain 0 including
 *  libc. When the tc needs to take control over libc, it also needs
 *  to run in domain 0. When the tc only protects a small and
 *  limited set of functions which do not require libc access
 *  (e.g. the cryptographic functions of OpenSSL), then the tc can
 *  run in domain 1 without changing the app.
 */

#ifndef MVEE_ERIM_H_
#define MVEE_ERIM_H_

#ifdef __cplusplus
extern "C"
{
#endif

//#define ERIM_DBG

/*
 * ERIM API (inlined)
 */
#include "MVEE_erim_api_inlined.h"

#define ERIM_FLAG_ISOLATE_TRUSTED    (1<<0)
#define ERIM_FLAG_ISOLATE_UNTRUSTED  (1<<1)
#define ERIM_FLAG_INTEGRITY_ONLY     (1<<2)

#define ERIM_TRUSTED_DOMAIN_ID(flag) ((flag & ERIM_FLAG_ISOLATE_TRUSTED) ? 1 : 0)

#ifdef __cplusplus
}
#endif

#endif /* MVEE_ERIM_H_ */
