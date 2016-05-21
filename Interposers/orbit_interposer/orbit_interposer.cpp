/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This shared library instruments usermode functions to which the libORBit
    library passes request IDs. Because these request IDs are generated from
    pointers, they can differ among the children and cause mismatches (see
    ORBit_small_invoke_stub and ORBit_small_invoke_async in
    src/orb/orb-core/orbit-small.c).

    When one of the instrumented functions is intercepted, the library passes
    the address to the request ID to the monitor and the monitor uses these
    addresses to give all non-master children the same request ID as the master
    child.

    // TODO: because the instrumented functions aren't exported as symbols in
    the release version of libORBit, a self-compiled version of libORBit is
    currently required. Ideally, this library should also use Detours
    for intercepting to prevent that requirement, just as is already done in the
    GTK interposer. One would probably first have to find a suitable libORBit
    initialization function to intercept though.
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
#include <errno.h>
#include <unistd.h>
#include <asm/unistd_32.h>
#include <orbit/util/basic_types.h>
#include "orbit_interposer.h"

/*-----------------------------------------------------------------------------
    write_orbit_operation
-----------------------------------------------------------------------------*/
void write_orbit_operation(int pos, CORBA_unsigned_long request_id)
{
    *(volatile CORBA_unsigned_long*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = request_id;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    is_mythread_orbit_operation
-----------------------------------------------------------------------------*/
bool is_mythread_orbit_operation(int pos)
{
    volatile int op = *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos);
    return op == masterthread_id;
}

/*-----------------------------------------------------------------------------
    read_orbit_operation
-----------------------------------------------------------------------------*/
void read_orbit_operation(int pos, CORBA_unsigned_long* result)
{
    CORBA_unsigned_long tmp = *(volatile CORBA_unsigned_long*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
    *result = tmp;
}

/*-----------------------------------------------------------------------------
    dummy
-----------------------------------------------------------------------------*/
CORBA_unsigned_long dummy(CORBA_unsigned_long request_id)
{
    return request_id;
}

/*-----------------------------------------------------------------------------
    Function definitions
-----------------------------------------------------------------------------*/

#define GIOP_RECV_LIST_SETUP_QUEUE_ENTRY_ARGTYPES   \
    (void*, void*, CORBA_unsigned_long, CORBA_unsigned_long)

extern "C" void giop_recv_list_setup_queue_entry (void *ent, void *cnx,
				  CORBA_unsigned_long    msg_type,
				  CORBA_unsigned_long    request_id)
{
    static void (*orig_giop_recv_list_setup_queue_entry) GIOP_RECV_LIST_SETUP_QUEUE_ENTRY_ARGTYPES;
    if (!orig_giop_recv_list_setup_queue_entry)
        orig_giop_recv_list_setup_queue_entry =
            (void (*)GIOP_RECV_LIST_SETUP_QUEUE_ENTRY_ARGTYPES)dlsym(RTLD_NEXT,
            "giop_recv_list_setup_queue_entry");

    DO_SYNC(CORBA_unsigned_long, giop_recv_list_setup_queue_entry, dummy, (request_id), MVEE_ORBIT_REQUEST_BUFFER, sizeof(int)*2, write_orbit_operation, read_orbit_operation, is_mythread_orbit_operation, 0, 0, 1, 0, 1, 2);
    orig_giop_recv_list_setup_queue_entry(ent, cnx, msg_type, result);
}

typedef enum {
  GIOP_1_0,
  GIOP_1_1,
  GIOP_1_2,
  GIOP_LATEST = GIOP_1_2,
  GIOP_NUM_VERSIONS
} GIOPVersion;

#define GIOP_SEND_BUFFER_USE_REQUEST_ARGTYPES   \
    (GIOPVersion, CORBA_unsigned_long, CORBA_boolean,   \
     const void*, const void*, const void*)

extern "C" void *giop_send_buffer_use_request (GIOPVersion giop_version,
			      CORBA_unsigned_long request_id,
			      CORBA_boolean response_expected,
			      const void *objkey,
			      const void *operation_vec,
			      const void *principal_vec)
{
    static void* (*orig_giop_send_buffer_use_request) GIOP_SEND_BUFFER_USE_REQUEST_ARGTYPES;
    if (!orig_giop_send_buffer_use_request)
        orig_giop_send_buffer_use_request =
            (void* (*)GIOP_SEND_BUFFER_USE_REQUEST_ARGTYPES)dlsym(RTLD_NEXT,
            "giop_send_buffer_use_request");
    DO_SYNC(CORBA_unsigned_long, giop_send_buffer_use_request, dummy, (request_id), MVEE_ORBIT_REQUEST_BUFFER, sizeof(int)*2, write_orbit_operation, read_orbit_operation, is_mythread_orbit_operation, 0, 0, 1, 0, 1, 2);
    return orig_giop_send_buffer_use_request(giop_version, result,
                                             response_expected, objkey,
                                             operation_vec, principal_vec);
}
