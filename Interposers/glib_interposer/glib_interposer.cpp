/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <glib.h>
//#include <gtypes.h>
//#include <goption.h>
#include <stdio.h>
#include "glib_interposer.h"

/*-----------------------------------------------------------------------------
    write_glib_guint_operation
-----------------------------------------------------------------------------*/
void write_glib_guint_operation(int pos, guint result)
{
    *(volatile guint*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = result;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    write_glib_gint_operation
-----------------------------------------------------------------------------*/
void write_glib_gint_operation(int pos, gint result)
{
    *(volatile gint*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = result;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    write_glib_gboolean_operation
-----------------------------------------------------------------------------*/
void write_glib_gboolean_operation(int pos, gboolean result)
{
    *(volatile gboolean*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = result;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    is_mythread_glib_operation
-----------------------------------------------------------------------------*/
int is_mythread_glib_operation(int pos)
{
    volatile int op = *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos);
    return op == masterthread_id;
}

/*-----------------------------------------------------------------------------
    read_glib_guint_operation
-----------------------------------------------------------------------------*/
void read_glib_guint_operation(int pos, guint* result)
{
    volatile guint op = *(volatile guint*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
    *result = op;
}

/*-----------------------------------------------------------------------------
    read_glib_gint_operation
-----------------------------------------------------------------------------*/
void read_glib_gint_operation(int pos, gint* result)
{
    volatile gint op = *(volatile gint*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
    *result = op;
}

/*-----------------------------------------------------------------------------
    read_glib_gboolean_operation
-----------------------------------------------------------------------------*/
void read_glib_gboolean_operation(int pos, gboolean* result)
{
    volatile gboolean op = *(volatile gboolean*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
    *result = op;
}

/*-----------------------------------------------------------------------------
    g_direct_hash
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(guint, g_direct_hash, (gconstpointer v))
{
//  printf("g_direct_hash\n");
  DO_SYNC(guint, g_direct_hash, __g_direct_hash, (v), MVEE_GLIB_HASH_BUFFER, 2*sizeof(int), write_glib_guint_operation, read_glib_guint_operation, is_mythread_glib_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    g_signal_key_cmp - patch required in gsignal.c
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(gint, g_signal_key_cmp, (gconstpointer node1, gconstpointer node2))
{
  DO_SYNC(gint, g_signal_key_cmp, __g_signal_key_cmp, (node1, node2), MVEE_GLIB_HASH_BUFFER, 2*sizeof(int), write_glib_gint_operation, read_glib_gint_operation, is_mythread_glib_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    g_instance_real_class_cmp - patch required in gtype.c
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(gint, g_instance_real_class_cmp, (gconstpointer p1, gconstpointer p2))
{
  DO_SYNC(gint, g_instance_real_class_cmp, __g_instance_real_class_cmp, (p1, p2), MVEE_GLIB_HASH_BUFFER, 2*sizeof(int), write_glib_gint_operation, read_glib_gint_operation, is_mythread_glib_operation, 0, 0, 1, 1, 2 );
    return result;
}

/*-----------------------------------------------------------------------------
    transform_entries_cmp - patch required in gvalue.c
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(gint, g_transform_entries_cmp, (gconstpointer bsearch_node1, gconstpointer bsearch_node2))
{
  DO_SYNC(gint, g_transform_entries_cmp, __g_transform_entries_cmp, (bsearch_node1, bsearch_node2), MVEE_GLIB_HASH_BUFFER, 2*sizeof(int), write_glib_gint_operation, read_glib_gint_operation, is_mythread_glib_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    class_closures_cmp - patch required in gsignal.c
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(gint, g_class_closures_cmp, (gconstpointer node1, gconstpointer node2))
{
  DO_SYNC(gint, g_class_closures_cmp, __g_class_closures_cmp, (node1, node2), MVEE_GLIB_HASH_BUFFER, 2*sizeof(int), write_glib_gint_operation, read_glib_gint_operation, is_mythread_glib_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    g_direct_equal
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(gboolean, g_direct_equal, (gconstpointer v1, gconstpointer v2))
{
  DO_SYNC(gboolean, g_direct_equal, __g_direct_equal, (v1, v2), MVEE_GLIB_HASH_BUFFER, 2*sizeof(int), write_glib_gboolean_operation, read_glib_gboolean_operation, is_mythread_glib_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    g_param_spec_pool_hash - patch required in gparam.c
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(guint, g_param_spec_pool_hash, (gconstpointer key_spec))
{
  //printf("g_param_spec_pool_hash\n");
  DO_SYNC(guint, g_param_spec_pool_hash, __g_param_spec_pool_hash, (key_spec), MVEE_GLIB_HASH_BUFFER, 2*sizeof(int), write_glib_guint_operation, read_glib_guint_operation, is_mythread_glib_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    g_param_spec_pool_equals - patch required in gparam.c
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(gboolean, g_param_spec_pool_equals, (gconstpointer key_spec_1, gconstpointer key_spec_2))
{
  //printf("g_param_spec_pool_equals\n");
  DO_SYNC(gboolean, g_param_spec_pool_equals, __g_param_spec_pool_equals, (key_spec_1, key_spec_2), MVEE_GLIB_HASH_BUFFER, 2*sizeof(int), write_glib_gboolean_operation, read_glib_gboolean_operation, is_mythread_glib_operation, 0, 0, 1, 1, 2);
    return result;
}

/*-----------------------------------------------------------------------------
    glib_interposer_init
-----------------------------------------------------------------------------*/
static void __attribute((constructor)) init()
{
    printf("Registering GLIB2.0 hooks...\n");

    INTERPOSER_DETOUR_HOOK(*, g_direct_hash, 0);
    INTERPOSER_DETOUR_HOOK(*, g_direct_equal, 0);
    INTERPOSER_DETOUR_HOOK(*, g_signal_key_cmp, 0);
    INTERPOSER_DETOUR_HOOK(*, g_instance_real_class_cmp, 0);
    INTERPOSER_DETOUR_HOOK(*, g_transform_entries_cmp, 0);
    INTERPOSER_DETOUR_HOOK(*, g_class_closures_cmp, 0);
    INTERPOSER_DETOUR_HOOK(*, g_param_spec_pool_hash, 0);
    INTERPOSER_DETOUR_HOOK(*, g_param_spec_pool_equals, 0);
}
