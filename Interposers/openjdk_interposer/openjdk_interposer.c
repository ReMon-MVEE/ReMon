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
#include <pthread.h>
#include <stdio.h>
#include "openjdk_interposer.h"
#include "jni.h"
#define STACK_DEPTH 1
#define USE_EIP_STACK 0

/*-----------------------------------------------------------------------------
    write_jdk_operation_jint
-----------------------------------------------------------------------------*/
void write_jdk_operation_jint(int pos, jint result)
{
    *(volatile jint*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = result;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    write_jdk_operation_jlong
-----------------------------------------------------------------------------*/
void write_jdk_operation_jlong(int pos, jlong result)
{
    *(volatile jlong*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = result;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    write_jdk_operation_voidptr
-----------------------------------------------------------------------------*/
void write_jdk_operation_voidptr(int pos, void* result)
{
    *(volatile void**)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int)) = result;
    __sync_synchronize();
    *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos) = masterthread_id;
}

/*-----------------------------------------------------------------------------
    is_mythread_jdk_operation
-----------------------------------------------------------------------------*/
int is_mythread_jdk_operation(int pos)
{
    volatile int op = *(volatile int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos);
    __sync_synchronize();
    return op == masterthread_id;
}

/*-----------------------------------------------------------------------------
    read_jdk_operation_jint
-----------------------------------------------------------------------------*/
void read_jdk_operation_jint(int pos, jint* result)
{
  if(result)
    {
      volatile jint op = *(volatile unsigned int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
      *result = op;
    }
}

/*-----------------------------------------------------------------------------
    read_jdk_operation_jlong
-----------------------------------------------------------------------------*/
void read_jdk_operation_jlong(int pos, jlong* result)
{
    volatile jlong op = *(volatile unsigned int*)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
    *result = op;
}

/*-----------------------------------------------------------------------------
    read_jdk_operation_voidptr
-----------------------------------------------------------------------------*/
void read_jdk_operation_voidptr(int pos, void** result)
{
    volatile void* op = *(volatile void**)((unsigned int)_shared_buffer + _shared_buffer_slot_size * pos + sizeof(int));
    *result = (void*)op;
}

/*-----------------------------------------------------------------------------
    _Atomic_add
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(jint, _Atomic_add, (jint add_value, volatile jint* dest))
{
  DO_SYNC_ATOMIC(jint, _Atomic_add, ___Atomic_add, (add_value, dest), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jint, read_jdk_operation_jint, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
  return result;
}

/*-----------------------------------------------------------------------------
    _Atomic_inc
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void, _Atomic_inc, (volatile jint* dest))
{
  DO_SYNC_ATOMIC_VOID(_Atomic_inc, ___Atomic_inc, (dest), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jint, read_jdk_operation_jint, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
}

/*-----------------------------------------------------------------------------
    _Atomic_inc_ptr
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void, _Atomic_inc_ptr, (volatile void* dest))
{
  DO_SYNC_ATOMIC_VOID(_Atomic_inc_ptr, ___Atomic_inc_ptr, (dest), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jint, read_jdk_operation_jint, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
}

/*-----------------------------------------------------------------------------
    _Atomic_dec
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void, _Atomic_dec, (volatile jint* dest))
{
  DO_SYNC_ATOMIC_VOID(_Atomic_dec, ___Atomic_dec, (dest), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jint, read_jdk_operation_jint, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
}

/*-----------------------------------------------------------------------------
    _Atomic_dec_ptr
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void, _Atomic_dec_ptr, (volatile void* dest))
{
  DO_SYNC_ATOMIC_VOID(_Atomic_dec_ptr, ___Atomic_dec_ptr, (dest), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jint, read_jdk_operation_jint, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
}

/*-----------------------------------------------------------------------------
    _Atomic_xchg
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(jint, _Atomic_xchg, (jint exchange_value, volatile jint* dest))
{
  DO_SYNC_ATOMIC(jint, _Atomic_xchg, ___Atomic_xchg, (exchange_value, dest), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jint, read_jdk_operation_jint, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
  return result;
}

/*-----------------------------------------------------------------------------
    _Atomic_xchg_ptr
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void*, _Atomic_xchg_ptr, (void* exchange_value, volatile void* dest))
{
  DO_SYNC_ATOMIC(void*, _Atomic_xchg_ptr, ___Atomic_xchg_ptr, (exchange_value, dest), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_voidptr, read_jdk_operation_voidptr, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
  return result;
}

/*-----------------------------------------------------------------------------
    _Atomic_cmpxchg_jint -

    *dest is compared with compare_value. If equal, dest is overwritten with
    exchange_value and exchange_value is returned. If not equal, the old *dest
    value is returned.
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(jint, _Atomic_cmpxchg_jint, (jint exchange_value, volatile jint* dest, jint compare_value))
{
  //printf("Atomic_cmpxchg_jint INIT: %d --- %d\n,", exchange_value, compare_value);
  //  syscall(224, 1337, 10000001, 57, exchange_value, compare_value, *dest);
  DO_SYNC_ATOMIC(jint, _Atomic_cmpxchg_jint, ___Atomic_cmpxchg_jint, (exchange_value, dest, compare_value), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jint, read_jdk_operation_jint, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
  //printf("Atomic_cmpxchg_jint: %d %d\n", result, *dest);
  return result;
}

/*-----------------------------------------------------------------------------
    _Atomic_cmpxchg_jlong
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(jlong, _Atomic_cmpxchg_jlong, (jlong exchange_value, volatile jlong* dest, jlong compare_value))
{
  DO_SYNC_ATOMIC(jlong, _Atomic_cmpxchg_jlong, ___Atomic_cmpxchg_jlong, (exchange_value, dest, compare_value), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jlong, read_jdk_operation_jlong, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
  //printf("Atomic_cmpxchg_jlong: %d %d\n", result, *dest);
  return result;
}

/*-----------------------------------------------------------------------------
    _Atomic_load
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(jlong, _Atomic_load, (volatile jlong* src))
{
  DO_SYNC_ATOMIC(jlong, _Atomic_load, ___Atomic_load, (src), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jlong, read_jdk_operation_jlong, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
  return result;
}

/*-----------------------------------------------------------------------------
    _Atomic_store
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void, _Atomic_store, (jlong store_value, jlong* dest))
{
  DO_SYNC_ATOMIC_VOID(_Atomic_store, ___Atomic_store, (store_value, dest), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jint, read_jdk_operation_jint, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
}

/*-----------------------------------------------------------------------------
    _Atomic_store_volatile
-----------------------------------------------------------------------------*/
INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void, _Atomic_store_volatile, (jlong store_value, volatile jlong* dest))
{
  DO_SYNC_ATOMIC_VOID(_Atomic_store_volatile, ___Atomic_store_volatile, (store_value, dest), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_jint, read_jdk_operation_jint, is_mythread_jdk_operation, 1, 0, 1, USE_EIP_STACK, STACK_DEPTH);
}

/*-----------------------------------------------------------------------------
    _ZN7Monitor7TryLockEv
-----------------------------------------------------------------------------*/
/*INTERPOSER_DETOUR_GENERATE_HOOKFUNC(int, _ZN7Monitor7TryLockEv, (int MonitorPtr))
{
  int result = ___ZN7Monitor7TryLockEv(MonitorPtr);
  syscall(__NR_gettid, 1337, 10000001, 55, result);
  //DO_SYNC(_ZN7Monitor7TryLockEv, ___ZN7Monitor7TryLockEv, (), MVEE_JDK_ATOMIC_BUFFER, 2*sizeof(int), write_jdk_operation_long, read_jdk_operation_long, is_mythread_jdk_operation, 1, 0, 1, 1);
  return result;
}*/

 /*INTERPOSER_DETOUR_GENERATE_HOOKFUNC(void, _ZN7Monitor5ILockEP6Thread, (int MonitorPtr, void* Self))
{
  printf("+++ Monitor::ILock\n");
  ___ZN7Monitor5ILockEP6Thread(MonitorPtr, Self);
  printf("--- Monitor::ILock\n");
  }*/

/*-----------------------------------------------------------------------------
    init
-----------------------------------------------------------------------------*/
void __attribute__((constructor)) init()
{
  //    printf("Registering OPENJDK Hooks ...\n");

    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_cmpxchg_jint, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_store_volatile, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_cmpxchg_jlong, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_inc, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_dec, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_add, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_inc_ptr, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_dec_ptr, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_xchg, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_load, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_xchg_ptr, 1);
    INTERPOSER_DETOUR_HOOK(libjvm.so, _Atomic_store, 1);
    //INTERPOSER_DETOUR_HOOK(libjvm.so, _ZN7Monitor5ILockEP6Thread);
    //INTERPOSER_DETOUR_HOOK(libjvm.so, _ZN7Monitor7TryLockEv);
}
