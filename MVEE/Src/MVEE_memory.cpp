/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <new>
#include "MVEE_memory.h"

/*-----------------------------------------------------------------------------
    mvee_rw_safe_alloc
-----------------------------------------------------------------------------*/
unsigned char* mvee_rw_safe_alloc(long alloc_size)
{
    unsigned char* result = NULL;
    try
    {
        result = new unsigned char[alloc_size];
    }
    catch (std::bad_alloc& ba)
    {
        fprintf(stderr, "mvee_rw_safe_alloc - bad allocation: %s\n", ba.what());
    }
    return result;
}

#ifdef MVEE_HAVE_MVEE_KERNEL
  #include "MVEE_memory_MVEE_kernel.h"
#else
  #include "MVEE_memory_stock_kernel.h"
#endif
