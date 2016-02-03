/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

#ifndef MVEE_MACROS_H_
#define MVEE_MACROS_H_

/*-----------------------------------------------------------------------------
  Generic Macros
-----------------------------------------------------------------------------*/
#define SERIALIZEVECTOR(vec, str)                              \
    std::string str;                                           \
    {                                                          \
        std::stringstream ss;                                  \
        ss << "[";                                             \
        for (size_t vecidx = 0; vecidx < vec.size(); ++vecidx) \
        {                                                      \
            if (vecidx > 0)                                    \
                ss << ", ";                                    \
            ss << vec[vecidx];                                 \
        }                                                      \
        ss << "]";                                             \
        str = ss.str();                                        \
    }

#define ROUND_DOWN(x, multiple) ( (((long)(x)))  & (~(multiple-1)) )
#define ROUND_UP(x, multiple)   ( (((long)(x)) + multiple-1)  & (~(multiple-1)) )

#define SAFEDELETEARRAY(a) \
    if (a != NULL)         \
    {                      \
        delete[] a;        \
        a = NULL;          \
    }

#define SAFEDELETE(a) \
    if (a != NULL)    \
    {                 \
        delete a;     \
        a = NULL;     \
    }

#define MIN(a, b)               ((a>b) ? b : a)
#define MAX(a, b)               ((a>b) ? a : b)

//
// Returns true if a and b are both NULL, false otherwise
//
#define COMPARE_NULL(a, b)      ( ((void*)a == NULL) == ((void*)b == NULL) )

#define ARRAYLENGTH(a)          ((int)(sizeof(a)/sizeof(a[0])))





#endif /* MVEE_MACROS_H_ */
