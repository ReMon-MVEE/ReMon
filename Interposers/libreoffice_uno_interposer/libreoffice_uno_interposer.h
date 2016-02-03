/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2014 Stijn Volckaert, Ghent University 
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

#include "../../MVEE/Inc/MVEE_fake_syscall.h"
#include "../../MVEE/Inc/MVEE_interposer_base.h"
extern "C" {
#include "../../Utilities/mvee_lazy_hooker/mvee_lazy_hooker.h"
}
