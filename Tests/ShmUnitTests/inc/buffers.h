//
// Created by jonas on 05.06.20.
//

#ifndef INSTRUCTION_TESTING_BUFFERS_H
#define INSTRUCTION_TESTING_BUFFERS_H


// =====================================================================================================================
//      buffers
// =====================================================================================================================
#include "instruction_testing.h"

namespace buffers
{
#ifdef SETUP_DQWORD
    extern __uint8_t dqword[DQWORD_SIZE];
    extern __uint8_t dqword_sink[DQWORD_SIZE];
#endif
#ifdef SETUP_BIGCHUNGUS
    extern __uint8_t* big_buffer;
    extern __uint8_t* big_buffer_sink;
#endif

    extern __uint8_t* shared_mapping;
    extern __uint8_t* shared_sink;


    int         setup                                   ();
    int         cleanup                                 ();
}

#endif //INSTRUCTION_TESTING_BUFFERS_H
