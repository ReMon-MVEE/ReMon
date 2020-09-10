//
// Created by jonas on 05.06.20.
//

#include <cstdint>
#include <cstdlib>

#include "buffers.h"
#include "instruction_testing.h"


// =====================================================================================================================
//      buffer definitions
// =====================================================================================================================
#ifdef SETUP_DQWORD
__uint8_t buffers::dqword[]         = DQWORD_CONTENT;
__uint8_t buffers::dqword_sink[]    = CONTENT_EMPTY;
#endif
#ifdef SETUP_BIGCHUNGUS
__uint8_t* buffers::big_buffer      = (__uint8_t*) malloc(SHARED_SIZE);
__uint8_t* buffers::big_buffer_sink = (__uint8_t*) malloc(SHARED_SIZE);
#endif

__uint8_t* buffers::shared_mapping = nullptr;
__uint8_t* buffers::shared_sink    = nullptr;


int                 buffers::setup                                  ()
{
    logf("runnig setup...\n");
#ifdef SETUP_BIGCHUNGUS
    logf("setting up big buffer...\n");
    for (unsigned int i = 0; i < SHARED_SIZE; i++)
    {
        buffers::big_buffer[i] = ((i % 15u) + 1) | (((i % 15u) + 1u) << 4u);
        buffers::big_buffer_sink[i] = 0x00;
    }
#endif

    logf("setting up shared mappings...\n");
    if (testing_aid::open_shared_memory((void**) &buffers::shared_mapping, (void**) &buffers::shared_sink) < 0)
        return -1;
#ifdef MEMEFD
    for (unsigned int i = 0; i < SHARED_SIZE; i++)
        *(buffers::shared_mapping + i) = ((i % 15u) + 1) | (((i % 15u) + 1u) << 4u);
    mprotect((void*) buffers::shared_mapping, SHARED_SIZE, PROT_READ);
#endif

    logf("setup done!\n");
    logf_spacer;

    return 0;
}