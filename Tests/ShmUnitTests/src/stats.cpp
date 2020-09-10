//
// Created by jonas on 05.06.20.
//

#include <cstdlib>
#include <cstring>
#include "stats.h"

// =====================================================================================================================
//      stats definitions
// =====================================================================================================================
int             stats::run                         = 0;
int             stats::success                     = 0;
failed*         stats::failed_queue                = nullptr;


void            stats::add_entry                                    (const char* tmp, unsigned int size)
{

    char* message = (char*) malloc(size + 1);
    auto* new_entry = (failed*) malloc(sizeof(failed));
    strncpy(message, tmp, size + 1);
    new_entry->message = message;
    new_entry->next = stats::failed_queue;
    stats::failed_queue = new_entry;
}