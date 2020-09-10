//
// Created by jonas on 05.06.20.
//

#ifndef INSTRUCTION_TESTING_STATS_H
#define INSTRUCTION_TESTING_STATS_H


// =====================================================================================================================
//      failed info
// =====================================================================================================================
struct failed
{
    char*           message;
    failed*         next;
};

// =====================================================================================================================
//      stats
// =====================================================================================================================
namespace stats
{
    extern int      run;
    extern int      success;
    extern failed*  failed_queue;


    void            add_entry                           (const char* tmp, unsigned int size);
}

#endif //INSTRUCTION_TESTING_STATS_H
