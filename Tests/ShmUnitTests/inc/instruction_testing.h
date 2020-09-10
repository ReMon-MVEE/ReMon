//
// Created by jonas on 04.06.20.
//

#ifndef INSTRUCTION_TESTING_INSTRUCTION_TESTING_H
#define INSTRUCTION_TESTING_INSTRUCTION_TESTING_H

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdarg>
#include <sstream>
#include <cstring>
#include <chrono>


// =====================================================================================================================
//      macros
// =====================================================================================================================
#define logf                                testing_general::log
#define logf_buff                           testing_general::log_buffer
#define logf_spacer                         testing_general::log_spacer()
#define logf_flush                          testing_general::log_flush()


#define START_TEST(message)                                                                                            \
    stats::run++;                                                                                                      \
    int test_parts = 0;                                                                                                \
    int test_parts_success = 0;                                                                                        \
    logf(message);                                                                                                     \
    logf_flush;

#define TEST_RESULT(message, condition)                                                                                \
    if (condition)                                                                                                     \
    {                                                                                                                  \
        test_parts_success++;                                                                                          \
        logf("\t%d: %s - successful\n", test_parts, message);                                                          \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        logf("\t%d: %s - unsuccessful\n", test_parts, message);                                                        \
        stats::add_entry(message, strlen(message));                                                                    \
    }                                                                                                                  \
    test_parts++;

#define FINISH_TEST(message_success, message_fail)                                                                     \
    if (test_parts == test_parts_success)                                                                              \
    {                                                                                                                  \
        stats::success++;                                                                                              \
        logf("%s - %d / %d\n", message_success, test_parts_success, test_parts - test_parts_success);                  \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        logf("%s - %d / %d\n", message_fail, test_parts_success, test_parts - test_parts_success);                     \
    }                                                                                                                  \
    logf_spacer;


#define COPY_BUFFERS(to, from, size)                                                                                   \
__asm(                                                                                                                 \
    ".intel_syntax noprefix;"                                                                                          \
    "mov rdi, rax;"                                                                                                    \
    "mov rsi, rdx;"                                                                                                    \
    "rep movsb;"                                                                                                       \
    ".att_syntax;"                                                                                                     \
    :                                                                                                                  \
    : "a" (to), "d" (from), "c" (size)                                                                                 \
)



#define ASM(asm_code)                                                                                                  \
    ".intel_syntax noprefix;"                                                                                          \
    asm_code                                                                                                           \
    ".att_syntax;"


// =====================================================================================================================
// config
// =====================================================================================================================
#define BYTE_CONTENT            { 0x11 }
#define WORD_CONTENT            { 0x11, 0x22 }
#define DWORD_CONTENT           { 0x11, 0x22, 0x33, 0x44 }
#define QWORD_CONTENT           { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }
#define DECABYTE_CONTENT        { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa }
#define DQWORD_CONTENT          { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xdd,  \
                                  0xff, 0x0f }

#define QWORD_CONTENT_REVERSE    { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 }

#define CONTENT_EMPTY           { 0x00 }

#define BYTE_SIZE                1u
#define WORD_SIZE                2u
#define DWORD_SIZE               4u
#define QWORD_SIZE               8u
#define DECABYTE_SIZE           10u
#define DQWORD_SIZE             16u


// =====================================================================================================================
//      logging
// =====================================================================================================================
namespace testing_general
{
    static FILE*   log_file = nullptr;

    void            setup_log                               ();
    void            log                                     (const char* format, ...);
    void            log_flush                               ();
    void            log_spacer                              ();
    void            log_stats                               (double duration);
    void            log_buffer                              (const __uint8_t* buffer, unsigned int size);
    void            terminate_log                           ();
}


// =====================================================================================================================
//      instruction aid
// =====================================================================================================================
namespace testing_aid
{
    int             open_shared_memory                      (void** shared_mapping, void** shared_sink_mapping);
    int             compare_buffers                         (const __uint8_t* first, const __uint8_t* second,
                                                             unsigned int size);
    void            clear_buffer                            (__uint8_t* buffer, unsigned int size);
}


#endif //INSTRUCTION_TESTING_INSTRUCTION_TESTING_H
