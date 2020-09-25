//
// Created by jonas on 04.06.20.
//
#include <cstdint>
#include <cstdlib>
#include <chrono>
#include <syscall.h>

#include "instruction_testing.h"
#include "instruction_tests.h"
#include "buffers.h"
#include "stats.h"


// =====================================================================================================================
// =====================================================================================================================
void            test                                                ()
{
    // duplicate shared mapping
    int shared_fd = memfd_create("SHARED_FILE", O_RDWR);
    if (shared_fd < 0)
    {
        logf("could not open duplicate shared mapping\n");
        exit(-1);
    }
    if (ftruncate(shared_fd, 0) || ftruncate(shared_fd, SHARED_SIZE))
    {
        logf("could not truncate memefd\n");
        exit(-1);
    }
    auto* shared_mapping_copy = (__uint8_t*) mmap(nullptr, SHARED_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED,
            shared_fd, 0);
    if (shared_mapping_copy == MAP_FAILED)
    {
        logf("could not map duplicate shared mapping\n");
        exit(-1);
    }
    close(shared_fd);


    START_TEST("running functionality tests...\n")


    TEST_RESULT("shared == private | non null",
            testing_aid::compare_buffers(buffers::shared_mapping, buffers::big_buffer, SHARED_SIZE) == 0)

    TEST_RESULT("private == shared | non null",
            testing_aid::compare_buffers(buffers::big_buffer, buffers::shared_mapping, SHARED_SIZE) == 0)

    TEST_RESULT("shared == shared, no buffer copy test | non null",
            testing_aid::compare_buffers(shared_mapping_copy, buffers::shared_mapping, SHARED_SIZE) == -1)

    for (unsigned int i = 0; i < SHARED_SIZE; i++)
        shared_mapping_copy[i] = buffers::shared_mapping[i];
    TEST_RESULT("shared == shared, buffer copy test | non null",
            testing_aid::compare_buffers(shared_mapping_copy, buffers::shared_mapping, SHARED_SIZE) == 0)

    TEST_RESULT("shared == private | null",
            testing_aid::compare_buffers(buffers::shared_sink, buffers::big_buffer_sink, SHARED_SIZE) == 0)

    TEST_RESULT("private == shared | null",
            testing_aid::compare_buffers(buffers::big_buffer_sink, buffers::shared_sink, SHARED_SIZE) == 0)

    TEST_RESULT("shared == shared, buffer not cleared | null",
            testing_aid::compare_buffers(shared_mapping_copy, buffers::shared_sink, SHARED_SIZE) == -1)

    testing_aid::clear_buffer(shared_mapping_copy, SHARED_SIZE);
    TEST_RESULT("shared == shared, buffer not cleared | null",
                testing_aid::compare_buffers(shared_mapping_copy, buffers::shared_sink, SHARED_SIZE) == 0)

    FINISH_TEST("functionality okay", "functionality issues")


    munmap(shared_mapping_copy, SHARED_SIZE);
}


// =====================================================================================================================
// main
// =====================================================================================================================
int             main                                                (int argc, char** argv)
{
    auto start = std::chrono::steady_clock::now();
    testing_general::setup_log();


    // setup -----------------------------------------------------------------------------------------------------------
    if (buffers::setup() < 0)
        return -1;
    // setup -----------------------------------------------------------------------------------------------------------


#ifdef TEST_FUNCTIONALITY
    test();
    goto end;
#endif

    // tests -----------------------------------------------------------------------------------------------------------
    instruction_tests::test_0x01();
    instruction_tests::test_0x03();
    instruction_tests::test_0x2b();
    instruction_tests::test_0x39();
    instruction_tests::test_0x3b();
    instruction_tests::test_0x83();
    instruction_tests::test_0x87();
    instruction_tests::test_0x89();
    instruction_tests::test_0x8b();
    instruction_tests::test_0xa4();
    instruction_tests::test_0xab();
    instruction_tests::test_0xc7();
    instruction_tests::test_0x0f_0x11();
    instruction_tests::test_0x0f_0x6f();
    instruction_tests::test_0x0f_0x7f();
    instruction_tests::test_0x0f_0xb1();
    instruction_tests::test_0x0f_0xb6();
    instruction_tests::test_0x0f_0xb7();
    instruction_tests::test_0x0f_0xbe();
    instruction_tests::test_0x0f_0xc1();
    instruction_tests::test_0x0f_0xe7();
    // instruction_tests::test_extras();
    // tests -----------------------------------------------------------------------------------------------------------


    // end
    end:
    double duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start)
            .count();
    testing_general::log_stats(duration);
    logf_spacer;
    testing_general::terminate_log();
    return 0;
}