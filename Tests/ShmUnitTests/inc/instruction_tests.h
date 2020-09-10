//
// Created by jonas on 05.06.20.
//

#ifndef INSTRUCTION_TESTING_INSTRUCTION_TESTS_H
#define INSTRUCTION_TESTING_INSTRUCTION_TESTS_H


// =====================================================================================================================
//      useful constants
// =====================================================================================================================
#define CF_MASK                             (0x1u << 00u)
#define PF_MASK                             (0x1u << 02u)
#define AF_MASK                             (0x1u << 04u)
#define ZF_MASK                             (0x1u << 06u)
#define SF_MASK                             (0x1u << 07u)
#define OF_MASK                             (0x1u << 11u)

// =====================================================================================================================
//      instruction tests
// =====================================================================================================================
namespace instruction_tests
{
    void        test_0x01                           ();

    void        test_0x39                           ();

    void        test_0x3b                           ();

    void        test_0x83                           ();

    void        test_0x87                           ();

    void        test_0x89                           ();

    void        test_0x8b                           ();

    void        test_0xa4                           ();

    void        test_0xab                           ();

    void        test_0xc7                           ();

    void        test_0x0f_0x11                      ();

    void        test_0x0f_0x6f                      ();

    void        test_0x0f_0x7f                      ();

    void        test_0x0f_0xb1                      ();

    void        test_0x0f_0xbe                      ();

    void        test_0x0f_0xc1                      ();

    void        test_0x0f_0xe7                      ();

    void        test_extras                         ();
}

#endif //INSTRUCTION_TESTING_INSTRUCTION_TESTS_H
