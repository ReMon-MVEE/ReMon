//
// Created by jonas on 16/03/2020.
//

#ifndef REMON_SHARED_MEM_REG_ACCESS_H
#define REMON_SHARED_MEM_REG_ACCESS_H


#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <MVEE.h>
#include <sys/user.h>
#include <MVEE_monitor.h>


// =====================================================================================================================
//      forward definitions
// =====================================================================================================================
class monitor;


// =====================================================================================================================
//      constants
// =====================================================================================================================
// some masks ----------------------------------------------------------------------------------------------------------
#define REG_SIZE_08                             0x00000000000000ffu
#define REG_SIZE_16                             0x000000000000ffffu
#define REG_SIZE_32                             0x00000000ffffffffu
#define REG_SIZE_64                             0xffffffffffffffffu
// ---------------------------------------------------------------------------------------------------------------------


// mm indexes ----------------------------------------------------------------------------------------------------------
/*                          MM      ST
 * +-------------------------+-------+
 * | __ __ __ __ __ __ __ __ | __ __ |
 * +-------------------------+-------+
 *
 */
#define MM0_FP_INDEX                             0u
#define MM1_FP_INDEX                             4u
#define MM2_FP_INDEX                             8u
#define MM3_FP_INDEX                            12u
#define MM4_FP_INDEX                            16u
#define MM5_FP_INDEX                            20u
#define MM6_FP_INDEX                            24u
#define MM7_FP_INDEX                            28u

#define ST0_FP_INDEX                             0u
#define ST1_FP_INDEX                             4u
#define ST2_FP_INDEX                             8u
#define ST3_FP_INDEX                            12u
#define ST4_FP_INDEX                            16u
#define ST5_FP_INDEX                            20u
#define ST6_FP_INDEX                            24u
#define ST7_FP_INDEX                            28u
// ---------------------------------------------------------------------------------------------------------------------


// xmm indexes ---------------------------------------------------------------------------------------------------------
/* Funny anecdote, writing this down so maybe I'll remember if it happens again.
 *
 * So when first writing these indexes for the XMM registers, I accidentally wrote it as:
 *   #define XMM01_FP_INDEX                           0u
 *   #define XMM00_FP_INDEX                           4u
 *
 * Which of course didn't work. It actually took me quite a while to figure out what was wrong. You know, since my log
 * files actually showed I was using the correct register, but I was in face very much not using the correct register.
 * Anyways, I did manage to fix it. Only to, SOMEHOW, have it revert back to the wrong version when writing it in the
 * new repo, and losing time here AGAIN.
 * */
#define XMM00_FP_INDEX                           0u
#define XMM01_FP_INDEX                           4u
#define XMM02_FP_INDEX                           8u
#define XMM03_FP_INDEX                          12u
#define XMM04_FP_INDEX                          16u
#define XMM05_FP_INDEX                          20u
#define XMM06_FP_INDEX                          24u
#define XMM07_FP_INDEX                          28u
#define XMM08_FP_INDEX                          32u
#define XMM09_FP_INDEX                          36u
#define XMM10_FP_INDEX                          40u
#define XMM11_FP_INDEX                          44u
#define XMM12_FP_INDEX                          48u
#define XMM13_FP_INDEX                          52u
#define XMM14_FP_INDEX                          56u
#define XMM15_FP_INDEX                          60u
// ---------------------------------------------------------------------------------------------------------------------


// =====================================================================================================================
//      macros
// =====================================================================================================================
#define ACCESS_GENERAL_NAME(reg_name)           access_##reg_name##_register
#define ACCESS_GENERAL_ARGUMENTS                                    (user_regs_struct* regs)
#define ACCESS_GENERAL_DEFINITION(reg_name)                                                                            \
static void*    ACCESS_GENERAL_NAME(reg_name)                       ACCESS_GENERAL_ARGUMENTS                           \
{                                                                                                                      \
    return &regs->reg_name;                                                                                            \
}

#define ACCESS_MM_ST_NAME(reg_name)                access_##reg_name##_register
#define ACCESS_MM_ST_ARGUMENTS                                         (user_fpregs_struct* regs)
#define ACCESS_MM_ST_DEFINITION(reg_name, index)                                                                       \
static void*    ACCESS_MM_ST_NAME(reg_name)                            ACCESS_MM_ST_ARGUMENTS                          \
{                                                                                                                      \
    return &regs->st_space[index];                                                                                     \
}

#define ACCESS_XMM_NAME(reg_name)                access_##reg_name##_register
#define ACCESS_XMM_ARGUMENTS                                         (user_fpregs_struct* regs)
#define ACCESS_XMM_DEFINITION(reg_name, index)                                                                         \
static void*    ACCESS_XMM_NAME(reg_name)                            ACCESS_XMM_ARGUMENTS                              \
{                                                                                                                      \
    return &regs->xmm_space[index];                                                                                    \
}


// =====================================================================================================================
//      class definition
// =====================================================================================================================
class shared_mem_register_access
{
public:
    // access definitions ==============================================================================================
    // general purpose -------------------------------------------------------------------------------------------------
    ACCESS_GENERAL_DEFINITION(rax)
    ACCESS_GENERAL_DEFINITION(rcx)
    ACCESS_GENERAL_DEFINITION(rdx)
    ACCESS_GENERAL_DEFINITION(rbx)
    ACCESS_GENERAL_DEFINITION(rsp)
    ACCESS_GENERAL_DEFINITION(rbp)
    ACCESS_GENERAL_DEFINITION(rsi)
    ACCESS_GENERAL_DEFINITION(rdi)
    ACCESS_GENERAL_DEFINITION( r8)
    ACCESS_GENERAL_DEFINITION( r9)
    ACCESS_GENERAL_DEFINITION(r10)
    ACCESS_GENERAL_DEFINITION(r11)
    ACCESS_GENERAL_DEFINITION(r12)
    ACCESS_GENERAL_DEFINITION(r13)
    ACCESS_GENERAL_DEFINITION(r14)
    ACCESS_GENERAL_DEFINITION(r15)
    // -----------------------------------------------------------------------------------------------------------------

    // segment ---------------------------------------------------------------------------------------------------------
    ACCESS_GENERAL_DEFINITION(es)
    ACCESS_GENERAL_DEFINITION(cs)
    ACCESS_GENERAL_DEFINITION(ss)
    ACCESS_GENERAL_DEFINITION(ds)
    ACCESS_GENERAL_DEFINITION(fs)
    ACCESS_GENERAL_DEFINITION(gs)
    // -----------------------------------------------------------------------------------------------------------------

    // mm --------------------------------------------------------------------------------------------------------------
    ACCESS_MM_ST_DEFINITION(mm0, MM0_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(mm1, MM1_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(mm2, MM2_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(mm3, MM3_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(mm4, MM4_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(mm5, MM5_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(mm6, MM6_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(mm7, MM7_FP_INDEX)
    // -----------------------------------------------------------------------------------------------------------------

    // st -------------------------------------------------------------------------------------------------------------
    ACCESS_MM_ST_DEFINITION(st0, ST0_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(st1, ST1_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(st2, ST2_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(st3, ST3_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(st4, ST4_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(st5, ST5_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(st6, ST6_FP_INDEX)
    ACCESS_MM_ST_DEFINITION(st7, ST7_FP_INDEX)
    // -----------------------------------------------------------------------------------------------------------------

    // xmm -------------------------------------------------------------------------------------------------------------
    ACCESS_XMM_DEFINITION(xmm00, XMM00_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm01, XMM01_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm02, XMM02_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm03, XMM03_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm04, XMM04_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm05, XMM05_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm06, XMM06_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm07, XMM07_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm08, XMM08_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm09, XMM09_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm10, XMM10_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm11, XMM11_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm12, XMM12_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm13, XMM13_FP_INDEX)
    ACCESS_XMM_DEFINITION(xmm14, XMM14_FP_INDEX)
    // -----------------------------------------------------------------------------------------------------------------

    // =================================================================================================================


    // access tables ===================================================================================================
    // general purpose -------------------------------------------------------------------------------------------------
    static constexpr void* (* const general_purpose_lookup[16]) ACCESS_GENERAL_ARGUMENTS =
            {
                    &ACCESS_GENERAL_NAME(rax),
                    &ACCESS_GENERAL_NAME(rcx),
                    &ACCESS_GENERAL_NAME(rdx),
                    &ACCESS_GENERAL_NAME(rbx),
                    &ACCESS_GENERAL_NAME(rsp),
                    &ACCESS_GENERAL_NAME(rbp),
                    &ACCESS_GENERAL_NAME(rsi),
                    &ACCESS_GENERAL_NAME(rdi),
                    &ACCESS_GENERAL_NAME( r8),
                    &ACCESS_GENERAL_NAME( r9),
                    &ACCESS_GENERAL_NAME(r10),
                    &ACCESS_GENERAL_NAME(r11),
                    &ACCESS_GENERAL_NAME(r12),
                    &ACCESS_GENERAL_NAME(r13),
                    &ACCESS_GENERAL_NAME(r14),
                    &ACCESS_GENERAL_NAME(r15)
            };
    // -----------------------------------------------------------------------------------------------------------------

    // segment ---------------------------------------------------------------------------------------------------------
    static constexpr void* (* const segment_lookup[6]) ACCESS_GENERAL_ARGUMENTS =
            {
                    &ACCESS_GENERAL_NAME(es),
                    &ACCESS_GENERAL_NAME(cs),
                    &ACCESS_GENERAL_NAME(ss),
                    &ACCESS_GENERAL_NAME(ds),
                    &ACCESS_GENERAL_NAME(fs),
                    &ACCESS_GENERAL_NAME(gs),
            };
    // -----------------------------------------------------------------------------------------------------------------

    // mm --------------------------------------------------------------------------------------------------------------
    static constexpr void* (* const mm_lookup[8]) ACCESS_MM_ST_ARGUMENTS =
            {
                    &ACCESS_MM_ST_NAME(mm0),
                    &ACCESS_MM_ST_NAME(mm1),
                    &ACCESS_MM_ST_NAME(mm2),
                    &ACCESS_MM_ST_NAME(mm3),
                    &ACCESS_MM_ST_NAME(mm4),
                    &ACCESS_MM_ST_NAME(mm5),
                    &ACCESS_MM_ST_NAME(mm6),
                    &ACCESS_MM_ST_NAME(mm7)
            };
    // -----------------------------------------------------------------------------------------------------------------
    // st --------------------------------------------------------------------------------------------------------------
    static constexpr void* (* const st_lookup[8]) ACCESS_MM_ST_ARGUMENTS =
            {
                    &ACCESS_MM_ST_NAME(st0),
                    &ACCESS_MM_ST_NAME(st1),
                    &ACCESS_MM_ST_NAME(st2),
                    &ACCESS_MM_ST_NAME(st3),
                    &ACCESS_MM_ST_NAME(st4),
                    &ACCESS_MM_ST_NAME(st5),
                    &ACCESS_MM_ST_NAME(st6),
                    &ACCESS_MM_ST_NAME(st7)
            };
    // -----------------------------------------------------------------------------------------------------------------

    // xmm -------------------------------------------------------------------------------------------------------------
    static constexpr void* (* const xmm_lookup[16]) ACCESS_XMM_ARGUMENTS =
            {
                    &ACCESS_XMM_NAME(xmm00),
                    &ACCESS_XMM_NAME(xmm01),
                    &ACCESS_XMM_NAME(xmm02),
                    &ACCESS_XMM_NAME(xmm03),
                    &ACCESS_XMM_NAME(xmm04),
                    &ACCESS_XMM_NAME(xmm05),
                    &ACCESS_XMM_NAME(xmm06),
                    &ACCESS_XMM_NAME(xmm07),
                    &ACCESS_XMM_NAME(xmm08),
                    &ACCESS_XMM_NAME(xmm09),
                    &ACCESS_XMM_NAME(xmm10),
                    &ACCESS_XMM_NAME(xmm11),
                    &ACCESS_XMM_NAME(xmm12),
                    &ACCESS_XMM_NAME(xmm13),
                    &ACCESS_XMM_NAME(xmm14),
            };
    static constexpr const char* xmm_lookup_names[16] =
            {
                    "xmm00",
                    "xmm01",
                    "xmm02",
                    "xmm03",
                    "xmm04",
                    "xmm05",
                    "xmm06",
                    "xmm07",
                    "xmm08",
                    "xmm09",
                    "xmm10",
                    "xmm11",
                    "xmm12",
                    "xmm13",
                    "xmm14",
            };
    // -----------------------------------------------------------------------------------------------------------------
    // =================================================================================================================
};

#endif //REMON_SHARED_MEM_REG_ACCESS_H
