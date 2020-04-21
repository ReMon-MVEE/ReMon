//
// Created by jonas on 15.04.20.
//

// implemented header
#include "shared_mem_reg_access.h"

// general purpose registers ===========================================================================================
constexpr void* (* const shared_mem_register_access::general_purpose_lookup[16]) ACCESS_GENERAL_ARGUMENTS;
// =====================================================================================================================

// general purpose registers ===========================================================================================
constexpr void* (* const shared_mem_register_access::segment_lookup[6]) ACCESS_GENERAL_ARGUMENTS;
// =====================================================================================================================

// general purpose registers ===========================================================================================
constexpr void* (* const shared_mem_register_access::mm_lookup[8]) ACCESS_MM_ST_ARGUMENTS;
// =====================================================================================================================

// general purpose registers ===========================================================================================
constexpr void* (* const shared_mem_register_access::st_lookup[8]) ACCESS_MM_ST_ARGUMENTS;
// =====================================================================================================================

// general purpose registers ===========================================================================================
constexpr void* (* const shared_mem_register_access::xmm_lookup[16]) ACCESS_XMM_ARGUMENTS;
constexpr const char* shared_mem_register_access::xmm_lookup_names[16];
// =====================================================================================================================