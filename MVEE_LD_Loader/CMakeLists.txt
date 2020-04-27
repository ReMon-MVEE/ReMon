# compile the loader
if (${ARCH} STREQUAL amd64)
    set(LD_LOADER_LONG_NAME MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib64_slash_ld-linux-x86-64.so.2_times_two)
elseif(${ARCH} STREQUAL arm)
    set(LD_LOADER_LONG_NAME MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib_slash_ld-linux-armhf.so.3_times_two)
elseif(${ARCH} STREQUAL i386)
    set(LD_LOADER_LONG_NAME MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib_slash_ld-linux.so.2_times_two)
endif()

set(CMAKE_C_COMPILER ${MUSL_GCC})

add_executable(${LD_LOADER_LONG_NAME}
    MVEE_LD_Loader.c
)
target_include_directories(${LD_LOADER_LONG_NAME} PRIVATE
    ${ARCH}
)
target_compile_definitions(${LD_LOADER_LONG_NAME} PRIVATE
    UNISTD_HDR=<${UNISTD_HDR}>
    MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
    MVEE_EMULATE_CPUID
)
target_compile_options(${LD_LOADER_LONG_NAME} PRIVATE
    -std=c99
)
# Ideally we use target_link_options here, but that's only introduced as of CMake 3.13
set_target_properties(${LD_LOADER_LONG_NAME} PROPERTIES
    LINK_FLAGS "-fuse-ld=bfd -static -T ${CMAKE_CURRENT_SOURCE_DIR}/linkerscript_${ARCH}.txt")
set_target_properties(${LD_LOADER_LONG_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
