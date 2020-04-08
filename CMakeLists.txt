cmake_minimum_required (VERSION 3.10.2)


# prerun ===============================================================================================================

# get architecture
execute_process(
        COMMAND bash -c "${CMAKE_SOURCE_DIR}/build_scripts/getmakearch.rb | grep ^ARCH | cut -d':' -f2 | tr -d '\n'"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE ARCH
        RESULT_VARIABLE GET_ARCH_RESULT
)
message("get architecture result: " ${ARCH})
message("")


# get alternative architecture
execute_process(
        COMMAND bash -c "${CMAKE_SOURCE_DIR}/build_scripts/getmakearch.rb | grep ^ALT_ARCH | cut -d':' -f2 | tr -d '\n'"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE ALT_ARCH
        RESULT_VARIABLE GET_ALT_ARCH_RESULT
)
message("get alternative architecture result: " ${ALT_ARCH})
message("")


# generate syscall tables
execute_process(
        COMMAND ${CMAKE_SOURCE_DIR}/build_scripts/generate_syscall_tables.rb
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE SYSCALL_GENERATOR_OUTPUT
        RESULT_VARIABLE SYSCALL_GENERATOR_RESULT
)
message("syscall generation result:\n"
        "\toutput:\n" ${SYSCALL_GENERATOR_OUTPUT}
        "\n\tresult: " ${SYSCALL_GENERATOR_RESULT})
message("")


# compile the syncagent
execute_process(
        COMMAND ${CMAKE_SOURCE_DIR}/build_scripts/compile_syncagent.rb
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE COMPILE_SYNCAGENT_OUTPUT
        RESULT_VARIABLE COMPILE_SYNCAGENT_RESULT
)
message("syncagent compilation result:\n"
        "\toutput:\n" ${COMPILE_SYNCAGENT_OUTPUT}
        "\n\tresult: " ${COMPILE_SYNCAGENT_RESULT})
message("")


# compile the loader
execute_process(
        COMMAND ./getunistd.rb
        OUTPUT_VARIABLE UNISTD_HDR
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/MVEE_LD_Loader
)

if (${ARCH} STREQUAL amd64)
    set(LD_LOADER_LONG_NAME MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib64_slash_ld-linux-x86-64.so.2_times_two)
elseif(${ARCH} STREQUAL arm)
    set(LD_LOADER_LONG_NAME MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib_slash_ld-linux-armhf.so.3_times_two)
elseif(${ARCH} STREQUAL i386)
    set(LD_LOADER_LONG_NAME MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib_slash_ld-linux.so.2_times_two)
endif()

add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/MVEE_LD_Loader/${LD_LOADER_LONG_NAME}
        COMMAND ${CMAKE_SOURCE_DIR}/deps/musl-install/bin/musl-gcc
            -I./${ARCH}/
            -DUNISTD_HDR="<${UNISTD_HDR}>"
            -fuse-ld=bfd
            -std=c99
            -o ${LD_LOADER_LONG_NAME}
            -static MVEE_LD_Loader.c
            -T linkerscript_${ARCH}.txt
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/MVEE_LD_Loader
)

add_custom_target(ld_loader
        DEPENDS ${CMAKE_SOURCE_DIR}/MVEE_LD_Loader/${LD_LOADER_LONG_NAME}
)

# ======================================================================================================================


# libraries ============================================================================================================
set(LIBC_VER 2.27.9000)
set(LIBC_DIR /home/jonas/sources/linux/libc/glibc_build)
add_custom_command(
        OUTPUT      ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libc.so.6
        COMMAND     ln -f -s libc-${LIBC_VER}.so patched_binaries/libc/${ARCH}/libc.so.6
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_custom_command(
        OUTPUT      ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libpthread.so.0
        COMMAND     ln -f -s libpthread-${LIBC_VER}.so patched_binaries/libc/${ARCH}/libpthread.so.0
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_custom_command(
        OUTPUT      ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libdl.so.2
        COMMAND     ln -f -s libdl-${LIBC_VER}.so patched_binaries/libc/${ARCH}/libdl.so.2
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_custom_command(
        OUTPUT      ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/librt.so.1
        COMMAND     ln -f -s librt-${LIBC_VER}.so patched_binaries/libc/${ARCH}/librt.so.1
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_custom_command(
        OUTPUT      ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libm.so.6
        COMMAND     ln -f -s libm-${LIBC_VER}.so patched_binaries/libc/${ARCH}/libm.so.6
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_custom_command(
        OUTPUT      ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libresolv.so.2
        COMMAND     ln -f -s libresolv-${LIBC_VER}.so patched_binaries/libc/${ARCH}/libresolv.so.2
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_custom_command(
        OUTPUT      ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libutil.so.1
        COMMAND     ln -f -s libutil-${LIBC_VER}.so patched_binaries/libc/${ARCH}/libutil.so.1
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_custom_command(
        OUTPUT      ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/ld-linux.so
        COMMAND     ln -f -s ld-${LIBC_VER}.so patched_binaries/libc/${ARCH}/ld-linux.so
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(linking
        DEPENDS     ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libc.so.6
                    ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libpthread.so.0
                    ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libdl.so.2
                    ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/librt.so.1
                    ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libm.so.6
                    ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libresolv.so.2
                    ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libutil.so.1
                    ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/ld-linux.so
)
# ======================================================================================================================


# custom targets =======================================================================================================

add_custom_target(
        debug
        COMMAND "${CMAKE_COMMAND}" .. -DCMAKE_BUILD_TYPE=Debug
)

add_custom_target(
        release
        COMMAND "${CMAKE_COMMAND}" .. -DCMAKE_BUILD_TYPE=Release
)

message("using:")
message("\t- " ${CMAKE_CXX_COMPILER})
message("\t- " ${CMAKE_LINKER})
message("\t- " ${CMAKE_AR})
message("\t- " ${CMAKE_RANLIB})
message("")
message("build type: " ${CMAKE_BUILD_TYPE})
# ======================================================================================================================


# project name
project(remon)

# files and directories for mvee executables ===========================================================================

# sources for mvee executable
file(GLOB MVEE_SOURCES
        ${CMAKE_SOURCE_DIR}/MVEE/Src/*.cpp
        ${CMAKE_SOURCE_DIR}/MVEE/Src/arch/${ARCH}/*.cpp
        ${CMAKE_SOURCE_DIR}/MVEE/Src/arch/${ARCH}/shared_mem/*.cpp
)

# include directories for mvee executable
set(MVEE_INCLUDE_DIRS
        PRIVATE ${CMAKE_SOURCE_DIR}/MVEE/Inc
        PRIVATE ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch
        PRIVATE ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}
        PRIVATE ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/shared_mem/
        PRIVATE ${CMAKE_SOURCE_DIR}/deps/jsoncpp/include
        PRIVATE ${CMAKE_SOURCE_DIR}/deps/libdwarf/libdwarf
        PRIVATE ${CMAKE_SOURCE_DIR}/deps/binutils/zlib
)

# ======================================================================================================================


# mvee executable ======================================================================================================

# binary definition
add_executable(mvee
        ${MVEE_SOURCES}
)

add_dependencies(mvee
        ld_loader
        linking
)

# include directories for mvee executable
target_include_directories(mvee ${MVEE_INCLUDE_DIRS})

# link dwarf, elf, and jsoncpp
target_link_libraries(mvee PRIVATE
        ${CMAKE_SOURCE_DIR}/deps/jsoncpp/build/src/lib_json/libjsoncpp.a
        ${CMAKE_SOURCE_DIR}/deps/libdwarf/libdwarf/.libs/libdwarf.a
        ${CMAKE_SOURCE_DIR}/deps/libelf/lib/libelf.a
        ${CMAKE_SOURCE_DIR}/deps/binutils/build-tree/zlib/libz.a
)

# link pathced binaries
target_link_libraries(mvee INTERFACE
        ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libc.so.6
        ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libpthread.so.0
        ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/librt.so.1
        ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libdl.so.2
        ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libm.so.6
        ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libresolv.so.2
        ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libutil.so.1
        ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/ld-linux.so
        ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libclang_rt.sync-${ALT_ARCH}.so
)

# link loader
target_link_libraries(mvee PRIVATE
)

# system libraries
target_link_libraries(mvee PRIVATE
        -lrt
        -ldl
        -lstdc++
        -lpthread
)

# compiler flags
target_compile_options(mvee PRIVATE
        -D__LINUX_X86__
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
        -Wno-unused-function
)

# output override
set_target_properties(mvee PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/MVEE/bin/${CMAKE_BUILD_TYPE}
)

# debug specific -------------------------------------------------------------------------------------------------------
if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    message("generating Debug build\n")

    # linker options
    target_link_libraries(mvee PRIVATE
            -rdynamic
    )

    # compiler flags
    target_compile_options(mvee PRIVATE
            -ggdb
            -std=c++14
            -pedantic-errors
            -fno-omit-frame-pointer
            -Werror
    )

    target_compile_definitions(mvee PRIVATE
            JNS_DEBUG
            ACCESS_INTENT_DEBUG
    )
# release specific -----------------------------------------------------------------------------------------------------
else()
    message("generating Release build\n")

    # linker options
    target_link_libraries(mvee PRIVATE
            -flto
            -O3
            -static
            -s
    )

    # compiler flags
    target_compile_options(mvee PRIVATE
            -flto
            -O3
            -ffast-math
            -std=c++14
            -static
            -fvisibility=hidden
    )
endif()
# ----------------------------------------------------------------------------------------------------------------------

# compile definitions, uncomment to set or comment to unset
target_compile_definitions(mvee PRIVATE
        
)
# ======================================================================================================================