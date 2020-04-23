cmake_minimum_required (VERSION 3.10.2)
project(remon)

if (NOT CMAKE_BUILD_TYPE)
        message(STATUS "CMAKE_BUILD_TYPE not defined. Defaulting to Release.")
        set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release" FORCE)
endif()

if(DEFINED ENV{MVEE_DEPS_PRESENT_IN_SYSTEM})
        set(DEPS_PRESENT_IN_SYSTEM TRUE)
endif()

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

# Get UNISTD
execute_process(
        COMMAND ./getunistd.rb
        OUTPUT_VARIABLE UNISTD_HDR
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/MVEE_LD_Loader
)

# generate syscall tables
add_custom_target(syscall_tables
        # TODO: Ideally this is turned into a (or several) add_custom_command with the generated headers as OUTPUT
        # This way the script is not *always* invoked, but only if one of the dependencies changes..
        COMMAND ${CMAKE_SOURCE_DIR}/build_scripts/generate_syscall_tables.rb
        DEPENDS ${CMAKE_SOURCE_DIR}/MVEE/Src/MVEE_syscalls_handlers.cpp ${UNISTD_HDR}
        COMMENT "Generating syscall tables"
)

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
if(DEPS_PRESENT_IN_SYSTEM)
    set(MUSL_GCC musl-gcc)
else()
    set(MUSL_GCC ${CMAKE_SOURCE_DIR}/deps/musl-install/bin/musl-gcc)
endif()
# ======================================================================================================================
add_subdirectory(MVEE_LD_Loader)

# libraries ============================================================================================================
set(LIBC_VER 2.27.9000)
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
)

if(DEPS_PRESENT_IN_SYSTEM)
        set(MVEE_INCLUDE_DIRS ${MVEE_INCLUDE_DIRS}
                PRIVATE /usr/include/jsoncpp/
                PRIVATE /usr/include/libdwarf/)
else()
        set(MVEE_INCLUDE_DIRS ${MVEE_INCLUDE_DIRS}
                PRIVATE ${CMAKE_SOURCE_DIR}/deps/jsoncpp/include
                PRIVATE ${CMAKE_SOURCE_DIR}/deps/libdwarf/libdwarf
                PRIVATE ${CMAKE_SOURCE_DIR}/deps/binutils/zlib)
endif()

# ======================================================================================================================


# mvee executable ======================================================================================================

# binary definition
add_executable(mvee
        ${MVEE_SOURCES}
)

add_dependencies(mvee
        linking
        syscall_tables
)

# include directories for mvee executable
target_include_directories(mvee ${MVEE_INCLUDE_DIRS})

# link dwarf, elf, and jsoncpp
if(DEPS_PRESENT_IN_SYSTEM)
        target_link_libraries(mvee
                PRIVATE jsoncpp
                PRIVATE dwarf
                PRIVATE elf
                PRIVATE z
        )
else()
        target_link_libraries(mvee PRIVATE
                ${CMAKE_SOURCE_DIR}/deps/jsoncpp/build/src/lib_json/libjsoncpp.a
                ${CMAKE_SOURCE_DIR}/deps/libdwarf/libdwarf/.libs/libdwarf.a
                ${CMAKE_SOURCE_DIR}/deps/libelf/lib/libelf.a
                ${CMAKE_SOURCE_DIR}/deps/binutils/build-tree/zlib/libz.a
        )
endif()

# link patched binaries
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
        MVEE_EMULATE_SHARED_MEMORY
        MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING
        #MVEE_SHARED_MEMORY_INSTRUCTION_LOG_FULL
)
# ======================================================================================================================
