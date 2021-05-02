cmake_minimum_required (VERSION 3.10.2)
project(remon)

if (NOT CMAKE_BUILD_TYPE)
        message(STATUS "CMAKE_BUILD_TYPE not defined. Defaulting to Release.")
        set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release" FORCE)
endif()

if(DEFINED ENV{MVEE_DEPS_PRESENT_IN_SYSTEM})
        set(DEPS_PRESENT_IN_SYSTEM TRUE)
endif()

# Set the output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

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
        DEPENDS ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/MVEE_syscall_alias_locks.h
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/MVEE_syscall_handler_prototypes.h
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/MVEE_syscall_handler_table.h
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/MVEE_syscall_string_table.h
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/MVEE_numcalls.h
        COMMENT "Generating syscall tables"
)

add_custom_command(
        OUTPUT  ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/MVEE_syscall_alias_locks.h
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/MVEE_syscall_handler_prototypes.h
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/MVEE_syscall_handler_table.h
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/MVEE_syscall_string_table.h
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/MVEE_numcalls.h
        COMMAND ${CMAKE_SOURCE_DIR}/build_scripts/generate_syscall_tables.rb
        DEPENDS ${CMAKE_SOURCE_DIR}/MVEE/Src/MVEE_syscalls_handlers.cpp ${UNISTD_HDR}
)

# generate shared memory access table
add_custom_target(shm_table
        DEPENDS ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/shared_mem/shared_memory_emulation_table.h
        COMMENT "Generating syscall tables"
)

add_custom_command(
        OUTPUT  ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/shared_mem/shared_memory_emulation_table.h
        COMMAND python ${CMAKE_SOURCE_DIR}/build_scripts/generate_shm_table.py
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/shared_mem/shared_memory_emulation.h
                ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/shared_mem/shared_memory_emulation_table.h
        DEPENDS ${CMAKE_SOURCE_DIR}/MVEE/Inc/arch/${ARCH}/shared_mem/shared_memory_emulation.h
)

if(DEPS_PRESENT_IN_SYSTEM)
    set(MUSL_GCC musl-gcc)
else()
    set(MUSL_GCC ${CMAKE_SOURCE_DIR}/deps/musl-install/bin/musl-gcc)
endif()

# ======================================================================================================================


# custom targets =======================================================================================================

add_custom_target(
        debug
        COMMAND "${CMAKE_COMMAND}" ..
            -DCMAKE_BUILD_TYPE=Debug
            -DBenchmarkMode=OFF
)

add_custom_target(
        release
        COMMAND "${CMAKE_COMMAND}" .. 
            -DCMAKE_BUILD_TYPE=Release
            -DBenchmarkMode=ON
)

add_custom_target(
        emulate-shm
        COMMAND "${CMAKE_COMMAND}" ..
            -DEmulateCPUID=ON
            -DEmulateShm=ON
            -DLogNonInstrumentedIns=ON
            -DShmInsLogging=OFF
            -DShmInsLoggingFull=OFF
            -DShmReplayLeader=ON
)

add_custom_target(
        block-shm
        COMMAND "${CMAKE_COMMAND}" ..
            -DEmulateCPUID=ON
            -DEmulateShm=OFF
            -DLogNonInstrumentedIns=ON
            -DShmInsLogging=OFF
            -DShmInsLoggingFull=OFF
            -DShmReplayLeader=ON
)

add_custom_target(
        trace-shm
        COMMAND "${CMAKE_COMMAND}" ..
            -DEmulateCPUID=ON
            -DEmulateShm=ON
            -DLogNonInstrumentedIns=ON
            -DShmInsLogging=ON
            -DShmInsLoggingFull=OFF
            -DShmReplayLeader=ON
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
        syscall_tables
        shm_table
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
        $<$<CXX_COMPILER_ID:Clang>:-no-integrated-as>
)

# output override
set_target_properties(mvee PROPERTIES
        OUTPUT_NAME mvee
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
            -O3
            -ffast-math
            -std=c++14
            -static
            -fvisibility=hidden
    )
endif()


# ----------------------------------------------------------------------------------------------------------------------
if (BenchmarkMode)
    set(LogNonInstrumentedIns OFF)
endif()
# ----------------------------------------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------------------------------------
option(BenchmarkMode "Run MVEE in Benchmark mode." OFF)
option(EmulateCPUID "Emulate CPUID instruction." ON)
option(EmulateShm "Emulate shared memory." ON)
option(LogNonInstrumentedIns "Log non-instrumented instructions using shared memory." ON)
option(ShmAllowPtrDiff "Allow pointers to be written to shared memory." ON)
option(ShmAllowShadow "Allow variants to allocate shadow memory." ON)
option(ShmInsLogging "Log instructions using shared memory." ON)
option(ShmInsLoggingFull "Log instructions using shared memory with more verbosity." OFF)
option(ShmReplayLeader "Modifies replaying of shared memory instructions to follow leader-follower principle." ON)
target_compile_definitions(mvee PRIVATE
    $<$<BOOL:${BenchmarkMode}>:MVEE_BENCHMARK>
    $<$<BOOL:${EmulateCPUID}>:MVEE_EMULATE_CPUID>
    $<$<BOOL:${EmulateShm}>:MVEE_EMULATE_SHARED_MEMORY>
    $<$<BOOL:${EmulateShm}>:MVEE_ALLOW_SHM>
    $<$<BOOL:${LogNonInstrumentedIns}>:MVEE_LOG_NON_INSTRUMENTED_INSTRUCTION>
    $<$<BOOL:${ShmAllowPtrDiff}>:MVEE_ALLOW_SHM_PTR_DIFF>
    $<$<BOOL:${ShmAllowShadow}>:MVEE_SHM_ALLOW_SHADOW>
    $<$<BOOL:${ShmInsLogging}>:MVEE_SHARED_MEMORY_INSTRUCTION_LOGGING>
    $<$<BOOL:${ShmInsLoggingFull}>:MVEE_SHARED_MEMORY_INSTRUCTION_LOG_FULL>
    $<$<BOOL:${ShmReplayLeader}>:MVEE_SHARED_MEMORY_REPLAY_LEADER>
    #MVEE_LOG_ALL_SHM_INSTRUCTIONS
)
# ======================================================================================================================
add_subdirectory(libsync)
add_subdirectory(MVEE_LD_Loader)
add_subdirectory(Utilities)
