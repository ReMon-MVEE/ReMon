cmake_minimum_required(VERSION 3.10.2)
project("instruction testing")


# force debug ==========================================================================================================
set(CMAKE_BUILD_TYPE "Debug")
# force debug ==========================================================================================================


# constants ============================================================================================================
set(OUTPUT_DIR
        ${CMAKE_SOURCE_DIR}/bin
)
set(SHARED_TEST_FILE
        shared_file
)
set(SHARED_TEST_SINK
        shared_sink
)
set(SHARED_TEST_SIZE
        8192
)

# constants ============================================================================================================


# test file ============================================================================================================
add_custom_target(test_files
        DEPENDS ${SHARED_TEST_FILE}
                ${SHARED_TEST_SINK})

add_custom_command(
        OUTPUT  ${SHARED_TEST_FILE}
                ${SHARED_TEST_SINK}
        COMMAND python3 ${CMAKE_SOURCE_DIR}/scripts/create_shared_mem_file.py
                        ${SHARED_TEST_FILE}
                        ${SHARED_TEST_SINK}
                        ${SHARED_TEST_SIZE}

)
# test file ============================================================================================================



# source definitions ===================================================================================================
file(GLOB SOURCES
        "${CMAKE_SOURCE_DIR}/src/*.cpp"
)

file(GLOB HEADERS
        "${CMAKE_SOURCE_DIR}/inc/*.h"
)
# source definitions ===================================================================================================


# constants ============================================================================================================
set(SETUP
        SETUP_BYTE
        SETUP_WORD
        SETUP_DWORD
        SETUP_QWORD
        SETUP_DECABYTE
        SETUP_DQWORD
        SETUP_BIGCHUNGUS
)

set(CONFIG
        #TEST_FUNCTIONALITY
        LOG
        LOG_FILE="log.log"
        SHARED_SIZE=${SHARED_TEST_SIZE}
        SHARED_FILE="${SHARED_TEST_FILE}"
        SHARED_SINK="${SHARED_TEST_SINK}"
        MEMFD
)
# constants ============================================================================================================


# binary definition ====================================================================================================
add_executable(instruction_tests
        ${SOURCES}
)

add_dependencies(instruction_tests
        test_files
)

target_include_directories(instruction_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/inc
)

target_compile_definitions(instruction_tests PRIVATE
        ${SETUP}
        ${CONFIG}
)

target_link_libraries(instruction_tests PRIVATE
        -lstdc++
        -lrt
)

set_target_properties(instruction_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/
)
# binary definition ====================================================================================================