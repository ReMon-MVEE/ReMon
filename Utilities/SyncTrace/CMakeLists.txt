set(DYNAMORIO_DIR ${CMAKE_SOURCE_DIR}/deps/dynamorio CACHE PATH "Path to the DynamoRIO installation.")
set(DynamoRIO_DIR ${DYNAMORIO_DIR}/cmake)

find_package(DynamoRIO)
if (DynamoRIO_FOUND)
    add_library(SyncTrace SHARED SyncTrace.cpp)
    configure_DynamoRIO_client(SyncTrace)
    use_DynamoRIO_extension(SyncTrace drcontainers)
    use_DynamoRIO_extension(SyncTrace drmgr)
    use_DynamoRIO_extension(SyncTrace droption)
    use_DynamoRIO_extension(SyncTrace drsyms)
    use_DynamoRIO_extension(SyncTrace drwrap)

    # Add compiler definitions to mvee for SyncTrace support
    target_compile_definitions(mvee PRIVATE
            DYNAMORIO_DIR="${DYNAMORIO_DIR}"
            SYNCTRACE_LIB="$<TARGET_FILE:SyncTrace>"
    )
endif(DynamoRIO_FOUND)
