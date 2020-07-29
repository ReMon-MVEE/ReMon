set(LIBSYNC_NAME clang_rt.sync-${ALT_ARCH})
add_library(${LIBSYNC_NAME} MODULE
    libsync.cpp
)
target_link_libraries(${LIBSYNC_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/libc.so.6
)
set_target_properties(${LIBSYNC_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/patched_binaries/libc/${ARCH}/
)
