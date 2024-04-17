enable_language(ASM)
option(PassRbPointerExplicitly "Pass the pointer to the replication buffer explicitly to the IP-MON enclave." ON)

set(generated_headers_list
  ${CMAKE_CURRENT_SOURCE_DIR}/MVEE_ipmon_maybe_checked.h
  ${CMAKE_CURRENT_SOURCE_DIR}/MVEE_ipmon_is_unsynced.h
  ${CMAKE_CURRENT_SOURCE_DIR}/MVEE_ipmon_precall.h
  ${CMAKE_CURRENT_SOURCE_DIR}/MVEE_ipmon_calcsize.h
  ${CMAKE_CURRENT_SOURCE_DIR}/MVEE_ipmon_postcall.h
)

add_custom_command(
  OUTPUT  ${generated_headers_list}
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/generate_headers.rb
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/MVEE_ipmon.cpp
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(generated_headers
  DEPENDS ${generated_headers_list}
)

add_library(ipmon SHARED
  MVEE_ipmon.cpp
  MVEE_ipmon_syscall.S
)

add_dependencies(ipmon
  generated_headers
)

target_compile_definitions(ipmon PRIVATE
    $<$<BOOL:${PassRbPointerExplicitly}>:IPMON_PASS_RB_POINTER_EXPLICITLY>
    $<$<BOOL:${IpmonPmveeHandling}>:IPMON_PMVEE_HANDLING>
)

target_compile_options(ipmon PRIVATE
  -ffixed-r12
  -fPIC
  -fvisibility=hidden
)

target_link_options(ipmon PRIVATE
  -fPIC
  $<$<CONFIG:RELEASE>:-s>
  -z noexecstack
)

target_link_libraries(ipmon PRIVATE
  dl
  c
)

set_target_properties(ipmon PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
