add_executable(MVEE_backtrace
    MVEE_backtrace.c
)
get_target_property(MVEE_NAME mvee OUTPUT_NAME)
target_compile_definitions(MVEE_backtrace PRIVATE
    MVEE="${MVEE_NAME}"
)
