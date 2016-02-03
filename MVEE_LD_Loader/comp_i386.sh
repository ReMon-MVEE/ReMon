/usr/local/musl/bin/musl-gcc -ggdb -std=c99 -o MVEE_LD_Loader -static MVEE_LD_Loader.c -T linkerscript_i386.txt
cp MVEE_LD_Loader MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib_slash_ld-linux.so.2_times_two
