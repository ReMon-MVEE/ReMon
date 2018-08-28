../deps/musl-install/bin/musl-gcc -I./arm/ -marm -mthumb-interwork -fuse-ld=bfd -std=c99 -o MVEE_LD_Loader -static MVEE_LD_Loader.c -T linkerscript_arm.txt
cp MVEE_LD_Loader MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib_slash_ld-linux-armhf.so.3_times_two
chmod a+x MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib_slash_ld-linux-armhf.so.3_times_two
